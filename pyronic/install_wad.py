#!/usr/bin/env python3
import os
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterable

from pyronic.client import IPCClient
from pyronic.ios import ES, FS


ALIGNMENT = 0x40
BLOCK_SIZE = 0x4000
SHARED_CONTENT = 0x8000

WAD_HEADER = struct.Struct(">IHHIIIIII")
TMD_CONTENT = struct.Struct(">IHHQ20s")
SIGNATURE_SIZES = {
    0x00010000: 0x240,  # RSA-4096
    0x00010001: 0x140,  # RSA-2048
    0x00010002: 0x080,  # ECDSA
}


class WadError(Exception):
    """A malformed WAD or failed ES operation."""


@dataclass(frozen=True)
class Content:
    cid: int
    index: int
    kind: int
    size: int
    sha1: bytes
    wad_offset: int

    @property
    def encrypted_size(self) -> int:
        return align_up(self.size, ALIGNMENT)


@dataclass(frozen=True)
class Wad:
    path: Path
    certificates: bytes
    crl: bytes
    ticket: bytes
    tmd: bytes
    title_id: int
    contents: tuple[Content, ...]


def align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def signature_payload_offset(blob: bytes, description: str) -> int:
    if len(blob) < 4:
        raise WadError(f"{description} is too short to contain a signature")
    signature_type = struct.unpack_from(">I", blob)[0]
    try:
        return SIGNATURE_SIZES[signature_type]
    except KeyError as exc:
        raise WadError(f"{description} has unknown signature type 0x{signature_type:08x}") from exc


def read_exact(fp: BinaryIO, offset: int, size: int, description: str) -> bytes:
    fp.seek(offset)
    data = fp.read(size)
    if len(data) != size:
        raise WadError(f"short read for {description}: wanted {size} bytes at 0x{offset:x}, got {len(data)}")
    return data


def parse_wad(path: os.PathLike[str] | str) -> Wad:
    wad_path = Path(path)
    try:
        file_size = wad_path.stat().st_size
        fp = wad_path.open("rb")
    except OSError as exc:
        raise WadError(f"cannot open {wad_path}: {exc}") from exc

    with fp:
        raw_header = read_exact(fp, 0, WAD_HEADER.size, "WAD header")
        (
            header_len,
            wad_type,
            padding,
            certs_len,
            crl_len,
            ticket_len,
            tmd_len,
            data_len,
            _footer_len,
        ) = WAD_HEADER.unpack(raw_header)

        if header_len != 0x20 or wad_type != 0x4973 or padding != 0:
            raise WadError("invalid WAD header (expected a standard installable WAD)")

        offset = align_up(header_len, ALIGNMENT)
        certificates = read_exact(fp, offset, certs_len, "certificate chain")
        offset += align_up(certs_len, ALIGNMENT)
        crl = read_exact(fp, offset, crl_len, "certificate revocation list")
        offset += align_up(crl_len, ALIGNMENT)
        ticket = read_exact(fp, offset, ticket_len, "ticket")
        offset += align_up(ticket_len, ALIGNMENT)
        tmd = read_exact(fp, offset, tmd_len, "TMD")
        offset += align_up(tmd_len, ALIGNMENT)
        data_offset = offset

        tik_payload = signature_payload_offset(ticket, "ticket")
        tmd_payload = signature_payload_offset(tmd, "TMD")
        if tik_payload + 0xA4 > len(ticket):
            raise WadError("ticket payload is truncated")
        if tmd_payload + 0xA4 > len(tmd):
            raise WadError("TMD payload is truncated")

        ticket_title_id = struct.unpack_from(">Q", ticket, tik_payload + 0x9C)[0]
        title_id = struct.unpack_from(">Q", tmd, tmd_payload + 0x4C)[0]
        content_count = struct.unpack_from(">H", tmd, tmd_payload + 0x9E)[0]
        expected_tmd_len = tmd_payload + 0xA4 + content_count * TMD_CONTENT.size
        if expected_tmd_len != len(tmd):
            raise WadError(f"TMD length mismatch: header says {len(tmd)}, metadata requires {expected_tmd_len}")
        if ticket_title_id != title_id:
            raise WadError(f"ticket title ID {ticket_title_id:016x} does not match TMD {title_id:016x}")

        contents = []
        content_offset = data_offset
        records_offset = tmd_payload + 0xA4
        for number in range(content_count):
            record_offset = records_offset + number * TMD_CONTENT.size
            cid, index, kind, size, sha1 = TMD_CONTENT.unpack_from(tmd, record_offset)
            content = Content(cid, index, kind, size, sha1, content_offset)
            contents.append(content)
            content_offset += content.encrypted_size

        required_data_len = content_offset - data_offset
        if required_data_len > data_len:
            raise WadError(f"content records require {required_data_len} bytes, but the WAD header declares {data_len}")
        if data_offset + data_len > file_size:
            raise WadError("WAD data section extends past the end of the host file")

    return Wad(
        wad_path,
        certificates,
        crl,
        ticket,
        tmd,
        title_id,
        tuple(contents),
    )


def es_call(ipc: IPCClient, esfd: int, command: ES, fmt: str, *args) -> int:
    return ipc.IOSIoctlv(esfd, command, fmt, *args, quiet=True)


def read_shared_hashes(ipc: IPCClient) -> set[bytes]:
    """Return hashes in /shared1/content.map, or an empty set if unavailable."""
    fd = ipc.IOSOpen("/shared1/content.map", 1)
    if fd < 0:
        return set()

    try:
        stats = ipc.alloc_raw(8)
        result = ipc.IOSIoctl(fd, FS.GetFileStats, ipc.alloc_raw(0), stats)
        if result < 0:
            return set()
        size = struct.unpack(">II", stats.read())[0]
        if size % 28:
            return set()

        hashes = set()
        remaining = size
        carry = b""
        buffer = ipc.alloc_raw(BLOCK_SIZE)
        while remaining:
            amount = min(remaining, BLOCK_SIZE)
            result = ipc.IOSRead(fd, buffer, amount)
            if result != amount:
                return set()
            data = carry + buffer.read(amount)
            complete = len(data) - (len(data) % 28)
            for offset in range(0, complete, 28):
                hashes.add(data[offset + 8 : offset + 28])
            carry = data[complete:]
            remaining -= amount
        return hashes
    finally:
        ipc.IOSClose(fd)


def selected_contents(wad: Wad, shared_hashes: set[bytes]) -> Iterable[Content]:
    for content in wad.contents:
        if content.kind & SHARED_CONTENT and content.sha1 in shared_hashes:
            print(f"Skipping existing shared content #{content.cid:08x}")
            continue
        yield content


def install_wad(wad: Wad, ipc: IPCClient) -> None:
    esfd = ipc.IOSOpen("/dev/es")
    if esfd < 0:
        raise WadError(f"IOS_Open(/dev/es) failed: {esfd}")

    title_started = False
    try:
        certs = ipc.alloc_buf(wad.certificates)
        crl = ipc.alloc_buf(wad.crl)
        ticket = ipc.alloc_buf(wad.ticket)
        tmd = ipc.alloc_buf(wad.tmd)

        print(f"Installing ticket for {wad.title_id:016x}...")
        result = es_call(ipc, esfd, ES.AddTicket, "ddd:", ticket, certs, crl)
        if result < 0:
            raise WadError(f"ES_AddTicket failed: {result}")

        print("Starting title installation...")
        result = es_call(ipc, esfd, ES.AddTitleStart, "dddi:", tmd, certs, crl, 1)
        if result < 0:
            raise WadError(f"ES_AddTitleStart failed: {result}")
        title_started = True

        shared_hashes = read_shared_hashes(ipc)
        with wad.path.open("rb") as fp:
            for content in selected_contents(wad, shared_hashes):
                print(f"Installing content #{content.cid:08x} ({content.encrypted_size} bytes)...")
                content_fd = es_call(ipc, esfd, ES.AddContentStart, "qi:", wad.title_id, content.cid)
                if content_fd < 0:
                    raise WadError(f"ES_AddContentStart({content.cid:08x}) failed: {content_fd}")

                try:
                    fp.seek(content.wad_offset)
                    remaining = content.encrypted_size
                    while remaining:
                        amount = min(remaining, BLOCK_SIZE)
                        data = fp.read(amount)
                        if len(data) != amount:
                            raise WadError(f"short read in content {content.cid:08x}: wanted {amount}, got {len(data)}")
                        data_buffer = ipc.alloc_buf(data)
                        result = es_call(ipc, esfd, ES.AddContentData, "id:", content_fd, data_buffer)
                        if result < 0:
                            raise WadError(f"ES_AddContentData({content.cid:08x}) failed: {result}")
                        remaining -= amount
                except Exception:
                    es_call(ipc, esfd, ES.AddContentFinish, "i:", content_fd)
                    raise

                result = es_call(ipc, esfd, ES.AddContentFinish, "i:", content_fd)
                if result < 0:
                    raise WadError(f"ES_AddContentFinish({content.cid:08x}) failed: {result}")

        print("Finishing title installation...")
        result = es_call(ipc, esfd, ES.AddTitleFinish, "")
        if result < 0:
            raise WadError(f"ES_AddTitleFinish failed: {result}")
        title_started = False
    except Exception:
        if title_started:
            cancel_result = es_call(ipc, esfd, ES.AddTitleCancel, "")
            if cancel_result < 0:
                print(f"Warning: ES_AddTitleCancel failed: {cancel_result}", file=sys.stderr)
        raise
    finally:
        ipc.IOSClose(esfd)


wad = parse_wad(sys.argv[1])
print(f"WAD {wad.path}: title {wad.title_id:016x}, {len(wad.contents)} content(s)")

ipc = IPCClient()
try:
    install_wad(wad, ipc)
finally:
    ipc.shutdown()
print("Installation complete.")
