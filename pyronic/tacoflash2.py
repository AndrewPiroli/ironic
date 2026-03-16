#!/usr/bin/env python3
"""flash_test.py - read /dev/flash via pyronic IPC, save, write back, verify."""
import os
import sys
import hashlib
import ctypes
import json
from struct import unpack
from dataclasses import dataclass
from typing import Iterable, List, Tuple, Any

from pyronic.client import IPCClient, MemHandle
from pyronic.ios import IPCMsg

READ_PATH     = "nand_flash.bin"
WRITTEN_PATH  = "nand_flash_written.bin"
REFERENCE_PATH = "nand_raw.bin"
BAD_MAP_PATH = "bad_map.json"
BAD_MAP_WRITTEN_PATH = "bad_map_written.json"

# Mirrors NandSizeInformation from IOS (0x1C bytes, big-endian)
class NandSizeInformation(ctypes.BigEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("NandSizeBitShift",       ctypes.c_uint32),  # 0x00
        ("BlockSizeBitShift",      ctypes.c_uint32),  # 0x04
        ("PageSizeBitShift",       ctypes.c_uint32),  # 0x08
        ("EccSizeBitShift",        ctypes.c_uint32),  # 0x0C
        ("HMACSizeShift",          ctypes.c_uint32),  # 0x10
        ("PageCopyMask",           ctypes.c_uint16),  # 0x14
        ("SupportPageCopy",        ctypes.c_uint16),  # 0x16
        ("EccDataCheckByteOffset", ctypes.c_uint16),  # 0x18
        ("Padding",                ctypes.c_uint16),  # 0x1A
    ]

_IOCTL_GET_STATS = 1

@dataclass
class BadMapEntry:
    block: int
    page: int
    offset: int
    size: int

    def to_dict(self) -> dict:
        # Write offset as hex string (including 0x) for easier human inspection
        return {"block": int(self.block), "page": int(self.page), "offset": hex(int(self.offset)), "size": int(self.size)}

    @classmethod
    def from_dict(cls, d: Any) -> "BadMapEntry":
        # Backwards-compat: older files may only contain block/page
        block = int(d.get("block", 0))
        page = int(d.get("page", 0))
        try:
            offset = int(d["offset"], 16)
        except Exception:
            raise ValueError(f"BadMapEntry.offset is not a valid hex string: {d["offset"]!r}")
        size = int(d.get("size", 0))
        return cls(block, page, offset, size)



@dataclass
class ReadResult:
    total: int
    bad_entries: List[BadMapEntry]

@dataclass
class NandStats:
    page_size:       int
    ecc_size:        int
    pages_per_block: int

    @property
    def chunk_size(self) -> int:
        return self.page_size + self.ecc_size

def get_nand_stats(ipc, fd) -> NandStats:
    """Call IOCTL_GET_STATS on /dev/flash and return a NandStats instance."""
    buf_len = ctypes.sizeof(NandSizeInformation)
    h = ipc.alloc_raw(buf_len)
    res = ipc.guest_ipc(IPCMsg(ipc.IPC_IOCTL, fd=fd,
                               args=[_IOCTL_GET_STATS, 0, 0, h.paddr, buf_len]))
    rb = res.read()
    if len(rb) < 8:
        raise RuntimeError(f"IOCTL_GET_STATS response too short: {rb.hex()}")
    rc = unpack(">i", rb[4:8])[0]
    if rc != 0:
        raise RuntimeError(f"IOCTL_GET_STATS failed: {rc}")
    raw = ipc.guest_read(h.paddr, buf_len)
    if not raw or len(raw) != buf_len:
        raise RuntimeError(f"IOCTL_GET_STATS: short read ({len(raw) if raw else 0} bytes)")
    info = NandSizeInformation.from_buffer_copy(raw)
    stats = NandStats(
        page_size       = 1 << (info.PageSizeBitShift  & 0xFF),
        ecc_size        = 1 << (info.EccSizeBitShift   & 0xFF),
        pages_per_block = 1 << ((info.BlockSizeBitShift - info.PageSizeBitShift) & 0xFF),
    )
    print(f"  NAND stats: page_size=0x{stats.page_size:x} ecc_size=0x{stats.ecc_size:x} "
          f"chunk_size=0x{stats.chunk_size:x} pages_per_block={stats.pages_per_block}")
    return stats


def human(n):
    for u in ("B", "KiB", "MiB", "GiB"):
        if n < 1024.0:
            return f"{n:.1f}{u}"
        n /= 1024.0
    return f"{n:.1f}TiB"


def ipc_read(ipc, fd, h: MemHandle):
    """Send one IPC_READ, return (rc, raw_response_bytes)."""
    res = ipc.guest_ipc(IPCMsg(ipc.IPC_READ, fd=fd, args=[h.paddr, h.size, 0, 0, 0]))
    rb  = res.read()
    if len(rb) < 8:
        raise RuntimeError(f"IPC_READ response too short: {rb.hex()}")
    rc = unpack(">i", rb[4:8])[0]
    return rc, rb


def ipc_write(ipc, fd, chunk, h: MemHandle):
    """Send one IPC_WRITE, raise on error or short write."""
    if h.size != len(chunk):
        raise RuntimeError("h.len() != len(chunk)")
    ipc.guest_write(h.paddr, chunk)
    res = ipc.guest_ipc(IPCMsg(ipc.IPC_WRITE, fd=fd, args=[h.paddr, len(chunk), 0, 0, 0]))
    rb  = res.read()
    if len(rb) < 8:
        raise RuntimeError(f"IPC_WRITE response too short: {rb.hex()}")
    rc = unpack(">i", rb[4:8])[0]
    if rc < 0:
        raise RuntimeError(f"IPC_WRITE failed: {rc}")
    if rc != len(chunk):
        raise RuntimeError(f"Short write: expected {len(chunk)}, got {rc}")
    return rc


def read_entire_nand(ipc, fd, out_path, pages_per_block: int, chunk_size: int) -> ReadResult:
    total = 0
    bad_entries: List[BadMapEntry] = []
    print(f"Reading NAND to {out_path}...")
    h = ipc.alloc_raw(chunk_size)
    zeroed = bytearray(chunk_size)
    with open(out_path, "wb") as f:
        while True:
            # memset
            ipc.guest_write(h.paddr, zeroed)
            rc, _ = ipc_read(ipc, fd, h)

            if rc == -4:
                print(f"  -4 (EINVAL) at 0x{total:08x} — end of flash, stopping")
                break

            if rc in (-11, -12):
                page  = total // chunk_size

                # Only append truly bad pages (rc == -12). Correctable (-11) are not recorded.
                if rc == -12:
                    # Compute block and page-in-block
                    block = page // pages_per_block
                    page_in_block = page % pages_per_block
                    bad_entries.append(BadMapEntry(block, page_in_block, total, chunk_size))
                label = "bad block" if rc == -12 else "correctable ECC"
                # IOS DMA'd the page data before the ECC check — read it from the guest buffer.
                data  = ipc.guest_read(h.paddr, chunk_size)
                if not data or len(data) != chunk_size:
                    raise RuntimeError(
                        f"{label} at 0x{total:08x} (page 0x{page:06x}): "
                        f"guest_read returned {len(data) if data else 0} bytes, expected {chunk_size}"
                    )
                print(f"  {label} at 0x{total:08x} (page 0x{page:06x}), saved DMA data")
                f.write(data)
                total += chunk_size
                # IOS only advances NandPosition on IPC_SUCCESS, so seek past the stuck page manually.
                ipc.guest_ipc(IPCMsg(ipc.IPC_SEEK, fd=fd, args=[1, 1, 0, 0, 0]))
                continue

            if rc < 0:
                raise RuntimeError(f"IPC_READ failed: {rc} at 0x{total:08x}")

            if rc == 0:
                break

            data = ipc.guest_read(h.paddr, rc)
            if not data:
                raise RuntimeError(f"guest_read returned no data (rc={rc}) at 0x{total:08x}")
            if len(data) != rc:
                raise RuntimeError(f"guest_read short: got {len(data)}, expected {rc} at 0x{total:08x}")

            f.write(data)
            total += rc
            print(f"  {human(total)}", end="\r", flush=True)

    print(f"\nDone: {human(total)} => {out_path}")
    return ReadResult(total=total, bad_entries=bad_entries)


def write_entire_nand(ipc, fd, in_path, chunk_size: int):
    size  = os.path.getsize(in_path)
    sent  = 0
    print(f"Writing {human(size)} from {in_path}...")
    h = ipc.alloc_raw(chunk_size)
    with open(in_path, "rb") as f:
        while chunk := f.read(chunk_size):
            # Enforce exact chunk_size writes; throw if last chunk is short
            if len(chunk) != chunk_size:
                raise RuntimeError(f"Unexpected chunk size: {len(chunk)} != {chunk_size}")
            sent += ipc_write(ipc, fd, chunk, h)
            print(f"  {human(sent)}/{human(size)}", end="\r", flush=True)
    print(f"\nDone: {human(sent)} written.")
    return sent


def write_bad_map_file(path: str, entries: Iterable[BadMapEntry]):
    """Write bad page/block mapping to JSON. Each entry maps to BadMapEntry."""
    entries_list = [e.to_dict() for e in entries]
    with open(path, "w") as f:
        json.dump(entries_list, f, separators=(",", ":"))


def read_bad_map_file(path: str) -> List[BadMapEntry]:
    """Read bad-map JSON file and return list of BadMapEntry instances."""
    if not os.path.exists(path):
        return []
    
    with open(path, "r") as f:
        data = json.load(f)
    entries: List[BadMapEntry] = []
    for item in data:
        entries.append(BadMapEntry.from_dict(item))
    return entries


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while b := f.read(1 << 20):
            h.update(b)
    return h.hexdigest()


def count_differences(a_path: str, b_path: str, entries: List[BadMapEntry],
                      pages_per_block: int, chunk_size: int):
    """
    Count byte differences between two files, optionally ignoring pages from a bad-map.
    entries: list of BadMapEntry to ignore (pass empty list to ignore none).
    Returns: (diffs, total_compared)
    """
    ranges: List[Tuple[int, int]] = []
    for entry in entries:
        block = entry.block
        page = entry.page

        start = (block * pages_per_block + page) * chunk_size
        end = start + chunk_size
        ranges.append((start, end))
    ranges.sort()

    diffs = 0
    total = 0
    with open(a_path, "rb") as fa, open(b_path, "rb") as fb:
        block_size = 1 << 20
        offset = 0
        range_idx = 0
        while True:
            a = fa.read(block_size)
            b = fb.read(block_size)
            if not a and not b:
                break
            la = len(a)
            lb = len(b)
            L = max(la, lb)

            block_start = offset
            block_end = offset + L
            cursor = block_start

            while range_idx < len(ranges) and ranges[range_idx][1] <= block_start:
                range_idx += 1

            ri = range_idx
            while ri < len(ranges) and ranges[ri][0] < block_end:
                rstart, rend = ranges[ri]
                comp_start = max(cursor, block_start)
                comp_end = min(rstart, block_end)
                if comp_end > comp_start:
                    si = comp_start - block_start
                    ei = comp_end - block_start
                    aa = a[si:ei]
                    bb = b[si:ei]
                    for x, y in zip(aa, bb):
                        total += 1
                        if x != y:
                            diffs += 1
                cursor = max(cursor, rend)
                ri += 1

            if cursor < block_end:
                si = cursor - block_start
                ei = block_end - block_start
                aa = a[si:ei]
                bb = b[si:ei]
                for x, y in zip(aa, bb):
                    total += 1
                    if x != y:
                        diffs += 1

            offset += L
    return diffs, total


def compare_with_reference(src_path: str, ref_path: str, stats, entries: List[BadMapEntry]):
    """Compare `src_path` against `ref_path` ignoring pages from `entries`.
    Raises RuntimeError if differences are found.
    """
    print(f"\n Comparing {src_path} vs {ref_path}...")
    ref_sha = sha256_file(ref_path)
    read_sha = sha256_file(src_path)
    diffs, total = count_differences(ref_path, src_path, entries, stats.pages_per_block, stats.chunk_size)
    print(f"  SHA-256 reference : {ref_sha}")
    print(f"  SHA-256 source dump : {read_sha}")
    if entries:
        print(f"  Ignored {len(entries)} bad page(s) in comparison")
    print(f"  Byte differences  : {diffs} / {total}")
    if diffs:
        raise RuntimeError(f"source dump differs from {ref_path} ({diffs} byte(s))")
    print("  OK — source dump matches reference (ignoring bad pages).")


def reopen(ipc, fd, label):
    try:
        ipc.IOSClose(fd)
    except Exception:
        pass
    fd = ipc.IOSOpen("/dev/flash")
    if fd < 0:
        raise RuntimeError(f"{label}: IOSOpen failed: {fd}")
    # Reset position to page 0 (SeekSet = 0)
    res = ipc.guest_ipc(IPCMsg(ipc.IPC_SEEK, fd=fd, args=[0, 0, 0, 0, 0]))
    rb = res.read()
    if len(rb) < 8:
        raise RuntimeError(f"{label}: seek(0) response too short: {rb.hex()}")
    rc = unpack(">i", rb[4:8])[0]
    if rc < 0:
        raise RuntimeError(f"{label}: seek(0) failed: {rc}")
    return fd


def compare_files(src_path: str, ref_path: str, stats: NandStats, entries: List[BadMapEntry]):
    if not os.path.exists(src_path):
        raise RuntimeError(f"Source file {src_path} not found for comparison.")
    if not os.path.exists(ref_path):
        raise RuntimeError(f"Reference file {ref_path} not found for comparison.")

    print(f"  Comparing {src_path} vs {ref_path}...")
    ref_sha  = sha256_file(ref_path)
    read_sha = sha256_file(src_path)
    diffs, total = count_differences(ref_path, src_path, entries, stats.pages_per_block, stats.chunk_size)
    print(f"  SHA-256 reference : {ref_sha}")
    print(f"  SHA-256 source dump : {read_sha}")
    if entries:
        print(f"  Ignored {len(entries)} bad page(s) in comparison")
    print(f"  Byte differences  : {diffs} / {total}")
    if diffs:
        raise RuntimeError(f"source dump differs from {ref_path} ({diffs} byte(s))")
    print("  OK — source dump matches reference (ignoring bad pages).")

def main():
    ipc = IPCClient()
    fd  = None
    try:
        print("Opening /dev/flash...")
        fd = ipc.IOSOpen("/dev/flash")
        if fd < 0:
            raise RuntimeError(f"IOSOpen failed: {fd}")
        print(f"fd={fd}")

        print("Fetching NAND stats via IOCTL_GET_STATS...")
        stats = get_nand_stats(ipc, fd)

        # Step 1: read & compare dump against reference NAND binary
        first_read = read_entire_nand(ipc, fd, READ_PATH, stats.pages_per_block, stats.chunk_size)
        write_bad_map_file(BAD_MAP_PATH, first_read.bad_entries)
        compare_files(READ_PATH, REFERENCE_PATH, stats, read_bad_map_file(BAD_MAP_PATH))

        # Step 2: write read dump back to flash
        print("\n[Step 2] Writing back to /dev/flash...")
        fd = reopen(ipc, fd, "write reopen")
        written = write_entire_nand(ipc, fd, READ_PATH, stats.chunk_size)
        if written != os.path.getsize(READ_PATH):
            raise RuntimeError(f"Written size {written} != file size {os.path.getsize(READ_PATH)}")
        print(f"  OK — wrote {human(written)} of {human(os.path.getsize(READ_PATH))} to /dev/flash.")
        print("  OK — write completed.")

        # Step 3: re-read and compare against the original dump
        print("\n[Step 3] Re-reading flash for verification...")
        fd = reopen(ipc, fd, "verify reopen")
        read = read_entire_nand(ipc, fd, WRITTEN_PATH, stats.pages_per_block, stats.chunk_size)
        write_bad_map_file(BAD_MAP_WRITTEN_PATH, read.bad_entries)

        entries = read_bad_map_file(BAD_MAP_PATH)
        compare_files(WRITTEN_PATH, READ_PATH, stats, entries)

        print("\nAll steps passed — verification successful.")
        return 0

    except Exception as e:
        print(f"Error: {e}")
        return 1
    finally:
        try:
            if fd is not None:
                ipc.IOSClose(fd)
            ipc.shutdown()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())

