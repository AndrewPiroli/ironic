#!/usr/bin/env python3
"""sha_raw_test.py

Compute SHA-1 over a 16512-byte input (ipad + salt64 + 16KiB zeros) and
ask the guest `/dev/sha` to compute the same digest via IOCTLV.

Usage: run next to the running emulator where pyronic is available.
"""

import struct
import hashlib
import sys
from pathlib import Path

local_pkg_root = str(Path(__file__).resolve().parents[2])
sys.path.insert(0, local_pkg_root)
from pyronic.client import IPCClient

DATA_PREFIX = bytes.fromhex('af56212ba96292921414fc805e9cc71fbf78cef0')
SALT_WORDS = [0x00000000, 0x73706163, 0x652e7379, 0x73000000,
              0x00000000, 0x0000001c, 0x00000000, 0x00000000]
salt64_be = b"".join(struct.pack(">I", w) for w in SALT_WORDS) + b"\x00" * 32

data_block = DATA_PREFIX + b"\x00" * (64 - len(DATA_PREFIX))
data_begin = bytes((b ^ 0x36) for b in data_block)

# Message: data + salt + zeroes
MSG = data_begin + salt64_be + (b"\x00" * (16 * 1024))

print(f"Prepared message: {len(MSG)} bytes")

# Compute expected SHA1 off-host
expected = hashlib.sha1(MSG).digest()
print('Expected SHA1:', expected.hex())

def make_handle(ipc, data: bytes):
    h = ipc.alloc_raw(len(data))
    try:
        h.write(data)
    except Exception:
        if hasattr(ipc, 'guest_write'):
            ipc.guest_write(h.paddr, data)
        else:
            raise
    return h


def main():
    ipc = IPCClient()
    fd = ipc.IOSOpen('/dev/sha')
    if fd < 0:
        print('Failed to open /dev/sha, rc=', fd)
        return 2
    print('/dev/sha opened as fd', fd)

    data_h = make_handle(ipc, MSG)
    ctx_h = ipc.alloc_raw(0x1C)
    out_h = ipc.alloc_raw(0x14)

    # Use fmt: one input 'd', two outputs 'd d' -> "d:dd"
    fmt = 'd:dd'

    # InitShaState (ioctl 0): seeds ShaContext with the SHA-1 initial state
    # and zeros Length.  Input must be < 64 bytes so no blocks are processed.
    init_h = make_handle(ipc, b'\x00')
    try:
        rc = ipc.IOSIoctlv(fd, 0, fmt, init_h, ctx_h, out_h)
    except Exception as e:
        print('IOSIoctlv InitShaState failed:', e)
        return 3
    if rc < 0:
        print('InitShaState failed, rc=', rc)
        return 3
    print('InitShaState rc:', rc)

    # FinalizeShaState (ioctl 2): process + finalize the full message
    try:
        rc = ipc.IOSIoctlv(fd, 2, fmt, data_h, ctx_h, out_h)
    except Exception as e:
        print('IOSIoctlv FinalizeShaState failed:', e)
        return 3
    print('FinalizeShaState rc:', rc)

    if rc < 0:
        print('FinalizeShaState failed, rc=', rc)
        return 4

    out = out_h.read()
    if not out or len(out) < 0x14:
        print('Short/empty digest readback:', out)
        return 5

    digest = out[:0x14]
    # Use the raw bytes returned by the guest/device for comparison.
    # Previous per-4-byte reversal caused an incorrect byte-ordering.
    print('SHA1 (guest) :', digest.hex())
    if digest == expected:
        print('OK: guest SHA1 matches expected')
        return 0
    else:
        print('Mismatch')
        return 6

if __name__ == '__main__':
    sys.exit(main())
