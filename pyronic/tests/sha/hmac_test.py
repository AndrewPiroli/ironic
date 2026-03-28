#!/usr/bin/env python3
"""sha_ipc_test.py

Reproduce the kernel HMAC sequence (Init/Contribute/Finalize) against /dev/sha
via pyronic IPC, matching the IPC vector layout used by IOSC_GenerateBlockMAC.

IPC vector layout (3 input + 2 IO, fmt "ddd:dd"):
  Data[0] = inputData        (message chunk; NULL/0 for Init and Finalize)
  Data[1] = ShaContext       (0x1C bytes, in/out)
  Data[2] = signData/output  (0x14 bytes, NULL/0 length for Init/Contribute)
  Data[3] = &keyHandle       (4-byte guest buffer containing the u32 handle)
  Data[4] = customData       (salt, 64 bytes for Init ONLY; NULL/0 for the rest)
"""

import hashlib
import hmac
import struct
import sys
import os
from pathlib import Path

local_pkg_root = str(Path(__file__).resolve().parents[2])
sys.path.insert(0, local_pkg_root)
from pyronic.client import IPCClient

KEY_HANDLE = 3  # KEYRING_CONST_NAND_HMAC

# Salt words as used in the kernel selftest (big-endian words)
SALT_WORDS = [0x00000000, 0x73706163, 0x652e7379, 0x73000000,
              0x00000000, 0x0000001c, 0x00000000, 0x00000000]

salt64_be = b"".join(struct.pack(">I", w) for w in SALT_WORDS) + b"\x00" * 32
assert len(salt64_be) == 64

# Full message: salt64 || 16KiB zeros  (what HMAC signs)
MSG = salt64_be + (b"\x00" * (16 * 1024))
print(f"Prepared message: {len(MSG)} bytes (salt64 + 16KiB zeros)")

# Off-host expected HMAC using the OTP-derived NAND HMAC key
script_dir = os.path.dirname(os.path.realpath(__file__))
otp_path = os.path.normpath(os.path.join(script_dir, '../../..', 'otp.bin'))
with open(otp_path, 'rb') as f:
    otp_data = f.read()
if len(otp_data) < 0x58:
    raise RuntimeError(f'otp.bin at {otp_path} is too small (need 0x58 bytes)')
nand_hmac_key = otp_data[0x44:0x58]   # 20-byte NAND HMAC key
EXPECTED = hmac.new(nand_hmac_key, MSG, hashlib.sha1).digest()
print(f"NAND HMAC key     : {nand_hmac_key.hex()}")
print(f"Expected HMAC     : {EXPECTED.hex()}")

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


def ioctlv_hmac(ipc, fd, ioctl, data0_h, ctx_h, out_h, key_h, data4_h):
    """Call /dev/sha with the correct 3-input + 2-IO vector layout.
    """
    return ipc.IOSIoctlv(fd, ioctl, "ddd:dd", data0_h, ctx_h, out_h, key_h, data4_h)


def main():
    ipc = IPCClient()
    fd = ipc.IOSOpen('/dev/sha')
    if fd < 0:
        print('Failed to open /dev/sha, rc=', fd)
        return 2
    print('/dev/sha opened as fd', fd)

    # Allocate all guest buffers up front
    ctx_h   = ipc.alloc_raw(0x1C)   # ShaContext (0x1C bytes)
    out_h   = ipc.alloc_raw(0x14)   # output digest (20 bytes)
    salt_h  = make_handle(ipc, salt64_be)              # 64-byte salt
    z_h     = make_handle(ipc, b'\x00' * 1024)         # 1KiB zero chunk
    dummy_h = ipc.alloc_raw(0)                         # zero-length null vector
    # Data[3]: 4-byte big-endian buffer containing the key handle value
    key_h   = make_handle(ipc, struct.pack('>I', KEY_HANDLE))

    # --- 1. Init ---
    # Data[0]=dummy(0), Data[4]=salt(64)
    print('\n== Init HMAC ==')
    rc = ioctlv_hmac(ipc, fd, 3, dummy_h, ctx_h, out_h, key_h, salt_h)
    print('Init rc:', rc)
    if rc < 0:
        print('Init failed')
        return 3

    # --- 2. Contribute 16KiB in 1KiB chunks ---
    # Data[0]=zchunk(1024), Data[4]=dummy(0)  <-- salt must NOT be passed here
    print('\n== Contribute HMAC (16x 1KiB) ==')
    for i in range(16):
        rc = ioctlv_hmac(ipc, fd, 4, z_h, ctx_h, out_h, key_h, dummy_h)
        if rc < 0:
            print(f'Contribute round {i+1} failed, rc={rc}')
            return 4

    # --- 3. Finalize ---
    # Data[0]=dummy(0), Data[4]=dummy(0)  <-- salt must NOT be passed here either
    print('\n== Finalize HMAC ==')
    rc = ioctlv_hmac(ipc, fd, 5, dummy_h, ctx_h, out_h, key_h, dummy_h)
    print('Finalize rc:', rc)
    if rc < 0:
        print('Finalize failed')
        return 5

    # Read back digest
    try:
        out = out_h.read()
    except Exception:
        out = ipc.guest_read(out_h.paddr, 0x14)

    if not out or len(out) < 0x14:
        print('Short/empty digest readback:', out)
        return 6

    digest = out[:0x14]
    print(f'\nDigest (guest)  : {digest.hex()}')
    print(f'Expected        : {EXPECTED.hex()}')

    if digest == EXPECTED:
        print('OK: digest matches expected')
        return 0

    print('MISMATCH')
    return 7


if __name__ == '__main__':
    sys.exit(main())
