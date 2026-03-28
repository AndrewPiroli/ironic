#!/usr/bin/env python3
"""aes_test_chunked.py

Encrypt/decrypt a 0x500-byte buffer in 0x100-byte chunks and verify
the final result matches a host-side AES-CBC operation. Prints only
per-chunk IV values and a final match/mismatch result.

Usage: run next to the running emulator where pyronic is available.
"""

import sys
from pathlib import Path

try:
    from Crypto.Cipher import AES
except Exception:
    try:
        from Cryptodome.Cipher import AES
    except Exception as e:
        print('PyCryptodome not available. Install into your virtualenv with:')
        print(f'  {sys.executable} -m pip install pycryptodome')
        sys.exit(2)

# Try to import local pyronic package (two levels up from tests/aes)
local_pkg_root = str(Path(__file__).resolve().parents[2])
sys.path.insert(0, local_pkg_root)
from pyronic.client import IPCClient


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


def chunked_process(fd: int, ipc: 'IPCClient', encrypt: bool = True) -> int:
    CHUNK = 0x100
    TOTAL = 0x500

    PLAINTEXT = bytes((i & 0xFF) for i in range(TOTAL))
    KEY = bytes.fromhex('00112233445566778899aabbccddeeff')
    IV = bytes.fromhex('0102030405060708090a0b0c0d0e0f10')

    # Host-side expected ciphertext for the entire buffer
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    expected_ct = cipher.encrypt(PLAINTEXT)

    fmt = 'dd:dd'
    IOCTL_ENCRYPT = 2
    IOCTL_DECRYPT = 3

    # Create a reusable key handle
    key_h = make_handle(ipc, KEY)

    # Encrypt (or decrypt) in chunks
    device_chunks = []
    cur_iv = IV
    for i in range(0, TOTAL, CHUNK):
        blk = PLAINTEXT[i:i+CHUNK]
        in_h = make_handle(ipc, blk) if encrypt else make_handle(ipc, expected_ct[i:i+CHUNK])
        out_h = ipc.alloc_raw(len(blk))
        iv_h = make_handle(ipc, cur_iv)

        try:
            if encrypt:
                rc = ipc.IOSIoctlv(fd, IOCTL_ENCRYPT, fmt, in_h, key_h, out_h, iv_h)
            else:
                rc = ipc.IOSIoctlv(fd, IOCTL_DECRYPT, fmt, in_h, key_h, out_h, iv_h)
        except Exception as e:
            print('IOSIoctlv failed:', e)
            return 3
        if rc < 0:
            print('Device ioctl returned error', rc)
            return 4

        chunk_out = out_h.read()
        if not chunk_out or len(chunk_out) < len(blk):
            print('Short/empty chunk readback:', i, chunk_out)
            return 5
        chunk_out = chunk_out[:len(blk)]
        device_chunks.append(chunk_out)

        # Read back the (possibly updated) IV from the iv handle
        new_iv = iv_h.read()
        if not new_iv or len(new_iv) < 16:
            print('Short/empty IV readback on chunk', i)
            return 6
        cur_iv = new_iv[:16]
        print(f'chunk {i//CHUNK}: iv {cur_iv.hex()}')

    device_result = b''.join(device_chunks)

    if encrypt:
        if device_result == expected_ct:
            print('Encryption: OK — final ciphertext matches host expected')
            return 0
        else:
            print('Encryption: MISMATCH — final ciphertext differs from host expected')
            return 1
    else:
        # Decrypted result should equal original plaintext
        if device_result == PLAINTEXT:
            print('Decryption: OK — final plaintext matches original')
            return 0
        else:
            print('Decryption: MISMATCH — final plaintext differs from original')
            return 1


def main():
    ipc = IPCClient()
    fd = ipc.IOSOpen('/dev/aes')
    if fd < 0:
        print('Failed to open /dev/aes, rc=', fd)
        return 2

    # Run both encrypt and decrypt checks
    rc = chunked_process(fd, ipc, encrypt=True)
    if rc != 0:
        return rc
    # Now decrypt the device-produced ciphertext in chunks and verify
    return chunked_process(fd, ipc, encrypt=False)


if __name__ == '__main__':
    sys.exit(main())
