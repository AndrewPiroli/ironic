#!/usr/bin/env python3
"""aes_test.py

Encrypt and decrypt a 0x100-byte buffer using a static key/IV and
compare host-computed results with the guest `/dev/aes` device via IOCTLV.

Usage: run next to the running emulator where pyronic is available.
"""

import sys
import hashlib
from pathlib import Path

local_pkg_root = str(Path(__file__).resolve().parents[2])
sys.path.insert(0, local_pkg_root)
from pyronic.client import IPCClient

try:
    from Crypto.Cipher import AES
except Exception:
    try:
        from Cryptodome.Cipher import AES
    except Exception as e:
        print('PyCryptodome not available. Install with: pip install pycryptodome', e)
        sys.exit(2)


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
    # Static test vectors
    PLAINTEXT = bytes((i & 0xFF) for i in range(0x100))
    KEY = bytes.fromhex('00112233445566778899aabbccddeeff')
    IV = bytes.fromhex('0102030405060708090a0b0c0d0e0f10')

    # Expected: AES-128-CBC off-host
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    expected_ct = cipher.encrypt(PLAINTEXT)
    print('Prepared plaintext 0x100 bytes')
    print('Expected ciphertext (host) :', expected_ct.hex())

    ipc = IPCClient()
    fd = ipc.IOSOpen('/dev/aes')
    if fd < 0:
        print('Failed to open /dev/aes, rc=', fd)
        return 2
    print('/dev/aes opened as fd', fd)

    # Make handles for input, key, output, iv. AES ioctl expects vectors:
    # Data[0] = input (len), Data[1] = key (0x10), Data[2] = output (len), Data[3] = iv (0x10)
    in_h = make_handle(ipc, PLAINTEXT)
    key_h = make_handle(ipc, KEY)
    out_h = ipc.alloc_raw(len(PLAINTEXT))
    iv_h = make_handle(ipc, IV)

    # Format: two inputs, two io -> "dd:dd" (input argc: outputs after inputs)
    fmt = 'dd:dd'

    # IOCTL 2 == encrypt, 3 == decrypt (matches kernel aes.c)
    IOCTL_ENCRYPT = 2
    IOCTL_DECRYPT = 3

    # Call encrypt
    try:
        rc = ipc.IOSIoctlv(fd, IOCTL_ENCRYPT, fmt, in_h, key_h, out_h, iv_h)
    except Exception as e:
        print('IOSIoctlv encrypt failed:', e)
        return 3
    print('Encrypt rc:', rc)
    if rc < 0:
        print('Device encrypt returned error', rc)
        return 4

    dev_ct = out_h.read()
    if not dev_ct or len(dev_ct) < len(PLAINTEXT):
        print('Short/empty ciphertext readback:', dev_ct)
        return 5
    dev_ct = dev_ct[:len(PLAINTEXT)]
    print('Ciphertext (device)     :', dev_ct.hex())

    if dev_ct == expected_ct:
        print('OK: device ciphertext matches expected')
    else:
        print('Mismatch: device ciphertext differs from expected')

    # Now decrypt the device ciphertext back
    # Write device ciphertext into a fresh input handle to decrypt
    ct_in_h = make_handle(ipc, dev_ct)
    dec_out_h = ipc.alloc_raw(len(PLAINTEXT))
    iv_h2 = make_handle(ipc, IV)
    try:
        rc = ipc.IOSIoctlv(fd, IOCTL_DECRYPT, fmt, ct_in_h, key_h, dec_out_h, iv_h2)
    except Exception as e:
        print('IOSIoctlv decrypt failed:', e)
        return 6
    print('Decrypt rc:', rc)
    if rc < 0:
        print('Device decrypt returned error', rc)
        return 7

    dec = dec_out_h.read()
    if not dec or len(dec) < len(PLAINTEXT):
        print('Short/empty decrypted readback:', dec)
        return 8
    dec = dec[:len(PLAINTEXT)]
    print('Decrypted (device)      :', dec.hex())

    if dec == PLAINTEXT:
        print('OK: device decrypted plaintext matches original')
        return 0
    else:
        print('Mismatch: decrypted plaintext does not match original')
        return 9


if __name__ == '__main__':
    sys.exit(main())
