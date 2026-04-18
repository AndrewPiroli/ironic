#!/usr/bin/env python3
from pyronic.client import *
from pyronic.ios import *

if __name__ == "__main__":
    ipc = IPCClient()
    patch_applied = ipc.guest_patch(Patches.Unprotect_FS_Format)
    if patch_applied == 0:
        print("Warning: Unprotect FS Patch did not seem to work. This may fail")
    if patch_applied > 1:
        print("hmm")
    fs = ipc.IOSOpen("/dev/fs")
    inb = ipc.alloc_raw(0)
    iob = ipc.alloc_raw(0)
    res = ipc.IOSIoctl(fs, FS.Format, inb, iob)
    if res == 0:
        print("Your SFFS filesystem is now formatted. IOS is still running and you are free to play around with it.\nDelete your saved-writes folder entry to recover boot.")
    elif res == -102:
        print("EACCESS: Patch didn't work??")
    else:
        print(f"failed {res}")

