#!/usr/bin/env python3

from struct import pack, unpack
from hexdump import hexdump
from pyronic.client import *
from sys import argv

if len(argv) < 2:
    print("Please provide a directory to list!")
    exit(1)

MAX_FILES = 200
ipc = IPCClient()

fs = ipc.IOSOpen("/dev/fs")
print(f"fd={fs}")

name = ipc.alloc_raw(0x40)
name.write(argv[1].encode("utf8") + b"\00")
maxcnt = ipc.alloc_raw(4)
maxcnt.write(pack(">L", MAX_FILES))
retnames = ipc.alloc_raw(13 * MAX_FILES)
retcnt = ipc.alloc_raw(4)
res = ipc.IOSIoctlv(fs, FS.ReadDir, "dd:dd", name, maxcnt, retnames, retcnt)
print(f"res={res}")
if res == -102:
    print("EACCES: Permission Denied. Apply the ISFS_Permissions patch to bypass this")
elif res == 0:
    retcntVal = unpack(">L", retcnt.read(0, 4))[0]
    print("Number of files:", retcntVal)
    print("Files:")
    off = 0
    for fileIdx in range(retcntVal):
        fnameRaw = retnames.read(off, 13)
        fnameLen = 0
        for b in fnameRaw:
            if b == 0:
                break
            fnameLen += 1

        off += fnameLen + 1
        fname = str(fnameRaw[0:fnameLen], "utf8")

        print(fname)
        

ipc.IOSClose(fs)
ipc.shutdown()

