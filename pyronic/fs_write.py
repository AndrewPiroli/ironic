#!/usr/bin/env python3

from struct import unpack
from pyronic.client import *
from sys import argv
from os.path import basename

if len(argv) < 3:
    print("Please provide a file to write and a path to write it to!")
    exit(1)

ipc = IPCClient()
fs = ipc.IOSOpen("/dev/fs")
print(f"fs fd: {fs}")

file = ipc.IOSOpen(argv[2], 1)
print(f"file fd={file}")
if file >= 0:
    print("File already exists, deleting it first...")
    ipc.IOSClose(file)
    fname = ipc.alloc_raw(0x40)
    fname.write(argv[2].encode("utf8"))
    res = ipc.IOSIoctl(fs, FS.Delete, fname, ipc.alloc_raw(0))
    print(f"fs delete res: {res}")
    if res != 0:
        print("failed")
        ipc.IOSClose(fs)
        ipc.shutdown()
        exit(1)

print("Creating file...")
filestruct = ipc.alloc_raw(0x4a)
filestruct.write(pack("<LH64sBBBB", 0, 0, argv[2].encode("utf8"), 0, 0, 0, 0))
res = ipc.IOSIoctl(fs, FS.CreateFile, filestruct, ipc.alloc_raw(0))
print(f"fs createfile res: {res}")
if res != 0:
    print("createfile failed")
    ipc.IOSClose(fs)
    ipc.shutdown()
    exit(1)

file = ipc.IOSOpen(argv[2], 2)
print(f"file fd={file}")
if (file < 0):
    print("open failed")
    ipc.iosclose(fs)
    ipc.shutdown()
    exit(1)

host_file = open(argv[1], "rb")
data = host_file.read()
size = len(data)
filebuf = ipc.alloc_raw(size)
filebuf.write(data)
res = ipc.IOSWrite(file, filebuf, size)
if res != size:
    print("write failed")
    ipc.IOSClose(fs)
    ipc.IOSClose(file)
    ipc.shutdown()
    host_file.close()
    exit(1)

print("success")
ipc.IOSClose(file)
ipc.IOSClose(fs)
ipc.shutdown()

