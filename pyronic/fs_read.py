#!/usr/bin/env python3

from struct import unpack
from pyronic.client import *
from sys import argv
from os.path import basename

if len(argv) < 2:
    print("Please provide a file to read!")
    exit(1)

ipc = IPCClient()

file = ipc.IOSOpen(argv[1], 1)
print(f"fd={file}")
if file == -102:
    print("EACCESS: Permission denied. Apply the ISFS_Permissions patch to bypass this")
if file < 0:
    print(f"failed to open {argv[1]}")
    ipc.shutdown()
    exit(1)

retstats = ipc.alloc_raw(8)
res = ipc.IOSIoctl(file, FS.GetFileStats, ipc.alloc_raw(0), retstats)
print(f"ioctl res={res}")
if res != 0:
    print("failed to do ioctl")
    ipc.IOSClose(file)
    ipc.shutdown()
    exit(1)

raw = unpack(">LL", retstats.read())
size = raw[0]
print("file size:", size)

filebuf = ipc.alloc_raw(size)
res = ipc.IOSRead(file, filebuf, size)
print(f"read res={res}")
if res != size:
    print("read failed")
    ipc.IOSClose(file)
    ipc.shutdown()
    exit(1)

# work around the fact that .read() bails on huge reads due to lack of splitting
chunks = int(size / 4096)
remainder = size % 4096
if remainder:
    chunks += 1

host_file = open(basename(argv[1]), "wb")

for i in range(chunks):
    data = filebuf.read(i * 4096, 4096)
    host_file.write(data)

host_file.close()

ipc.IOSClose(file)
ipc.shutdown()

