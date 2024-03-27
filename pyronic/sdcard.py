#!/usr/bin/python3

from struct import pack, unpack
from hexdump import hexdump
from pyronic.client import *
from pyronic.ios import ES

ipc = IPCClient()

slot0 = ipc.IOSOpen("/dev/sdio/slot0")
print(f"fd={slot0}")

buf = ipc.alloc_raw(4)
res = ipc.IOSIoctl(slot0, SDIO.ResetCard, ipc.alloc_raw(1), buf)
res = buf.read(4)
hexdump(res)
#print(f"{res=}")
res = ipc.IOSIoctl(slot0, SDIO.GetStatus, ipc.alloc_raw(1), buf)
res = buf.read(4)
hexdump(res[:4])
#print(f"{res=}")

ipc.IOSClose(slot0)
ipc.shutdown()

