#!/usr/bin/env python3

from struct import pack, unpack
from hexdump import hexdump
from sys import argv
from pyronic.client import *
from pyronic.ios import *

if len(argv) < 2:
    print("Please provide an IOS to load!")
    exit(1)
if int(argv[1]) > 255 or int(argv[1]) < 3:
    print("Invalid range [3-255]")
    exit(1)
ios_tid = 0x0000000100000000 | int(argv[1])

ipc = IPCClient()
esfd = ipc.IOSOpen("/dev/es")
print("fd={}".format(esfd))

num_views_ptr = ipc.alloc_raw(4)

res = ipc.IOSIoctlv(esfd, ES.GetNumTicketViews, "q:d", ios_tid, num_views_ptr)
if res < 0:
    print("ES_GetNumTicketViews() returned {}".format(res))
    ipc.IOSClose(esfd)
    ipc.shutdown()
    exit(0)

num_views = unpack(">I", num_views_ptr.read(4))[0]

SIZEOF_TIKVIEW = 0xd8
tikviews = ipc.alloc_raw(num_views * SIZEOF_TIKVIEW)

res = ipc.IOSIoctlv(esfd, ES.GetTicketViews, "qi:d", ios_tid, num_views, tikviews)
if res < 0:
    print("ES_GetTicketViews() returned {}".format(res))
    ipc.IOSClose(esfd)
    ipc.shutdown()
    exit(0)
ipc.IOSIoctlv(esfd, ES.LaunchTitle, "qd:", ios_tid, tikviews, noret=True)
print("Sorry no more feedback available. check the console to see if it worked!")

