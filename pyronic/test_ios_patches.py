#!/usr/bin/env python3
from collections import OrderedDict
from pyronic.client import *
from pyronic.ios import Patches

patches = OrderedDict()
for x in dir(Patches):
    if not x.startswith('_') and isinstance(Patches.__dict__[x], PatchRange):
        patches.update({x: Patches.__dict__[x]})
ipc = IPCClient()
ipc.disable_ppc_protections()
for name, patch in patches.items():
    print(f"Applying patch: {name}: ", end='')
    applied = ipc.guest_patch(patch)
    if applied == 0:
        print("- failed no match")
    elif applied == 1:
        print("- success")
    else:
        print(f"- success (matched {applied} times)")
ipc.shutdown()