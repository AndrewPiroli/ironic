from enum import IntEnum
from struct import pack, unpack
from . import ToBuffer, PatchRange

class IOSErr(IntEnum):
    FS_EINVAL       = -4
    FS_EACCESS      = -102
    FS_ENOENT       = -106
    ES_EINVAL       = -1017

class FS(IntEnum):
    Format          = 0x01
    GetStats        = 0x02
    CreateDir       = 0x03
    ReadDir         = 0x04
    SetAttr         = 0x05
    GetAttr         = 0x06
    Delete          = 0x07
    Rename          = 0x08
    CreateFile      = 0x09
    SetFileVerCtrl  = 0x0a
    GetFileStats    = 0x0b
    GetUsage        = 0x0c
    Shutdown        = 0x0d
    Unk             = 0x0e

class ES(IntEnum):
    AddTicket       = 0x01
    AddTitleStart   = 0x02
    AddContentStart = 0x03
    AddContentData  = 0x04
    AddContentFinish= 0x05
    AddTitleFinish  = 0x06
    LaunchTitle     = 0x08
    GetTitlesCount  = 0x0e
    GetNumTicketViews  = 0x12
    GetTicketViews  = 0x13
    GetTitles       = 0x0f
    AddTitleCancel  = 0x2f
    LaunchBC        = 0x25

class AES(IntEnum):
    Copy = 0x0
    Encrypt = 0x02
    Decrypt = 0x03

class SDIO(IntEnum):
    Write8 = 0x1
    Read8 = 0x2
    ResetCard = 0x4
    SetClock = 0x6
    Command = 0x7
    GetStatus = 0xb
    GetOCR = 0xc

class IPCMsg(ToBuffer):
    """ A structure representing some PPC-to-ARM IPC message. 
    After this is filled out, the user will obtain the raw bytes and write 
    them to physical memory somewhere (aligned to 32-byte boundaries).
    """
    def __init__(self, cmd, fd=0, args=[0,0,0,0,0]):
        self.cmd = cmd
        self.res = 0
        self.fd = fd
        self.args = args

    def to_buffer(self) -> bytes:
        """ Convert to a big-endian binary representation """
        while len(self.args) < 5: 
            self.args.append(0)
        assert len(self.args) == 5
        return pack(">Lii5L", self.cmd, self.res, self.fd, *self.args)

class Patches:
    Trucha  = PatchRange(0x133E0000, 0x14000000, bytearray([0x20, 0x07, 0x23, 0xA2]), bytearray([0,]), 1)
    Trucha2 = PatchRange(0x133E0000, 0x14000000, bytearray([0x20, 0x07, 0x4B, 0x0B]), bytearray([0,]), 1)
    ISFS_Permissions = PatchRange(0x133E0000, 0x14000000, bytearray([0x42, 0x8B, 0xD0, 0x01, 0x25, 0x66]), bytearray([0x42, 0x8B, 0xE0, 0x01, 0x25, 0x66]), 0)
    ES_Identify = PatchRange(0x133E0000, 0x14000000, bytearray([0x28, 0x03, 0xD1, 0x23]), bytearray([0, 0]), 2)
    ES_TitleVersionCheck = PatchRange(0x133E0000, 0x14000000, bytearray([0xD2, 0x01, 0x4E, 0x56]), bytearray([0xE0, 0x01, 0x4E, 0x56]), 0)
    ES_TitleDeleteCheck = PatchRange(0x133E0000, 0x14000000, bytearray([0xD8, 0x00, 0x4A, 0x04]), bytearray([0xE0, 0x00, 0x4A, 0x04]), 0)
    ES_ImportBoot_Downgrade = PatchRange(0x133E0000, 0x14000000, bytearray([0x68, 0x5a, 0x9b, 0x1e, 0x42, 0x9a, 0xd2, 0x01]), bytearray([0x68, 0x5a, 0x9b, 0x1e, 0x42, 0x9a, 0xe0, 0x01]), 0)
    ES_SetUID = PatchRange(0x133E0000, 0x14000000, bytearray([0xD1, 0x2A, 0x1C, 0x39]), bytearray([0x46, 0xC0]), 0)
    ES_Force_AHBPROT = PatchRange(0x133E0000, 0x14000000, bytearray([0x68, 0x5B, 0x22, 0xEC, 0x00, 0x52, 0x18, 0x9B, 0x68, 0x1B, 0x46, 0x98, 0x07, 0xDB]), bytearray([0x23, 0xFF]), 8)
    # These are for IOSes that never exposed /dev/flash, while this patch is active /dev/boot2 is inaccessible
    # There is a different patch for older IOSes that had /dev/flash patched out
    NewIOS_DevFlash_part1 = PatchRange(0x133E0000, 0x14000000, bytearray([0x66, 0x73, 0x00, 0x00, 0x62, 0x6f, 0x6f, 0x74, 0x32]), bytearray([0x66, 0x73, 0x00, 0x00, 0x66, 0x6C, 0x61, 0x73, 0x68]), 0)
    NewIOS_DevFlash_part2 = PatchRange(0x133E0000, 0x14000000, bytearray([0xd0, 0x02, 0x20, 0x01, 0x42, 0x40, 0xe0, 0x08, 0xf7, 0xfa, 0xfc, 0xb7]), bytearray([0xe0, 0x02, 0x20, 0x01, 0x42, 0x40, 0xe0, 0x08, 0xf7, 0xff, 0xfd, 0xeb]), 0)
    Unprotect_FS_Format = PatchRange(0x133E0000, 0x14000000, bytearray([0x28, 0x00, 0xd0, 0x02, 0x24, 0x66, 0x42, 0x64]), bytearray([0x43, 0x80]), 0)
