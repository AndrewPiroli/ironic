from struct import pack, unpack
from pyronic.client import *

ipc = IPCClient()
sock = ipc.sock

regs_arr = [ 0x0d806800, 0x0d806814, 0x0d806828 ]
CSR = 0
MAR = 4
LENGTH = 8
CR = 12
DATA = 16

def exi_init(ch):
    regs = regs_arr[ch]

    sock.send_ppc_write32(regs + CSR, 0b101 << 4)

def exi_xfer(ch, cs, tx):
    regs = regs_arr[ch]

    res = sock.send_ppc_read32(regs + CSR)
    val = unpack(">L", res)[0]
    val = val & 0x3c7f
    val = val | (1 << (7 + cs))
    res = sock.send_ppc_write32(regs + CSR, val)

    sock.send_ppc_write32(regs + DATA, tx)
    sock.send_ppc_write32(regs + CR, 0b111001)
    while True:
        res = sock.send_ppc_read32(regs + CR)
        val = unpack(">L", res)[0]
        if not (val & 0x00000001):
            break

    res = sock.send_ppc_read32(regs + DATA)
    val = unpack(">L", res)[0]
    return val

def ug_putc(ch, cs, c):
    exi_xfer(ch, cs, 0xb0000000 | (int(ord(c)) << 20))

def ug_puts(ch, cs, msg):
    for c in msg:
        ug_putc(ch, cs, c)


exi_init(1)
id = exi_xfer(1, 0, 0x90000000)
print("USB Gecko ID: " + hex(id))
ug_puts(1, 0, "hello")
