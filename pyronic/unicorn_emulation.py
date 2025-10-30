#!/usr/bin/python3
#
# Unicorn-based PowerPC LLE for Ironic
#
# Copyright (C) 2025 Techflash
#

from unicorn import *
from unicorn.ppc_const import *
from pyronic.client import *
ipc = IPCClient()

class MemRegion(object):
    def __init__(self, start, size, end, handle, handle_offset=0):
        self.start = start
        self.size = size
        self.end = end
        self.handle = handle
        self.handle_offset = handle_offset


# continue emulation
keep_going = True

# reset vector, mapped to EXI boot stub
reset_vec = 0xffff0100

# mem1
mem1_start = 0x0
mem1_size  = 0x01800000
mem1_end   = mem1_start + mem1_size
mem1_hndl  = ipc.alloc_raw(mem1_size, mem1_start)
mem1       = None

# mem2
mem2_start = 0x10000000
mem2_size  = 0x04000000
mem2_end   = mem2_start + mem2_size
mem2_hndl  = ipc.alloc_raw(mem2_size, mem2_start)
mem2       = None

# Legacy regs
legc_start = 0x0c000000
legc_size  = 0x00800000
legc_end   = legc_start + legc_size
legc_hndl  = ipc.alloc_raw(legc_size, legc_start)
legc       = None

# Hollywood regs
hlwd_start = 0x0d800000
hlwd_size  = 0x00800000
hlwd_end   = hlwd_start + hlwd_size
hlwd_hndl  = ipc.alloc_raw(hlwd_size, hlwd_start)
hlwd       = None

# Hollywood regs (mirror)
mirr_start = 0x0d000000
mirr_size  = 0x00800000
mirr_end   = mirr_start + mirr_size
mirr_hndl  = ipc.alloc_raw(mirr_size, mirr_start)
mirr       = None

# Broadway reset vector
rvec_real_start = 0x0d806840
rvec_start = 0xffff0000
rvec_size  = 0x1000
rvec_end   = rvec_start + rvec_size
rvec_hndl  = ipc.alloc_raw(rvec_size, rvec_real_start)
rvec       = None

def dump_regs(mu):
        print("r0 - r3  : {:08x} {:08x} {:08x} {:08x}".format(mu.reg_read(UC_PPC_REG_0), mu.reg_read(UC_PPC_REG_1), mu.reg_read(UC_PPC_REG_2), mu.reg_read(UC_PPC_REG_3)))
        print("r4 - r7  : {:08x} {:08x} {:08x} {:08x}".format(mu.reg_read(UC_PPC_REG_4), mu.reg_read(UC_PPC_REG_5), mu.reg_read(UC_PPC_REG_6), mu.reg_read(UC_PPC_REG_7)))
        print("r8 - r11 : {:08x} {:08x} {:08x} {:08x}".format(mu.reg_read(UC_PPC_REG_8), mu.reg_read(UC_PPC_REG_9), mu.reg_read(UC_PPC_REG_10), mu.reg_read(UC_PPC_REG_11)))
        print("r12 - r15: {:08x} {:08x} {:08x} {:08x}".format(mu.reg_read(UC_PPC_REG_12), mu.reg_read(UC_PPC_REG_13), mu.reg_read(UC_PPC_REG_14), mu.reg_read(UC_PPC_REG_15)))
        print("r16 - r19: {:08x} {:08x} {:08x} {:08x}".format(mu.reg_read(UC_PPC_REG_16), mu.reg_read(UC_PPC_REG_17), mu.reg_read(UC_PPC_REG_18), mu.reg_read(UC_PPC_REG_19)))
        print("r20 - r23: {:08x} {:08x} {:08x} {:08x}".format(mu.reg_read(UC_PPC_REG_20), mu.reg_read(UC_PPC_REG_21), mu.reg_read(UC_PPC_REG_22), mu.reg_read(UC_PPC_REG_23)))
        print("r24 - r27: {:08x} {:08x} {:08x} {:08x}".format(mu.reg_read(UC_PPC_REG_24), mu.reg_read(UC_PPC_REG_25), mu.reg_read(UC_PPC_REG_26), mu.reg_read(UC_PPC_REG_27)))
        print("r28 - r31: {:08x} {:08x} {:08x} {:08x}".format(mu.reg_read(UC_PPC_REG_28), mu.reg_read(UC_PPC_REG_29), mu.reg_read(UC_PPC_REG_30), mu.reg_read(UC_PPC_REG_31)))

def mem_read(uc, offset, size, info):
    # FIXME: Massive log spam and makes the emulation even astronomically slower
    # than it already is, disabled by default.

    #print("mem_read @ " + str(hex(offset + info.start)) + f" {size} bytes")
    #offset = offset & 0x0FFFFFFF
    #print("phys offset @ " + str(hex(offset + info.start)))
    val = bytearray()
    if size == 4:
        val = info.handle.read32(offset + info.handle_offset)
        return val[0] << 24 | val[1] << 16 | val[2] << 8 | val[3]
    elif size == 2:
        val = info.handle.read16(offset + info.handle_offset)
        return val[0] << 8 | val[1]
    elif size == 1:
        val = info.handle.read8(offset + info.handle_offset)
        return val[0]
    else:
        print("FATAL: Unknown read size: ", size)
        keep_going = False
        return 0

def mem_write(uc, offset, size, value, info):
    #print("mem_write @ " + str(hex(offset + info.start)) + f" {size} bytes, value " + str(hex(value)))
    #offset = offset & 0x0FFFFFFF
    #print("phys offset @ " + str(hex(offset + info.start)))
    if size == 4:
        info.handle.write32(value, offset + info.handle_offset)
    elif size == 2:
        info.handle.write16(value, offset + info.handle_offset)
    elif size == 1:
        info.handle.write8(value, offset + info.handle_offset)
    else:
        print("FATAL: Unknown write size: ", size)
        keep_going = False
        return

def handle_invalid_instruction(uc, uc_err, user_data):
    pc = uc.reg_read(UC_PPC_REG_PC)
    inst = uc.mem_read(pc, 4)
    val = int.from_bytes(inst, "big")
    print("Handling invalid instruction {:08x}".format(val))

    if (val >> 26) == 0x38:  # psq_l
        print(f"[STUB] Skipping psq_l at 0x{pc:08X}")
        uc.reg_write(UC_PPC_REG_PC, pc + 4)
        return True

    return False

def handle_interrupt(uc, int_no, user_data):
    print("Interrupt " + str(int_no) + " fired!")


try:
    # Initialize emulator in PPC 750CL mode
    mu = Uc(UC_ARCH_PPC, UC_MODE_PPC32 | UC_MODE_BIG_ENDIAN, UC_CPU_PPC32_750CL_V2_0)

    # map MEM1
    print("Setting up MEM1...")
    mem1 = MemRegion(mem1_start, mem1_size, mem1_end, mem1_hndl)
    mu.mmio_map(mem1_start, mem1_size, mem_read, mem1, mem_write, mem1)
    mu.mem_protect(mem1_start, mem1_size)

    # map MEM2
    print("Setting up MEM2...")
    mem2 = MemRegion(mem2_start, mem2_size, mem2_end, mem2_hndl)
    mu.mmio_map(mem2_start, mem2_size, mem_read, mem2, mem_write, mem2)
    mu.mem_protect(mem2_start, mem2_size)

    # map Hollywood register range
    print("Setting up Hollywood registers...")
    hlwd = MemRegion(hlwd_start, hlwd_size, hlwd_end, hlwd_hndl)
    mu.mmio_map(hlwd_start, hlwd_size, mem_read, hlwd, mem_write, hlwd)
    mu.mem_protect(hlwd_start, hlwd_size)

    # map Hollywood (mirror) register range
    print("Setting up Hollywood (mirror) registers...")
    mirr = MemRegion(mirr_start, mirr_size, mirr_end, mirr_hndl)
    mu.mmio_map(mirr_start, mirr_size, mem_read, mirr, mem_write, mirr)
    mu.mem_protect(mirr_start, mirr_size)

    # map legacy register range
    print("Setting up legacy (Flipper) registers...")
    legc = MemRegion(legc_start, legc_size, legc_end, legc_hndl)
    mu.mmio_map(legc_start, legc_size, mem_read, legc, mem_write, legc)
    mu.mem_protect(legc_start, legc_size)

    # map Broadway reset vector to EXI boot stub
    print("Setting up reset vector...")
    rvec = MemRegion(rvec_start, rvec_size, rvec_end, rvec_hndl, -256)
    mu.mmio_map(rvec_start, rvec_size, mem_read, rvec, mem_write, rvec)
    mu.mem_protect(rvec_start, rvec_size)

    mu.hook_add(UC_HOOK_INSN_INVALID, handle_invalid_instruction)
    mu.hook_add(UC_HOOK_INTR, handle_interrupt)

    print("Starting Broadway emulation...")
    pc = reset_vec

    while keep_going:
        #mu.emu_start(pc, 0xffffffff)
        mu.emu_start(pc, 0xffffffff, 0, 1) # single-step for better logging when something goes wrong
        pc = mu.reg_read(UC_PPC_REG_PC)
        pcTemp = pc & 0x0FFFFFFF
        #print("Emulating @ " + str(hex(pcTemp)))
        try:
            data = mu.mem_read(pcTemp, 4)
            #print("Code:")
            #hexdump(data)
            #print("Registers:")
            #dumpRegs(mu)
        except:
            continue

except UcError as e:
    print("ERROR: " + str(e) + ", occurred @ " + str(hex(pc)))
    pc = pc & 0x0FFFFFFF
    data = mu.mem_read(pc, 4)
    print("Code:")
    hexdump(data)
    print("Registers:")
    dumpRegs(mu)
