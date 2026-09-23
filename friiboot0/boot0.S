@ friiboot0
@ SPDX-License-Identifier: BSD-2-Clause
@ Copyright 2026 Andrew Piroli

#include "asminc.h"

.section .text
.global _vectors

.arm
_vectors:
	ldr	pc, =reset
	nop
	nop
	nop
	nop
	nop
	nop @ weeeeeeeeeeeeee
	ldr	pc, =hang

.equ stack, 0x0d417e00 @ Real boot0 has is a little lower
.equ boot1addr, 0x0d400000

reset:
	ldr sp,=stack
	bl InitHardware
	bl LoadAndDecrypt
	ldr pc, =#0xfff00000
hang:
	bkpt #0xff

BEGIN_ASM_FUNC InitHardware
@ Need to init AES & NAND Flash
@ Also will init SHA and OTP, even though we are not using them
@ I don't know if boot1 cares, but in case it does then those devices
@ will be in the proper state.
@
@ r2 will be a loop counter
@ r3 will be 0
@ r4 will be our Reg Base
@ r5 will be a write value
	mov r4,#0x0d800000
@ srnprot (offset 0x60)
@ allow AES (bit 1), SHA (bit 2), and NAND (bit 4) interfaces to talk to SRAM.
	mov r5, #7
	str r5, [r4, #0x60]
@
@ GPIO init
@
	mov r5,#0x00FF0000
	str r5, [r4, #0x0dc]
	str r5, [r4, #0x0e4]
@
@ OTP init
@
	mov r5,#0x80000000
	str r5, [r4, #0x1ec]
@
@ AES init
@
	eor r4, #0x820000
@ Reset AES Ctrl
	str r3, [r4]
@ Clear IV (offset 0x10)
clriv:
	str r3, [r4, #0x10]
	add r2, #1
	cmp r2, #4
	bne clriv
@
	mov r2, #0
@ Write boot1 AES key (offset 0x0c)
@ r5 = keyPtr
@ r6 = keyVal
	ldr r5,=bootkey
setkey:
	ldr r6, [r5, r2, lsl #0x2]
	str r6, [r4, #0x0c]
	add r2,#1
	cmp r2, #4
	bne setkey
@ Write AES Src & Dest (offsets 0x4 & 0x8)
	ldr r5, =boot1addr
	str r5, [r4, #0x4]
	str r5, [r4, #0x8]
@
@ Partial SHA init
@
	orr r4,#0x10000
@ SHA Ctrl (offset 0) Reset
	str r3, [r4]
@ Write SHA Src (offset 0x4)
	str r5, [r4, #0x4]
@
@ Init NAND
@
	bic r4, #0x20000
@ NAND Config Register (offset 0x4) Set Enable
	mov r5, #0x08000000
	str r5, [r4, #0x4]
@ Zero following NAND Interface Registers
@ ADDR1   (0x08)
@ ADDR2   (0x0c)
@ DATABUF (0x10)
@ ECCBUF  (0x14)
	lsr r5, #24
nandifzero:
	str r3, [r4, r5]
	add r5, #4
	cmp r5, #0x18
	bne nandifzero
@ Send NAND Reset Command
	mov r5, #0xff
	lsl r5, #16
	orr r5, #0x80000000
	orr r5, #0x8000
	str r5, [r4]
@ Done
	mov pc, lr
END_ASM_FUNC

BEGIN_ASM_FUNC LoadAndDecrypt
@
@ Load 94k from block 0 of flash to =boot1addr
@ decrypt with AES
@ check ECC
@ return if ok, otherwise we die here
@
@	r1 = current nand page
@	r2 = nand "read setup" writeval
@	r3 = 0
@	r4 = nand iface base ptr
@	r5 = nand "read" writeval
@	r6 = boot1 base
@	r7 = NAND data buf addr
@	r8 = NAND ecc buf base addr
@	r9 = NAND ecc buf calculated addr
@	r10  AES interface base ptr
@	r11  AES decrypt writeval
	push {lr}
	mov r2, #0x9F000000
	ldr r5, nandreadval
	ldr r6, =boot1addr
	ldr r10, aesbaseaddr
	ldr r11, aeswriteval
	add r8, r6, #0x17800
readpage:
	str r1, [r4, #0xc] @ NAND_ADDR2
	bl WaitNand
	str r2, [r4] @ read setup cmd
	@ write NAND databuf to boot1addr + currPage << 11
	add r7, r6, r1, lsl #11
	str r7, [r4, #0x10]
	@ write NAND eccbuf to base + 17800h + ((currPage & 1) << 7)
	and r9, r1, #1
	add r9, r8, r9, lsl #7
	str r9, [r4, #0x14]
	bl WaitNand
	str r5, [r4] @ read cmd
	bl WaitNand
@ loaded from Nand, fix any bit flips before decrypting
	bl FixupEcc
	bl WaitAes
	cmp r1, #0
	biceq r11,#0x1000 @ first page uses iv
	orrne r11,#0x1000 @ subsequent pages chain from prev block
	str r11, [r10]
	cmp r1, #46
	addne r1, #1
	bne readpage
	bl WaitAes
@ done
	pop {pc}
nandreadval:
.word 0x8030b840 @ https://wiibrew.org/wiki/Hardware/NAND_Interface
aesbaseaddr:
.word 0x0d020000
aeswriteval:
.word 0x9800007F @ https://wiibrew.org/wiki/Hardware/AES_engine
END_ASM_FUNC

BEGIN_ASM_FUNC WaitNand
@
@ Wait for the Nand Interface to be ready
@ ... I mean it should always be but we are going
@ to be good boys in case future me does something wack
@
	push {r3, r5, lr}
	ldr r5, =0x80000000
nandbusy:
	ldr r3, [r4]
	tst r3, r5
	bmi nandbusy
	pop {r3, r5, pc}
.align 4
END_ASM_FUNC

BEGIN_ASM_FUNC WaitAes
@
@ Wait for the AES Interface to be ready
@ Same story as above
@
	push {r3-r5, lr}
	ldr r5, =0x80000000
	mov r4, r10
aesbusy:
	ldr r3, [r4]
	tst r3, r5
	bmi aesbusy
	pop {r3-r5, pc}
.align 4
END_ASM_FUNC

BEGIN_ASM_FUNC FixupEcc
@ 64 bytes of ECC per 2048 byte flash page.
@ The NAND interface calculates the ECC of the last data for us.
@ r0 = loop counter
@ r1 = pointer to the flash data <- read from r7 (LoadAndDecrypt)
@ r2 = pointer to both the stored and computed ECC <- read from r8 (LoadAndDecrypt)
@ r3 = ecc offset (loop counter * 4)
@ r4 = computed ecc / scratch
@ r5 = stored ecc / scratch /  ecc fix hi
@ r6 = scratch / ecc fix lo
@ r7 = 0x00000fff
@ r8 = ecc correction pointer
@ r9 = corrected byte
	push {r0-r9, lr}
	mov r1, r7
	mov r2, r8
	mov r7, #0x1000
	sub r7, #1
@ r0 = loop counter
	mov r0, #0
ecc_loop:
@ r3 = offset
	mov r3, r0, lsl #2
@ load computed ecc into r4 (base + 64 + offset)
@ load stored into r5 (base + 48 + offset)
	mov r4, r2
	add r4, #64
	ldr r4, [r4, r3]
	mov r5, r2
	add r5, #48
	ldr r5, [r5, r3]
@ simplest case is stored == computed, we can move on to the next word instantly
	cmp r4, r5
	beq eccout
@
@ Ok, so there must be an error
@
@ ecc data is in little endian, for this part we need big endian
@ swap both r4 and r5
@
	eor r6, r4 ,r4, ror #16
	bic r6, r6, #0x00ff0000
	mov r4, r4, ror #8
	eor r4, r4, r6, lsr #8

	eor r6, r5 ,r5, ror #16
	bic r6, r6, #0x00ff0000
	mov r5, r5, ror #8
	eor r5, r5, r6, lsr #8
@ Xor computed and stored ecc values (r4)
	eor r4, r4, r5
@ If the result is a power of two, that means the error is inside the ECC code itself
@ the data is good and we can move on.
@
	sub r5, r4, #1
	ands r5, r5, r4
	beq eccout @ yay
@ xor the upper 16 bits (r5) of ecc with the lower 12 bits (r6)
@ keep result in r6, we will need the upper bits again for corrections (if possible)
	mov r5, r4, lsr #16
	and r6, r4, r7
	eor r6, r5
@ if that xor == 0x0fff, there is a correctable single-bit error
@ otherwise it is a mutli bit error and we're dead
	cmp r6, r7
	bne hang @ todo panic function
@
@ perform the correction
@
@ build data pointer to the section of flash data controlled by this ecc word (r8)
	mov r8, r0, lsl #9
	add r8, r7
@ bits 3 - 11 of ecc hi (r5) indicate the byte offset into the data
	sub r6, r7, #7 @ build mask
	and r4, r5, r6
@ load corrupted word from memory
	ldr r9, [r8, r4]
@ bits 0 - 2 of ecc hi (r5) indiciate the flipped bit
	mov r4, #1
	mov r6, #0x7
	and r6, r5
	eor r9, r4, lsl r6
	str r9, [r8]
@ is that it?
eccout:
	add r0, #1
	cmp r0, #4
	bne ecc_loop
	pop {r0-r9, pc}
END_ASM_FUNC

legal:
.ascii "friiboot0 - Copyright 2026 Andrew Piroli"
.ascii "BSD 2 Clause"

.align 4
bootkey:
.byte     0x92, 0x58, 0xa7, 0x52, 0x64, 0x96, 0x0d, 0x82, 0x67, 0x6f, 0x90, 0x44, 0x56, 0x88, 0x2a, 0x73
