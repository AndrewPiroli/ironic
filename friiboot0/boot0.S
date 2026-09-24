#include "asminc.h"

.section .text
.global _vectors

.arm
_vectors:
	ldr	pc, =reset
	ldr	pc, =hang
	ldr	pc, =hang
	ldr	pc, =hang
	ldr	pc, =hang
	ldr	pc, =hang
	ldr	pc, =hang
	ldr	pc, =hang

.equ stack, 0x0d417c00
.equ boot1addr, 0x0d400000

reset:
	ldr sp,=stack
	blx InitHardware
	blx LoadAndDecrypt
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
	ldr r5, [r5]
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
@
@ Reset Registers
@ just read some 0s from mem1 lmao
@ keep base ptr in r4
	ldmia r3, {r2,r5,r6}
	bx lr
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
	ldr r6, [r6] @ stupid
	ldr r10, aesbaseaddr
	ldr r11, aeswriteval
	add r8, r6, #0x17800
readpage:
	str r1, [r4, #0xc] @ NAND_ADDR2
	blx WaitNand
	str r2, [r4] @ read setup cmd
	@ write NAND databuf to boot1addr + currPage << 11
	add r7, r6, r1, lsl #11
	str r7, [r4, #0x10]
	@ write NAND eccbuf to base + 17800h + ((currPage & 1) << 7)
	and r9, r1, #1
	add r9, r8, r9, lsl #7
	str r9, [r4, #0x14]
	blx WaitNand
	str r5, [r4] @ read cmd
@ loaded from Nand
@ todo check & fix ECC
	blx WaitAes
	cmp r1, #1
	orreq r11,#0x1000 @ set chain for first page
	eorne r11,#0x1000 @ clear for all other pages
	str r11, [r10]
	cmp r1, #47
	addne r1, #1
	bne readpage
loadout:
	pop {pc}
nandreadval:
.word 0x8030b840
aesbaseaddr:
.word 0x0d020000
aeswriteval:
.word 0x9800007F
END_ASM_FUNC

.thumb
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

.thumb
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


.align 4
bootkey:
.byte     0x92, 0x58, 0xa7, 0x52, 0x64, 0x96, 0x0d, 0x82, 0x67, 0x6f, 0x90, 0x44, 0x56, 0x88, 0x2a, 0x73
