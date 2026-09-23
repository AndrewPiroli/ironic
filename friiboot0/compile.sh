#!/bin/bash
$DEVKITARM/bin/arm-none-eabi-gcc -mcpu=arm926ej-s -mbig-endian -x assembler-with-cpp \
	-ffreestanding -nostdlib -nodefaultlibs \
	-Ttext 0xffff0000 -e _vectors \
	boot0.S -o boot0.elf
$DEVKITARM/bin/arm-none-eabi-objcopy --only-section=.text --output-target binary boot0.elf boot0.bin
