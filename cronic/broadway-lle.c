/*
 * Ironic - Broadway Emulation
 *
 * Copyright (C) 2025 - 2026 Techflash
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <ppcemu/ppcemu.h>
#include "cronic.h"
#include "endian.h"

typedef struct {
	uint8_t  e_ident[16];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint32_t e_entry;
	uint32_t e_phoff;
	uint32_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
} __attribute__((packed)) Elf32_Ehdr;

typedef struct {
	uint32_t p_type;
	uint32_t p_offset;
	uint32_t p_vaddr;
	uint32_t p_paddr;
	uint32_t p_filesz;
	uint32_t p_memsz;
	uint32_t p_flags;
	uint32_t p_align;
} __attribute__((packed)) Elf32_Phdr;


// This is not perfect.
static void wiiInit(struct ppcemu_state * emu) {
	//1. Set initial MSR (real mode: FP | ME | RI, no DR/IR)
	// MSR_FP=0x2000, MSR_ME=0x1000, MSR_RI=0x0002
	ppcemu_set_msr(emu, PPCEMU_MSR_FP | PPCEMU_MSR_ME | PPCEMU_MSR_RI);
	// = 0x00003002
	//2. HID0 — disable L1 caches, set DPM/NHR/ICFI/DCFI/SPD/DCFA/BTIC/BHT
	// DPM  = bit 20 = 0x00100000
	// NHR  = bit 19 = 0x00080000
	// ICFI = bit 14 = 0x00004000
	// DCFI = bit 13 = 0x00002000
	// SPD  = bit 12 = 0x00001000
	// DCFA = bit 10 = 0x00000400
	// BTIC = bit  8 = 0x00000100
	// BHT  = bit  4 = 0x00000010
	ppcemu_set_spr(emu, PPCEMU_SPRN_HID0, 0x00187510);
	//3. L2CR — disable L2
	//ppcemu_set_spr(emu, PPCEMU_SPRN_L2CR, 0x00000000);
	//4. HID2 — enable LSQE and PSE (Broadway/Wii)
	// LSQE (BW) = bit 31 = 0x80000000
	// PSE        = bit 29 = 0x20000000
	ppcemu_set_spr(emu, PPCEMU_SPRN_HID2_GEKKO, 0xA0000000);
	//5. HID4 — set H4A/SBE/ST0/LPE/L2CFI (Wii only)
	// H4A   = bit 31 = 0x80000000  (PPCEMU_HID4_RSRVD1 — must-be-1, also enables HID4 access)
	// SBE   = bit 25 = 0x02000000  (PPCEMU_HID4_SBE)
	// ST0   = bit 24 = 0x01000000  (PPCEMU_HID4_BW_ST0)
	// LPE   = bit 23 = 0x00800000  (PPCEMU_HID4_BW_LPE)
	// L2CFI = bit 20 = 0x00100000  (PPCEMU_HID4_L2CFI)
	ppcemu_set_spr(emu, PPCEMU_SPRN_HID4, 0x83900000);
	//6. L2CR — start L2 invalidation
	// L2I = bit 21 = 0x00200000
	//ppcemu_set_spr(emu, PPCEMU_SPRN_L2CR, 0x00200000);
	//7. Clear all BAT upper registers (disable all BATs)
	// Lower 8 BATs (all models)
	ppcemu_set_spr(emu, PPCEMU_SPRN_IBAT0U, 0x00000000);
	ppcemu_set_spr(emu, PPCEMU_SPRN_IBAT1U, 0x00000000);
	ppcemu_set_spr(emu, PPCEMU_SPRN_IBAT2U, 0x00000000);
	ppcemu_set_spr(emu, PPCEMU_SPRN_IBAT3U, 0x00000000);
	ppcemu_set_spr(emu, PPCEMU_SPRN_DBAT0U, 0x00000000);
	ppcemu_set_spr(emu, PPCEMU_SPRN_DBAT1U, 0x00000000);
	ppcemu_set_spr(emu, PPCEMU_SPRN_DBAT2U, 0x00000000);
	ppcemu_set_spr(emu, PPCEMU_SPRN_DBAT3U, 0x00000000);
	// Upper 8 BATs (Wii/Broadway)
	ppcemu_set_spr(emu, PPCEMU_SPRN_IBAT4U, 0x00000000);
	ppcemu_set_spr(emu, PPCEMU_SPRN_IBAT5U, 0x00000000);
	ppcemu_set_spr(emu, PPCEMU_SPRN_IBAT6U, 0x00000000);
	ppcemu_set_spr(emu, PPCEMU_SPRN_IBAT7U, 0x00000000);
	ppcemu_set_spr(emu, PPCEMU_SPRN_DBAT4U, 0x00000000);
	ppcemu_set_spr(emu, PPCEMU_SPRN_DBAT5U, 0x00000000);
	ppcemu_set_spr(emu, PPCEMU_SPRN_DBAT6U, 0x00000000);
	ppcemu_set_spr(emu, PPCEMU_SPRN_DBAT7U, 0x00000000);
	//Note: Segment registers (SR0–SR15) are all set to 0x80000000 (direct-store bit) in the assembly, but there is no ppcemu_set_sr() in the public API. If the emulator supports segment registers, you'll need an internal/extended API call or they may initialize to a safe state by default.
	//8. BAT0: 256MB @ 0x80000000 → PA 0x00000000, WIMG=0000, R/W
	// BATU: BEPI=0x8000 (VA 0x8000_0000), BL=0x7FF (256MB), VS=1, VP=1
	//   = (0x8000 << 17) | (0x7FF << 2) | 3 = 0x80000000 | 0x1FFC | 3 = 0x80001FFF
	// BATL: BPRN=0 (PA 0x0000_0000), WIMG=0b0000, PP=0b10 (R/W)
	//   = (0 << 17) | (0b0000 << 3) | 2 = 0x00000002

	ppcemu_set_spr(emu, PPCEMU_SPRN_IBAT0L, 0x00000002);
	ppcemu_set_spr(emu, PPCEMU_SPRN_IBAT0U, 0x80001FFF);
	ppcemu_set_spr(emu, PPCEMU_SPRN_DBAT0L, 0x00000002);
	ppcemu_set_spr(emu, PPCEMU_SPRN_DBAT0U, 0x80001FFF);
	//9. BAT4: 256MB @ 0x90000000 → PA 0x10000000, WIMG=0000, R/W (Wii)
	// BATU: BEPI=0x9000 → 0x90001FFF
	// BATL: BPRN=0x1000 → PA 0x10000000, WIMG=0b0000, PP=0b10 → 0x10000002

	ppcemu_set_spr(emu, PPCEMU_SPRN_IBAT4L, 0x10000002);
	ppcemu_set_spr(emu, PPCEMU_SPRN_IBAT4U, 0x90001FFF);
	ppcemu_set_spr(emu, PPCEMU_SPRN_DBAT4L, 0x10000002);
	ppcemu_set_spr(emu, PPCEMU_SPRN_DBAT4U, 0x90001FFF);
	//10. DBAT1: 256MB @ 0xC0000000 → PA 0x00000000, WIMG=0101 (cache-inhibited + guarded), R/W
	// BATU: BEPI=0xC000 → 0xC0001FFF
	// BATL: BPRN=0, WIMG=0b0101 → (0b0101 << 3)=0x28, PP=0b10=2 → 0x0000002A

	ppcemu_set_spr(emu, PPCEMU_SPRN_DBAT1L, 0x0000002A);
	ppcemu_set_spr(emu, PPCEMU_SPRN_DBAT1U, 0xC0001FFF);
	//11. DBAT5: 256MB @ 0xD0000000 → PA 0x10000000, WIMG=0101, R/W (Wii)
	// BATU: 0xD0001FFF
	// BATL: 0x1000002A

	ppcemu_set_spr(emu, PPCEMU_SPRN_DBAT5L, 0x1000002A);
	ppcemu_set_spr(emu, PPCEMU_SPRN_DBAT5U, 0xD0001FFF);
	//12. Clear all GQRs
	ppcemu_set_spr(emu, PPCEMU_SPRN_GQR0, 0x00000000);
	ppcemu_set_spr(emu, PPCEMU_SPRN_GQR1, 0x00000000);
	ppcemu_set_spr(emu, PPCEMU_SPRN_GQR2, 0x00000000);
	ppcemu_set_spr(emu, PPCEMU_SPRN_GQR3, 0x00000000);
	ppcemu_set_spr(emu, PPCEMU_SPRN_GQR4, 0x00000000);
	ppcemu_set_spr(emu, PPCEMU_SPRN_GQR5, 0x00000000);
	ppcemu_set_spr(emu, PPCEMU_SPRN_GQR6, 0x00000000);
	ppcemu_set_spr(emu, PPCEMU_SPRN_GQR7, 0x00000000);
	//13. Clear performance monitor SPRs
	ppcemu_set_spr(emu, PPCEMU_SPRN_MMCR0, 0x00000000);
	ppcemu_set_spr(emu, PPCEMU_SPRN_MMCR1, 0x00000000);
	ppcemu_set_spr(emu, PPCEMU_SPRN_PMC1,  0x00000000);
	ppcemu_set_spr(emu, PPCEMU_SPRN_PMC2,  0x00000000);
	ppcemu_set_spr(emu, PPCEMU_SPRN_PMC3,  0x00000000);
	ppcemu_set_spr(emu, PPCEMU_SPRN_PMC4,  0x00000000);
	//14. L2CR — wait for invalidation to finish, then enable L2
	//The original code polls L2CR_L2IP (bit 20 = 0x00100000) until it clears. Since you're driving the emulator externally (not running real hardware), you can just skip the poll and write the final value directly:
	// L2E = bit 31 = 0x80000000
	//ppcemu_set_spr(emu, PPCEMU_SPRN_L2CR, 0x80000000);
	//15. HID0 — re-enable L1 I-cache and D-cache
	// Add ICE (bit 18 = 0x00040000) and DCE (bit 17 = 0x00020000) to what was set in step 2
	// 0x00187510 | 0x00060000 = 0x001E7510
	// Note: ICFI and DCFI bits (14 and 13) were a one-shot pulse; real HW clears them.
	// Writing them here is fine as the emulator will handle them on write.
	ppcemu_set_spr(emu, PPCEMU_SPRN_HID0, 0x001E7510);
	//16. Set final MSR — re-enable address translation (DR | IR)
	// FP=0x2000, ME=0x1000, RI=0x0002, DR=0x0010, IR=0x0020
	ppcemu_set_msr(emu, PPCEMU_MSR_FP | PPCEMU_MSR_ME | PPCEMU_MSR_RI |
	                    PPCEMU_MSR_DR | PPCEMU_MSR_IR);
}


#define PT_LOAD  1

static int loadElf(const char *path, uint32_t * const out_pc) {
	FILE *f;
	Elf32_Ehdr ehdr;
	Elf32_Phdr phdr;
	uint8_t *buf;
	uint32_t entry, phoff, phentsize, phnum;
	uint32_t offset, vaddr, filesz, memsz;
	uint32_t i, zeros;
	static const uint8_t zero_block[256] = {0};

	f = fopen(path, "rb");
	if (!f) {
		perror("Failed to open ELF file");
		return -1;
	}

	if (fread(&ehdr, sizeof(ehdr), 1, f) != 1) {
		puts("Failed to read ELF header");
		fclose(f);
		return -1;
	}

	if (ehdr.e_ident[0] != 0x7f || ehdr.e_ident[1] != 'E' ||
	    ehdr.e_ident[2] != 'L'  || ehdr.e_ident[3] != 'F') {
		puts("Not a valid ELF file");
		fclose(f);
		return -1;
	}

	entry     = cronic_be32_to_cpu(ehdr.e_entry);
	phoff     = cronic_be32_to_cpu(ehdr.e_phoff);
	phentsize = cronic_be16_to_cpu(ehdr.e_phentsize);
	phnum     = cronic_be16_to_cpu(ehdr.e_phnum);

	printf("ELF entry point: 0x%08x\r\n", entry);
	*out_pc = entry;

	for (i = 0; i < phnum; i++) {
		if (fseek(f, (long)(phoff + i * phentsize), SEEK_SET) != 0) {
			puts("Failed to seek to program header");
			fclose(f);
			return -1;
		}

		if (fread(&phdr, sizeof(phdr), 1, f) != 1) {
			puts("Failed to read program header");
			fclose(f);
			return -1;
		}

		if (cronic_be32_to_cpu(phdr.p_type) != PT_LOAD)
			continue;

		offset = cronic_be32_to_cpu(phdr.p_offset);
		vaddr  = cronic_be32_to_cpu(phdr.p_vaddr);
		filesz = cronic_be32_to_cpu(phdr.p_filesz);
		memsz  = cronic_be32_to_cpu(phdr.p_memsz);

		printf("Loading segment %u: file offset 0x%08x -> vaddr 0x%08x, filesz 0x%08x, memsz 0x%08x\r\n",
		       i, offset, vaddr, filesz, memsz);

		if (filesz > 0) {
			buf = malloc(filesz);
			if (!buf) {
				puts("Out of memory");
				fclose(f);
				return -1;
			}

			if (fseek(f, (long)offset, SEEK_SET) != 0) {
				puts("Failed to seek to segment data");
				free(buf);
				fclose(f);
				return -1;
			}

			if (fread(buf, filesz, 1, f) != 1) {
				puts("Failed to read segment data");
				free(buf);
				fclose(f);
				return -1;
			}

			IPC_Write(~(0x3 << 30) & vaddr, buf, filesz);
			free(buf);

			if (IPC_Err) {
				puts("IPC error while loading segment");
				fclose(f);
				return -1;
			}
		}

		// zero-fill
		zeros = memsz - filesz;
		while (zeros > 0) {
			uint32_t chunk = zeros < sizeof(zero_block) ? zeros : (uint32_t)sizeof(zero_block);
			IPC_Write(~(0x3 << 30) & (vaddr + filesz + (memsz - filesz - zeros)), (void *)zero_block, chunk);
			if (IPC_Err) {
				puts("IPC error while zeroing segment");
				fclose(f);
				return -1;
			}
			zeros -= chunk;
		}
	}

	fclose(f);
	return 0;
}

/*#define DEBUG_BUS*/
#define NUM_BREAKPOINTS 16
#define NUM_WATCHPOINTS 16

static bool previouslyRunning = false;
static bool running = false;
static bool started = false;
static bool singleStep = false;
static bool gotIRQ = false;
static uint32_t breakpoints[NUM_BREAKPOINTS];
static bool breakpointsActive[NUM_BREAKPOINTS];
static uint32_t watchpoints[NUM_WATCHPOINTS];
static bool watchpointsActive[NUM_WATCHPOINTS];
static bool continuePastBP = false;
static char *debuggerReason = NULL;
static uint32_t dbgOldGPRs[32];
static uint32_t dbgOldPC, dbgOldLR, dbgOldCTR, dbgOldCR, dbgOldXER, dbgOldMSR, dbgOldSRR0, dbgOldSRR1, dbgOldDEC;
static uint64_t dbgOldTB;
static void debugger(struct ppcemu_state *emu);

static void bus_hook(struct ppcemu_state *emu, uint32_t addr, unsigned int len, void *data, bool is_write) {
	/* emu, addr, len, the pointer to data, and is_write are host-endian; the bytes pointed to by data are big-endian */
#ifdef DEBUG_BUS
	printf("Got bus transaction (%s) for %08x, %dB", is_write ? "write" : "read", addr, len);
	if (is_write) {
		printf(", data ");
		if (len == 1)
			printf("%02x\r\n", *(uint8_t *)data);
		else if (len == 2)
			printf("%04x\r\n", ppcemu_be16_to_cpu(*(uint16_t *)data));
		else if (len == 4)
			printf("%08x\r\n", ppcemu_be32_to_cpu(*(uint32_t *)data));
		else
			printf("[buffer]\r\n");
	}
	else
		puts("");
#endif

	/* Ironic returns already-big-endian data from the IPC interface, but we need to swap for writes */

	if (addr >= 0xfff00100 && addr <= 0xfff00200 && len == 4) { /* special case for EXI boot vector alias */
		if (is_write)
			return;
		else
			*(uint32_t *)data = IPC_Read32((addr - 0xfff00100) + 0x0d806840);
	}
	else if ((addr >= 0x00000000 && addr <= 0x017ffffff) || (addr >= 0x0c000000 && addr <= 0xdfffffff) || (addr >= 0x10000000 && addr <= 0x13ffffff)) {
		if (len == 1) {
			if (is_write)
				IPC_Write8(addr, *(uint8_t *)data);
			else
				*(uint8_t *)data = IPC_Read8(addr);
		}
		else if (len == 2) {
			if (is_write)
				IPC_Write16(addr, ppcemu_be16_to_le16(*(uint16_t *)data));
			else
				*(uint16_t *)data = IPC_Read16(addr);
		}
		else if (len == 4) {
			if (is_write)
				IPC_Write32(addr, ppcemu_be32_to_le32(*(uint32_t *)data));
			else
				*(uint32_t *)data = IPC_Read32(addr);
		}
		else if (len == 32) { /* cacheline fill / store */
			if (is_write) {
#ifdef DEBUG_BUS
				printf("Filling cacheline from 0x%08x\r\n", addr);
#endif
				IPC_Write(addr, data, len);
			}
			else {
#ifdef DEBUG_BUS
				printf("Storing cacheline from 0x%08x\r\n", addr);
#endif
				IPC_Read(addr, data, len);
			}
		}
	}
	else {
		printf("Unknown address: 0x%08x\r\n", addr);
		exit(1);
	}
}

static void loadstore_hook(struct ppcemu_state *emu, uint32_t addr, unsigned int len, void *data, bool is_write) {
	int i;

	for (i = 0; i < NUM_WATCHPOINTS; i++) {
		if (addr == watchpoints[i] && watchpointsActive[i]) { /* watchpoint hit */
			printf("Hit watchpoint %d (0x%08x), %s", i, addr, is_write ? "writen with value: " : "read");
			if (is_write && len == 1)
				printf("0x%02x\r\n", *(uint8_t *)data);
			else if (is_write && len == 2)
				printf("0x%04x\r\n", ppcemu_be16_to_cpu(*(uint16_t *)data));
			else if (is_write && len == 4)
				printf("0x%08x\r\n", ppcemu_be32_to_cpu(*(uint32_t *)data));
			else
				puts("");

			running = false;
			debuggerReason = "watchpoint";
			while (!running)
				debugger(emu);

			return;
		}
	}
}

static void ctrlcHandler(int sig) {
	(void)sig;
	running = false;
	debuggerReason = "Ctrl-C";
}

static void __attribute__((noreturn)) cleanup(int ret) {
	/* TODO: ppcemu_cleanup once I write that */
	IPC_Cleanup();
	exit(ret);
}

static int dbgAddBP(uint32_t addr) {
	int i;

	for (i = 0; i < NUM_BREAKPOINTS; i++) {
		if (!breakpointsActive[i]) {
			breakpoints[i] = addr;
			breakpointsActive[i] = true;
			return i;
		}
	}

	return -1;
}

static int dbgDelBP(uint32_t addr) {
	int i;

	for (i = 0; i < NUM_BREAKPOINTS; i++) {
		if (breakpointsActive[i] && breakpoints[i] == addr) {
			breakpoints[i] = 0;
			breakpointsActive[i] = false;
			return i;
		}
	}

	return -1;
}

static int dbgAddWP(uint32_t addr) {
	int i;

	for (i = 0; i < NUM_WATCHPOINTS; i++) {
		if (!watchpointsActive[i]) {
			watchpoints[i] = addr;
			watchpointsActive[i] = true;
			return i;
		}
	}

	return -1;
}

static int dbgDelWP(uint32_t addr) {
	int i;

	for (i = 0; i < NUM_WATCHPOINTS; i++) {
		if (watchpointsActive[i] && watchpoints[i] == addr) {
			watchpoints[i] = 0;
			watchpointsActive[i] = false;
			return i;
		}
	}

	return -1;
}


static void dbgHelp(void) {
	puts(
"Ironic Broadway LLE\r\n\
\r\n\
Commands:\r\n\
	help			Display this help message.\r\n\
\r\n\
	q, quit			Quit the emulator (does not quit Ironic).\r\n\
\r\n\
	info [target]		Get info about something.\r\n\
		regs, registers		Dump the CPU registers.\r\n\
		spr [name/num]		Dump the SPR at index [num] or\r\n\
					with name [name].\r\n\
\r\n\
	set [target]		Set something.\r\n\
		gpr [idx] [val]	Set GPR r[idx] to [val].\r\n\
		spr [idx] [val]	Set SPR r[idx] to [val].\r\n\
\r\n\
	b, break [addr]		Set a breakpoint at [addr].\r\n\
\r\n\
	bd [addr]		Delete the breakpoint at [addr].\r\n\
\r\n\
	bl			List created breakpoints.\r\n\
\r\n\
	w, watch [addr]		Set a watchpoint at [addr].\r\n\
\r\n\
	wd [addr]		Delete the watchpoint at [addr].\r\n\
\r\n\
	wl			List created watchpoints.\r\n\
\r\n\
	r, run			Start the emulator from Hard Reset and\r\n\
				run indefinitely, or until a breakpoint\r\n\
				is hit.\r\n\
\r\n\
	c, cont, continue	Continue emulation indefinitely, or\r\n\
				until a breakpoint is hit.\r\n\
\r\n\
	s, step			Step forward one instruction.\r\n\
\r\n\
	log [source] [level]	Set logging level for [source] to [level],\r\n\
				where [source] is one of \"translation\",\r\n\
				\"ifetch\",\"decode\", \"branch\",\r\n\
				\"loadstore\", \"cache\", or \"misc\", and\r\n\
				[level] is one of \"debug\", \"verbose\",\r\n\
				\"info\", \"warn\", or \"error\".\r\n\
\r\n\
	xfbdump <path>		Dump the current XFB to <path>.\r\n\
				If omitted, the path defaults to\r\n\
				xfb.bmp.");
}


static bool dbgConfirm(const char *msg, bool autoYes) {
	char *conf = NULL;
	size_t size = 0;
	ssize_t ret;

	while (true) {
		printf("%s %s ", msg, autoYes ? "[Y/n]" : "[N/y]");
		ret = getline(&conf, &size, stdin);

		if (ret == -1)
			cleanup(1);

		/* trim trailing newlines and spaces */
		size--;
		while (size > 0 && (conf[size] == '\r' || conf[size] == '\n' || conf[size] == ' ' || conf[size] == '\0')) {
			conf[size] = '\0';
			size--;
		}

		if (!strcmp(conf, "yes") || !strcmp(conf, "y") || !strcmp(conf, "Y") || !strcmp(conf, "Yes") || !strcmp(conf, "YES") || (!strcmp(conf, "") && autoYes)) {
			free(conf);
			return true;
		}
		else if (!strcmp(conf, "no") || !strcmp(conf, "n") || !strcmp(conf, "N") || !strcmp(conf, "No") || !strcmp(conf, "NO") || (!strcmp(conf, "") && !autoYes)) {
			free(conf);
			return false;
		}
		else {
			puts("Invalid response, please try again.");
			free(conf);
		}
	}

	free(conf);
}

static void dbgPrintReg(const char *prefix, uint32_t new, uint32_t old) {
	if (new != old)
		printf("%s\x1b[1;31m[%08x]\x1b[0m", prefix, new);
	else
		printf("%s\x1b[0m %08x ", prefix, new);
}

static void dbgPrintReg64(const char *prefix, uint64_t new, uint64_t old) {
	if (new != old)
		printf("%s\x1b[1;31m[%016x]\x1b[0m", prefix, new);
	else
		printf("%s\x1b[0m %016x ", prefix, new);
}


static void dbgRegDump(struct ppcemu_state *emu) {
	uint32_t gpr[32];
	uint64_t fpr[32];
	uint64_t tb;
	uint32_t pc, msr, lr, xer, cr, ctr, srr0, srr1, dec;
	int i;

	for (i = 0; i < 32; i++)
		gpr[i] = ppcemu_get_gpr(emu, i);

	pc = ppcemu_get_pc(emu);
	msr = ppcemu_get_msr(emu);
	lr = ppcemu_get_spr(emu, PPCEMU_SPRN_LR);
	xer = ppcemu_get_spr(emu, PPCEMU_SPRN_XER);
	ctr = ppcemu_get_spr(emu, PPCEMU_SPRN_CTR);
	srr0 = ppcemu_get_spr(emu, PPCEMU_SPRN_SRR0);
	srr1 = ppcemu_get_spr(emu, PPCEMU_SPRN_SRR1);
	dec = ppcemu_get_spr(emu, PPCEMU_SPRN_DEC);
	cr = ppcemu_get_cr(emu);
	tb = ppcemu_get_tb(emu);

	puts("GPRs:");
	puts("     r0-r7         r8-r15        r16-r23       r24-r31");
	for (i = 0; i < 8; i++) {
		dbgPrintReg("    ", gpr[i], dbgOldGPRs[i]);
		dbgPrintReg("    ", gpr[8 + i], dbgOldGPRs[8 + i]);
		dbgPrintReg("    ", gpr[16 + i], dbgOldGPRs[16 + i]);
		dbgPrintReg("    ", gpr[24 + i], dbgOldGPRs[24 + i]);
		puts("");
	}

	memcpy(dbgOldGPRs, gpr, sizeof(gpr));

	puts("");
	dbgPrintReg("PC: ", pc, dbgOldPC);
	dbgPrintReg("    MSR: ", msr, dbgOldMSR);
	dbgPrintReg("    XER: ", xer, dbgOldXER);
	puts("");
	dbgPrintReg("LR: ", lr, dbgOldLR);
	dbgPrintReg("   SRR0: ", srr0, dbgOldSRR0);
	dbgPrintReg("   SRR1: ", srr1, dbgOldSRR1);
	puts("");
	dbgPrintReg("CR: ", cr, dbgOldCR);
	dbgPrintReg("    CTR: ", ctr, dbgOldCTR);
	dbgPrintReg("    DEC: ", dec, dbgOldDEC);
	puts("");
	dbgPrintReg64("TB: ", tb, dbgOldTB);
	puts("");

	dbgOldPC = pc;
	dbgOldMSR = msr;
	dbgOldLR = lr;
	dbgOldXER = xer;
	dbgOldCR = cr;
	dbgOldCTR = ctr;
	dbgOldSRR0 = srr0;
	dbgOldSRR1 = srr1;
	dbgOldDEC = dec;
	dbgOldTB = tb;
}

static void debugger(struct ppcemu_state *emu) {
	char *cmd = NULL, *arg = NULL, *tmp;
	size_t cmdSize = 0;
	ssize_t ret;
	bool confirmed;
	uint32_t addr, val;
	int i, idx;
	enum ppcemu_loglevel level;
	enum ppcemu_log_source source;

	if (previouslyRunning && !singleStep)
		printf("Broke into debugger from %s at PC=0x%08x\r\n", debuggerReason, ppcemu_get_pc(emu));

	printf("(ppcdbg) ");
	ret = getline(&cmd, &cmdSize, stdin);

	if (ret == -1)
		cleanup(1);

	/* trim trailing newlines and spaces */
	cmdSize--;
	while (cmdSize > 0 && (cmd[cmdSize] == '\r' || cmd[cmdSize] == '\n' || cmd[cmdSize] == ' ') || cmd[cmdSize] == '\0') {
		cmd[cmdSize] = '\0';
		cmdSize--;
	}

	if (cmd[0] == '\r' || cmd[0] == '\n' || cmd[0] == '\0')
		return;

	/* split by space */
	strtok(cmd, " ");

	if (!strcmp(cmd, "help"))
		dbgHelp();
	else if (!strcmp(cmd, "q") || !strcmp(cmd, "quit")) {
		free(cmd);
		cleanup(0);
	}
	else if (!strcmp(cmd, "info")) {
		arg = strtok(NULL, " ");
		if (!arg) {
			puts("Missing info target argument");
			goto out;
		}
		else if (!strcmp(arg, "regs") || !strcmp(arg, "registers"))
			dbgRegDump(emu);
		else if (!strcmp(arg, "spr")) {
			arg = strtok(NULL, " ");
			if (!arg) {
				puts("Missing SPR name/number argument");
				goto out;
			}

			if (!strcasecmp(arg, "XER"))
				idx = PPCEMU_SPRN_XER;
			else if (!strcasecmp(arg, "LR"))
				idx = PPCEMU_SPRN_LR;
			else if (!strcasecmp(arg, "CTR"))
				idx = PPCEMU_SPRN_CTR;
			else if (!strcasecmp(arg, "HID0"))
				idx = PPCEMU_SPRN_HID0;
			else if (!strcasecmp(arg, "HID2"))
				idx = PPCEMU_SPRN_HID2_GEKKO;
			else if (!strcasecmp(arg, "HID4"))
				idx = PPCEMU_SPRN_HID4;
			else if (!strcasecmp(arg, "SRR0"))
				idx = PPCEMU_SPRN_SRR0;
			else if (!strcasecmp(arg, "SRR1"))
				idx = PPCEMU_SPRN_SRR1;
			else {
				idx = strtoul(arg, &tmp, 10);
				if (tmp == arg || idx > 1024) {
					printf("Invalid SPR number: %s\r\n", arg);
					goto out;
				}
			}

			val = ppcemu_get_spr(emu, idx);
			printf("SPR %d: %08x\r\n", idx, val);
		}
		else
			printf("Unknown info target: %s\r\n", arg);
	}
	else if (!strcmp(cmd, "set")) {
		arg = strtok(NULL, " ");
		if (!arg) {
			puts("Missing set target argument");
			goto out;
		}
		else if (!strcmp(arg, "gpr")) {
			arg = strtok(NULL, " ");
			if (!arg) {
				puts("Missing GPR index argument");
				goto out;
			}

			if (arg[0] == 'r')
				arg++;

			idx = strtoul(arg, &tmp, 10);
			if (tmp == arg || idx > 31) {
				printf("Invalid GPR number: %s\r\n", arg);
				goto out;
			}

			arg = strtok(NULL, " ");
			if (!arg) {
				puts("Missing value argument");
				goto out;
			}

			val = strtoul(arg, &tmp, 16);
			if (tmp == arg || val > 0xffffffff) {
				printf("Invalid GPR value: %s\r\n", arg);
				goto out;
			}

			ppcemu_set_gpr(emu, idx, val);
		}
		else if (!strcmp(arg, "spr")) {
			arg = strtok(NULL, " ");
			if (!arg) {
				puts("Missing SPR index argument");
				goto out;
			}

			idx = strtoul(arg, &tmp, 10);
			if (tmp == arg || idx > 1024) {
				printf("Invalid SPR number: %s\r\n", arg);
				goto out;
			}

			arg = strtok(NULL, " ");
			if (!arg) {
				puts("Missing value argument");
				goto out;
			}

			val = strtoul(arg, &tmp, 16);
			if (tmp == arg || val > 0xffffffff) {
				printf("Invalid SPR value: %s\r\n", arg);
				goto out;
			}

			ppcemu_set_spr(emu, idx, val);
		}
		else
			printf("Unknown set target: %s\r\n", arg);
	}
	else if (!strcmp(cmd, "b") || !strcmp(cmd, "break")) {
		arg = strtok(NULL, " ");
		if (!arg) {
			puts("Missing address");
			goto out;
		}

		addr = strtoul(arg, &tmp, 16);
		if (tmp == arg || addr > 0xffffffff)
			printf("Invalid breakpoint address: %s\r\n", arg);
		else {
			idx = dbgAddBP(addr);
			if (idx == -1)
				puts("Could not add breakpoint");
			else
				printf("Added breakpoint %d for PC=0x%08x\r\n", idx, addr);
		}

	}
	else if (!strcmp(cmd, "bl")) {
		for (i = 0; i < NUM_BREAKPOINTS; i++) {
			if (breakpointsActive[i])
				printf("Breakpoint %d: 0x%08x\r\n", i, breakpoints[i]);
		}
	}
	else if (!strcmp(cmd, "bd")) {
		arg = strtok(NULL, " ");
		if (!arg) {
			puts("Missing address");
			goto out;
		}

		addr = strtoul(arg, &tmp, 16);
		if (tmp == arg || addr > 0xffffffff)
			printf("Invalid breakpoint address: %s\r\n", arg);
		else {
			idx = dbgDelBP(addr);
			if (idx == -1)
				printf("There is no breakpoint at PC=0x%08x\r\n", addr);
			else
				printf("Deleted breakpoint %d @ PC=0x%08x\r\n", idx, addr);
		}
	}
	else if (!strcmp(cmd, "w") || !strcmp(cmd, "watch")) {
		arg = strtok(NULL, " ");
		if (!arg) {
			puts("Missing address");
			goto out;
		}

		addr = strtoul(arg, &tmp, 16);
		if (tmp == arg || addr > 0xffffffff)
			printf("Invalid watchpoint address: %s\r\n", arg);
		else {
			idx = dbgAddWP(addr);
			if (idx == -1)
				puts("Could not add watchpoint");
			else
				printf("Added watchpoint %d for PC=0x%08x\r\n", idx, addr);
		}

	}
	else if (!strcmp(cmd, "wl")) {
		for (i = 0; i < NUM_WATCHPOINTS; i++) {
			if (watchpointsActive[i])
				printf("Watchpoint %d: 0x%08x\r\n", i, watchpoints[i]);
		}
	}
	else if (!strcmp(cmd, "wd")) {
		arg = strtok(NULL, " ");
		if (!arg) {
			puts("Missing address");
			goto out;
		}

		addr = strtoul(arg, &tmp, 16);
		if (tmp == arg || addr > 0xffffffff)
			printf("Invalid watchpoint address: %s\r\n", arg);
		else {
			idx = dbgDelWP(addr);
			if (idx == -1)
				printf("There is no watchpoint at PC=0x%08x\r\n", addr);
			else
				printf("Deleted watchpoint %d @ PC=0x%08x\r\n", idx, addr);
		}
	}
	else if (!strcmp(cmd, "log")) {
		arg = strtok(NULL, " ");
		if (!arg) {
			puts("Missing log source");
			goto out;
		}

		if (!strcmp(arg, "translation"))
			source = PPCEMU_LOG_SOURCE_ADDR_TRANSLATION;
		else if (!strcmp(arg, "ifetch"))
			source = PPCEMU_LOG_SOURCE_IFETCH;
		else if (!strcmp(arg, "decode"))
			source = PPCEMU_LOG_SOURCE_INSTR_DECODE;
		else if (!strcmp(arg, "branch"))
			source = PPCEMU_LOG_SOURCE_BRANCH;
		else if (!strcmp(arg, "loadstore"))
			source = PPCEMU_LOG_SOURCE_LOADSTORE;
		else if (!strcmp(arg, "cache"))
			source = PPCEMU_LOG_SOURCE_CACHE;
		else if (!strcmp(arg, "misc"))
			source = PPCEMU_LOG_SOURCE_MISC;
		else {
			printf("Unknown log source: %s\r\n", arg);
			goto out;
		}


		arg = strtok(NULL, " ");
		if (!arg) {
			puts("Missing log level");
			goto out;
		}

		if (!strcmp(arg, "debug"))
			level = PPCEMU_LOGLEVEL_DEBUG;
		else if (!strcmp(arg, "verbose"))
			level = PPCEMU_LOGLEVEL_VERBOSE;
		else if (!strcmp(arg, "info"))
			level = PPCEMU_LOGLEVEL_INFO;
		else if (!strcmp(arg, "warn"))
			level = PPCEMU_LOGLEVEL_WARN;
		else if (!strcmp(arg, "error"))
			level = PPCEMU_LOGLEVEL_ERROR;
		else {
			printf("Unknown log level: %s\r\n", arg);
			goto out;
		}

		ppcemu_set_loglevel(source, level);
	}
	else if (!strcmp(cmd, "xfbdump")) {
		arg = strtok(NULL, " ");
		if (!arg)
			arg = "xfb.bmp";

		IPC_DumpXFB(arg);
	}
	else if (!strcmp(cmd, "r") || !strcmp(cmd, "run")) {
		if (started) {
			confirmed = dbgConfirm("The emulated Broadway is already running, would you like to restart it?", true);
			if (confirmed) {
				/* TODO: reset */
				running = true;
			}
			ppcemu_set_timing_mode(emu, PPCEMU_TIMING_MODE_RT);
		}
		else {
			running = true;
			started = true;
			singleStep = false;
			ppcemu_set_timing_mode(emu, PPCEMU_TIMING_MODE_RT);
		}
	}
	else if (!strcmp(cmd, "c") || !strcmp(cmd, "cont") || !strcmp(cmd, "continue")) {
		if (started) {
			running = true;
			continuePastBP = true;
			singleStep = false;
			ppcemu_set_timing_mode(emu, PPCEMU_TIMING_MODE_RT);
		}
		else
			puts("The emulated Broadway is not running, cannot continue.");
	}
	else if (!strcmp(cmd, "s") || !strcmp(cmd, "step")) {
		running = true;
		singleStep = true;
		continuePastBP = true;
		ppcemu_set_timing_mode(emu, PPCEMU_TIMING_MODE_SYNTH);
	}
	else
		printf("Unknown command: %s.  Try \"help\" for help.\r\n", cmd);

out:
	free(cmd);
}

static void emuStep(struct ppcemu_state *emu) {
	static unsigned int irqPollCounter = 0;
	uint32_t pc;
	int i;

	if (!gotIRQ && (++irqPollCounter & 0x3ff) == 0)
		IPC_PollFlipperIrq();

	if (gotIRQ) {
		ppcemu_external_interrupt(emu);
		gotIRQ = false;
	}

	/* check for breakpoints */
	if (!continuePastBP) {
		pc = ppcemu_get_pc(emu);

		for (i = 0; i < NUM_BREAKPOINTS; i++) {
			if (pc == breakpoints[i] && breakpointsActive[i]) { /* breakpoint hit */
				running = false;
				debuggerReason = "breakpoint";
				return;
			}
		}
	}

	continuePastBP = false;

	if (singleStep)
		running = false;

	/* actually run an instruction */
	ppcemu_step(emu);
}

static void irqHandler(void) {
	gotIRQ = true;
}

int main(int argc, char *argv[]) {
	struct ppcemu_state *emu;
	bool tmpRunning;

	emu = ppcemu_init(PPCEMU_CPU_MODEL_BROADWAY, bus_hook, 243000, 3);
	if (!emu) {
		puts("libppcemu init failed");
		return 1;
	}

	if (IPC_Init()) {
		puts("cronic init failed");
		return 1;
	}

	if (argc >= 2) {
		uint32_t newpc;
		if (loadElf(argv[1], &newpc) != 0) {
			puts("Failed to load ELF");
			IPC_Cleanup();
			return 1;
		}
		wiiInit(emu);
		ppcemu_set_pc(emu, newpc);
	}

	IPC_EnableFlipperIrqs(irqHandler);
	if (IPC_Err) {
		puts("Failed to enable Flipper IRQ forwarding");
		return 1;
	}

	/* to break into the debugger */
	signal(SIGINT, ctrlcHandler);

	/* clean up debugger state */
	memset(breakpoints, 0, sizeof(breakpoints));
	memset(breakpointsActive, 0, sizeof(breakpointsActive));
	memset(dbgOldGPRs, 0, sizeof(dbgOldGPRs));
	dbgOldPC = dbgOldLR = dbgOldCTR = dbgOldCR = dbgOldXER = dbgOldMSR = 0;

	/* register load/store hook for watchpoints */
	ppcemu_set_loadstore_hook(emu, loadstore_hook);

	ppcemu_set_cache_mode(emu, PPCEMU_CACHE_MODE_PERMISSIVE);

	while (true) {
		if (IPC_Err) {
			printf("Hit IPC error @ PC=0x%08x\r\n", ppcemu_get_pc(emu));
			cleanup(1);
		}

		tmpRunning = running;

		if (running)
			emuStep(emu);
		else
			debugger(emu);

		previouslyRunning = tmpRunning;
	}
}
