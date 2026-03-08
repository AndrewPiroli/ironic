/*
 * Ironic - C glue for the IPC interface
 *
 * Copyright (C) 2025 - 2026 Techflash
 */

#ifndef _CRONIC_CRONIC_H
#define _CRONIC_CRONIC_H

#include <stdint.h>

extern bool IPC_Initialized;
extern int IPC_Err;

typedef union {
	uint32_t u32[4];
	uint32_t u16[8];
	uint8_t  u8 [16];
} ipc_msg_t;

enum {
	IRONIC_READ		= 1,
	IRONIC_WRITE		= 2,
	IRONIC_MSG		= 3,
	IRONIC_ACK		= 4,
	IRONIC_MSGNORET		= 5,
	IRONIC_PPC_READ8	= 6,
	IRONIC_PPC_READ16	= 7,
	IRONIC_PPC_READ32	= 8,
	IRONIC_PPC_WRITE8	= 9,
	IRONIC_PPC_WRITE16 	= 10,
	IRONIC_PPC_WRITE32 	= 11
};

extern int IPC_Init(void);
extern void IPC_Cleanup(void);
extern uint8_t IPC_Read8(uint32_t addr);
extern uint16_t IPC_Read16(uint32_t addr);
extern uint32_t IPC_Read32(uint32_t addr);
extern void IPC_Write8(uint32_t addr, uint8_t data);
extern void IPC_Write16(uint32_t addr, uint16_t data);
extern void IPC_Write32(uint32_t addr, uint32_t data);

#endif /* _CRONIC_CRONIC_H */
