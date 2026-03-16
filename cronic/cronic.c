/*
 * Ironic - C glue for the IPC interface
 *
 * Copyright (C) 2025 - 2026 Techflash
 */

#define PPC_SOCK "/tmp/ironic-ppc.sock"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>
#include "cronic.h"
#include "endian.h"

bool IPC_Initialized = false;
int IPC_Err = 0;
static int IPC_Sock = -1;
static ipc_msg_t msg;

/* Flipper IRQ forwarding state */
static bool irq_forwarding = false;
static IPC_IrqCallback irq_callback = NULL;

/*
 * Read exactly `len` bytes from the socket.
 * Returns 0 on success, -1 on error.
 */
static int ipc_read_exact(void *buf, int len) {
	int total = 0;
	ssize_t n;

	while (total < len) {
		n = read(IPC_Sock, (char *)buf + total, len - total);
		if (n <= 0)
			return -1;
		total += n;
	}
	return 0;
}

/*
 * Read a response of `len` bytes plus the piggybacked IRQ flag (if enabled).
 * Fires the IRQ callback when the flag byte is non-zero.
 * Returns 0 on success, -1 on error.
 */
static int ipc_recv_response(void *buf, int len) {
	uint8_t flag;

	if (!irq_forwarding)
		return ipc_read_exact(buf, len);

	/* read data, then the 1-byte flag */
	if (ipc_read_exact(buf, len) < 0)
		return -1;
	if (ipc_read_exact(&flag, 1) < 0)
		return -1;

	if (flag && irq_callback)
		irq_callback();

	return 0;
}

/*
 * Read a 2-byte "OK" response (plus IRQ flag if enabled).
 * Returns 0 on success, -1 on error/bad response.
 */
static int ipc_recv_ok(void) {
	uint8_t buf[3]; /* "OK" + optional IRQ flag */
	int rlen = irq_forwarding ? 3 : 2;

	if (ipc_read_exact(buf, rlen) < 0)
		return -1;

	if (buf[0] != 'O' || buf[1] != 'K')
		return -1;

	if (irq_forwarding && buf[2] && irq_callback)
		irq_callback();
	return 0;
}

int IPC_Init(void) {
	struct sockaddr_un srv;
	int ret, set = 1;
	if (IPC_Initialized) {
		puts("IPC: trying to initialize 2nd client?");
		return 1;
	}
	IPC_Initialized = true;

	/* ignore sigpipe if we get it, else we crash if ironic blows up */
	signal(SIGPIPE, SIG_IGN);

	IPC_Sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (IPC_Sock < 0) {
		perror("socket");
		return 1;
	}

	/* try to gracefully downgrade it to just setting errno to EPIPE */
#ifdef SO_NOSIGPIPE
	ret = setsockopt(IPC_Sock, SOL_SOCKET, SO_NOSIGPIPE, (void *)&set, sizeof(int));
	if (ret < 0) {
		perror("setsockopt (not fatal)");
		puts("Note that the PPC LLE may crash if Ironic throws an error!");
	}
#else
	puts("System does not support SO_NOSIGPIPE - note that the PPC LLE may crash if Ironic throws an error!");
#endif

	srv.sun_family = AF_UNIX;
	strcpy(srv.sun_path, PPC_SOCK);

	ret = connect(IPC_Sock, (struct sockaddr *)&srv, sizeof(srv));
	if (ret < 0) {
		perror("socket");
		close(IPC_Sock);
		return 1;
	}

	return 0;
}

void IPC_Cleanup(void) {
	if (IPC_Sock != -1)
		close(IPC_Sock);
}

void IPC_EnableFlipperIrqs(IPC_IrqCallback callback) {
	char resp[2];
	msg.u32[0] = cronic_cpu_to_le32(IRONIC_ENABLE_FLIPPER_IRQ_FORWARDING);
	msg.u32[1] = 0;
	msg.u32[2] = 0;
	if (write(IPC_Sock, &msg, 12) != 12) {
		IPC_Err = 1;
		return;
	}

	if (ipc_recv_ok() < 0) {
		IPC_Err = 1;
		return;
	}

	irq_forwarding = true;
	irq_callback = callback;
}

uint8_t IPC_Read8(uint32_t addr) {
	uint8_t ret;
	msg.u32[0] = cronic_cpu_to_le32(IRONIC_PPC_READ8);
	msg.u32[1] = cronic_cpu_to_le32(addr);
	msg.u32[2] = 0;
	if (write(IPC_Sock, &msg, 12) != 12) {
		IPC_Err = 1;
		return 0;
	}

	if (ipc_recv_response(&ret, 1) < 0) {
		IPC_Err = 1;
		return 0;
	}

	return ret;
}

uint16_t IPC_Read16(uint32_t addr) {
	uint16_t ret;
	msg.u32[0] = cronic_cpu_to_le32(IRONIC_PPC_READ16);
	msg.u32[1] = cronic_cpu_to_le32(addr);
	msg.u32[2] = 0;
	if (write(IPC_Sock, &msg, 12) != 12) {
		IPC_Err = 1;
		return 0;
	}

	if (ipc_recv_response(&ret, 2) < 0) {
		IPC_Err = 1;
		return 0;
	}

	return ret;
}

uint32_t IPC_Read32(uint32_t addr) {
	uint32_t ret;
	msg.u32[0] = cronic_cpu_to_le32(IRONIC_PPC_READ32);
	msg.u32[1] = cronic_cpu_to_le32(addr);
	msg.u32[2] = 0;
	if (write(IPC_Sock, &msg, 12) != 12) {
		IPC_Err = 1;
		return 0;
	}

	if (ipc_recv_response(&ret, 4) < 0) {
		IPC_Err = 1;
		return 0;
	}

	return ret;
}

void IPC_Write8(uint32_t addr, uint8_t data) {
	msg.u32[0]  = cronic_cpu_to_le32(IRONIC_PPC_WRITE8);
	msg.u32[1]  = cronic_cpu_to_le32(addr);
	msg.u32[2]  = 0;
	msg.u8 [12] = data;
	if (write(IPC_Sock, &msg, 13) != 13) {
		IPC_Err = 1;
		return;
	}

	if (ipc_recv_ok() < 0) {
		IPC_Err = 1;
		return;
	}
}

void IPC_Write16(uint32_t addr, uint16_t data) {
	msg.u32[0] = cronic_cpu_to_le32(IRONIC_PPC_WRITE16);
	msg.u32[1] = cronic_cpu_to_le32(addr);
	msg.u32[2] = 0;
	msg.u16[6] = data; /* assumed already le16 */
	if (write(IPC_Sock, &msg, 14) != 14) {
		IPC_Err = 1;
		return;
	}

	if (ipc_recv_ok() < 0) {
		IPC_Err = 1;
		return;
	}
}

void IPC_Write32(uint32_t addr, uint32_t data) {
	msg.u32[0] = cronic_cpu_to_le32(IRONIC_PPC_WRITE32);
	msg.u32[1] = cronic_cpu_to_le32(addr);
	msg.u32[2] = 0;
	msg.u32[3] = data; /* assumed already le32 */
	if (write(IPC_Sock, &msg, 16) != 16) {
		IPC_Err = 1;
		return;
	}

	if (ipc_recv_ok() < 0) {
		IPC_Err = 1;
		return;
	}
}

/* FIXME: should use a proper PPC 'read buffer' command at some point */
void IPC_Read(uint32_t addr, void *data, unsigned int len) {
	msg.u32[0] = cronic_cpu_to_le32(IRONIC_READ);
	msg.u32[1] = cronic_cpu_to_le32(addr);
	msg.u32[2] = cronic_cpu_to_le32(len);

	if (write(IPC_Sock, &msg, 12) != 12) {
		IPC_Err = 1;
		return;
	}

	if (ipc_recv_response(data, len) < 0) {
		IPC_Err = 1;
		return;
	}
}

/* FIXME: should use a proper PPC 'write buffer' command at some point */
void IPC_Write(uint32_t addr, void *data, unsigned int len) {
	msg.u32[0] = cronic_cpu_to_le32(IRONIC_WRITE);
	msg.u32[1] = cronic_cpu_to_le32(addr);
	msg.u32[2] = cronic_cpu_to_le32(len);
	if (len > sizeof(msg) - 12) {
		printf("IPC_Write: data too big: %u\r\n", len);
		return;
	}
	memcpy(&msg.u32[3], data, len);

	if (write(IPC_Sock, &msg, 12 + len) != 12 + len) {
		IPC_Err = 1;
		return;
	}

	if (ipc_recv_ok() < 0) {
		IPC_Err = 1;
		return;
	}
}
