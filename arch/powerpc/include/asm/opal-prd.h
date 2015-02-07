/*
 * OPAL Runtime Diagnostics interface driver
 * Supported on POWERNV platform
 *
 * (C) Copyright IBM 2015
 *
 * Author: Vaidyanathan Srinivasan <svaidy at linux.vnet.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef _UAPI_LINUX_OPAL_DIAG_H_
#define _UAPI_LINUX_OPAL_DIAG_H_


/* IOCTLs for /dev/opal-diag */

struct opald_scom {
	uint64_t chip;
	uint64_t addr;
	uint64_t data;
};

#define MAX_NAME_LEN	128	/* Keep 128 bytes to copy the string */

struct opald_mem {
	char name[MAX_NAME_LEN];
	uint64_t addr;
	uint64_t size;
};

#define OPALD_SCOM_READ		_IOR('o', 0x10, struct opald_scom)
#define OPALD_SCOM_WRITE	_IOW('o', 0x11, struct opald_scom)
#define OPALD_GET_MAP_SIZE	_IOR('o', 0x01, unsigned long)
#define OPALD_GET_RESERVED_MEM	_IOWR('o', 0x02, struct opald_mem)

#endif
