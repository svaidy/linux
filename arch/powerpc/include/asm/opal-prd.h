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

#define OPAL_PRD_VERSION		1
#define OPAL_PRD_RANGE_NAME_LEN		32
#define OPAL_PRD_MAX_RANGES		8

struct opal_prd_range {
	char		name[OPAL_PRD_RANGE_NAME_LEN];
	uint64_t	physaddr;
	uint64_t	size;
};

struct opal_prd_info {
	uint64_t		version;
	uint64_t		code_size;
	struct opal_prd_range	ranges[OPAL_PRD_MAX_RANGES];

};

struct opal_prd_scom {
	uint64_t chip;
	uint64_t addr;
	uint64_t data;
};

#define OPAL_PRD_GET_INFO	_IOR('o', 0x01, struct opal_prd_info)
#define OPAL_PRD_SCOM_READ	_IOR('o', 0x10, struct opal_prd_scom)
#define OPAL_PRD_SCOM_WRITE	_IOW('o', 0x11, struct opal_prd_scom)

/* read/write interface for events */
struct opal_prd_attn_response {
	uint64_t	proc;
	uint64_t	ipoll_unmask;
};

#endif
