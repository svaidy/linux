
/*
 * Basic mmap test case
 */

#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdbool.h>
#include <time.h>

#include <endian.h>

#include <sys/ioctl.h>

#include <asm/opal-prd.h>

#include "hostboot-interface.h"

static uint64_t user_mapped_base_addr;
static int opald_fd;
static uint64_t page_size;
static struct opal_prd_info info;
#define HBRT_CODE_REGION_NAME "ibm,hbrt-code-image"

/* This is the "real" HBRT call table for calling into HBRT as
 * provided by it. It will be used by the assembly thunk
 */
struct runtime_interfaces *hservice_runtime;
struct runtime_interfaces hservice_runtime_fixed;

/* This is the callback table provided by assembly code */
extern struct host_interfaces hinterface;

/* Create opd to call hostservice init */
struct func_desc {
	void *addr;
	void *toc;
} hbrt_entry;

/* HBRT init wrappers */
extern struct runtime_interfaces *call_hbrt_init(struct host_interfaces *);

/* hservice Call wrappers */

extern void call_cxxtestExecute(void *);
extern const uint32_t * call_get_lid_list(size_t * o_num);
extern int call_loadOCC(uint64_t i_homer_addr_phys,
			uint64_t i_homer_addr_va,
			uint64_t i_common_addr_phys,
			uint64_t i_common_addr_va,
			uint64_t i_chip);
extern int call_startOCCs(uint64_t* i_chip,
			  size_t i_num_chips);
extern int call_stopOCCs(uint64_t* i_chip,
			 size_t i_num_chips);

extern int call_handle_attns(uint64_t i_proc,
			uint64_t i_ipollStatus,
			uint64_t i_ipollMask);

/* Dummy calls for hservices */

void hservice_puts(const char *str)
{
	printf("%s\n", str);
}

void hservice_assert(void)
{
	printf("HBRT Called ASSERT() running while(1)\n");
	while(1);
}

void *hservice_malloc(size_t size)
{
	return malloc(size);
}

void hservice_free(void *ptr)
{
	free(ptr);
}

void *hservice_realloc(void *ptr, size_t size)
{
	return realloc(ptr, size);
}

int hservice_send_error_log(uint32_t plid, uint32_t dsize, void *data)
{
	printf("FIXME: Calling ........hservice_send_error_log()\n");
	return 0;
}


int hservice_scom_read(uint64_t chip_id, uint64_t addr, void *buf)
{
	int rc;
	struct opal_prd_scom scom;

	scom.chip = chip_id;
	scom.addr = addr;

	rc = ioctl(opald_fd, OPAL_PRD_SCOM_READ, &scom);
	if (rc) {
		perror("ioctl scom_read");
		return 0;
	}
	/* Copy byte by byte to avoid endian flip */
	memcpy(buf, &scom.data, sizeof(uint64_t));

	printf("scom read: chip %lx addr %lx val %lx\n", chip_id, addr, scom.data);

	return 0;
}

int hservice_scom_write(uint64_t chip_id, uint64_t addr,
                               const void *buf)
{
	int rc;
	struct opal_prd_scom scom;

	scom.chip = chip_id;
	scom.addr = addr;
	/* Copy byte by byte to avoid endian flip */
	memcpy(&scom.data, buf, sizeof(uint64_t));

	rc = ioctl(opald_fd, OPAL_PRD_SCOM_WRITE, &scom);
	if (rc) {
		perror("ioctl scom_write");
		return 0;
	}

	printf("scom write: chip %lx addr %lx val %lx\n", chip_id, addr, scom.data);

	return 0;
}

int hservice_lid_load(uint32_t lid, void **buf, size_t *len)
{
	printf("FIXME: Calling ........hservice_lid_load()\n");
	return 0;
}

int hservice_lid_unload(void *buf)
{
	printf("FIXME: Calling ........hservice_lid_unload()\n");
	return 0;
}

uint64_t hservice_get_reserved_mem(const char *name)
{
	struct opal_prd_range *code_range = NULL;
	uint64_t addr;
	int i, rc;
	uint64_t align_physaddr, offset;

	printf("hservice_get_reserved_mem: %s\n", name);

	/* Search for requested region */
	for (i = 0; i < OPAL_PRD_MAX_RANGES; i++) {
		if  (!strcmp(info.ranges[i].name, name)) {
			code_range = &info.ranges[i];
			break;
		}
	}

	if (!code_range)
		return 0;


	printf("Mapping 0x%016lx 0x%08lx %s\n", code_range->physaddr,
			code_range->size, code_range->name);

	align_physaddr = code_range->physaddr & ~(page_size-1);
	offset = code_range->physaddr & (page_size-1);
	addr = mmap(NULL, code_range->size,
				PROT_WRITE|PROT_READ|PROT_EXEC,
				MAP_PRIVATE, opald_fd, align_physaddr);

	if (addr == MAP_FAILED) {
		perror("mmap");
		return 0;
	}

	printf("hservice_get_reserved_mem: %s address %016llx\n", name, addr);
	if (addr) {
		return addr + offset;
	}

	return 0;
}

void hservice_nanosleep(uint64_t i_seconds, uint64_t i_nano_seconds)
{
    printf("FIXME:Calling ........hservice_nanosleep()\n");
}

int hservice_set_special_wakeup()
{
    printf("FIXME:Calling ........hservice_set_special_wakeup()\n");
}

int hservice_clr_special_wakeup()
{
    printf("FIXME:Calling ........hservice_clr_special_wakeup()\n");
}

int hservice_wakeup(uint32_t i_core, uint32_t i_mode)
{
    printf("FIXME:Calling ........hservice_set_wakeup()\n");
}

int hservice_set_page_execute(void *addr)
{
    printf("FIXME:Calling ........hservice_set_page_execute()\n");
}

void hservice_report_failure( uint64_t i_status, uint64_t i_partId )
{
    printf("FIXME:Calling ........hservice_report_failure()\n");
}

int hservice_clock_gettime(clockid_t i_clkId, struct timespec *o_tp)
{
    printf("FIXME:Calling ........hservice_clock_gettime()\n");
}

int hservice_pnor_read(uint32_t i_proc, const char* i_partitionName,
		uint64_t i_offset, void* o_data, size_t i_sizeBytes)
{
    printf("FIXME:Calling ........hservice_pnor_read()\n");
}

int hservice_pnor_write(uint32_t i_proc, const char* i_partitionName,
		uint64_t i_offset, void* o_data, size_t i_sizeBytes)
{
    printf("FIXME:Calling ........hservice_pnor_write()\n");
}


bool hservices_init(void *mamaddr)
{
	void *code = NULL;
	struct runtime_interfaces *(*hbrt_init)(struct host_interfaces *);
	int i, sz;
	uint64_t *s, *d;

	code  =  (void *)mamaddr;
	printf("code Address : [%016p]\n",code);

	/* We enter at 0x100 into the image. */
	/* Load func desc in BE since we reverse it in thunk */

	hbrt_entry.addr = htobe64(code + 0x100);
	hbrt_entry.toc = 0; /* No toc for init entry point */

	if (memcmp(code, "HBRTVERS", 8) != 0) {
		printf("HBRT: Bad signature for ibm,hbrt-code-image! exiting\n");
		exit(-1);
	}

	printf("HBRT: calling ibm,hbrt_init() %p!!!!\n",hservice_runtime);
	hservice_runtime = call_hbrt_init(&hinterface);
	printf("HBRT: hbrt_init passed..... %p version %p!!!!\n", hservice_runtime,
		hservice_runtime->interface_version);

	sz = sizeof(struct runtime_interfaces)/sizeof(uint64_t);
	s = (uint64_t *)hservice_runtime;
	d = (uint64_t *)&hservice_runtime_fixed;
	/* Byte swap the function pointers */
	for (i = 0; i < sz; i++) {
		d[i] = be64toh(s[i]);
		printf(" 	hservice_runtime_fixed[%d] = %p\n", i, d[i]);
	}

}

static void fixup_hinterface_table(void)
{
	uint64_t *t64;
	unsigned int i, sz;

	/* Swap interface version */
	hinterface.interface_version =
		htobe64(hinterface.interface_version);

	/* Swap OPDs */
	sz = sizeof(struct host_interfaces) / sizeof(uint64_t);
	t64 = (uint64_t *)&hinterface;
	for (i = 1; i < sz; i++) {
		uint64_t *opd = (uint64_t *)t64[i];
		if (!opd)
			continue;
		t64[i] = htobe64(t64[i]);
		opd[0] = htobe64(opd[0]);
		opd[1] = htobe64(opd[1]);
		opd[2] = htobe64(opd[2]);
	}
}


static unsigned long get_region_info()
{
	int rc;
	int i;

	rc = ioctl(opald_fd, OPAL_PRD_GET_INFO, &info);
	if (rc) {
		perror("ioctl get info");
		return rc;
	}

	for (i = 0; i < OPAL_PRD_MAX_RANGES; i++) {
		printf("\t0x%016lx 0x%08lx %s\n", info.ranges[i].physaddr,
				info.ranges[i].size, info.ranges[i].name);
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int hb, rc, i;
	size_t sz;
	uint64_t mapped_addr;
	unsigned long hbrt_size;
	unsigned long *p;
	char *hostboot_file_name=NULL;
	struct stat hb_stat;
	int hb_file = 0;
	void *hb_mapped;
	uint64_t val;
	struct opal_prd_range *code_range = NULL;
	uint64_t align_physaddr, offset;

	/* Parse options */
	while(1) {
		static struct option opal_diag_options[] = {
			{"hostboot", required_argument, NULL, 'f'},
		};
		int c, idx=1;
		c = getopt_long(argc, argv, "h", opal_diag_options, &idx);
		if (c == EOF)
			break;
		switch (c) {
		case 'f':
			hostboot_file_name = optarg;
			printf("Using hostboot file: %s\n", hostboot_file_name);
			hb_file = 1;
			break;
		case 'h':
			printf("Usage: %s --hostboot <hostboot.bin file> \n");
			printf("By default use image from memory\n");
		}
	}

	page_size = sysconf(_SC_PAGE_SIZE);

	if ((opald_fd=open("/dev/opal-prd", O_RDWR))<0) {
		perror("open");
		exit(-1);
	}

	rc = get_region_info();
	if (rc) {
		printf("Error getting region info\n");
		exit(-1);
	}

	if (hb_file) {
		if ((hb = open(hostboot_file_name, O_RDONLY)) < 0) {
			perror("Hostboot file");
			exit(-1);
		}
		/* Load HB code from file */
		rc = fstat(hb, &hb_stat);
		if (rc) {
			perror("Hostboot file");
			exit(-1);
		}
		sz = hb_stat.st_size;
		printf("Hostboot file size %d bytes\n", sz);
		/* Get page aligned executable memory */
		hb_mapped = mmap(0, sz, PROT_WRITE|PROT_READ|PROT_EXEC,
				MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
		if (!hb_mapped) {
			perror("Hostboot malloc");
			exit(-1);
		}

		rc = read(hb, hb_mapped, sz);
		if (rc < 0) {
			perror("Hostboot read");
			exit(-1);
		}
		p = (unsigned long *)hb_mapped;
		printf("Addr %016llx Data %08llx\n", hb_mapped, hb_mapped);
		printf("Addr %016llx String %s\n", hb_mapped, hb_mapped);

	} else {

		/* Search for HBRT code region */
		for (i = 0; i < OPAL_PRD_MAX_RANGES; i++) {
			if  (!strcmp(info.ranges[i].name, HBRT_CODE_REGION_NAME)) {
				code_range = &info.ranges[i];
				break;
			}
		}

		if (!code_range) {
			printf("Unable to get code area\n");
			exit(-1);
		}


		printf("Mapping 0x%016lx 0x%08lx %s\n", code_range->physaddr,
			code_range->size, code_range->name);

		align_physaddr = code_range->physaddr & ~(page_size-1);
		offset = code_range->physaddr & (page_size-1);

		mapped_addr = mmap(NULL, code_range->size,
				PROT_WRITE|PROT_READ|PROT_EXEC,
				MAP_PRIVATE, opald_fd, align_physaddr);

		if (mapped_addr == MAP_FAILED) {
			perror("mmap");
			exit(-1);
		}

		user_mapped_base_addr = mapped_addr;

		p = (unsigned long *) (mapped_addr | offset);
		printf("Addr %016llx Data %08llx\n", &p[0], &p[0]);
		printf("Addr %016llx String %s\n", &p[0], &p[0]);

		printf("Addr %016llx Data %016llx\n", &p[0x2000/8], p[0x2000/8]);
		printf("Addr %016llx Data %016llx\n", &p[0x2008/8], p[0x2008/8]);

	}

	fixup_hinterface_table();

	printf("calling hservices_init\n");
	if (hb_file) {
		/* Use ibm,hbrt-code-image from file, rest from memory */
		hservices_init(hb_mapped);
	} else {
		/* Use all sections from memory */
		hservices_init(&p[0]);
	}

	//printf("calling hservice_runtime->loadOCC()\n");
	//rc = hservice_runtime->loadOCC(0, 0,0,0,0);

	/* Chip IDs 0x00, 0x01, 0x10, 0x11 */
	printf("calling hservice_runtime->handle_attns()\n");
	if (hservice_runtime->handle_attns) {
		rc = call_handle_attns(0x00, 0, 0);
	} else {
		printf("ERROR: 	hservice_runtime->handle_attns() not found\n");
	}

	/* Test more SCOMS */

	hservice_scom_read(0x00, 0x1502000d, &val);
	/* Convert to LE before using val */
	val &= ~0x8000000000000000ULL;
	hservice_scom_write(0x00, 0x1502000d, &val);
	hservice_scom_read(0x00, 0x1502000d, &val);
	val |= 0x8000000000000000ULL;
	hservice_scom_write(0x00, 0x1502000d, &val);
	hservice_scom_read(0x00, 0x1502000d, &val);

	/* FIXME: Track and unmap */

	close(opald_fd);
	return(0);
}

