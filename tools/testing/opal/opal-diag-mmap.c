
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

#include <asm/ioctl.h>

#include <linux/opal-diag.h>

static uint64_t user_mapped_base_addr;
static int opald_fd;

/* Dummy calls for hservices */

static void hservice_puts(const char *str)
{
	printf("%s\n", str);
}

static void hservice_assert(void)
{
	printf("HBRT Called ASSERT() running while(1)\n");
	while(1);
}

static void *hservice_malloc(size_t size)
{
	return malloc(size);
}

static void hservice_free(void *ptr)
{
	free(ptr);
}

static void *hservice_realloc(void *ptr, size_t size)
{
	return realloc(ptr, size);
}

static int hservice_send_error_log(uint32_t plid, uint32_t dsize, void *data)
{
	printf("FIXME: Calling ........hservice_send_error_log()\n");
	return 0;
}

static int hservice_scom_read(uint64_t chip_id, uint64_t addr, void *buf)
{
	int rc;
	struct opald_scom scom;
	uint64_t *p = buf;

	scom.chip = chip_id;
	scom.addr = addr;
	
	rc = ioctl(opald_fd, OPALD_SCOM_READ, &scom);
	if (rc) {
		perror("ioctl scom_read");
		return 0;
	}
	*p = scom.data;

	printf("scom read: chip %lx addr %lx val %lx\n", chip_id, addr, *p);

	return 0;
}

static int hservice_scom_write(uint64_t chip_id, uint64_t addr,
                               const void *buf)
{
	int rc;
	struct opald_scom scom;
	uint64_t *p = buf;

	scom.chip = chip_id;
	scom.addr = addr;
	scom.data = *p;
	
	rc = ioctl(opald_fd, OPALD_SCOM_WRITE, &scom);
	if (rc) {
		perror("ioctl scom_write");
		return 0;
	}

	printf("scom write: chip %lx addr %lx val %lx\n", chip_id, addr, *p);

	return 0;
}

static int hservice_lid_load(uint32_t lid, void **buf, size_t *len)
{
	printf("FIXME: Calling ........hservice_lid_load()\n");
	return 0;
}

static int hservice_lid_unload(void *buf)
{
	printf("FIXME: Calling ........hservice_lid_unload()\n");
	return 0;
}

static uint64_t hservice_get_reserved_mem(const char *name)
{
	struct opald_mem mem;
	uint64_t addr;
	int rc;

	/* Need ioctl to goto kernel.  This is a hack for testing */
	/* Address offsets coded for ltctul57a-fsp */
	printf("hservice_get_reserved_mem: %s\n", name);

	strncpy(mem.name, name, MAX_NAME_LEN);

	rc = ioctl(opald_fd, OPALD_GET_RESERVED_MEM, &mem);
	if (rc) {
		perror("ioctl get reserved mem");
		return 0;
	}

	printf("hservice_get_reserved_mem: %s address %016llx\n", name, mem.addr);
	return mem.addr;
}

static void hservice_nanosleep(uint64_t i_seconds, uint64_t i_nano_seconds)
{
    printf("FIXME:Calling ........hservice_nanosleep()\n");
}

static int hservice_set_special_wakeup()
{
    printf("FIXME:Calling ........hservice_set_special_wakeup()\n");
}

static int hservice_clr_special_wakeup()
{
    printf("FIXME:Calling ........hservice_clr_special_wakeup()\n");
}

static int hservice_wakeup(uint32_t i_core, uint32_t i_mode)
{
    printf("FIXME:Calling ........hservice_set_wakeup()\n");
}

/* Hostboot runtime interface */
/* Derived from src/include/runtime/interface.h in Hostboot */

/** @typedef hostInterfaces_t
 *  @brief Interfaces provided by the underlying environment (ex. Sapphire).
 *
 *  @note Some of these functions are not required (marked optional) and
 *        may be NULL.
 */
struct host_interfaces
{
	/** Interface version. */
	uint64_t interfaceVersion;
	
	/** Put a string to the console. */
	void (*puts)(const char*);
	/** Critical failure in runtime execution. */
	void (*assert)();
	
	/** OPTIONAL. Hint to environment that the page may be executed. */
	int (*set_page_execute)(void*);
	
	/** malloc */
	void* (*malloc)(size_t);
	/** free */
	void (*free)(void*);
	/** realloc */
	void* (*realloc)(void*, size_t);
	
	/** sendErrorLog
	 * @param[in] plid Platform Log identifier
	 * @param[in] data size in bytes
	 * @param[in] pointer to data
	 * @return 0 on success else error code
	 */
	int (*send_error_log)(uint32_t,uint32_t,void *);
	
	/** Scan communication read
	 * @param[in] chip_id (based on devtree defn)
	 * @param[in] address
	 * @param[in] pointer to 8-byte data buffer
	 * @return 0 on success else return code
	 */
	int (*scom_read)(uint64_t, uint64_t, void*);
	
	/** Scan communication write
	 * @param[in] chip_id (based on devtree defn)
	 * @param[in] address
	 * @param[in] pointer to 8-byte data buffer
	 * @return 0 on success else return code
	 */
	int (*scom_write)(uint64_t, uint64_t, void* );
	
	/** lid_load
	 *  Load a LID from PNOR, FSP, etc.
	 *
	 *  @param[in] LID number.
	 *  @param[out] Allocated buffer for LID.
	 *  @param[out] Size of LID (in bytes).
	 *
	 *  @return 0 on success, else RC.
	 */
	int (*lid_load)(uint32_t, void**, size_t*);
	
	/** lid_unload
	 *  Release memory from previously loaded LID.
	 *
	 *  @param[in] Allocated buffer for LID to release.
	 *
	 *  @return 0 on success, else RC.
	 */
	int (*lid_unload)(void*);
	
	/** Get the address of a reserved memory region by its devtree name.
	 *
	 *  @param[in] Devtree name (ex. "ibm,hbrt-vpd-image")
	 *  @return physical address of region (or NULL).
	 **/
	uint64_t (*get_reserved_mem)(const char*);
	
	/**
	 * @brief  Force a core to be awake, or clear the force
	 * @param[in] i_core  Core to wake (based on devtree defn)
	 * @param[in] i_mode  0=force awake
	 *                    1=clear force
	 *                    2=clear all previous forces
	 * @return rc non-zero on error
	 */
	int (*wakeup)(uint32_t i_core, uint32_t i_mode );
	
	/**
	 * @brief Delay/sleep for at least the time given
	 * @param[in] seconds
	 * @param[in] nano seconds
	 */
	void (*nanosleep)(uint64_t i_seconds, uint64_t i_nano_seconds);
	
	/**
	 * @brief Report an error to the host
	 * @param[in] Failing status that identifies the nature of the fail
	 * @param[in] Identifier that specifies the failing part
	 */
	void (*report_failure)( uint64_t i_status, uint64_t i_partId );
	
	/**
	 *  @brief Reads the clock value from a POSIX clock.
	 *  @param[in]  i_clkId - The clock ID to read.
	 *  @param[out] o_tp - The timespec struct to store the clock value in.
	 *
	 *  @return 0 or -(errno).
	 *  @retval 0 - SUCCESS.
	 *  @retval -EINVAL - Invalid clock requested.
	 *  @retval -EFAULT - NULL ptr given for timespec struct.
	 *
	 */
	int (*clock_gettime)(clockid_t i_clkId, struct timespec *o_tp);
	
	/**
	 * @brief Read Pnor
	 * @param[in] i_proc: processor Id
	 * @param[in] i_partitionName: name of the partition to read
	 * @param[in] i_offset: offset within the partition
	 * @param[out] o_data: pointer to the data read
	 * @param[in] i_sizeBytes: size of data to read
	 * @retval rc - non-zero on error
	 */
	int (*pnor_read) (uint32_t i_proc, const char* i_partitionName,
	               uint64_t i_offset, void* o_data, size_t i_sizeBytes);
	
	/**
	 * @brief Write to Pnor
	 * @param[in] i_proc: processor Id
	 * @param[in] i_partitionName: name of the partition to write
	 * @param[in] i_offset: offset withing the partition
	 * @param[in] i_data: pointer to the data to write
	 * @param[in] i_sizeBytes: size of data to write
	 * @retval rc - non-zero on error
	 */
	int (*pnor_write) (uint32_t i_proc, const char* i_partitionName,
	               uint64_t i_offset, void* i_data, size_t i_sizeBytes);
	
	// Reserve some space for future growth.
	void (*reserved[32])(void);
};

struct runtime_interfaces {

	/** Interface version. */
	uint64_t interfaceVersion;
	
	/** Execute CxxTests that may be contained in the image.
	 *
	 *  @param[in] - Pointer to CxxTestStats structure for results reporting.
	 */
	void (*cxxtestExecute)(void*);
	
	/** Get a list of lids numbers of the lids known to HostBoot
	 *
	 * @param[out] o_num - the number of lids in the list
	 * @return a pointer to the list
	 */
	const uint32_t * (*get_lid_list)(size_t * o_num);
	
	/** Load OCC Image and common data into mainstore, also setup OCC BARSs
	 *
	 * @param[in] i_homer_addr_phys - The physical mainstore address of the
	 *                                start of the HOMER image
	 * @param[in] i_homer_addr_va - Virtual memory address of the HOMER image
	 * @param[in] i_common_addr_phys - The physical mainstore address of the
	 *                                 OCC common area.
	 * @param[in] i_common_addr_va - Virtual memory address of the common area
	 * @param[in] i_chip - XSCOM chip id of processor based on devtree defn
	 * @return 0 on success else return code
	 */
	int(*occ_load)(uint64_t i_homer_addr_phys,
	              uint64_t i_homer_addr_va,
	              uint64_t i_common_addr_phys,
	              uint64_t i_common_addr_va,
	              uint64_t i_chip);
	
	/** Start OCC on all chips, by module
	 *
	 *  @param[in] i_chip - Array of functional processor chip ids
	 *                      XSCOM chip id based on devtree defn
	 *  @Note The caller must include a complete modules worth of chips
	 *  @param[in] i_num_chips - Number of chips in the array
	 *  @return 0 on success else return code
	 */
	int (*occ_start)(uint64_t* i_chip,
	                 size_t i_num_chips);
	
	/** Stop OCC hold OCCs in reset
	 *
	 *  @param[in] i_chip - Array of functional processor chip ids
	 *                      XSCOM chip id based on devtree defn
	 *  @Note The caller must include a complete modules worth of chips
	 *  @param[in] i_num_chips - Number of chips in the array
	 *  @return 0 on success else return code
	 */
	int (*occ_stop)(uint64_t* i_chip,
	                size_t i_num_chips);
	
	/** Reset OCC upon failure
	 *  @param [in]: i_chipId: Id of processor with failing OCC
	 *  @return NONE
	 */
	void (*occ_error) (uint64_t i_chipId);
	
	/** Enable chip attentions
	 *
	 *  @return 0 on success else return code
	 */
	int (*enable_attns)(void);
	
	/** Disable chip attentions
	 *
	 *  @return 0 on success else return code
	 */
	int (*disable_attns)(void);
	
	/** brief handle chip attentions
	 *
	 *  @param[in] i_proc - processor chip id at attention
	 *                      XSCOM chip id based on devtree defn
	 *  @param[in] i_ipollStatus - processor chip Ipoll status
	 *  @param[in] i_ipollMask   - processor chip Ipoll mask
	 *  @return 0 on success else return code
	 */
	int (*handle_attns)(uint64_t i_proc,
	                    uint64_t i_ipollStatus,
	                    uint64_t i_ipollMask);
	
	// Reserve some space for future growth.
	void (*reserved[32])(void);

};

static struct runtime_interfaces *hservice_runtime;

struct host_interfaces hinterface = {
        .puts = hservice_puts,
        .assert = hservice_assert,
        .malloc = hservice_malloc,
        .free = hservice_free,
        .realloc = hservice_realloc,
        .send_error_log = hservice_send_error_log,
        .scom_read = hservice_scom_read,
        .scom_write = hservice_scom_write,
        .lid_load = hservice_lid_load,
        .lid_unload = hservice_lid_unload,
        .get_reserved_mem = hservice_get_reserved_mem,
        .wakeup = hservice_wakeup,
        .nanosleep = hservice_nanosleep,
};

bool hservices_init(void *mamaddr)
{
    void *code = NULL;
    struct runtime_interfaces *(*hbrt_init)(struct host_interfaces *);

    struct function_descriptor {
            void *addr;
            void *toc;
    } fdesc;
    //code = (void *)hservice_get_reserved_mem("ibm,hbrt-code-image");
    code  =  (void *)mamaddr;
    printf("code Address : [%016p]\n",code);
    /* We enter at 0x100 into the image. */
    fdesc.addr = code + 0x100;
    /* It doesn't care about TOC */
    fdesc.toc = 0;

    if (memcmp(code, "HBRTVERS", 8) != 0) {
            printf("HBRT: Bad signature for ibm,hbrt-code-image! exiting\n");
	    exit(-1);
    }

    hbrt_init = (void *)&fdesc;
    printf("HBRT: calling ibm,hbrt_init()!!!!\n");
    hservice_runtime = hbrt_init(&hinterface);
    printf("HBRT: hbrt_init passed.....!!!!\n");

}

static unsigned long get_mmap_size()
{
	int rc;
	unsigned long size;

	rc = ioctl(opald_fd, OPALD_GET_MAP_SIZE, &size);
	if (rc) {
		perror("ioctl map size");
		return 0;
	}
	
	printf("HBRT mmap size 0x%lx\n", size);
	return size;	
}

int main(int argc, char *argv[])
{
	int hb, rc;
	size_t sz;
	unsigned int *mapped_addr;
	unsigned long hbrt_size;
	unsigned long *p;
	char *hostboot_file_name=NULL; 
	struct stat hb_stat;
	int hb_file = 0;
	void *hb_mapped;
	uint64_t val;

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
	}

	
	if ((opald_fd=open("/dev/opal-diag", O_RDWR))<0) {
		perror("open");
		exit(-1);
	}

	hbrt_size = get_mmap_size();

	if (!hbrt_size) {
		printf("Unable to get mmap size.  exiting\n");
		exit(-1);
	}

	mapped_addr = mmap(0, hbrt_size, PROT_WRITE|PROT_READ|PROT_EXEC,
			MAP_SHARED, opald_fd, 0);

	if (mapped_addr == MAP_FAILED) {
		perror("mmap");
		exit(-1);
	}
	user_mapped_base_addr = mapped_addr;

	p = (unsigned long *)&mapped_addr[0];
	printf("Addr %016llx Data %08llx\n", &p[0], &p[0]);
	printf("Addr %016llx String %s\n", &p[0], &p[0]);

	printf("Addr %016llx Data %016llx\n", &p[0x2000/8], p[0x2000/8]);
	printf("Addr %016llx Data %016llx\n", &p[0x2008/8], p[0x2008/8]);

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
		rc = hservice_runtime->handle_attns(0x00, 0, 0);
	} else {
		printf("ERROR: 	hservice_runtime->handle_attns() not found\n");
	}

	/* Test more SCOMS */

	hservice_scom_read(0x11, 0x1502000d, &val);
	val &= ~0x8000000000000000ULL;
	hservice_scom_write(0x11, 0x1502000d, &val);
	hservice_scom_read(0x11, 0x1502000d, &val);
	val |= 0x8000000000000000ULL;
	hservice_scom_write(0x11, 0x1502000d, &val);
	hservice_scom_read(0x11, 0x1502000d, &val);
		
	if(munmap(mapped_addr, hbrt_size) == -1) {
		perror("munmap failed\n");
	}

	close(opald_fd);
	return(0);
}

