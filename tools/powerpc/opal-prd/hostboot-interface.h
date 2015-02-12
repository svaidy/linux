/* Copyright 2013-2014 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <stdint.h>

/* Hostboot runtime interface */
/* Derived from src/include/runtime/interface.h in Hostboot */

#define HOSTBOOT_RUNTIME_INTERFACE_VERSION 1


/** @typedef hostInterfaces_t
 *  @brief Interfaces provided by the underlying environment (ex. Sapphire).
 *
 *  @note Some of these functions are not required (marked optional) and
 *        may be NULL.
 */
struct host_interfaces
{
	/** Interface version. */
	uint64_t interface_version;

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
	uint64_t interface_version;

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


