/*
 * OPAL Runtime Diagnostics interface driver
 * Supported on POWERNV platform
 *
 * (C) Copyright IBM 2015
 *
 * Author: Vishal Kulkarni <kvishal at in.ibm.com>
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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/of.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <asm/opal-prd.h>
#include <asm/opal.h>
#include <asm/io.h>
#include <asm/uaccess.h>        /* for get_user and put_user */

#define	MAX_OPAL_DIAG_REGIONS	3

/* 
 * FIXME:  name can hold pointer into device tree. But what if
 * this property gets updated at runtime? Avoid dangling pointer.
 */

#define MAP_COPY	0x01	/* Map a RW copy in kernel memory */
struct opal_diag_mem_regions {
	char name[MAX_NAME_LEN];
	u8 flags;
	u64 addr;
	u64 size;
	void *alloc_buf;
	u64 copy_addr;
	u64 copy_size;
	u64 mmap_addr;
	u64 mmap_size;
};

struct opal_diag_info {
	int nr_mem_regions;
	struct opal_diag_mem_regions mem_regions[MAX_OPAL_DIAG_REGIONS];
};

static struct opal_diag_info opal_diag;

static int opal_diag_open(struct inode *inode, struct file *file)
{

	printk("opal_diag_open called\n");
	return 0;
}

/*
 * opal_diag_mmap - maps the hbrt binary into userspace
 * @file: file structure for the device
 * @vma: VMA to map the registers into
 */

/* Tested on ltctul57a where:
 * [6290319034,5]   0x00effd568000..00effd6b4fff : ibm,hbrt-code-image
 * [6290324582,5]   0x00effd6b5000..00effd6fffff : ibm,hbrt-target-image
 * [6290330588,5]   0x00effd700000..00effd7fffff : ibm,hbrt-vpd-image
*/
static int opal_diag_mmap(struct file *file, struct vm_area_struct *vma)
{
	u64 total_mmap_size = 0;
	u64 size, offset = 0;
	int i, rc;

	printk("opal_diag_mmap called\n");
	printk("opal_diag_mmap start %016llx end %016llx\n", vma->vm_start, vma->vm_end);

	/* Compute total size required */
	for (i = 0; i < opal_diag.nr_mem_regions; i++) {
		total_mmap_size += opal_diag.mem_regions[i].mmap_size;
	}

	if (vma->vm_end - vma->vm_start < total_mmap_size)
		return -EINVAL;

	vma->vm_page_prot = phys_mem_access_prot(file, vma->vm_pgoff,
						 total_mmap_size,
						 vma->vm_page_prot);

	for (i = 0; i < opal_diag.nr_mem_regions; i++) {

		if (opal_diag.mem_regions[i].flags & MAP_COPY) {
			opal_diag.mem_regions[i].copy_size = 
				(opal_diag.mem_regions[i].size + PAGE_SIZE-1) &
					~(PAGE_SIZE-1);
					
			opal_diag.mem_regions[i].mmap_size = 
				opal_diag.mem_regions[i].copy_size;
			/* Alloc 1 more page for align up */
			/* FIXME: Use vmalloc and map each page */
			opal_diag.mem_regions[i].alloc_buf =
					kmalloc(opal_diag.mem_regions[i].copy_size
						+ PAGE_SIZE, GFP_KERNEL);
			/* Page align the mapping source address */		
			opal_diag.mem_regions[i].copy_addr =
				((u64) opal_diag.mem_regions[i].alloc_buf + PAGE_SIZE-1)
				& ~(PAGE_SIZE-1);

			BUG_ON(!opal_diag.mem_regions[i].copy_addr);		
			memcpy(opal_diag.mem_regions[i].copy_addr,
				phys_to_virt(opal_diag.mem_regions[i].addr),
				opal_diag.mem_regions[i].size
			
			);
					
			rc = remap_pfn_range(vma, vma->vm_start + offset,
				virt_to_phys(opal_diag.mem_regions[i].copy_addr) >> PAGE_SHIFT,
				opal_diag.mem_regions[i].copy_size, vma->vm_page_prot);
			
			opal_diag.mem_regions[i].mmap_addr = vma->vm_start + offset;
			offset += opal_diag.mem_regions[i].copy_size;

		} else {
			rc = remap_pfn_range(vma, vma->vm_start + offset,
				opal_diag.mem_regions[i].addr >> PAGE_SHIFT,
				opal_diag.mem_regions[i].mmap_size, vma->vm_page_prot);
			
			opal_diag.mem_regions[i].mmap_addr = vma->vm_start + offset;
			offset += opal_diag.mem_regions[i].mmap_size;
		}

		if (rc)
			break;
	}
	printk("opal_diag_mmap rc = %d\n", rc);
	return rc;

}

static int opal_diag_ioctl(struct file *file, unsigned long cmd, void *param)
{

	switch(cmd) {

	case OPALD_GET_MAP_SIZE:
	{
		unsigned long size = 0;
		int i;
		if(!param)
			return -EINVAL;
		/* Compute total size required */
		for (i = 0; i < opal_diag.nr_mem_regions; i++) {
			size += opal_diag.mem_regions[i].mmap_size;
		}

		copy_to_user((unsigned long __user *) param,
				&size, sizeof(unsigned long));

		printk("opald ioctl GET_MAP_SIZE returned %p\n", size);
		return 0;
	}
	case OPALD_GET_RESERVED_MEM:
	{
		struct opald_mem mem;
		int i;
		int rc = -EINVAL;
		if (!param)
			return -EINVAL;
		copy_from_user(&mem, (struct opald_mem __user *) param,
				sizeof(struct opald_mem));

		for (i = 0; i < opal_diag.nr_mem_regions; i++) {
			if (strncmp(opal_diag.mem_regions[i].name,
				mem.name, MAX_NAME_LEN) == 0) {
				mem.addr = opal_diag.mem_regions[i].mmap_addr;
				/* Add offset within page */
				mem.addr += opal_diag.mem_regions[i].addr &
						(PAGE_SIZE-1);
				mem.size = opal_diag.mem_regions[i].mmap_size;
				rc = 0;
				break;
			}
		}

		copy_to_user((struct opald_mem __user *) param,
				&mem, sizeof(struct opald_mem));

		printk("opald ioctl GET_RESERVED_MEM Name %s, addr %p size %p\n",
					mem.name, mem.addr, mem.size);	
		return rc;
	}
	case OPALD_SCOM_READ:
	{
		struct opald_scom scom;
		uint64_t rc;
		if (!param)
			return -EINVAL;

		copy_from_user(&scom, (struct opald_scom __user *) param,
				sizeof(struct opald_scom));

		rc = opal_xscom_read(scom.chip, scom.addr, (__be64 *) &scom.data);
		printk("opald ioctl SCOM_READ: chip %x addr %016llx data %016llx rc %d\n",
			scom.chip, scom.addr, scom.data, rc);

		copy_to_user((struct opald_mem __user *) param,
				&scom, sizeof(struct opald_scom));

		if (rc)
			return -EINVAL;
			
		return 0;
	}
	case OPALD_SCOM_WRITE:
	{
		struct opald_scom scom;
		uint64_t rc;
		if (!param)
			return -EINVAL;

		copy_from_user(&scom, (struct opald_scom __user *) param,
				sizeof(struct opald_scom));

		rc = opal_xscom_write(scom.chip, scom.addr, scom.data);
		printk("opald ioctl SCOM_WRITE: chip %x addr %016llx data %016llx rc %d\n",
			scom.chip, scom.addr, scom.data, rc);

		if (rc)
			return -EINVAL;
			
		return 0;
	}

	default:
		return -EINVAL;
	}	
}

struct file_operations opal_diag_fops = {
	.open           = opal_diag_open,
	.mmap          = opal_diag_mmap,
	.unlocked_ioctl = opal_diag_ioctl,
	.owner		= THIS_MODULE,
};

// This structure has entry for device id and event number need more info

static struct miscdevice opal_diag_dev = {
        .minor = MISC_DYNAMIC_MINOR,
        .name = "opal-diag",
        .fops = &opal_diag_fops,
};


static void get_regions_from_dt(void)
{
	struct device_node *np;
	const char *prop_names;
	char *p, *end;
	const __be32 *prop_ranges;
	u32 val[4];
	unsigned int len_names, len_ranges;
	int nr_ranges, i, count, index;
	u64 mmap_size;

	printk("OPAL DIAG: Parsing Device Tree\n");
	np = of_find_node_by_path("/");
	if (!np)
		return;

	nr_ranges = of_property_count_strings(np, "reserved-names");
	if (nr_ranges < 0)
		return;
			
	count = of_property_count_u32_elems(np, "reserved-ranges");
	if (count != nr_ranges *4) {
		printk("DT has incorrect %d reserved-names and %d reserved-ranges\n",
			nr_ranges, count);
		return;
	}

	prop_ranges = of_get_property(np, "reserved-ranges", &len_ranges);
	if (!prop_ranges)
		return;

	for (i = 0; i < nr_ranges; i++) {
		of_property_read_string_index(np, "reserved-names", i, &p);	
		if (strstr(p, "hbrt")) { /* Pick HBRT areas */
			index = opal_diag.nr_mem_regions;
			opal_diag.mem_regions[index].addr =
				of_read_number(prop_ranges + 4*i+0, 2);
			opal_diag.mem_regions[index].size =
				of_read_number(prop_ranges + 4*i+2, 2);
			strncpy(opal_diag.mem_regions[index].name, p, MAX_NAME_LEN-1);
			/* Detect special flags */
			if (strcmp(p, "ibm,hbrt-code-image") == 0) {
				/* Mark as a copy map */
				opal_diag.mem_regions[index].flags |= MAP_COPY;
			}
			opal_diag.nr_mem_regions++;
			BUG_ON(opal_diag.nr_mem_regions > MAX_OPAL_DIAG_REGIONS);
		}
	}
	of_node_put(np);

	/* Lets see what we gathered */
	for (i = 0; i < opal_diag.nr_mem_regions; i++) {
		/* Compute mmap size for application */
		/* Add offset within page size */
		mmap_size = opal_diag.mem_regions[i].size +
			(opal_diag.mem_regions[i].addr & (PAGE_SIZE-1));
		/* Round up to next page size */
		mmap_size = (mmap_size + PAGE_SIZE-1) & ~(PAGE_SIZE-1);
		opal_diag.mem_regions[i].mmap_size = mmap_size;

		printk("Name: %25s Addr %016llx Size %016llx MMap size %016llx\n",
			opal_diag.mem_regions[i].name,
			opal_diag.mem_regions[i].addr,
			opal_diag.mem_regions[i].size,
			opal_diag.mem_regions[i].mmap_size);
	}
}

/*
 *Initialize the module - Register the character device
 */
int __init opal_diag_init(void)
{
	int rc;
	//Register the character device
	// Negative values signify an error
	if (misc_register(&opal_diag_dev)) {
		printk(KERN_ERR "prd_init: failed to register device\n");
		return rc;
	}
	get_regions_from_dt();
	return 0;
}

//Cleanup - unregister the appropriate file from /proc
void __exit opal_diag_cleanup(void)
{
	/* FIXME: Free kmalloc memory */	
	misc_deregister(&opal_diag_dev);

}

module_init(opal_diag_init);
module_exit(opal_diag_cleanup);

MODULE_DESCRIPTION("PowerNV OPAL runtime diagnostic driver");
MODULE_LICENSE("GPL");

