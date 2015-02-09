

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/ioctl.h>

#include <asm/opal-prd.h>

static const char *device_name = "/dev/opal-prd";
static const char *code_range_name = "test";

int main(void)
{
	struct opal_prd_range *code_range;
	struct opal_prd_info info;
	int fd, rc, i;
	uint8_t *buf;

	fd = open(device_name, O_RDWR);
	if (fd < 0)
		err(EXIT_FAILURE, "failed opening %s", device_name);

	rc = ioctl(fd, OPAL_PRD_GET_INFO, &info);
	if (rc)
		err(EXIT_FAILURE, "ioctl(OPAL_PRD_GET_INFO)");

	printf("version:  %lx\n", info.version);
	printf("ranges:\n");
	for (i = 0; i < OPAL_PRD_MAX_RANGES; i++) {
		printf("\t0x%016lx 0x%08lx %s\n", info.ranges[i].physaddr,
				info.ranges[i].size, info.ranges[i].name);
		if (!strcmp(info.ranges[i].name, code_range_name))
			code_range = &info.ranges[i];
	}


	buf = mmap(NULL, code_range->size, PROT_READ | PROT_EXEC, MAP_PRIVATE,
			fd, code_range->physaddr);
	if (buf == MAP_FAILED)
		err(EXIT_FAILURE, "mmap");

	printf("map contents: %x %x %x %x\n", buf[0], buf[1], buf[2], buf[3]);

	return EXIT_SUCCESS;
}



