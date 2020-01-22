// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>

#include "hlthunk.h"
#include "hlthunk_err_inject.h"
#include "libhlthunk_supp.h"

#define _GNU_SOURCE

#define PAGE_SHIFT_4KB			12
#define PAGE_SHIFT_64KB			16

#define PAGE_SIZE_4KB			(1UL << PAGE_SHIFT_4KB)
#define PAGE_SIZE_64KB			(1UL << PAGE_SHIFT_64KB)

#define TEMPERATURE_SKEW		5000

hlthunk_public int hlthunk_err_inject_endless_command(int fd)
{
	struct hlthunk_asic_funcs *asic_funcs = hlthunk_get_asic_funcs(fd);
	struct hlthunk_pkt_info pkt_info;
	struct hlthunk_cb_obj *cb_obj;
	uint64_t seq = 0;
	uint32_t cb_size = 4096, offset = 0;
	int rc, i;

	if (!asic_funcs)
		return -ENODEV;

	cb_obj = hlthunk_create_cb_obj(fd, cb_size, 0);
	if (!cb_obj)
		return -ENOMEM;

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = false;
	pkt_info.mb = false;
	pkt_info.fence.dec_val = 1;
	pkt_info.fence.gate_val = 1;
	pkt_info.fence.fence_id = 0;
	offset = asic_funcs->add_fence_pkt(cb_obj->cb_ptr, offset, &pkt_info);
	rc = hlthunk_submit_and_wait_cs(fd, cb_obj, offset,
					asic_funcs->get_dma_down_qid
						  (DCORE_MODE_FULL_CHIP,
						   STREAM0),
					HL_WAIT_CS_STATUS_TIMEDOUT);

	/* Command lockup generates a soft reset, wait for it to finish */
	for (i = 0 ; i < 5 ; i++) {
		sleep(2);
		if (hlthunk_get_device_status_info(fd) !=
				    HL_DEVICE_STATUS_IN_RESET)
			break;
	}

	/* On success - no need to destroy the CB because device is in reset */
	if (rc)
		hlthunk_destroy_cb(fd, cb_obj);

	return rc;
}

hlthunk_public int hlthunk_err_inject_non_fatal_event(int fd, int *event_num)
{
	struct hlthunk_asic_funcs *asic_funcs = hlthunk_get_asic_funcs(fd);
	int rc;

	rc = asic_funcs->generate_non_fatal_event(fd, event_num);
	/* Let the driver time to handle the event */
	sleep(5);
	return rc;
}

hlthunk_public int hlthunk_err_inject_fatal_event(int fd, int *event_num)
{
	struct hlthunk_asic_funcs *asic_funcs = hlthunk_get_asic_funcs(fd);
	struct hlthunk_debugfs debugfs;
	int rc, i;
	char pci_bus_id[13];

	rc = hlthunk_get_pci_bus_id_from_fd(fd,
					    pci_bus_id, sizeof(pci_bus_id));
	if (rc) {
		hlthunk_close(fd);
		return -ENODEV;
	}

	rc = hlthunk_debugfs_open(fd, &debugfs);
	/* Close the fd to prevent the driver from killing us during reset */
	hlthunk_close(fd);
	if (rc)
		return -ENOTSUP;

	rc = asic_funcs->generate_fatal_event(&debugfs, event_num);
	/* Close the fs to prevent the driver from killing us during reset */
	hlthunk_debugfs_close(&debugfs);
	if (rc)
		return rc;

	printf("Wait for driver to detect the error\n");
	sleep(5);

	printf("Wait up to 60 sec for driver reset process to complete\n");
	for (i = 0 ; i < 12 ; i++) {
		fd = hlthunk_open(HLTHUNK_DEVICE_DONT_CARE, pci_bus_id);
		if ((fd >= 0) &&
		    (hlthunk_get_device_status_info(fd) !=
				    HL_DEVICE_STATUS_IN_RESET))
			break;
		sleep(5);
	}

	if (fd < 0)
		return -ENXIO;

	close(fd);
	return 0;
}

hlthunk_public int hlthunk_err_inject_loss_of_heartbeat(int fd)
{
	struct hlthunk_asic_funcs *asic_funcs = hlthunk_get_asic_funcs(fd);
	struct hlthunk_debugfs debugfs;
	char pci_bus_id[13];
	int rc, i;


	rc = hlthunk_get_pci_bus_id_from_fd(fd,
					    pci_bus_id, sizeof(pci_bus_id));
	if (rc) {
		hlthunk_close(fd);
		return -ENODEV;
	}

	rc = hlthunk_debugfs_open(fd, &debugfs);
	/* Close the fd to prevent the driver from killing us during reset */
	hlthunk_close(fd);
	if (rc)
		return -ENOTSUP;

	rc = asic_funcs->halt_cpu(&debugfs);
	hlthunk_debugfs_close(&debugfs);
	if (rc) {
		printf("Failed to halt the device cpu\n");
		return -EIO;
	}

	printf("Wait for driver to detect the loss of heartbeat\n");
	sleep(5);

	printf("Wait up to 60 sec for driver reset process to complete\n");
	for (i = 0 ; i < 12 ; i++) {
		fd = hlthunk_open(HLTHUNK_DEVICE_DONT_CARE, pci_bus_id);
		if ((fd >= 0) &&
		    (hlthunk_get_device_status_info(fd) !=
				    HL_DEVICE_STATUS_IN_RESET))
			break;
		sleep(5);
	}

	if (fd < 0)
		return -ENXIO;

	close(fd);
	return 0;
}

static int open_device_temperature_file(int fd, const char *fname, int flags)
{
	const char *base_path = "/sys/bus/pci/devices/";
	const char *hwmon_dir_name = "/hwmon/";
	const char *device_hwmon_dir_prefix = "hwmon";
	char pci_bus_id[13];
	char *fd_path;
	struct dirent *entry;
	DIR *dir = NULL;
	int rc, temp_fd;

	if (fname == NULL || strlen(fname) > NAME_MAX)  {
		printf("Invalid file name");
		return -EINVAL;
	}

	rc = hlthunk_get_pci_bus_id_from_fd(fd, pci_bus_id, sizeof(pci_bus_id));
	if (rc) {
		printf("No PCI device was found for fd %d\n", fd);
		return -ENODEV;
	}

	fd_path = malloc(PATH_MAX + 1);
	if (fd_path == NULL) {
		printf("Failed to allocate memory\n");
		return -ENOMEM;
	}

	/* Open device hwmon dir
	 *  example: /sys/bus/pci/devices/0000:01:00.0/hwmon/
	 */
	snprintf(fd_path, PATH_MAX, "%s%s%s",
		 base_path, pci_bus_id, hwmon_dir_name);

	dir = opendir(fd_path);
	if (dir == NULL) {
		rc = -errno;
		printf("Failed to open device directory %s\n", fd_path);
		goto exit;
	}

	while ((entry = readdir(dir)) != NULL) {
		if (strstr(entry->d_name, device_hwmon_dir_prefix) != NULL)
			break;
	}
	if (entry == NULL) {
		printf("Failed to find device hwmon directory\n");
		rc = -ENOENT;
		goto exit;
	}

	/*
	 * Create the paths to the requested temperature sensor attribute file
	 *  example: /sys/bus/pci/devices/0000:01:00.0/hwmon/hwmon3/temp1_max
	 */
	snprintf(fd_path, PATH_MAX, "%s%s%s%s/%s", base_path,
		 pci_bus_id, hwmon_dir_name, entry->d_name, fname);

	temp_fd = open(fd_path, flags);
	if (temp_fd < 0) {
		rc = -errno;
		printf("failed to open %s, %s\n", fd_path, strerror(errno));
		goto exit;
	}
	rc = temp_fd;
exit:
	free(fd_path);
	if (dir)
		closedir(dir);
	return rc;
}

hlthunk_public int hlthunk_err_inject_thermal_event(int fd)
{
	long temp_max, temp_offset;
	int temp_offset_fd, temp_max_fd;
	ssize_t size;
	int rc;
	char value[64] = "";

	temp_max_fd = open_device_temperature_file(fd,
						     "temp1_max", O_RDONLY);
	if (temp_max_fd < 0)
		return temp_max_fd;

	temp_offset_fd = open_device_temperature_file(fd,
						      "temp1_offset", O_RDWR);
	if (temp_offset_fd < 0) {
		close(temp_max_fd);
		return temp_offset_fd;
	}

	/* Read the max temperature */
	size = pread(temp_max_fd, value, sizeof(value), 0);
	if (size < 0) {
		printf("Failed to read from temperature offset fd [rc %zd]\n",
		       size);
		rc = size;
		goto exit;
	}

	temp_max = strtol(value, NULL, 10);

	/* Read the temperature offset */
	size = pread(temp_offset_fd, value, sizeof(value), 0);
	if (size < 0) {
		printf("Failed to read from temperature offset fd [rc %zd]\n",
		       size);
		rc = size;
		goto exit;
	}

	temp_offset = strtol(value, NULL, 10);

	/* Modify temperature offset */
	sprintf(value, "%ld", temp_offset + temp_max + TEMPERATURE_SKEW);

	size = write(temp_offset_fd, value, strlen(value) + 1);
	if (size < 0) {
		printf("Failed to write to temperature offset fd [rc %zd]\n",
		       size);
		rc = size;
		goto exit;
	}

	printf("Wait for driver to detect the thermal event\n");
	sleep(1);

	rc = 0;
exit:
	close(temp_offset_fd);
	close(temp_max_fd);
	return rc;
}

hlthunk_public int hlthunk_err_eject_thermal_event(int fd)
{
	long temp_offset, temp_max;
	int temp_offset_fd, temp_max_fd;
	ssize_t size;
	int rc = 0;
	char value[64] = "";

	temp_max_fd = open_device_temperature_file(fd,
						   "temp1_max", O_RDONLY);
	if (temp_max_fd < 0)
		return temp_max_fd;

	temp_offset_fd = open_device_temperature_file(fd,
						      "temp1_offset", O_RDWR);
	if (temp_offset_fd < 0) {
		close(temp_max_fd);
		return temp_offset_fd;
	}

	/* Read the max temperature */
	size = pread(temp_max_fd, value, sizeof(value), 0);
	if (size < 0) {
		printf("Failed to read from temperature offset fd [rc %zd]\n",
		       size);
		rc = size;
		goto exit;
	}

	temp_max = strtol(value, NULL, 10);

	/* Read the temperature offset */
	size = pread(temp_offset_fd, value, sizeof(value), 0);
	if (size < 0) {
		printf("Failed to read from temperature offset fd [rc %zd]\n",
		       size);
		rc = size;
		goto exit;
	}

	temp_offset = strtol(value, NULL, 10);

	/* Modify temperature offset */
	sprintf(value, "%ld", temp_offset - temp_max - TEMPERATURE_SKEW);

	size = write(temp_offset_fd, value, strlen(value) + 1);
	if (size < 0) {
		printf("Failed to write to temperature offset fd [rc %zd]\n",
		       size);
		rc = size;
	}

exit:
	close(temp_max_fd);
	close(temp_offset_fd);
	return rc;
}
