/*
 * Copyright (c) 2019 HabanaLabs Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#include "libhlthunk.h"
#include "specs/pci_ids.h"

#define _GNU_SOURCE

#include <errno.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

int hlthunk_debug_level = HLTHUNK_DEBUG_LEVEL_NA;

static int hlthunk_ioctl(int fd, unsigned long request, void *arg)
{
	int ret;

	do {
		ret = ioctl(fd, request, arg);
	} while (ret == -1 && (errno == EINTR || errno == EAGAIN));

	return ret;
}

static const char* hlthunk_get_device_name_by_type(int type)
{
	switch (type) {
	case HLTHUNK_NODE_PRIMARY:
		return HLTHUNK_DEV_NAME_PRIMARY;
	default:
		return NULL;
	}
}

static int hlthunk_open_by_busid(const char *busid, int type)
{
	const char *dev_name = hlthunk_get_device_name_by_type(type);

	if (!dev_name)
		return -1;

	return -1;
}

static int hlthunk_open_minor(int minor, const char *dev_name)
{
	char buf[64];
	int fd;

	sprintf(buf, dev_name, minor);
	if ((fd = open(buf, O_RDWR | O_CLOEXEC, 0)) >= 0)
		return fd;
	return -errno;
}

static int hlthunk_open_device(int type)
{
	int fd, i;
	const char *dev_name = hlthunk_get_device_name_by_type(type);

	if (!dev_name)
		return -1;

	for (i = 0 ; i < HLTHUNK_MAX_MINOR ; i++)
		if ((fd = hlthunk_open_minor(i, dev_name)) >= 0)
			return fd;

	return -1;
}

hlthunk_public void* hlthunk_malloc(int size)
{
	return calloc(1, size);
}

hlthunk_public void hlthunk_free(void *pt)
{
	free(pt);
}

hlthunk_public int hlthunk_open(const char *busid)
{
	if (busid) {
		int fd = hlthunk_open_by_busid(busid, HLTHUNK_NODE_PRIMARY);
		if (fd >= 0)
			return fd;
	}

	return hlthunk_open_device(HLTHUNK_NODE_PRIMARY);
}

hlthunk_public int hlthunk_close(int fd)
{
	return close(fd);
}

hlthunk_public int hlthunk_get_hw_ip_info(int fd,
					struct hlthunk_hw_ip_info *hw_ip)
{
	struct hl_info_args args = {};
	struct hl_info_hw_ip_info hl_hw_ip = {};
	size_t size;
	int rc;

	if (!hw_ip)
		return -EINVAL;

	args.op = HL_INFO_HW_IP_INFO;
	args.return_pointer = (__u64) (uintptr_t) &hl_hw_ip;
	args.return_size = sizeof(hl_hw_ip);

	rc = hlthunk_ioctl(fd, HL_IOCTL_INFO, &args);
	if (rc)
		return rc;

	hw_ip->sram_base_address = hl_hw_ip.sram_base_address;
	hw_ip->dram_base_address = hl_hw_ip.dram_base_address;
	hw_ip->dram_size = hl_hw_ip.dram_size;
	hw_ip->sram_size = hl_hw_ip.sram_size;
	hw_ip->num_of_events = hl_hw_ip.num_of_events;
	hw_ip->device_id = hl_hw_ip.device_id;
	hw_ip->armcp_cpld_version = hl_hw_ip.armcp_cpld_version;
	hw_ip->psoc_pci_pll_nr = hl_hw_ip.psoc_pci_pll_nr;
	hw_ip->psoc_pci_pll_nf = hl_hw_ip.psoc_pci_pll_nf;
	hw_ip->psoc_pci_pll_od = hl_hw_ip.psoc_pci_pll_od;
	hw_ip->psoc_pci_pll_div_factor = hl_hw_ip.psoc_pci_pll_div_factor;
	hw_ip->tpc_enabled_mask = hl_hw_ip.tpc_enabled_mask;
	hw_ip->dram_enabled = hl_hw_ip.dram_enabled;
	size = HL_INFO_VERSION_MAX_LEN > HLTHUNK_INFO_VERSION_MAX_LEN ?
			HL_INFO_VERSION_MAX_LEN : HLTHUNK_INFO_VERSION_MAX_LEN;
	memcpy(hw_ip->armcp_version, hl_hw_ip.armcp_version, size);

	return 0;
}

hlthunk_public int hlthunk_request_command_buffer(int fd, uint32_t cb_size,
							uint64_t *cb_handle)
{
	union hl_cb_args args = {};
	int rc;

	if (!cb_handle)
		return -EINVAL;

	args.in.op = HL_CB_OP_CREATE;
	args.in.cb_size = cb_size;

	rc = hlthunk_ioctl(fd, HL_IOCTL_CB, &args);
	if (rc)
		return rc;

	*cb_handle = args.out.cb_handle;

	return 0;
}

hlthunk_public int hlthunk_destroy_command_buffer(int fd, uint64_t cb_handle)
{
	union hl_cb_args args = {};

	args.in.op = HL_CB_OP_DESTROY;
	args.in.cb_handle = cb_handle;

	return hlthunk_ioctl(fd, HL_IOCTL_CB, &args);
}

hlthunk_public int hlthunk_get_device_type_from_fd(int fd,
						uint16_t *device_type)
{
	struct hlthunk_hw_ip_info hw_ip = {};
	int rc = 0;

	if (!device_type)
		return -EINVAL;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	if (rc)
		return -EINVAL;

	switch (hw_ip.device_id) {
	case PCI_IDS_GOYA:
		*device_type = (uint16_t) hw_ip.device_id;
		break;
	default:
		rc = -EINVAL;
	}

	return rc;
}

hlthunk_public int hlthunk_get_info(int fd, struct hl_info_args *info)
{
	return hlthunk_ioctl(fd, HL_IOCTL_INFO, info);
}

hlthunk_public int hlthunk_command_buffer(int fd, union hl_cb_args *cb)
{
	return hlthunk_ioctl(fd, HL_IOCTL_CB, cb);
}

hlthunk_public int hlthunk_command_submission(int fd, union hl_cs_args *cs)
{
	return hlthunk_ioctl(fd, HL_IOCTL_CS, cs);
}

hlthunk_public int hlthunk_wait_for_cs(int fd,
					union hl_wait_cs_args *wait_for_cs)
{
	return hlthunk_ioctl(fd, HL_IOCTL_WAIT_CS, wait_for_cs);
}

hlthunk_public int hlthunk_memory(int fd, union hl_mem_args *mem)
{
	return hlthunk_ioctl(fd, HL_IOCTL_MEMORY, mem);
}

hlthunk_public int hlthunk_debug(int fd, struct hl_debug_args *debug)
{
	return hlthunk_ioctl(fd, HL_IOCTL_DEBUG, debug);
}
