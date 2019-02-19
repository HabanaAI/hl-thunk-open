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
	memcpy(hw_ip->armcp_version, hl_hw_ip.armcp_version,
		HL_INFO_VERSION_MAX_LEN);

	return 0;
}

hlthunk_public int hlthunk_request_command_buffer(int fd, uint32_t size,
		uint64_t *handle)
{
	union hl_cb_args args = {};
	int rc;

	if (!handle)
		return -EINVAL;

	args.in.op = HL_CB_OP_CREATE;
	args.in.cb_size = size;

	rc = hlthunk_ioctl(fd, HL_IOCTL_CB, &args);
	if (rc)
		return rc;

	*handle = args.out.cb_handle;

	return 0;
}

hlthunk_public int hlthunk_destroy_command_buffer(int fd, uint64_t handle)
{
	union hl_cb_args args = {};

	args.in.op = HL_CB_OP_DESTROY;
	args.in.cb_handle = handle;

	return hlthunk_ioctl(fd, HL_IOCTL_CB, &args);
}

hlthunk_public int hlthunk_command_submission(int fd, struct hlthunk_cs_in *in,
		struct hlthunk_cs_out *out)
{
	union hl_cs_args args = {};
	struct hl_cs_in *hl_in;
	struct hl_cs_out *hl_out;
	int rc;

	hl_in = &args.in;
	hl_in->chunks_restore = (__u64) (uintptr_t) in->chunks_restore;
	hl_in->chunks_execute = (__u64) (uintptr_t) in->chunks_execute;
	hl_in->num_chunks_restore = in->num_chunks_restore;
	hl_in->num_chunks_execute = in->num_chunks_execute;
	hl_in->cs_flags = in->flags;

	rc = hlthunk_ioctl(fd, HL_IOCTL_CS, &args);
	if (rc)
		return rc;

	hl_out = &args.out;
	out->seq = hl_out->seq;
	out->status = hl_out->status;

	return 0;
}

hlthunk_public int hlthunk_wait_for_cs(int fd, struct hlthunk_wait_cs_in *in,
		struct hlthunk_wait_cs_out *out)
{
	union hl_wait_cs_args args = {};
	struct hl_wait_cs_in *hl_in;
	struct hl_wait_cs_out *hl_out;
	int rc;

	hl_in = &args.in;
	hl_in->seq = in->seq;
	hl_in->timeout_us = in->timeout_us;

	rc = hlthunk_ioctl(fd, HL_IOCTL_WAIT_CS, &args);
	if (rc)
		return rc;

	hl_out = &args.out;
	out->status = hl_out->status;

	return 0;
}

hlthunk_public enum hl_pci_ids hlthunk_get_device_type_from_fd(int fd)
{
	struct hlthunk_hw_ip_info hw_ip = {};

	if (hlthunk_get_hw_ip_info(fd, &hw_ip))
		return PCI_IDS_INVALID;

	return (enum hl_pci_ids) hw_ip.device_id;
}

hlthunk_public int hlthunk_get_info(int fd, struct hl_info_args *info)
{
	return hlthunk_ioctl(fd, HL_IOCTL_INFO, info);
}

hlthunk_public int hlthunk_memory_alloc(int fd, struct hlthunk_mem_alloc *args,
					uint64_t *mem_handle)
{
	union hl_mem_args ioctl_args = {0};
	int rc;

	if ((!args) || (!mem_handle))
		return -EINVAL;

	ioctl_args.in.alloc.mem_size = args->mem_size;
	ioctl_args.in.flags = args->flags;
	ioctl_args.in.ctx_id = args->ctx_id;
	ioctl_args.in.op = HL_MEM_OP_ALLOC;

	rc = hlthunk_ioctl(fd, HL_IOCTL_MEMORY, &ioctl_args);
	if (rc)
		return rc;

	*mem_handle = ioctl_args.out.handle;

	return 0;
}

hlthunk_public int hlthunk_memory_free(int fd, struct hlthunk_mem_free *args)
{
	union hl_mem_args ioctl_args = {0};

	if (!args)
		return -EINVAL;

	ioctl_args.in.free.handle = args->handle;
	ioctl_args.in.ctx_id = args->ctx_id;
	ioctl_args.in.op = HL_MEM_OP_FREE;

	return hlthunk_ioctl(fd, HL_IOCTL_MEMORY, &ioctl_args);
}

hlthunk_public int hlthunk_memory_map(int fd, struct hlthunk_mem_map *args,
					uint64_t *device_virtual_address)
{
	union hl_mem_args ioctl_args = {0};
	int rc;

	if ((!args) || (!device_virtual_address))
		return -EINVAL;

	ioctl_args.in.map_device.hint_addr = args->hint_addr;
	ioctl_args.in.map_device.handle = args->handle;
	ioctl_args.in.flags = args->flags;
	ioctl_args.in.ctx_id = args->ctx_id;
	ioctl_args.in.op = HL_MEM_OP_MAP;

	rc = hlthunk_ioctl(fd, HL_IOCTL_MEMORY, &ioctl_args);
	if (rc)
		return rc;

	*device_virtual_address = ioctl_args.out.device_virt_addr;

	return 0;
}

hlthunk_public int hlthunk_memory_unmap(int fd, struct hlthunk_mem_unmap *args)
{
	union hl_mem_args ioctl_args = {0};

	if (!args)
		return -EINVAL;

	ioctl_args.in.unmap.device_virt_addr = args->device_virt_addr;
	ioctl_args.in.ctx_id = args->ctx_id;
	ioctl_args.in.op = HL_MEM_OP_UNMAP;

	return hlthunk_ioctl(fd, HL_IOCTL_MEMORY, &ioctl_args);
}

hlthunk_public int hlthunk_debug(int fd, struct hl_debug_args *debug)
{
	return hlthunk_ioctl(fd, HL_IOCTL_DEBUG, debug);
}
