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

static int hlthunk_open_by_busid(const char *busid)
{
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

static enum hlthunk_device_name hlthunk_get_device_name_from_fd(int fd)
{
	enum hl_pci_ids device_id = hlthunk_get_device_id_from_fd(fd);

	switch (device_id) {
	case PCI_IDS_GOYA:
	case PCI_IDS_GOYA_SIMULATOR:
		return HLTHUNK_DEVICE_GOYA;
		break;
	default:
		printf("Invalid device type %d\n", device_id);
		break;
	}

	return HLTHUNK_DEVICE_INVALID;
}

static int hlthunk_open_device_by_name(enum hlthunk_device_name device_name)
{
	int fd, i;

	for (i = 0 ; i < HLTHUNK_MAX_MINOR ; i++) {
		fd = hlthunk_open_minor(i, HLTHUNK_DEV_NAME_PRIMARY);
		if (fd >= 0) {
			if (hlthunk_get_device_name_from_fd(fd) ==
								device_name)
				return fd;
			hlthunk_close(fd);
		}
	}

	return -1;
}

hlthunk_public void* hlthunk_malloc(int size)
{
	return calloc(1, size);
}

hlthunk_public void hlthunk_free(void *pt)
{
	if (pt)
		free(pt);
}

/**
 * This function opens the habanalabs device according to specified busid, or
 * according to the device name, if busid is NULL. If busid is specifies but
 * the device can't be opened, the function fails.
 * @param device_name name of the device that the user wants to open
 * @param busid pci address of the device on the host pci bus
 * @return file descriptor handle or negative value in case of error
 */
hlthunk_public int hlthunk_open(enum hlthunk_device_name device_name,
				const char *busid)
{
	if (busid)
		return hlthunk_open_by_busid(busid);

	return hlthunk_open_device_by_name(device_name);
}

hlthunk_public int hlthunk_close(int fd)
{
	return close(fd);
}

hlthunk_public int hlthunk_get_hw_ip_info(int fd,
					struct hlthunk_hw_ip_info *hw_ip)
{
	struct hl_info_args args;
	struct hl_info_hw_ip_info hl_hw_ip;
	int rc;

	if (!hw_ip)
		return -EINVAL;

	memset(&args, 0, sizeof(args));
	memset(&hl_hw_ip, 0, sizeof(hl_hw_ip));

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

hlthunk_public enum hl_device_status hlthunk_get_device_status_info(int fd)
{
	struct hl_info_args args;
	struct hl_info_device_status hl_dev_status;
	int rc;

	memset(&args, 0, sizeof(args));

	args.op = HL_INFO_DEVICE_STATUS;
	args.return_pointer = (__u64) (uintptr_t) &hl_dev_status;
	args.return_size = sizeof(hl_dev_status);

	rc = hlthunk_ioctl(fd, HL_IOCTL_INFO, &args);
	if (rc)
		return rc;

	return hl_dev_status.status;
}

hlthunk_public bool hlthunk_is_device_idle(int fd)
{
	struct hl_info_args args;
	struct hl_info_hw_idle hl_hw_idle;
	int rc;

	memset(&args, 0, sizeof(args));

	args.op = HL_INFO_HW_IDLE;
	args.return_pointer = (__u64) (uintptr_t) &hl_hw_idle;
	args.return_size = sizeof(hl_hw_idle);

	rc = hlthunk_ioctl(fd, HL_IOCTL_INFO, &args);
	if (rc)
		return false;

	return hl_hw_idle.is_idle;
}

hlthunk_public int hlthunk_request_command_buffer(int fd, uint32_t cb_size,
							uint64_t *cb_handle)
{
	union hl_cb_args args;
	int rc;

	if (!cb_handle)
		return -EINVAL;

	memset(&args, 0, sizeof(args));
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
	union hl_cb_args args;

	memset(&args, 0, sizeof(args));
	args.in.op = HL_CB_OP_DESTROY;
	args.in.cb_handle = cb_handle;

	return hlthunk_ioctl(fd, HL_IOCTL_CB, &args);
}

hlthunk_public int hlthunk_command_submission(int fd, struct hlthunk_cs_in *in,
						struct hlthunk_cs_out *out)
{
	union hl_cs_args args;
	struct hl_cs_in *hl_in;
	struct hl_cs_out *hl_out;
	int rc;

	memset(&args, 0, sizeof(args));

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

hlthunk_public int hlthunk_wait_for_cs(int fd, uint64_t seq,
					uint64_t timeout_us, uint32_t *status)
{
	union hl_wait_cs_args args;
	struct hl_wait_cs_in *hl_in;
	struct hl_wait_cs_out *hl_out;
	int rc;

	memset(&args, 0, sizeof(args));

	hl_in = &args.in;
	hl_in->seq = seq;
	hl_in->timeout_us = timeout_us;

	rc = hlthunk_ioctl(fd, HL_IOCTL_WAIT_CS, &args);
	if (rc)
		return rc;

	hl_out = &args.out;
	*status = hl_out->status;

	return 0;
}

hlthunk_public enum hl_pci_ids hlthunk_get_device_id_from_fd(int fd)
{
	struct hlthunk_hw_ip_info hw_ip;

	memset(&hw_ip, 0, sizeof(hw_ip));
	if (hlthunk_get_hw_ip_info(fd, &hw_ip))
		return PCI_IDS_INVALID;

	return (enum hl_pci_ids) hw_ip.device_id;
}

hlthunk_public int hlthunk_get_info(int fd, struct hl_info_args *info)
{
	return hlthunk_ioctl(fd, HL_IOCTL_INFO, info);
}

/**
 * This function allocates DRAM memory on the device
 * @param fd file descriptor of the device on which to allocate the memory
 * @param size how much memory to allocate
 * @param contiguous whether the memory area will be physically contiguous
 * @param shared whether this memory can be shared with other user processes
 * on the device
 * @return opaque handle representing the memory allocation. 0 is returned
 * upon failure
 */
hlthunk_public uint64_t hlthunk_device_memory_alloc(int fd, uint64_t size,
						bool contiguous, bool shared)
{
	union hl_mem_args ioctl_args;
	int rc;

	memset(&ioctl_args, 0, sizeof(ioctl_args));
	ioctl_args.in.alloc.mem_size = (uint32_t) size;
	if (contiguous)
		ioctl_args.in.flags |= HL_MEM_CONTIGUOUS;
	if (shared)
		ioctl_args.in.flags |= HL_MEM_SHARED;
	ioctl_args.in.op = HL_MEM_OP_ALLOC;

	rc = hlthunk_ioctl(fd, HL_IOCTL_MEMORY, &ioctl_args);
	if (rc)
		return 0;

	return ioctl_args.out.handle;
}

/**
 * This function frees DRAM memory that was allocated on the device using
 * hlthunk_device_memory_alloc
 * @param fd file descriptor of the device that this memory belongs to
 * @param handle the opaque handle that represents this memory
 * @return 0 for success, negative value for failure
 */
hlthunk_public int hlthunk_device_memory_free(int fd, uint64_t handle)
{
	union hl_mem_args ioctl_args;

	memset(&ioctl_args, 0, sizeof(ioctl_args));
	ioctl_args.in.free.handle = handle;
	ioctl_args.in.op = HL_MEM_OP_FREE;

	return hlthunk_ioctl(fd, HL_IOCTL_MEMORY, &ioctl_args);
}

/**
 * This function asks the driver to map a previously allocated DRAM memory
 * to the device's MMU and to allocate for it a VA in the device address space
 * @param fd file descriptor of the device that this memory belongs to
 * @param handle the opaque handle that represents this memory
 * @param hint_addr the user can request from the driver that the VA will be
 * a specific address. The driver doesn't have to comply to this request but
 * will take it under consideration
 * @return VA in the device address space. 0 is returned upon failure
 */
hlthunk_public uint64_t hlthunk_device_memory_map(int fd, uint64_t handle,
							uint64_t hint_addr)
{
	union hl_mem_args ioctl_args;
	int rc;

	memset(&ioctl_args, 0, sizeof(ioctl_args));
	ioctl_args.in.map_device.hint_addr = hint_addr;
	ioctl_args.in.map_device.handle = handle;
	ioctl_args.in.op = HL_MEM_OP_MAP;

	rc = hlthunk_ioctl(fd, HL_IOCTL_MEMORY, &ioctl_args);
	if (rc)
		return 0;

	return ioctl_args.out.device_virt_addr;
}

/**
 * This function asks the driver to map a previously allocated host memory
 * to the device's MMU and to allocate for it a VA in the device address space
 * @param fd file descriptor of the device that this memory will be mapped to
 * @param host_virt_addr the user's VA of memory area on the host
 * @param hint_addr the user can request from the driver that the device VA will
 * be a specific address. The driver doesn't have to comply to this request but
 * will take it under consideration
 * @param host_size the size of the memory area
 * @return VA in the device address space. 0 is returned upon failure
 */
hlthunk_public uint64_t hlthunk_host_memory_map(int fd, void *host_virt_addr,
						uint64_t hint_addr,
						uint64_t host_size)
{
	union hl_mem_args ioctl_args;
	int rc;

	memset(&ioctl_args, 0, sizeof(ioctl_args));
	ioctl_args.in.map_host.host_virt_addr = (uint64_t) host_virt_addr;
	ioctl_args.in.map_host.mem_size = host_size;
	ioctl_args.in.map_host.hint_addr = hint_addr;
	ioctl_args.in.flags = HL_MEM_USERPTR;
	ioctl_args.in.op = HL_MEM_OP_MAP;

	rc = hlthunk_ioctl(fd, HL_IOCTL_MEMORY, &ioctl_args);
	if (rc)
		return 0;

	return ioctl_args.out.device_virt_addr;
}

/**
 * This function unmaps a mapping in the device's MMU that was previously done
 * using either hlthunk_device_memory_map or hlthunk_host_memory_map
 * @param fd file descriptor of the device that contains the mapping
 * @param device_virt_addr the VA in the device address space representing
 * the device or host memory area
 * @return 0 for success, negative value for failure
 */
hlthunk_public int hlthunk_memory_unmap(int fd, uint64_t device_virt_addr)
{
	union hl_mem_args ioctl_args;

	memset(&ioctl_args, 0, sizeof(ioctl_args));
	ioctl_args.in.unmap.device_virt_addr = device_virt_addr;
	ioctl_args.in.op = HL_MEM_OP_UNMAP;

	return hlthunk_ioctl(fd, HL_IOCTL_MEMORY, &ioctl_args);
}

hlthunk_public int hlthunk_debug(int fd, struct hl_debug_args *debug)
{
	return hlthunk_ioctl(fd, HL_IOCTL_DEBUG, debug);
}
