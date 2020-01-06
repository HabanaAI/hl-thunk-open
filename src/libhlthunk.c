// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
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
#include <dirent.h>
#include <linux/limits.h>
#include <pthread.h>
#include <dlfcn.h>

int hlthunk_debug_level = HLTHUNK_DEBUG_LEVEL_NA;
#define BUSID_WITHOUT_DOMAIN_LEN	7
#define BUSID_WITH_DOMAIN_LEN		12

/*
 * This table holds the pointers to the functions that should be called for
 * this operations. In case profiling the hl-thunk than the profiler will
 * get this 'default' table, and this table's pointers will point to the
 * profiler functions so it will wrap all this functions with profiling
 */
struct hlthunk_functions_pointers functions_pointers_table = {
	.fp_hlthunk_command_submission = hlthunk_command_submission_original,
	.fp_hlthunk_open = hlthunk_open_original,
	.fp_hlthunk_close = hlthunk_close_original,
	.fp_hlthunk_profiler_start = hlthunk_profiler_start_original,
	.fp_hlthunk_profiler_stop = hlthunk_profiler_stop_original,
	.fp_hlthunk_profiler_get_trace = hlthunk_profiler_get_trace_original,
	.fp_hlthunk_debug = hlthunk_debug,
	.fp_hlthunk_device_memory_alloc = hlthunk_device_memory_alloc,
	.fp_hlthunk_device_memory_free = hlthunk_device_memory_free,
	.fp_hlthunk_device_memory_map = hlthunk_device_memory_map,
	.fp_hlthunk_host_memory_map = hlthunk_host_memory_map,
	.fp_hlthunk_memory_unmap = hlthunk_memory_unmap,
	.fp_hlthunk_request_command_buffer = hlthunk_request_command_buffer,
	.fp_hlthunk_destroy_command_buffer = hlthunk_destroy_command_buffer,
	.fp_hlthunk_wait_for_cs = hlthunk_wait_for_cs,
	.fp_hlthunk_get_device_name_from_fd = hlthunk_get_device_name_from_fd,
	.fp_hlthunk_get_pci_bus_id_from_fd = hlthunk_get_pci_bus_id_from_fd,
	.fp_hlthunk_get_device_index_from_pci_bus_id =
		hlthunk_get_device_index_from_pci_bus_id,
	.fp_hlthunk_malloc = hlthunk_malloc,
	.fp_hlthunk_free = hlthunk_free
};

struct global_hlthunk_members {
	bool is_profiler_checked;
	void *shared_object_handle;
	pthread_mutex_t profiler_init_lock;
};

struct global_hlthunk_members global_members = {
	.is_profiler_checked = false,
	.shared_object_handle = NULL
};

static int hlthunk_ioctl(int fd, unsigned long request, void *arg)
{
	int ret;

	do {
		ret = ioctl(fd, request, arg);
	} while (ret == -1 && (errno == EINTR || errno == EAGAIN));

	return ret;
}

static const char *get_temp_dir(void)
{
	char *tmpdir;

	tmpdir = getenv("TEMP");
	if (tmpdir)
		return tmpdir;

	tmpdir = getenv("TMP");
	if (tmpdir)
		return tmpdir;

	tmpdir = getenv("TMPDIR");
	if (tmpdir)
		return tmpdir;

	return "/tmp";
}

static int hlthunk_open_minor(int device_index, enum hlthunk_node_type type)
{
	char buf[64], *dev_name;
	int fd;

	switch (type) {
	case HLTHUNK_NODE_PRIMARY:
		dev_name = HLTHUNK_DEV_NAME_PRIMARY;
		break;

	case HLTHUNK_NODE_CONTROL:
		dev_name = HLTHUNK_DEV_NAME_CONTROL;
		break;

	default:
		printf("invalid type %d\n", type);
		return -1;
	}

	sprintf(buf, dev_name, device_index);
	fd = open(buf, O_RDWR | O_CLOEXEC, 0);
	if (fd >= 0)
		return fd;
	return -errno;
}

static int hlthunk_open_by_busid(const char *busid, enum hlthunk_node_type type)
{
	int device_index;

	device_index = hlthunk_get_device_index_from_pci_bus_id(busid);
	if (device_index < 0) {
		printf("No Device for the given PCI address\n");
		return -EINVAL;
	}

	return hlthunk_open_minor(device_index, type);
}

hlthunk_public int hlthunk_get_device_index_from_pci_bus_id(const char *busid)
{
	const char *base_path = "/sys/class/habanalabs/";
	char *substr_ptr;
	struct dirent *entry;
	DIR *dir;
	const char *device_prefix = "hl";
	const char *virtual_device_prefix = "hlv";
	const char *sim_device_prefix = "hls";
	const char *pci_bus_prefix = "pci_addr";
	char pci_bus_file_name[PATH_MAX];
	char read_busid[16], full_busid[16];
	int fd, rc, device_index;

	if (!busid)
		return -EINVAL;

	if (strlen(busid) == BUSID_WITHOUT_DOMAIN_LEN) {
		snprintf(full_busid, BUSID_WITH_DOMAIN_LEN + 1, "0000:%s",
				busid);
	} else {
		strncpy(full_busid, busid, BUSID_WITH_DOMAIN_LEN);
		full_busid[BUSID_WITH_DOMAIN_LEN] = '\0';
	}

	dir = opendir(base_path);
	if (dir == NULL) {
		printf("Failed to open habanalabs directory\n");
		return errno;
	}

	while ((entry = readdir(dir)) != NULL) {
		if (strstr(entry->d_name, virtual_device_prefix) != NULL)
			// Ignoring "hlv" entry-name
			continue;
		else if (strstr(entry->d_name, sim_device_prefix) != NULL)
			// Ignoring "hls" entry-name
			continue;

		substr_ptr = strstr(entry->d_name, device_prefix);
		if (substr_ptr != NULL)
			device_index = atoi(substr_ptr + 2);
		else
			continue;

		sprintf(pci_bus_file_name, "%s%s/%s", base_path,
					entry->d_name, pci_bus_prefix);

		fd = open(pci_bus_file_name, O_RDONLY);
		if (fd < 0)
			continue;

		rc = read(fd, read_busid, BUSID_WITH_DOMAIN_LEN);
		if (rc < 0) {
			close(fd);
			continue;
		}

		read_busid[BUSID_WITH_DOMAIN_LEN] = '\0';
		close(fd);

		if (!strcmp(read_busid, full_busid)) {
			closedir(dir);
			return device_index;
		}
	}

	closedir(dir);

	return -1;
}

hlthunk_public enum hlthunk_device_name hlthunk_get_device_name_from_fd(int fd)
{
	enum hl_pci_ids device_id = hlthunk_get_device_id_from_fd(fd);

	switch (device_id) {
	case PCI_IDS_GOYA:
	case PCI_IDS_GOYA_SIMULATOR:
		return HLTHUNK_DEVICE_GOYA;
	default:
		printf("Invalid device type %d\n", device_id);
		break;
	}

	return HLTHUNK_DEVICE_INVALID;
}

hlthunk_public int hlthunk_get_pci_bus_id_from_fd(int fd, char *pci_bus_id,
							int len)
{
	const char *base_path = "/sys/class/habanalabs/";
	const char *pci_bus_prefix = "pci_addr";
	const char *device_prefix = "hl";
	char tmp_name[32], str[64], dev_name[16], read_busid[16],
				pci_bus_file_name[128], *p;
	FILE *output;
	pid_t pid;
	int lsof_fd, pci_fd, rc = 0;

	snprintf(tmp_name, 31, "%s/hltXXXXXX", get_temp_dir());
	lsof_fd = mkstemp(tmp_name);
	if (lsof_fd < 0)
		return -1;

	output = fdopen(lsof_fd, "r");
	if (!output) {
		rc = -1;
		goto out;
	}

	pid = getpid();
	snprintf(str, 63, "lsof -F n /proc/%d/fd/%d > %s 2> /dev/null",
			pid, fd, tmp_name);
	if (system(str) == -1) {
		rc = -1;
		goto close_output;
	}

	p = fgets(str, sizeof(str), output);
	while (p) {
		if (*p == 'n') {
			p = strstr(p, device_prefix);
			if (p)
				break;
		}
		p = fgets(str, sizeof(str), output);
	};

	if (!p) {
		rc = -1;
		goto close_output;
	}

	sscanf(p, "%[^\n]", dev_name);

	snprintf(pci_bus_file_name, 127, "%s%s/%s", base_path, dev_name,
		pci_bus_prefix);

	pci_fd = open(pci_bus_file_name, O_RDONLY);
	if (pci_fd < 0) {
		rc = -1;
		goto close_output;
	}

	rc = read(pci_fd, read_busid, BUSID_WITH_DOMAIN_LEN);
	if (rc < 0) {
		rc = -1;
		goto close_pci_fd;
	}

	rc = 0;

	read_busid[BUSID_WITH_DOMAIN_LEN] = '\0';

	strncpy(pci_bus_id, read_busid, len);

close_pci_fd:
	close(pci_fd);
close_output:
	fclose(output);
out:
	close(lsof_fd);
	snprintf(str, 63, "rm -f %s", tmp_name);
	system(str);

	return rc;
}

static int hlthunk_open_device_by_name(enum hlthunk_device_name device_name,
					enum hlthunk_node_type type)
{
	enum hlthunk_device_name asic_name;
	int fd, i;

	for (i = 0 ; i < HLTHUNK_MAX_MINOR ; i++) {
		fd = hlthunk_open_minor(i, type);
		if (fd >= 0) {
			asic_name = hlthunk_get_device_name_from_fd(fd);

			if ((device_name == HLTHUNK_DEVICE_DONT_CARE) ||
					(asic_name == device_name))
				return fd;

			hlthunk_close(fd);
		}
	}

	return -1;
}

hlthunk_public void *hlthunk_malloc(int size)
{
	return calloc(1, size);
}

hlthunk_public void hlthunk_free(void *pt)
{
	if (pt)
		free(pt);
}

void hlthunk_set_profiler(void)
{
	void (*set_profiler_function)(
		struct hlthunk_functions_pointers *functions_table);
	global_members.shared_object_handle =
		dlopen("libSynapse_profiler.so", RTLD_LAZY);
	if (global_members.shared_object_handle == NULL)
		return;
	*(void **) (&set_profiler_function) =
		dlsym(global_members.shared_object_handle,
		      "hlthunk_set_profiler");
	if (set_profiler_function)
		(*set_profiler_function)(&functions_pointers_table);
}
int hlthunk_open_original(enum hlthunk_device_name device_name,
			  const char *busid)
{
	if (busid)
		return hlthunk_open_by_busid(busid, HLTHUNK_NODE_PRIMARY);

	return hlthunk_open_device_by_name(device_name, HLTHUNK_NODE_PRIMARY);
}

hlthunk_public int hlthunk_open(enum hlthunk_device_name device_name,
				const char *busid)
{
	const char *env_var;

	if (!global_members.is_profiler_checked) {
		pthread_mutex_lock(&global_members.profiler_init_lock);

		if (!global_members.is_profiler_checked) {
			env_var = getenv("HABANA_PROFILE");
			if (env_var && strcmp(env_var, "1") == 0)
				hlthunk_set_profiler();

			global_members.is_profiler_checked = true;
		}

		pthread_mutex_unlock(&global_members.profiler_init_lock);
	}

	return (*functions_pointers_table.fp_hlthunk_open)(device_name, busid);
}

hlthunk_public int hlthunk_open_control(int dev_id, const char *busid)
{
	if (busid)
		return hlthunk_open_by_busid(busid, HLTHUNK_NODE_CONTROL);

	return hlthunk_open_minor(dev_id, HLTHUNK_NODE_CONTROL);
}

int hlthunk_close_original(int fd)
{
	return close(fd);
}

hlthunk_public int hlthunk_close(int fd)
{
	return (*functions_pointers_table.fp_hlthunk_close)(fd);
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
	memcpy(hw_ip->card_name, hl_hw_ip.card_name,
		HL_INFO_CARD_NAME_MAX_LEN);

	return 0;
}

hlthunk_public int hlthunk_get_dram_usage(int fd,
				struct hlthunk_dram_usage_info *dram_usage)
{
	struct hl_info_args args;
	struct hl_info_dram_usage hl_dram_usage;
	int rc;

	if (!dram_usage)
		return -EINVAL;

	memset(&args, 0, sizeof(args));
	memset(&hl_dram_usage, 0, sizeof(hl_dram_usage));

	args.op = HL_INFO_DRAM_USAGE;
	args.return_pointer = (__u64) (uintptr_t) &hl_dram_usage;
	args.return_size = sizeof(hl_dram_usage);

	rc = hlthunk_ioctl(fd, HL_IOCTL_INFO, &args);
	if (rc)
		return rc;

	dram_usage->dram_free_mem = hl_dram_usage.dram_free_mem;
	dram_usage->ctx_dram_mem = hl_dram_usage.ctx_dram_mem;

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

static int hlthunk_get_hw_idle_info(int fd, uint32_t *is_idle,
					uint32_t *busy_engines_mask)
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
		return rc;

	*is_idle = hl_hw_idle.is_idle;
	*busy_engines_mask = hl_hw_idle.busy_engines_mask;

	return 0;
}

hlthunk_public bool hlthunk_is_device_idle(int fd)
{
	uint32_t is_idle, mask;
	int rc;

	rc = hlthunk_get_hw_idle_info(fd, &is_idle, &mask);
	if (rc)
		return false;

	return !!is_idle;
}

hlthunk_public int hlthunk_get_busy_engines_mask(int fd, uint32_t *mask)
{
	uint32_t is_idle;
	int rc;

	rc = hlthunk_get_hw_idle_info(fd, &is_idle, mask);

	return rc;
}

hlthunk_public int hlthunk_get_device_utilization(int fd, uint32_t period_ms,
						uint32_t *rate)
{
	struct hl_info_args args;
	struct hl_info_device_utilization hl_info;
	int rc, i;

	if (!rate)
		return -EINVAL;

	memset(&args, 0, sizeof(args));
	memset(&hl_info, 0, sizeof(hl_info));

	args.op = HL_INFO_DEVICE_UTILIZATION;
	args.return_pointer = (__u64) (uintptr_t) &hl_info;
	args.return_size = sizeof(hl_info);
	args.period_ms = period_ms;

	rc = hlthunk_ioctl(fd, HL_IOCTL_INFO, &args);
	if (rc)
		return rc;

	*rate = hl_info.utilization;

	return 0;
}

hlthunk_public int hlthunk_get_hw_events_arr(int fd, bool aggregate,
						uint32_t hw_events_arr_size,
						uint32_t *hw_events_arr)
{
	struct hl_info_args args;
	int rc;

	if (!hw_events_arr)
		return -EINVAL;

	memset(&args, 0, sizeof(args));
	if (aggregate)
		args.op = HL_INFO_HW_EVENTS_AGGREGATE;
	else
		args.op = HL_INFO_HW_EVENTS;

	args.return_pointer = (__u64) (uintptr_t) hw_events_arr;
	args.return_size = hw_events_arr_size;

	rc = hlthunk_ioctl(fd, HL_IOCTL_INFO, &args);
	if (rc)
		return rc;

	return 0;
}

hlthunk_public int hlthunk_get_clk_rate(int fd, uint32_t *cur_clk_mhz,
					uint32_t *max_clk_mhz)
{
	struct hl_info_args args;
	struct hl_info_clk_rate hl_clk_rate;
	int rc, i;

	if ((!cur_clk_mhz) || (!max_clk_mhz))
		return -EINVAL;

	memset(&args, 0, sizeof(args));
	memset(&hl_clk_rate, 0, sizeof(hl_clk_rate));

	args.op = HL_INFO_CLK_RATE;
	args.return_pointer = (__u64) (uintptr_t) &hl_clk_rate;
	args.return_size = sizeof(hl_clk_rate);

	rc = hlthunk_ioctl(fd, HL_IOCTL_INFO, &args);
	if (rc)
		return rc;

	*cur_clk_mhz = hl_clk_rate.cur_clk_rate_mhz;
	*max_clk_mhz = hl_clk_rate.max_clk_rate_mhz;

	return 0;

}

hlthunk_public int hlthunk_get_reset_count_info(int fd,
					struct hlthunk_reset_count_info *info)
{
	struct hl_info_args args;
	struct hl_info_reset_count hl_reset_count;
	int rc, i;

	if (!info)
		return -EINVAL;

	memset(&args, 0, sizeof(args));
	memset(&hl_reset_count, 0, sizeof(hl_reset_count));

	args.op = HL_INFO_RESET_COUNT;
	args.return_pointer = (__u64) (uintptr_t) &hl_reset_count;
	args.return_size = sizeof(hl_reset_count);

	rc = hlthunk_ioctl(fd, HL_IOCTL_INFO, &args);
	if (rc)
		return rc;

	info->hard_reset_count = hl_reset_count.hard_reset_cnt;
	info->soft_reset_count = hl_reset_count.soft_reset_cnt;

	return 0;

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

int hlthunk_command_submission_original(int fd, struct hlthunk_cs_in *in,
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

hlthunk_public int hlthunk_command_submission(int fd, struct hlthunk_cs_in *in,
					      struct hlthunk_cs_out *out)
{
	return (*functions_pointers_table.fp_hlthunk_command_submission)(
				fd, in, out);
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

	hl_out = &args.out;
	*status = hl_out->status;

	return rc;
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
	ioctl_args.in.alloc.mem_size = size;
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

int hlthunk_profiler_start_original(int fd)
{
	return -1;
}

hlthunk_public int hlthunk_profiler_start(int fd)
{
	return (*functions_pointers_table.fp_hlthunk_profiler_start)(fd);
}

int hlthunk_profiler_stop_original(int fd)
{
	return -1;
}

hlthunk_public int hlthunk_profiler_stop(int fd)
{
	return (*functions_pointers_table.fp_hlthunk_profiler_stop)(fd);
}

int hlthunk_profiler_get_trace_original(int fd, void *buffer, uint64_t *size)
{
	return -1;
}

hlthunk_public int hlthunk_profiler_get_trace(int fd, void *buffer,
					      uint64_t *size)
{
	return (*functions_pointers_table.fp_hlthunk_profiler_get_trace)(
				fd, buffer, size);
}
