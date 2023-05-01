// SPDX-License-Identifier: MIT

/*
 * Copyright 2019-2022 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "libhlthunk.h"
#include "specs/common/pci_ids.h"
#include "specs/common/shim_types.h"

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
#include <sys/mman.h>
#include <pthread.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/eventfd.h>
#include <sys/poll.h>
#include <limits.h>

extern const char *HLTHUNK_SHA1_VERSION;

int hlthunk_debug_level = HLTHUNK_DEBUG_LEVEL_NA;
#define BUSID_WITHOUT_DOMAIN_LEN	7
#define BUSID_WITH_DOMAIN_LEN		12

/*
 * This table holds the pointers to the functions that should be called for
 * this operations. In case profiling the hl-thunk than the profiler will
 * get this 'default' table, and this table's pointers will point to the
 * profiler functions so it will wrap all this functions with profiling
 */
struct hlthunk_functions_pointers default_functions_pointers_table =
	INIT_FUNCS_POINTERS_TABLE;

struct hlthunk_functions_pointers *functions_pointers_table =
	&default_functions_pointers_table;

struct global_hlthunk_members {
	bool is_profiler_checked;
	void *shared_object_handle;
	void (*pfn_shim_finish)(enum shim_api_type apiType);
	pthread_mutex_t profiler_init_lock;
};

struct global_hlthunk_members global_members = {
	.is_profiler_checked = false,
	.shared_object_handle = NULL,
	.pfn_shim_finish = NULL
};

static int hlthunk_ioctl(int fd, unsigned long request, void *arg)
{
	int ret;

	do {
		ret = ioctl(fd, request, arg);
	} while (ret == -1 && (errno == EINTR || errno == EAGAIN));

	if (ret)
		return -errno;

	return 0;
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
	if (device_index < 0)
		return -EINVAL;

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
	if (dir == NULL)
		return -errno;

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
		return HLTHUNK_DEVICE_GOYA;
	case PCI_IDS_GAUDI:
	case PCI_IDS_GAUDI_SEC:
		return HLTHUNK_DEVICE_GAUDI;
	case PCI_IDS_GAUDI2:
		return HLTHUNK_DEVICE_GAUDI2;
	default:
		break;
	}

	return HLTHUNK_DEVICE_INVALID;
}

hlthunk_public int hlthunk_get_pci_bus_id_from_fd(int fd, char *pci_bus_id, int len)
{
	char pci_bus_file_name[128], read_busid[16];
	const char *base_path = "/sys/dev/char";
	const char *pci_bus_prefix = "pci_addr";
	int rc, major_num, minor_num, pci_fd;
	struct stat fd_stat;

	if (!pci_bus_id)
		return -EINVAL;

	rc = fstat(fd, &fd_stat);
	if (rc < 0)
		return rc;

	major_num = major(fd_stat.st_rdev);
	minor_num = minor(fd_stat.st_rdev);

	/* If the FD represents a control device, use the real device to get
	 * the PCI BDF
	 */
	if (minor_num & 1)
		minor_num--;

	snprintf(pci_bus_file_name, 127, "%s/%d:%d/%s", base_path, major_num,
						minor_num, pci_bus_prefix);

	pci_fd = open(pci_bus_file_name, O_RDONLY);
	if (pci_fd < 0)
		return pci_fd;

	rc = read(pci_fd, read_busid, BUSID_WITH_DOMAIN_LEN);
	close(pci_fd);

	if (rc < 0)
		return rc;

	read_busid[BUSID_WITH_DOMAIN_LEN] = '\0';

	strncpy(pci_bus_id, read_busid, len);

	return 0;
}

static int hlthunk_open_device_by_name(enum hlthunk_device_name device_name,
					enum hlthunk_node_type type)
{
	enum hlthunk_device_name asic_name;
	int fd, fd_ctrl, i, last_valid_errno;

	/* Initialize to ENOENT in case there is no asic matching device_name */
	last_valid_errno = ENOENT;

	/* We do not know what minor is in use, so try them all. */
	for (i = 0 ; i < HLTHUNK_MAX_MINOR ; i++) {
		/* Regardless of what type of device the user requested, we
		 * start by opening the control device. This is needed to get
		 * the device name. We need the device name to tell if it is
		 * relevant for user request, and we can't use the real device
		 * for that as it may be busy.
		 */
		fd_ctrl = hlthunk_open_minor(i, HLTHUNK_NODE_CONTROL);
		if (fd_ctrl >= 0) {
			asic_name = hlthunk_get_device_name_from_fd(fd_ctrl);

			if ((device_name == HLTHUNK_DEVICE_DONT_CARE) ||
					(asic_name == device_name)) {

				/* If control device requested, just return it.
				 * We already have it open.
				 */
				if (type == HLTHUNK_NODE_CONTROL)
					return fd_ctrl;

				fd = hlthunk_open_minor(i, type);
				/* Closing the control device only after open,
				 * to prevent the device being removed at this
				 * time interval.
				 */
				hlthunk_close_original(fd_ctrl);
				if (fd >= 0)
					return fd;

				/* If there was an error - remember it. This is
				 * to prevent errno from being overridden from
				 * trying to open non-existent devices.
				 */
				if (errno != ENOENT)
					last_valid_errno = errno;
			} else {
				/* Need to close fd_ctrl to prevent resource
				 * leak because we will use this variable
				 * to hold fd of the next device in this loop
				 */
				hlthunk_close_original(fd_ctrl);
			}
		}
	}

	errno = last_valid_errno;

	return -1;
}

hlthunk_public void *hlthunk_malloc(size_t size)
{
	return calloc(1, size);
}

hlthunk_public void hlthunk_free(void *pt)
{
	if (pt)
		free(pt);
}

void hlthunk_enable_shim(void)
{
#ifndef DISABLE_PROFILER
	void* (*shim_get_functions)(
		enum shim_api_type api_type, void *orig_functions);

	global_members.shared_object_handle =
		dlopen(SHIM_LIB_NAME, RTLD_LAZY);
	if (global_members.shared_object_handle == NULL)
		return;

	*(void **) (&shim_get_functions) =
		dlsym(global_members.shared_object_handle,
		      SHIM_GET_FUNCTIONS);

	if (shim_get_functions != NULL) {
		global_members.is_profiler_checked = true;

		*(void **) (&global_members.pfn_shim_finish) =
			dlsym(global_members.shared_object_handle,
			      SHIM_FINISH);
		/*
		 * TODO: start/stop profiling is not supported at the moment.
		 * Currently, we call ShimGetFunctions only once in the initialization
		 * To support profiling during execution,
		 * we will have to call it before every (or specific) API call
		 */
		functions_pointers_table = shim_get_functions(SHIM_API_HLTHUNK,
			functions_pointers_table);
	} else {
		dlclose(global_members.shared_object_handle);
		global_members.shared_object_handle = NULL;
	}
#else /* shim layer won't be loaded, if HABANA_PROFILE=1 need to notify*/

	char file_name[64];
	char *env_var, *line = NULL;
	int flag = 0;
	FILE *file;

	env_var = getenv("HABANA_PROFILE");
	if (!env_var || strcmp(env_var, "0") != 0x0)
		return;

	sprintf(file_name, "/proc/%d/maps", getpid());
	file = fopen(file_name, "r");

	if (file) {
		while (getline(&line, NULL, file) != -1) {
			if (strstr(line, SHIM_LIB_NAME) != NULL) {
				flag = 1;
				break;
			}
		}
		fclose(file);
	}
#endif
}

int hlthunk_open_original(enum hlthunk_device_name device_name,
			  const char *busid)
{
	if (busid)
		return hlthunk_open_by_busid(busid, HLTHUNK_NODE_PRIMARY);

	return hlthunk_open_device_by_name(device_name, HLTHUNK_NODE_PRIMARY);
}

hlthunk_public int hlthunk_open(enum hlthunk_device_name device_name, const char *busid)
{
	const char *env_var;

	if (!global_members.is_profiler_checked) {
		pthread_mutex_lock(&global_members.profiler_init_lock);

		if (!global_members.is_profiler_checked) {
			env_var = getenv("HABANA_SHIM_DISABLE");
			if (env_var == NULL || strcmp(env_var, "1") != 0)
				hlthunk_enable_shim();
		}

		pthread_mutex_unlock(&global_members.profiler_init_lock);
	}

	return (*functions_pointers_table->fp_hlthunk_open)(device_name, busid);
}

hlthunk_public int hlthunk_open_by_module_id(uint32_t module_id)
{
	const char *base_path = "/sys/class/habanalabs/";
	const char *char_base_path = "/sys/dev/char/";
	const char *device_prefix = "hl_controlD";
	const char *dev_file_prefix = "dev";
	const char *pci_addr_prefix = "pci_addr";
	char dev_name[64], read_busid[16], sys_file_name[128];
	int i, rc, ctrl_fd, major, minor, pci_fd;
	bool found = false;
	FILE *sys_file;

	for (i = 0 ; i < HLTHUNK_MAX_MINOR ; i++) {
		struct hlthunk_hw_ip_info hw_ip;

		ctrl_fd = hlthunk_open_control(i, NULL);
		if (ctrl_fd < 0)
			continue;

		rc = hlthunk_get_hw_ip_info(ctrl_fd, &hw_ip);

		hlthunk_close_original(ctrl_fd);

		if ((rc) || (hw_ip.module_id != module_id))
			continue;

		found = true;
		break;
	}

	if (!found)
		return -1;

	sprintf(dev_name, "%s%d", device_prefix, i);

	sprintf(sys_file_name, "%s%s/%s", base_path, dev_name, dev_file_prefix);

	sys_file = fopen(sys_file_name, "r");
	if (!sys_file)
		return -1;

	rc = fscanf(sys_file, "%d:%d", &major, &minor);
	fclose(sys_file);

	if (rc != 2)
		return -1;

	sprintf(sys_file_name, "%s%d:%d/%s", char_base_path, major, minor - 1,
						pci_addr_prefix);

	pci_fd = open(sys_file_name, O_RDONLY);
	if (pci_fd < 0)
		return pci_fd;

	rc = read(pci_fd, read_busid, BUSID_WITH_DOMAIN_LEN);
	close(pci_fd);

	if (rc < 0)
		return rc;

	read_busid[BUSID_WITH_DOMAIN_LEN] = '\0';

	return hlthunk_open(HLTHUNK_DEVICE_DONT_CARE, read_busid);
}

hlthunk_public int hlthunk_open_control(int dev_id, const char *busid)
{
	if (busid)
		return hlthunk_open_by_busid(busid, HLTHUNK_NODE_CONTROL);

	return hlthunk_open_minor(dev_id, HLTHUNK_NODE_CONTROL);
}

hlthunk_public int hlthunk_open_control_by_name(enum hlthunk_device_name device_name,
					const char *busid)
{
	if (busid)
		return hlthunk_open_by_busid(busid, HLTHUNK_NODE_CONTROL);

	return hlthunk_open_device_by_name(device_name, HLTHUNK_NODE_CONTROL);
}

int hlthunk_close_original(int fd)
{
	return close(fd);
}

hlthunk_public int hlthunk_close(int fd)
{
	return (*functions_pointers_table->fp_hlthunk_close)(fd);
}

hlthunk_public int hlthunk_get_open_stats(int fd, struct hlthunk_open_stats_info *open_stats)
{
	struct hl_open_stats_info hl_open_stats;
	struct hl_info_args args;
	int rc;

	if (!open_stats)
		return -EINVAL;

	memset(&args, 0, sizeof(args));
	memset(&hl_open_stats, 0, sizeof(hl_open_stats));

	args.op = HL_INFO_OPEN_STATS;
	args.return_pointer = (__u64) (uintptr_t) &hl_open_stats;
	args.return_size = sizeof(hl_open_stats);

	rc = hlthunk_ioctl(fd, HL_IOCTL_INFO, &args);
	if (rc)
		return rc;

	open_stats->open_counter = hl_open_stats.open_counter;
	open_stats->last_open_period_ms = hl_open_stats.last_open_period_ms;
	open_stats->is_compute_ctx_active = hl_open_stats.is_compute_ctx_active;
	open_stats->compute_ctx_in_release = hl_open_stats.compute_ctx_in_release;

	return 0;
}

hlthunk_public int hlthunk_get_hw_asic_status(int fd, struct hlthunk_hw_asic_status *hw_asic_status)
{
	int rc;

	if (!hw_asic_status)
		return -EINVAL;

	hw_asic_status->valid = 0;

	rc = hlthunk_get_clk_throttle_info(fd, &hw_asic_status->throttle);
	if (rc)
		return rc;

	rc = hlthunk_get_open_stats(fd, &hw_asic_status->open_stats);
	if (rc)
		return rc;

	rc = hlthunk_get_power_info(fd, &hw_asic_status->power);
	if (rc)
		return rc;

	hw_asic_status->status = hlthunk_get_device_status_info(fd);
	if (hw_asic_status->status < 0)
		return hw_asic_status->status;

	hw_asic_status->timestamp_sec = time(NULL);

	hw_asic_status->valid = 1;

	return 0;
}

hlthunk_public int hlthunk_get_hw_ip_info(int fd, struct hlthunk_hw_ip_info *hw_ip)
{
	struct hl_info_hw_ip_info hl_hw_ip;
	struct hl_info_args args;
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
	hw_ip->cpld_version = hl_hw_ip.cpld_version;
	hw_ip->psoc_pci_pll_nr = hl_hw_ip.psoc_pci_pll_nr;
	hw_ip->psoc_pci_pll_nf = hl_hw_ip.psoc_pci_pll_nf;
	hw_ip->psoc_pci_pll_od = hl_hw_ip.psoc_pci_pll_od;
	hw_ip->psoc_pci_pll_div_factor = hl_hw_ip.psoc_pci_pll_div_factor;
	hw_ip->tpc_enabled_mask = hl_hw_ip.tpc_enabled_mask;
	hw_ip->tpc_enabled_mask_ext = hl_hw_ip.tpc_enabled_mask_ext;
	hw_ip->dram_enabled = hl_hw_ip.dram_enabled;
	memcpy(hw_ip->cpucp_version, hl_hw_ip.cpucp_version, HL_INFO_VERSION_MAX_LEN);
	memcpy(hw_ip->card_name, hl_hw_ip.card_name, HL_INFO_CARD_NAME_MAX_LEN);
	hw_ip->module_id = hl_hw_ip.module_id;
	hw_ip->decoder_enabled_mask = hl_hw_ip.decoder_enabled_mask;
	hw_ip->mme_master_slave_mode = hl_hw_ip.mme_master_slave_mode;
	hw_ip->dram_page_size = hl_hw_ip.dram_page_size;
	hw_ip->first_available_interrupt_id = hl_hw_ip.first_available_interrupt_id;
	hw_ip->edma_enabled_mask = hl_hw_ip.edma_enabled_mask;
	hw_ip->server_type = hl_hw_ip.server_type;
	hw_ip->number_of_user_interrupts = hl_hw_ip.number_of_user_interrupts;
	hw_ip->device_mem_alloc_default_page_size = hl_hw_ip.device_mem_alloc_default_page_size;

	return 0;
}

hlthunk_public int hlthunk_get_dram_usage(int fd, struct hlthunk_dram_usage_info *dram_usage)
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
	memset(&hl_dev_status, 0, sizeof(hl_dev_status));

	args.op = HL_INFO_DEVICE_STATUS;
	args.return_pointer = (__u64) (uintptr_t) &hl_dev_status;
	args.return_size = sizeof(hl_dev_status);

	rc = hlthunk_ioctl(fd, HL_IOCTL_INFO, &args);
	if (rc)
		return rc;

	return hl_dev_status.status;
}

static int hlthunk_get_hw_idle_info(int fd, struct hlthunk_engines_idle_info *info)
{
	struct hl_info_args args;
	struct hl_info_hw_idle hl_hw_idle;
	int rc, i;

	if (!info)
		return -EINVAL;

	memset(&args, 0, sizeof(args));
	memset(&hl_hw_idle, 0, sizeof(hl_hw_idle));

	args.op = HL_INFO_HW_IDLE;
	args.return_pointer = (__u64) (uintptr_t) &hl_hw_idle;
	args.return_size = sizeof(hl_hw_idle);

	rc = hlthunk_ioctl(fd, HL_IOCTL_INFO, &args);
	if (rc)
		return rc;

	info->is_idle = hl_hw_idle.is_idle;
	for (i = 0 ; i < HL_BUSY_ENGINES_MASK_EXT_SIZE ; i++)
		info->mask[i] = hl_hw_idle.busy_engines_mask_ext[i];

	return 0;
}

hlthunk_public bool hlthunk_is_device_idle(int fd)
{
	struct hlthunk_engines_idle_info info;

	int rc;

	rc = hlthunk_get_hw_idle_info(fd, &info);
	if (rc)
		return false;

	return !!info.is_idle;
}

hlthunk_public int hlthunk_get_busy_engines_mask(int fd, struct hlthunk_engines_idle_info *info)
{
	return hlthunk_get_hw_idle_info(fd, info);
}

hlthunk_public int hlthunk_get_pll_frequency(int fd, uint32_t index,
			struct hlthunk_pll_frequency_info *frequency)
{
	struct hl_info_args args;
	struct hl_pll_frequency_info hl_info;
	int rc;

	if (!frequency)
		return -EINVAL;

	memset(&args, 0, sizeof(args));
	memset(&hl_info, 0, sizeof(hl_info));

	args.op = HL_INFO_PLL_FREQUENCY;
	args.return_pointer = (__u64) (uintptr_t) &hl_info;
	args.return_size = sizeof(hl_info);
	args.pll_index = index;

	rc = hlthunk_ioctl(fd, HL_IOCTL_INFO, &args);
	if (rc)
		return rc;

	memcpy(frequency, &hl_info, sizeof(struct hlthunk_pll_frequency_info));

	return 0;
}

hlthunk_public int hlthunk_get_device_utilization(int fd, uint32_t period_ms, uint32_t *rate)
{
	struct hl_info_args args;
	struct hl_info_device_utilization hl_info;
	int rc;

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

hlthunk_public int hlthunk_get_hw_events_arr(int fd, bool aggregate, uint32_t hw_events_arr_size,
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

hlthunk_public int hlthunk_get_clk_rate(int fd, uint32_t *cur_clk_mhz, uint32_t *max_clk_mhz)
{
	struct hl_info_args args;
	struct hl_info_clk_rate hl_clk_rate;
	int rc;

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

hlthunk_public int hlthunk_get_reset_count_info(int fd, struct hlthunk_reset_count_info *info)
{
	struct hl_info_args args;
	struct hl_info_reset_count hl_reset_count;
	int rc;

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

hlthunk_public int hlthunk_get_time_sync_info(int fd, struct hlthunk_time_sync_info *info)
{
	struct hl_info_args args;
	struct hl_info_time_sync hl_time_sync;
	int rc;

	if (!info)
		return -EINVAL;

	memset(&args, 0, sizeof(args));
	memset(&hl_time_sync, 0, sizeof(hl_time_sync));

	args.op = HL_INFO_TIME_SYNC;
	args.return_pointer = (__u64) (uintptr_t) &hl_time_sync;
	args.return_size = sizeof(hl_time_sync);

	rc = hlthunk_ioctl(fd, HL_IOCTL_INFO, &args);
	if (rc)
		return rc;

	info->device_time = hl_time_sync.device_time;
	info->host_time = hl_time_sync.host_time;

	return 0;
}

hlthunk_public int hlthunk_get_sync_manager_info(int fd, int dcore_id,
					struct hlthunk_sync_manager_info *info)
{
	struct hl_info_args args;
	struct hl_info_sync_manager sm_info;
	int rc;

	if (!info)
		return -EINVAL;

	memset(&args, 0, sizeof(args));
	memset(&sm_info, 0, sizeof(sm_info));

	args.op = HL_INFO_SYNC_MANAGER;
	args.dcore_id = dcore_id;
	args.return_pointer = (__u64) (uintptr_t) &sm_info;
	args.return_size = sizeof(sm_info);

	rc = hlthunk_ioctl(fd, HL_IOCTL_INFO, &args);
	if (rc)
		return rc;

	info->first_available_monitor = sm_info.first_available_monitor;
	info->first_available_sync_object = sm_info.first_available_sync_object;
	info->first_available_cq = sm_info.first_available_cq;

	return 0;
}

hlthunk_public int hlthunk_get_dev_memalloc_page_orders(int fd, uint64_t *page_order_bitmask)
{
	struct hl_info_dev_memalloc_page_sizes page_size_info;
	struct hl_info_args args;
	int rc;

	if (!page_order_bitmask)
		return -EINVAL;

	memset(&args, 0, sizeof(args));
	memset(&page_size_info, 0, sizeof(page_size_info));

	args.op = HL_INFO_DEV_MEM_ALLOC_PAGE_SIZES;
	args.return_pointer = (__u64) (uintptr_t) &page_size_info;
	args.return_size = sizeof(page_size_info);

	rc = hlthunk_ioctl(fd, HL_IOCTL_INFO, &args);
	if (rc)
		return rc;

	*page_order_bitmask = page_size_info.page_order_bitmask;

	return 0;
}

hlthunk_public int hlthunk_get_cs_counters_info(int fd, struct hl_info_cs_counters *info)
{
	struct hl_info_args args;
	struct hl_info_cs_counters hl_cs_counters;
	int rc;

	if (!info)
		return -EINVAL;

	memset(&args, 0, sizeof(args));
	memset(&hl_cs_counters, 0, sizeof(hl_cs_counters));

	args.op = HL_INFO_CS_COUNTERS;
	args.return_pointer = (__u64) (uintptr_t) &hl_cs_counters;
	args.return_size = sizeof(hl_cs_counters);

	rc = hlthunk_ioctl(fd, HL_IOCTL_INFO, &args);
	if (rc)
		return rc;

	info->total_device_in_reset_drop_cnt =
		hl_cs_counters.total_device_in_reset_drop_cnt;
	info->total_out_of_mem_drop_cnt =
		hl_cs_counters.total_out_of_mem_drop_cnt;
	info->total_parsing_drop_cnt =
		hl_cs_counters.total_parsing_drop_cnt;
	info->total_queue_full_drop_cnt =
		hl_cs_counters.total_queue_full_drop_cnt;
	info->total_max_cs_in_flight_drop_cnt =
		hl_cs_counters.total_max_cs_in_flight_drop_cnt;
	info->total_validation_drop_cnt =
		hl_cs_counters.total_validation_drop_cnt;

	info->ctx_device_in_reset_drop_cnt =
		hl_cs_counters.ctx_device_in_reset_drop_cnt;
	info->ctx_out_of_mem_drop_cnt =
		hl_cs_counters.ctx_out_of_mem_drop_cnt;
	info->ctx_parsing_drop_cnt =
		hl_cs_counters.ctx_parsing_drop_cnt;
	info->ctx_queue_full_drop_cnt =
		hl_cs_counters.ctx_queue_full_drop_cnt;
	info->ctx_max_cs_in_flight_drop_cnt =
		hl_cs_counters.ctx_max_cs_in_flight_drop_cnt;
	info->ctx_validation_drop_cnt =
		hl_cs_counters.ctx_validation_drop_cnt;

	return 0;
}

hlthunk_public int hlthunk_get_pci_counters_info(int fd, struct hlthunk_pci_counters_info *info)
{
	struct hl_info_args args;
	struct hl_info_pci_counters pci_counters;
	int rc;

	if (!info)
		return -EINVAL;

	memset(&args, 0, sizeof(args));
	memset(&pci_counters, 0, sizeof(pci_counters));

	args.op = HL_INFO_PCI_COUNTERS;
	args.return_pointer = (__u64) (uintptr_t) &pci_counters;
	args.return_size = sizeof(pci_counters);

	rc = hlthunk_ioctl(fd, HL_IOCTL_INFO, &args);
	if (rc)
		return rc;

	info->rx_throughput = pci_counters.rx_throughput;
	info->tx_throughput = pci_counters.tx_throughput;
	info->replay_cnt = pci_counters.replay_cnt;

	return 0;
}

hlthunk_public int hlthunk_get_clk_throttle_info(int fd, struct hlthunk_clk_throttle_info *info)
{
	struct hl_info_clk_throttle clk_throttle;
	struct hl_info_args args;
	int i, rc;

	if (!info)
		return -EINVAL;

	memset(&args, 0, sizeof(args));
	memset(&clk_throttle, 0, sizeof(clk_throttle));

	args.op = HL_INFO_CLK_THROTTLE_REASON;
	args.return_pointer = (__u64) (uintptr_t) &clk_throttle;
	args.return_size = sizeof(clk_throttle);

	rc = hlthunk_ioctl(fd, HL_IOCTL_INFO, &args);
	if (rc)
		return rc;

	info->clk_throttle_reason_bitmask = clk_throttle.clk_throttling_reason;

	for (i = 0 ; i < HL_CLK_THROTTLE_TYPE_MAX ; i++) {
		info->clk_throttle_start_timestamp_us[i] =
				clk_throttle.clk_throttling_timestamp_us[i];
		info->clk_throttle_duration_ns[i] =
				clk_throttle.clk_throttling_duration_ns[i];
	}

	return 0;
}

hlthunk_public int hlthunk_get_total_energy_consumption_info(int fd,
								struct hlthunk_energy_info *info)
{
	struct hl_info_energy energy_info;
	struct hl_info_args args;
	int rc;

	if (!info)
		return -EINVAL;

	memset(&args, 0, sizeof(args));
	memset(&energy_info, 0, sizeof(energy_info));

	args.op = HL_INFO_TOTAL_ENERGY;
	args.return_pointer = (__u64) (uintptr_t) &energy_info;
	args.return_size = sizeof(energy_info);

	rc = hlthunk_ioctl(fd, HL_IOCTL_INFO, &args);
	if (rc)
		return rc;

	info->total_energy_consumption = energy_info.total_energy_consumption;

	return 0;
}

hlthunk_public int hlthunk_get_power_info(int fd, struct hlthunk_power_info *info)
{
	struct hl_power_info power_info;
	struct hl_info_args args;
	int rc;

	if (!info)
		return -EINVAL;

	memset(&args, 0, sizeof(args));
	memset(&power_info, 0, sizeof(power_info));

	args.op = HL_INFO_POWER;
	args.return_pointer = (__u64) (uintptr_t) &power_info;
	args.return_size = sizeof(power_info);

	rc = hlthunk_ioctl(fd, HL_IOCTL_INFO, &args);
	if (rc)
		return rc;

	info->power = power_info.power;

	return 0;
}

static int _hlthunk_get_dram_replaced_rows_info(int fd,
						struct hlthunk_dram_replaced_rows_info *info)
{
	struct hlthunk_dram_replaced_rows_info repl_rows_info;
	struct hl_info_args args;
	int rc;

	if (!info)
		return -EINVAL;

	memset(&args, 0, sizeof(args));
	memset(&repl_rows_info, 0, sizeof(repl_rows_info));

	args.op = HL_INFO_DRAM_REPLACED_ROWS;
	args.return_pointer = (__u64) (uintptr_t) &repl_rows_info;
	args.return_size = sizeof(repl_rows_info);

	rc = hlthunk_ioctl(fd, HL_IOCTL_INFO, &args);
	if (rc)
		return rc;

	memcpy(info, &repl_rows_info, sizeof(*info));

	return 0;
}

static int _hlthunk_get_dram_pending_rows_info(int fd, uint32_t *out)
{
	uint32_t pend_rows_num = 0;
	struct hl_info_args args;
	int rc;

	if (!out)
		return -EINVAL;

	memset(&args, 0, sizeof(args));

	args.op = HL_INFO_DRAM_PENDING_ROWS;
	args.return_pointer = (__u64) (uintptr_t) &pend_rows_num;
	args.return_size = sizeof(pend_rows_num);

	rc = hlthunk_ioctl(fd, HL_IOCTL_INFO, &args);
	if (rc)
		return rc;

	*out = pend_rows_num;

	return 0;
}

int hlthunk_get_dram_replaced_rows_info_original(int fd,
				struct hlthunk_dram_replaced_rows_info *out)
{
	return _hlthunk_get_dram_replaced_rows_info(fd, out);
}

hlthunk_public int hlthunk_get_dram_replaced_rows_info(int fd,
				struct hlthunk_dram_replaced_rows_info *out)
{
	return (*functions_pointers_table->fp_get_dram_replaced_rows_info)(fd, out);
}

int hlthunk_get_dram_pending_rows_info_original(int fd, uint32_t *out)
{
	return _hlthunk_get_dram_pending_rows_info(fd, out);
}

hlthunk_public int hlthunk_get_dram_pending_rows_info(int fd, uint32_t *out)
{
	return (*functions_pointers_table->fp_get_dram_pending_rows_info)(fd, out);
}

hlthunk_public int hlthunk_request_command_buffer(int fd, uint32_t cb_size, uint64_t *cb_handle)
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

hlthunk_public int hlthunk_request_mapped_command_buffer(int fd, uint32_t cb_size,
								uint64_t *cb_handle)
{
	union hl_cb_args args;
	int rc;

	if (!cb_handle)
		return -EINVAL;

	memset(&args, 0, sizeof(args));
	args.in.op = HL_CB_OP_CREATE;
	args.in.cb_size = cb_size;
	args.in.flags = HL_CB_FLAGS_MAP;

	rc = hlthunk_ioctl(fd, HL_IOCTL_CB, &args);
	if (rc)
		return rc;

	*cb_handle = args.out.cb_handle;

	return 0;
}

int hlthunk_get_mapped_cb_device_va_by_handle_original(int fd, uint64_t cb_handle,
							uint64_t *device_va)
{
	union hl_cb_args args;
	int rc;

	memset(&args, 0, sizeof(args));

	args.in.op = HL_CB_OP_INFO;
	args.in.cb_handle = cb_handle;
	args.in.flags = HL_CB_FLAGS_GET_DEVICE_VA;

	rc = hlthunk_ioctl(fd, HL_IOCTL_CB, &args);
	if (rc)
		return rc;

	*device_va = args.out.device_va;

	return 0;
}

hlthunk_public int hlthunk_get_mapped_cb_device_va_by_handle(int fd, uint64_t cb_handle,
							uint64_t *device_va)
{
	return (*functions_pointers_table->fp_hlthunk_get_mapped_cb_device_va_by_handle)(fd,
							cb_handle, device_va);
}

hlthunk_public int hlthunk_destroy_command_buffer(int fd, uint64_t cb_handle)
{
	union hl_cb_args args;

	memset(&args, 0, sizeof(args));
	args.in.op = HL_CB_OP_DESTROY;
	args.in.cb_handle = cb_handle;

	return hlthunk_ioctl(fd, HL_IOCTL_CB, &args);
}

hlthunk_public int hlthunk_get_cb_usage_count(int fd, uint64_t cb_handle, uint32_t *usage_cnt)
{
	union hl_cb_args args;
	int rc;

	if (!usage_cnt)
		return -EINVAL;

	memset(&args, 0, sizeof(args));
	args.in.op = HL_CB_OP_INFO;
	args.in.cb_handle = cb_handle;

	rc = hlthunk_ioctl(fd, HL_IOCTL_CB, &args);
	if (rc)
		return rc;

	*usage_cnt = args.out.usage_cnt;

	return 0;
}

static int _hlthunk_command_submission(int fd, struct hlthunk_cs_in *in, struct hlthunk_cs_out *out,
					uint32_t timeout)
{
	union hl_cs_args args;
	struct hl_cs_in *hl_in;
	struct hl_cs_out *hl_out;
	int rc;

	if (!in || !out)
		return -EINVAL;

	memset(&args, 0, sizeof(args));

	hl_in = &args.in;
	hl_in->chunks_restore = (__u64) (uintptr_t) in->chunks_restore;
	hl_in->chunks_execute = (__u64) (uintptr_t) in->chunks_execute;
	hl_in->num_chunks_restore = in->num_chunks_restore;
	hl_in->num_chunks_execute = in->num_chunks_execute;
	hl_in->cs_flags = in->flags;
	if (timeout) {
		hl_in->cs_flags |= HL_CS_FLAGS_CUSTOM_TIMEOUT;
		hl_in->timeout = timeout;
	}

	rc = hlthunk_ioctl(fd, HL_IOCTL_CS, &args);
	if (rc)
		return rc;

	hl_out = &args.out;
	out->seq = hl_out->seq;
	out->status = hl_out->status;

	return 0;
}

int hlthunk_command_submission_original(int fd, struct hlthunk_cs_in *in,
					struct hlthunk_cs_out *out)
{
	return _hlthunk_command_submission(fd, in, out, 0);
}

int hlthunk_command_submission_timeout_original(int fd, struct hlthunk_cs_in *in,
						struct hlthunk_cs_out *out, uint32_t timeout)
{
	return _hlthunk_command_submission(fd, in, out, timeout);
}

hlthunk_public int hlthunk_command_submission(int fd, struct hlthunk_cs_in *in,
					      struct hlthunk_cs_out *out)
{
	struct hlthunk_cs_out cs_info;
	int rc;

	rc = (*functions_pointers_table->fp_hlthunk_command_submission)(fd, in, &cs_info);

	if (rc)
		return rc;

	out->seq = cs_info.seq;
	out->status = cs_info.status;

	return 0;
}

hlthunk_public int hlthunk_command_submission_timeout(int fd, struct hlthunk_cs_in *in,
							struct hlthunk_cs_out *out,
							uint32_t timeout)
{
	struct hlthunk_cs_out cs_info;
	int rc;

	rc = (*functions_pointers_table->fp_hlthunk_command_submission_timeout)
				(fd, in, &cs_info, timeout);

	if (rc)
		return rc;

	out->seq = cs_info.seq;
	out->status = cs_info.status;

	return 0;
}

static int _hlthunk_staged_command_submission(int fd, uint64_t sequence, struct hlthunk_cs_in *in,
						struct hlthunk_cs_out *out, uint32_t timeout)
{
	union hl_cs_args args;
	struct hl_cs_in *hl_in;
	struct hl_cs_out *hl_out;
	int rc;

	if (!in || !out)
		return -EINVAL;

	if (!(in->flags & HL_CS_FLAGS_STAGED_SUBMISSION))
		return -EINVAL;

	memset(&args, 0, sizeof(args));

	hl_in = &args.in;
	hl_in->seq = sequence;
	hl_in->chunks_restore = (__u64) (uintptr_t) in->chunks_restore;
	hl_in->chunks_execute = (__u64) (uintptr_t) in->chunks_execute;
	hl_in->num_chunks_restore = in->num_chunks_restore;
	hl_in->num_chunks_execute = in->num_chunks_execute;
	hl_in->cs_flags = in->flags;
	if (timeout) {
		hl_in->cs_flags |= HL_CS_FLAGS_CUSTOM_TIMEOUT;
		hl_in->timeout = timeout;
	}

	rc = hlthunk_ioctl(fd, HL_IOCTL_CS, &args);
	if (rc)
		return rc;

	hl_out = &args.out;
	out->seq = hl_out->seq;
	out->status = hl_out->status;

	return 0;
}

int hlthunk_staged_command_submission_original(int fd, uint64_t sequence, struct hlthunk_cs_in *in,
						struct hlthunk_cs_out *out)
{
	return _hlthunk_staged_command_submission(fd, sequence, in, out, 0);
}

int hlthunk_staged_command_submission_timeout_original(int fd, uint64_t sequence,
							struct hlthunk_cs_in *in,
							struct hlthunk_cs_out *out,
							uint32_t timeout)
{
	return _hlthunk_staged_command_submission(fd, sequence, in, out, timeout);
}

hlthunk_public int hlthunk_staged_command_submission(int fd, uint64_t sequence,
							struct hlthunk_cs_in *in,
							struct hlthunk_cs_out *out)
{
	struct hlthunk_cs_out cs_info;
	int rc;

	rc = (*functions_pointers_table->fp_hlthunk_staged_command_submission)
								(fd, sequence, in, &cs_info);

	if (rc)
		return rc;

	out->seq = cs_info.seq;
	out->status = cs_info.status;

	return 0;

}

hlthunk_public int hlthunk_staged_command_submission_timeout(int fd, uint64_t sequence,
								struct hlthunk_cs_in *in,
								struct hlthunk_cs_out *out,
								uint32_t timeout)
{
	struct hlthunk_cs_out cs_info;
	int rc;

	rc = (*functions_pointers_table->fp_hlthunk_staged_cs_timeout)
							(fd, sequence, in, &cs_info, timeout);

	if (rc)
		return rc;

	out->seq = cs_info.seq;
	out->status = cs_info.status;

	return 0;

}

int hlthunk_reserve_encaps_signals_original(int fd, struct hlthunk_sig_res_in *in,
						struct hlthunk_sig_res_out *out)
{
	union hl_cs_args args;
	struct hl_cs_in *hl_in;
	struct hl_cs_out *hl_out;
	int rc;

	memset(&args, 0, sizeof(args));

	hl_in = &args.in;
	hl_in->encaps_signals_count = in->count;
	hl_in->encaps_signals_q_idx = in->queue_index;
	hl_in->num_chunks_execute = 1;
	hl_in->cs_flags |= HL_CS_FLAGS_RESERVE_SIGNALS_ONLY;

	rc = hlthunk_ioctl(fd, HL_IOCTL_CS, &args);
	if (rc)
		return rc;

	hl_out = &args.out;

	if (hl_out->status != HL_CS_STATUS_SUCCESS)
		return -EINVAL;

	hl_out = &args.out;
	out->handle.id = hl_out->handle_id;
	out->handle.sob_base_addr_offset = hl_out->sob_base_addr_offset;
	out->handle.count = hl_out->count;
	out->status = hl_out->status;

	return 0;
}

hlthunk_public int hlthunk_reserve_encaps_signals(int fd, struct hlthunk_sig_res_in *in,
							struct hlthunk_sig_res_out *out)
{
	return (*functions_pointers_table->fp_hlthunk_reserve_signals)(fd, in, out);
}

int hlthunk_unreserve_encaps_signals_original(int fd, struct reserve_sig_handle *handle,
						uint32_t *status)
{
	union hl_cs_args args;
	struct hl_cs_in *hl_in;
	struct hl_cs_out *hl_out;
	int rc;

	memset(&args, 0, sizeof(args));

	hl_in = &args.in;
	hl_in->encaps_sig_handle_id = handle->id;
	hl_in->num_chunks_execute = 1;
	hl_in->cs_flags |= HL_CS_FLAGS_UNRESERVE_SIGNALS_ONLY;

	rc = hlthunk_ioctl(fd, HL_IOCTL_CS, &args);
	if (rc)
		return rc;

	hl_out = &args.out;

	if (hl_out->status != HL_CS_STATUS_SUCCESS)
		return -EINVAL;

	hl_out = &args.out;
	*status = hl_out->status;

	return 0;
}

hlthunk_public int hlthunk_unreserve_encaps_signals(int fd, struct reserve_sig_handle *handle,
							uint32_t *status)
{
	return (*functions_pointers_table->fp_hlthunk_unreserve_signals)(fd, handle, status);
}

int hlthunk_staged_command_submission_encaps_signals_original(int fd, uint64_t handle_id,
								struct hlthunk_cs_in *in,
								struct hlthunk_cs_out *out)
{
	union hl_cs_args args;
	struct hl_cs_in *hl_in;
	struct hl_cs_out *hl_out;
	int rc;

	if (!(in->flags & HL_CS_FLAGS_STAGED_SUBMISSION))
		return -EINVAL;

	memset(&args, 0, sizeof(args));

	hl_in = &args.in;
	hl_in->encaps_sig_handle_id = (__u32)handle_id;
	hl_in->chunks_restore = (__u64) (uintptr_t) in->chunks_restore;
	hl_in->chunks_execute = (__u64) (uintptr_t) in->chunks_execute;
	hl_in->num_chunks_restore = in->num_chunks_restore;
	hl_in->num_chunks_execute = in->num_chunks_execute;
	hl_in->cs_flags = in->flags | HL_CS_FLAGS_ENCAP_SIGNALS;

	rc = hlthunk_ioctl(fd, HL_IOCTL_CS, &args);
	if (rc)
		return rc;

	hl_out = &args.out;
	out->seq = hl_out->seq;
	out->status = hl_out->status;
	out->sob_count_before_submission = hl_out->sob_count_before_submission;

	return 0;
}

hlthunk_public int hlthunk_staged_command_submission_encaps_signals(int fd, uint64_t handle_id,
									struct hlthunk_cs_in *in,
									struct hlthunk_cs_out *out)
{
	struct hlthunk_cs_out cs_info;
	int rc;

	rc = (*functions_pointers_table->fp_hlthunk_staged_cs_encaps_signals)
								(fd, handle_id, in, &cs_info);
	if (rc)
		return rc;

	out->seq = cs_info.seq;
	out->status = cs_info.status;
	out->sob_count_before_submission = cs_info.sob_count_before_submission;

	return 0;
}

int hlthunk_get_hw_block_original(int fd, uint64_t block_address, uint32_t *block_size,
					uint64_t *handle)
{
	union hl_mem_args ioctl_args;
	int rc;

	if (!block_size || !handle)
		return -EINVAL;

	memset(&ioctl_args, 0, sizeof(ioctl_args));
	ioctl_args.in.map_block.block_addr = block_address;
	ioctl_args.in.op = HL_MEM_OP_MAP_BLOCK;

	rc = hlthunk_ioctl(fd, HL_IOCTL_MEMORY, &ioctl_args);
	if (rc)
		return rc;

	*handle = ioctl_args.out.block_handle;
	*block_size = ioctl_args.out.block_size;

	return 0;
}

hlthunk_public int hlthunk_get_hw_block(int fd, uint64_t block_address, uint32_t *block_size,
					uint64_t *handle)
{
	return (*functions_pointers_table->fp_hlthunk_get_hw_block)(
				fd, block_address, block_size, handle);
}

static int _hlthunk_signal_submission(int fd, struct hlthunk_signal_in *in,
					struct hlthunk_signal_out *out, uint32_t timeout)
{
	union hl_cs_args args;
	struct hl_cs_chunk chunk_execute;
	struct hl_cs_in *hl_in;
	struct hl_cs_out *hl_out;
	int rc;

	if (!in || !out)
		return -EINVAL;

	memset(&args, 0, sizeof(args));
	memset(&chunk_execute, 0, sizeof(chunk_execute));
	chunk_execute.queue_index = in->queue_index;

	hl_in = &args.in;
	hl_in->chunks_restore = (__u64) (uintptr_t) in->chunks_restore;
	hl_in->num_chunks_restore = in->num_chunks_restore;
	hl_in->chunks_execute = (__u64) (uintptr_t) &chunk_execute;
	hl_in->num_chunks_execute = 1;
	hl_in->cs_flags = in->flags | HL_CS_FLAGS_SIGNAL;
	if (timeout) {
		hl_in->cs_flags |= HL_CS_FLAGS_CUSTOM_TIMEOUT;
		hl_in->timeout = timeout;
	}

	rc = hlthunk_ioctl(fd, HL_IOCTL_CS, &args);
	if (rc)
		return rc;

	hl_out = &args.out;

	if (hl_out->status != HL_CS_STATUS_SUCCESS)
		return -EINVAL;

	hl_out = &args.out;
	out->seq = hl_out->seq;
	out->status = hl_out->status;
	out->sob_base_addr_offset = hl_out->sob_base_addr_offset;
	out->sob_count_before_submission = hl_out->sob_count_before_submission;

	return 0;
}

int hlthunk_signal_submission_original(int fd, struct hlthunk_signal_in *in,
					struct hlthunk_signal_out *out)
{
	return _hlthunk_signal_submission(fd, in, out, 0);
}

int hlthunk_signal_submission_timeout_original(int fd, struct hlthunk_signal_in *in,
						struct hlthunk_signal_out *out, uint32_t timeout)
{
	return _hlthunk_signal_submission(fd, in, out, timeout);
}

hlthunk_public int hlthunk_signal_submission(int fd, struct hlthunk_signal_in *in,
						struct hlthunk_signal_out *out)
{
	struct hlthunk_signal_out signal_info;
	int rc;

	rc = (*functions_pointers_table->fp_hlthunk_signal_submission)(fd, in, &signal_info);
	if (rc)
		return rc;

	out->seq = signal_info.seq;
	out->status = signal_info.status;
	out->sob_base_addr_offset = signal_info.sob_base_addr_offset;
	out->sob_count_before_submission = signal_info.sob_count_before_submission;

	return 0;
}

hlthunk_public int hlthunk_signal_submission_timeout(int fd, struct hlthunk_signal_in *in,
							struct hlthunk_signal_out *out,
							uint32_t timeout)
{
	struct hlthunk_signal_out signal_info;
	int rc;

	rc = (*functions_pointers_table->fp_hlthunk_signal_submission_timeout)(fd, in,
									&signal_info, timeout);
	if (rc)
		return rc;

	out->seq = signal_info.seq;
	out->status = signal_info.status;
	out->sob_base_addr_offset = signal_info.sob_base_addr_offset;
	out->sob_count_before_submission = signal_info.sob_count_before_submission;

	return 0;
}

static int _hlthunk_wait_for_signal(int fd, struct hlthunk_wait_in *in,
					struct hlthunk_wait_out *out, uint32_t timeout,
					bool encaps_signals)
{
	union hl_cs_args args;
	struct hl_cs_chunk chunk_execute;
	struct hlthunk_wait_for_signal_data *wait_for_signal;
	struct hl_cs_in *hl_in;
	struct hl_cs_out *hl_out;
	int rc;

	if (!in || !out)
		return -EINVAL;

	if (in->num_wait_for_signal != 1)
		return -EINVAL;

	wait_for_signal =
		(struct hlthunk_wait_for_signal_data *) in->hlthunk_wait_for_signal;

	if (wait_for_signal->signal_seq_nr != 1)
		return -EINVAL;

	memset(&args, 0, sizeof(args));
	memset(&chunk_execute, 0, sizeof(chunk_execute));
	chunk_execute.queue_index = wait_for_signal->queue_index;

	if (encaps_signals) {
		chunk_execute.encaps_signal_offset = wait_for_signal->encaps_signal_offset;
		chunk_execute.encaps_signal_seq = wait_for_signal->encaps_signal_seq;
	} else {
		chunk_execute.signal_seq_arr = (__u64) (uintptr_t) wait_for_signal->signal_seq_arr;
		chunk_execute.num_signal_seq_arr = 1;
	}

	hl_in = &args.in;
	hl_in->chunks_restore = (__u64) (uintptr_t) in->chunks_restore;
	hl_in->num_chunks_restore = in->num_chunks_restore;
	hl_in->chunks_execute = (__u64) (uintptr_t) &chunk_execute;
	hl_in->num_chunks_execute = 1;
	hl_in->cs_flags = in->flags | HL_CS_FLAGS_WAIT;

	if (encaps_signals)
		hl_in->cs_flags |= HL_CS_FLAGS_ENCAP_SIGNALS;

	if (timeout) {
		hl_in->cs_flags |= HL_CS_FLAGS_CUSTOM_TIMEOUT;
		hl_in->timeout = timeout;
	}

	rc = hlthunk_ioctl(fd, HL_IOCTL_CS, &args);
	if (rc)
		return rc;

	hl_out = &args.out;

	if (hl_out->status != HL_CS_STATUS_SUCCESS)
		return -EINVAL;

	hl_out = &args.out;
	out->seq = hl_out->seq;
	out->status = hl_out->status;

	return 0;
}

int hlthunk_wait_for_signal_original(int fd, struct hlthunk_wait_in *in,
					struct hlthunk_wait_out *out)
{
	return _hlthunk_wait_for_signal(fd, in, out, 0, false);
}

int hlthunk_wait_for_signal_timeout_original(int fd, struct hlthunk_wait_in *in,
						struct hlthunk_wait_out *out, uint32_t timeout)
{
	return _hlthunk_wait_for_signal(fd, in, out, timeout, false);
}

hlthunk_public int hlthunk_wait_for_signal(int fd, struct hlthunk_wait_in *in,
						struct hlthunk_wait_out *out)
{
	return (*functions_pointers_table->fp_hlthunk_wait_for_signal)(fd, in, out);
}

hlthunk_public int hlthunk_wait_for_signal_timeout(int fd, struct hlthunk_wait_in *in,
						struct hlthunk_wait_out *out, uint32_t timeout)
{
	return (*functions_pointers_table->fp_hlthunk_wait_for_signal_timeout)(
									fd, in, out, timeout);
}

static int _hlthunk_wait_for_collective_signal(int fd, struct hlthunk_wait_in *in,
						struct hlthunk_wait_out *out, uint32_t timeout,
						bool encaps_signals)
{
	union hl_cs_args args;
	struct hl_cs_chunk chunk_execute;
	struct hlthunk_wait_for_signal_data *wait_for_signal;
	struct hl_cs_in *hl_in;
	struct hl_cs_out *hl_out;
	int rc;

	if (!in || !out)
		return -EINVAL;

	if (in->num_wait_for_signal != 1)
		return -EINVAL;

	wait_for_signal =
		(struct hlthunk_wait_for_signal_data *) in->hlthunk_wait_for_signal;

	if (wait_for_signal->signal_seq_nr != 1)
		return -EINVAL;

	memset(&args, 0, sizeof(args));
	memset(&chunk_execute, 0, sizeof(chunk_execute));
	chunk_execute.queue_index = wait_for_signal->queue_index;

	if (encaps_signals) {
		chunk_execute.encaps_signal_offset = wait_for_signal->encaps_signal_offset;
		chunk_execute.encaps_signal_seq = wait_for_signal->encaps_signal_seq;
	} else {
		chunk_execute.signal_seq_arr = (__u64) (uintptr_t) wait_for_signal->signal_seq_arr;
		chunk_execute.num_signal_seq_arr = 1;
	}

	chunk_execute.collective_engine_id = wait_for_signal->collective_engine_id;

	hl_in = &args.in;
	hl_in->chunks_restore = (__u64) (uintptr_t) in->chunks_restore;
	hl_in->num_chunks_restore = in->num_chunks_restore;
	hl_in->chunks_execute = (__u64) (uintptr_t) &chunk_execute;
	hl_in->num_chunks_execute = 1;
	hl_in->cs_flags = in->flags | HL_CS_FLAGS_COLLECTIVE_WAIT;

	if (encaps_signals)
		hl_in->cs_flags |= HL_CS_FLAGS_ENCAP_SIGNALS;

	if (timeout) {
		hl_in->cs_flags |= HL_CS_FLAGS_CUSTOM_TIMEOUT;
		hl_in->timeout = timeout;
	}

	rc = hlthunk_ioctl(fd, HL_IOCTL_CS, &args);
	if (rc)
		return rc;

	hl_out = &args.out;

	if (hl_out->status != HL_CS_STATUS_SUCCESS)
		return -EINVAL;

	hl_out = &args.out;
	out->seq = hl_out->seq;
	out->status = hl_out->status;

	return 0;
}

int hlthunk_wait_for_collective_signal_original(int fd, struct hlthunk_wait_in *in,
						struct hlthunk_wait_out *out)
{
	return _hlthunk_wait_for_collective_signal(fd, in, out, 0, false);
}

int hlthunk_wait_for_collective_signal_timeout_original(int fd, struct hlthunk_wait_in *in,
						struct hlthunk_wait_out *out, uint32_t timeout)
{
	return _hlthunk_wait_for_collective_signal(fd, in, out, timeout, false);
}

hlthunk_public int hlthunk_wait_for_collective_signal(int fd, struct hlthunk_wait_in *in,
							struct hlthunk_wait_out *out)
{
	return (*functions_pointers_table->fp_hlthunk_wait_for_collective_sig)(fd, in, out);
}

hlthunk_public int hlthunk_wait_for_collective_signal_timeout(int fd, struct hlthunk_wait_in *in,
								struct hlthunk_wait_out *out,
								uint32_t timeout)
{
	return
	(*functions_pointers_table->fp_hlthunk_wait_for_collective_sig_timeout)
		(fd, in, out, timeout);
}

hlthunk_public int hlthunk_wait_for_cs(int fd, uint64_t seq, uint64_t timeout_us, uint32_t *status)
{
	union hl_wait_cs_args args;
	struct hl_wait_cs_in *hl_in;
	struct hl_wait_cs_out *hl_out;
	int rc;

	if (!status)
		return -EINVAL;

	memset(&args, 0, sizeof(args));

	hl_in = &args.in;
	hl_in->seq = seq;
	hl_in->timeout_us = timeout_us;

	rc = hlthunk_ioctl(fd, HL_IOCTL_WAIT_CS, &args);

	hl_out = &args.out;
	*status = hl_out->status;

	return rc;
}

hlthunk_public int hlthunk_wait_for_cs_with_timestamp(int fd, uint64_t seq, uint64_t timeout_us,
							uint32_t *status, uint64_t *timestamp)
{
	union hl_wait_cs_args args;
	struct hl_wait_cs_in *hl_in;
	struct hl_wait_cs_out *hl_out;
	int rc;

	if (!status || !timestamp)
		return -EINVAL;

	memset(&args, 0, sizeof(args));

	hl_in = &args.in;
	hl_in->seq = seq;
	hl_in->timeout_us = timeout_us;

	rc = hlthunk_ioctl(fd, HL_IOCTL_WAIT_CS, &args);

	hl_out = &args.out;
	*status = hl_out->status;

	if (hl_out->flags & HL_WAIT_CS_STATUS_FLAG_TIMESTAMP_VLD)
		*timestamp = hl_out->timestamp_nsec;

	return rc;
}

static int hlthunk_wait_for_multi_cs_common(int fd, union hl_wait_cs_args *args,
					struct hlthunk_wait_multi_cs_in *in,
					struct hlthunk_wait_multi_cs_out *out)
{
	struct hl_wait_cs_in *hl_in;
	struct hl_wait_cs_out *hl_out;
	int rc;

	if (!in || !out)
		return -EINVAL;

	memset(args, 0, sizeof(*args));

	hl_in = &args->in;
	hl_in->seq = (__u64) (uintptr_t) in->seq;
	hl_in->seq_arr_len = in->seq_len;
	hl_in->timeout_us = in->timeout_us;
	hl_in->flags = HL_WAIT_CS_FLAGS_MULTI_CS;

	rc = hlthunk_ioctl(fd, HL_IOCTL_WAIT_CS, args);

	hl_out = &args->out;
	out->status = hl_out->status;
	if (!rc) {
		out->seq_set = hl_out->cs_completion_map;
		out->completed = (uint32_t)__builtin_popcountll(hl_out->cs_completion_map);
	}

	return rc;
}

hlthunk_public int hlthunk_wait_for_multi_cs(int fd, struct hlthunk_wait_multi_cs_in *in,
						struct hlthunk_wait_multi_cs_out *out)
{
	union hl_wait_cs_args args;

	return hlthunk_wait_for_multi_cs_common(fd, &args, in, out);
}

hlthunk_public int hlthunk_wait_for_multi_cs_with_timestamp(int fd,
							struct hlthunk_wait_multi_cs_in *in,
							struct hlthunk_wait_multi_cs_out *out,
							uint64_t *timestamp)
{
	union hl_wait_cs_args args;
	int rc;

	if (!timestamp)
		return -EINVAL;

	*timestamp = 0;

	rc = hlthunk_wait_for_multi_cs_common(fd, &args, in, out);

	if (args.out.flags & HL_WAIT_CS_STATUS_FLAG_TIMESTAMP_VLD)
		*timestamp = args.out.timestamp_nsec;

	return rc;
}

int hlthunk_wait_for_reserved_encaps_signals_original(int fd, struct hlthunk_wait_in *in,
							struct hlthunk_wait_out *out)
{
	return _hlthunk_wait_for_signal(fd, in, out, 0, true);
}

hlthunk_public int hlthunk_wait_for_reserved_encaps_signals(int fd, struct hlthunk_wait_in *in,
								struct hlthunk_wait_out *out)
{
	struct hlthunk_functions_pointers *fp = functions_pointers_table;

	return (*fp->fp_hlthunk_wait_for_reserved_encaps_signals)(fd, in, out);
}

int hlthunk_wait_for_reserved_encaps_collective_signals_original(int fd, struct hlthunk_wait_in *in,
								struct hlthunk_wait_out *out)
{
	return _hlthunk_wait_for_collective_signal(fd, in, out, 0, true);
}

hlthunk_public int hlthunk_wait_for_reserved_encaps_collective_signals(int fd,
								struct hlthunk_wait_in *in,
								struct hlthunk_wait_out *out)
{
	struct hlthunk_functions_pointers *fp = functions_pointers_table;

	return (*fp->fp_hlthunk_wait_for_collective_reserved_encap_sig)(fd, in, out);
}

hlthunk_public int hlthunk_wait_for_interrupt_by_handle_with_timestamp(int fd,
					uint64_t cq_counters_handle,
					uint64_t cq_counters_offset,
					uint64_t target_value,
					uint32_t interrupt_id,
					uint64_t timeout_us,
					uint32_t *status,
					uint64_t *timestamp)
{
	union hl_wait_cs_args args;
	struct hl_wait_cs_in *hl_in;
	struct hl_wait_cs_out *hl_out;
	int rc;

	if (!status)
		return -EINVAL;

	memset(&args, 0, sizeof(args));

	hl_in = &args.in;
	hl_in->cq_counters_handle = cq_counters_handle;
	hl_in->cq_counters_offset = cq_counters_offset;
	hl_in->target = target_value;
	hl_in->interrupt_timeout_us = timeout_us;
	hl_in->flags = HL_WAIT_CS_FLAGS_INTERRUPT | HL_WAIT_CS_FLAGS_INTERRUPT_KERNEL_CQ;

	if (interrupt_id == UINT_MAX)
		hl_in->flags |= HL_WAIT_CS_FLAGS_INTERRUPT_MASK;
	else
		hl_in->flags |= interrupt_id << __builtin_ctz(HL_WAIT_CS_FLAGS_INTERRUPT_MASK);

	rc = hlthunk_ioctl(fd, HL_IOCTL_WAIT_CS, &args);

	hl_out = &args.out;
	*status = hl_out->status;

	if (timestamp && hl_out->flags & HL_WAIT_CS_STATUS_FLAG_TIMESTAMP_VLD)
		*timestamp = hl_out->timestamp_nsec;

	return rc;
}

hlthunk_public int hlthunk_wait_for_interrupt_with_timestamp(int fd,
					void *addr,
					uint64_t target_value,
					uint32_t interrupt_id,
					uint64_t timeout_us,
					uint32_t *status,
					uint64_t *timestamp)
{
	union hl_wait_cs_args args;
	struct hl_wait_cs_in *hl_in;
	struct hl_wait_cs_out *hl_out;
	int rc;

	if (!addr || !status)
		return -EINVAL;

	memset(&args, 0, sizeof(args));

	hl_in = &args.in;
	hl_in->addr = (uint64_t) addr;
	hl_in->target = target_value;
	hl_in->interrupt_timeout_us = timeout_us;
	hl_in->flags = HL_WAIT_CS_FLAGS_INTERRUPT;

	if (interrupt_id == UINT_MAX)
		hl_in->flags |= HL_WAIT_CS_FLAGS_INTERRUPT_MASK;
	else
		hl_in->flags |= interrupt_id << __builtin_ctz(HL_WAIT_CS_FLAGS_INTERRUPT_MASK);

	rc = hlthunk_ioctl(fd, HL_IOCTL_WAIT_CS, &args);

	hl_out = &args.out;
	*status = hl_out->status;

	if (timestamp && hl_out->flags & HL_WAIT_CS_STATUS_FLAG_TIMESTAMP_VLD)
		*timestamp = hl_out->timestamp_nsec;

	return rc;
}

hlthunk_public int hlthunk_register_timestamp_interrupt(int fd, uint32_t interrupt_id,
						uint64_t cq_counters_handle,
						uint64_t cq_counters_offset,
						uint64_t target_value,
						uint64_t timestamp_handle,
						uint64_t timestamp_offset)
{
	union hl_wait_cs_args args;
	struct hl_wait_cs_in *hl_in;
	struct hl_wait_cs_out *hl_out;
	int rc;

	memset(&args, 0, sizeof(args));

	hl_in = &args.in;
	hl_in->cq_counters_handle = cq_counters_handle;
	hl_in->cq_counters_offset = cq_counters_offset;
	hl_in->target = target_value;
	hl_in->timestamp_handle = timestamp_handle;
	hl_in->timestamp_offset = timestamp_offset;
	hl_in->interrupt_timeout_us = 0xff; /* anything != 0 */

	hl_in->flags =  HL_WAIT_CS_FLAGS_INTERRUPT |
		HL_WAIT_CS_FLAGS_INTERRUPT_KERNEL_CQ |
		HL_WAIT_CS_FLAGS_REGISTER_INTERRUPT;

	if (interrupt_id == UINT_MAX)
		hl_in->flags |= HL_WAIT_CS_FLAGS_INTERRUPT_MASK;
	else
		hl_in->flags |= interrupt_id << __builtin_ctz(HL_WAIT_CS_FLAGS_INTERRUPT_MASK);

	rc = hlthunk_ioctl(fd, HL_IOCTL_WAIT_CS, &args);

	hl_out = &args.out;

	return rc;
}

hlthunk_public int hlthunk_wait_for_interrupt_by_handle(int fd, uint64_t cq_counters_handle,
						uint64_t cq_counters_offset, uint64_t target_value,
						uint32_t interrupt_id, uint64_t timeout_us,
						uint32_t *status)
{
	return hlthunk_wait_for_interrupt_by_handle_with_timestamp(fd, cq_counters_handle,
			cq_counters_offset, target_value, interrupt_id, timeout_us, status, NULL);
}

hlthunk_public int hlthunk_wait_for_interrupt(int fd, void *addr, uint64_t target_value,
						uint32_t interrupt_id, uint64_t timeout_us,
						uint32_t *status)
{
	return hlthunk_wait_for_interrupt_with_timestamp(
		fd, addr, target_value, interrupt_id, timeout_us, status, NULL);
}

hlthunk_public uint32_t hlthunk_get_device_id_from_fd(int fd)
{
	struct hlthunk_hw_ip_info hw_ip;

	memset(&hw_ip, 0, sizeof(hw_ip));
	if (hlthunk_get_hw_ip_info(fd, &hw_ip))
		return PCI_IDS_INVALID;

	return hw_ip.device_id;
}

hlthunk_public int hlthunk_get_info(int fd, struct hl_info_args *info)
{
	return hlthunk_ioctl(fd, HL_IOCTL_INFO, info);
}

hlthunk_public uint64_t hlthunk_device_memory_alloc(int fd, uint64_t size, uint64_t page_size,
							bool contiguous, bool shared)
{
	union hl_mem_args ioctl_args;
	int rc;

	memset(&ioctl_args, 0, sizeof(ioctl_args));

	ioctl_args.in.alloc.mem_size = size;
	ioctl_args.in.alloc.page_size = page_size;
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

hlthunk_public int hlthunk_device_memory_free(int fd, uint64_t handle)
{
	union hl_mem_args ioctl_args;

	memset(&ioctl_args, 0, sizeof(ioctl_args));
	ioctl_args.in.free.handle = handle;
	ioctl_args.in.op = HL_MEM_OP_FREE;

	return hlthunk_ioctl(fd, HL_IOCTL_MEMORY, &ioctl_args);
}

hlthunk_public uint64_t hlthunk_device_memory_map(int fd, uint64_t handle, uint64_t hint_addr)
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

uint64_t hlthunk_host_memory_map_original(int fd, void *host_virt_addr,
							uint64_t hint_addr, uint64_t host_size)
{
	return hlthunk_host_memory_map_flags(fd, host_virt_addr, hint_addr, host_size, 0);
}

hlthunk_public uint64_t hlthunk_host_memory_map(int fd, void *host_virt_addr, uint64_t hint_addr,
						uint64_t host_size)
{
	return (*functions_pointers_table->fp_hlthunk_host_memory_map)(
						fd, host_virt_addr, hint_addr, host_size);
}

uint64_t hlthunk_host_memory_map_flags_original(int fd, void *host_virt_addr, uint64_t hint_addr,
						uint64_t host_size, uint32_t flags)
{
	union hl_mem_args ioctl_args;
	int rc;

	memset(&ioctl_args, 0, sizeof(ioctl_args));
	ioctl_args.in.map_host.host_virt_addr = (uint64_t) host_virt_addr;
	ioctl_args.in.map_host.mem_size = host_size;
	ioctl_args.in.map_host.hint_addr = hint_addr;
	ioctl_args.in.flags = flags | HL_MEM_USERPTR;
	ioctl_args.in.op = HL_MEM_OP_MAP;

	rc = hlthunk_ioctl(fd, HL_IOCTL_MEMORY, &ioctl_args);
	if (rc)
		return 0;

	return ioctl_args.out.device_virt_addr;
}

hlthunk_public uint64_t hlthunk_host_memory_map_flags(int fd, void *host_virt_addr,
							uint64_t hint_addr, uint64_t host_size,
							uint32_t flags)
{
	return (*functions_pointers_table->fp_hlthunk_host_memory_map_flags)(
			fd, host_virt_addr, hint_addr, host_size, flags);
}

int hlthunk_memory_unmap_original(int fd, uint64_t device_virt_addr)
{
	union hl_mem_args ioctl_args;

	memset(&ioctl_args, 0, sizeof(ioctl_args));
	ioctl_args.in.unmap.device_virt_addr = device_virt_addr;
	ioctl_args.in.op = HL_MEM_OP_UNMAP;

	return hlthunk_ioctl(fd, HL_IOCTL_MEMORY, &ioctl_args);
}

hlthunk_public int hlthunk_memory_unmap(int fd, uint64_t device_virt_addr)
{
	return (*functions_pointers_table->fp_hlthunk_memory_unmap)(fd, device_virt_addr);
}

hlthunk_public int hlthunk_device_memory_export_dmabuf_fd(int fd, uint64_t handle, uint64_t size,
								uint32_t flags)
{
	union hl_mem_args ioctl_args;
	int rc;

	memset(&ioctl_args, 0, sizeof(ioctl_args));
	ioctl_args.in.export_dmabuf_fd.handle = handle;
	ioctl_args.in.export_dmabuf_fd.mem_size = size;
	ioctl_args.in.flags = O_RDWR | O_CLOEXEC;
	ioctl_args.in.op = HL_MEM_OP_EXPORT_DMABUF_FD;

	rc = hlthunk_ioctl(fd, HL_IOCTL_MEMORY, &ioctl_args);
	if (rc)
		return rc;

	return ioctl_args.out.fd;
}

hlthunk_public int hlthunk_allocate_timestamp_elements(int fd, uint32_t num_elements,
							uint64_t *handle)
{
	union hl_mem_args ioctl_args;
	int rc;

	memset(&ioctl_args, 0, sizeof(ioctl_args));
	ioctl_args.in.num_of_elements = num_elements;
	ioctl_args.in.op = HL_MEM_OP_TS_ALLOC;

	rc = hlthunk_ioctl(fd, HL_IOCTL_MEMORY, &ioctl_args);

	*handle = ioctl_args.out.handle;

	return rc;
}

hlthunk_public int hlthunk_debug(int fd, struct hl_debug_args *debug)
{
	return hlthunk_ioctl(fd, HL_IOCTL_DEBUG, debug);
}

hlthunk_public int hlthunk_get_event_record(int fd, enum hlthunk_event_record_id event_id,
						void *buf)
{
	struct hlthunk_event_record_open_dev_time *open_dev_time_buf = buf;
	struct hlthunk_event_record_cs_timeout *cs_timeout_buf = buf;
	struct hlthunk_event_record_razwi_event *razwi_buf = buf;
	struct hlthunk_event_record_undefined_opcode *undef_opcode_buf = buf;
	struct hl_info_last_err_open_dev_time open_dev_time;
	struct hl_info_cs_timeout_event cs_timeout;
	struct hl_info_razwi_event razwi;
	struct hl_info_undefined_opcode_event undef_opcode;
	struct hl_info_args args;
	int rc;

	if (!buf)
		return -EINVAL;

	memset(&args, 0, sizeof(args));

	switch (event_id) {
	case HLTHUNK_OPEN_DEV:
		memset(&open_dev_time, 0, sizeof(open_dev_time));
		args.op = HL_INFO_LAST_ERR_OPEN_DEV_TIME;
		args.return_pointer = (__u64) (uintptr_t) &open_dev_time;
		args.return_size = sizeof(open_dev_time);
		break;
	case HLTHUNK_CS_TIMEOUT:
		memset(&cs_timeout, 0, sizeof(cs_timeout));
		args.op = HL_INFO_CS_TIMEOUT_EVENT;
		args.return_pointer = (__u64) (uintptr_t) &cs_timeout;
		args.return_size = sizeof(cs_timeout);
		break;
	case HLTHUNK_RAZWI_EVENT:
		memset(&razwi, 0, sizeof(razwi));
		args.op = HL_INFO_RAZWI_EVENT;
		args.return_pointer = (__u64) (uintptr_t) &razwi;
		args.return_size = sizeof(razwi);
		break;
	case HLTHUNK_UNDEFINED_OPCODE:
		memset(&undef_opcode, 0, sizeof(undef_opcode));
		args.op = HL_INFO_UNDEFINED_OPCODE_EVENT;
		args.return_pointer = (__u64) (uintptr_t) &undef_opcode;
		args.return_size = sizeof(undef_opcode);
		break;
	default:
		return -EINVAL;
	}

	rc = hlthunk_ioctl(fd, HL_IOCTL_INFO, &args);
	if (rc)
		return rc;

	switch (event_id) {
	case HLTHUNK_OPEN_DEV:
		open_dev_time_buf->timestamp = open_dev_time.timestamp;
		break;
	case HLTHUNK_CS_TIMEOUT:
		cs_timeout_buf->timestamp = cs_timeout.timestamp;
		cs_timeout_buf->seq = cs_timeout.seq;
		break;
	case HLTHUNK_RAZWI_EVENT:
		razwi_buf->timestamp = razwi.timestamp;
		razwi_buf->addr = razwi.addr;
		razwi_buf->engine_id_1 = razwi.engine_id_1;
		razwi_buf->engine_id_2 = razwi.engine_id_2;
		razwi_buf->no_engine_id = razwi.no_engine_id;
		razwi_buf->error_type = razwi.error_type;
		break;
	case HLTHUNK_UNDEFINED_OPCODE:
		undef_opcode_buf->timestamp = undef_opcode.timestamp;
		undef_opcode_buf->engine_id = undef_opcode.engine_id;
		undef_opcode_buf->stream_id = undef_opcode.stream_id;
		undef_opcode_buf->cb_addr_streams_len = undef_opcode.cb_addr_streams_len;
		undef_opcode_buf->cq_addr = undef_opcode.cq_addr;
		undef_opcode_buf->cq_size = undef_opcode.cq_size;
		memcpy(undef_opcode_buf->cb_addr_streams, undef_opcode.cb_addr_streams,
					sizeof(undef_opcode_buf->cb_addr_streams));
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

hlthunk_public char *hlthunk_get_version(void)
{
	char *version;

	version = hlthunk_malloc(128);
	if (!version)
		return NULL;

	snprintf(version, 127, "%d.%d.%d-%s", HL_DRIVER_MAJOR, HL_DRIVER_MINOR,
		HL_DRIVER_PATCHLEVEL, HLTHUNK_SHA1_VERSION);

	return version;
}

int hlthunk_profiler_start_original(int fd)
{
	return -1;
}

hlthunk_public int hlthunk_profiler_start(int fd)
{
	return (*functions_pointers_table->fp_hlthunk_profiler_start)(fd);
}

int hlthunk_profiler_stop_original(int fd)
{
	return -1;
}

hlthunk_public int hlthunk_profiler_stop(int fd)
{
	return (*functions_pointers_table->fp_hlthunk_profiler_stop)(fd);
}

int hlthunk_profiler_get_trace_original(int fd, void *buffer, uint64_t *size, uint64_t *num_entries)
{
	return -1;
}

hlthunk_public int hlthunk_profiler_get_trace(int fd, void *buffer, uint64_t *size,
						uint64_t *num_entries)
{
	return (*functions_pointers_table->fp_hlthunk_profiler_get_trace)(
				fd, buffer, size, num_entries);
}

void hlthunk_profiler_destroy_original(void)
{
	pthread_mutex_lock(&global_members.profiler_init_lock);

	global_members.is_profiler_checked = false;
	functions_pointers_table = &default_functions_pointers_table;

	if (global_members.shared_object_handle != NULL) {
		if (global_members.pfn_shim_finish != NULL)
			global_members.pfn_shim_finish(SHIM_API_HLTHUNK);
		dlclose(global_members.shared_object_handle);
		global_members.shared_object_handle = NULL;
	}

	pthread_mutex_unlock(&global_members.profiler_init_lock);
}

hlthunk_public void hlthunk_profiler_destroy(void)
{
	(*functions_pointers_table->fp_hlthunk_profiler_destroy)();
}

hlthunk_public int hlthunk_debugfs_open(int fd, struct hlthunk_debugfs *debugfs)
{
	char pci_bus_id[13];
	char *path;
	char clk_gate_str[16] = "0";
	ssize_t size;
	int device_idx, rc = 0;
	int clk_gate_fd = -1, debugfs_addr_fd = -1, debugfs_data_fd = -1;

	rc = hlthunk_get_pci_bus_id_from_fd(fd, pci_bus_id, sizeof(pci_bus_id));
	if (rc)
		return -ENODEV;

	device_idx = hlthunk_get_device_index_from_pci_bus_id(pci_bus_id);
	if (device_idx < 0)
		return -ENODEV;

	path = hlthunk_malloc(PATH_MAX);
	if (!path)
		return -ENOMEM;

	snprintf(path, PATH_MAX, "//sys/kernel/debug/habanalabs/hl%d/addr", device_idx);

	debugfs_addr_fd = open(path, O_WRONLY);
	if (debugfs_addr_fd == -1) {
		rc = -EPERM;
		goto err_exit;
	}

	snprintf(path, PATH_MAX, "//sys/kernel/debug/habanalabs/hl%d/data32", device_idx);

	debugfs_data_fd = open(path, O_RDWR);

	if (debugfs_data_fd == -1) {
		rc = -EPERM;
		goto err_exit;
	}

	snprintf(path, PATH_MAX, "//sys/kernel/debug/habanalabs/hl%d/clk_gate", device_idx);

	clk_gate_fd = open(path, O_RDWR);

	if (clk_gate_fd == -1) {
		rc = -EPERM;
		goto err_exit;
	}

	debugfs->addr_fd = debugfs_addr_fd;
	debugfs->data_fd = debugfs_data_fd;
	debugfs->clk_gate_fd = clk_gate_fd;

	size = pread(debugfs->clk_gate_fd, debugfs->clk_gate_val, sizeof(debugfs->clk_gate_val), 0);
	if (size < 0) {
		rc = -EIO;
		goto err_exit;
	}

	size = write(debugfs->clk_gate_fd, clk_gate_str, strlen(clk_gate_str) + 1);
	if (size < 0) {
		rc = -EIO;
		goto err_exit;
	}

	hlthunk_free(path);
	return 0;

err_exit:
	if (debugfs_addr_fd != -1)
		close(debugfs_addr_fd);

	if (debugfs_data_fd != -1)
		close(debugfs_data_fd);

	hlthunk_free(path);
	return rc;
}

hlthunk_public int hlthunk_debugfs_read(struct hlthunk_debugfs *debugfs, uint64_t full_address,
					uint32_t *val)
{
	char addr_str[64] = "", value[64] = "";
	ssize_t size;

	sprintf(addr_str, "0x%lx", full_address);

	size = write(debugfs->addr_fd, addr_str, strlen(addr_str) + 1);
	if (size < 0)
		return -errno;

	size = pread(debugfs->data_fd, value, sizeof(value), 0);
	if (size < 0)
		return -errno;

	*val = strtoul(value, NULL, 16);
	return 0;
}

hlthunk_public int hlthunk_debugfs_write(struct hlthunk_debugfs *debugfs, uint64_t full_address,
						uint32_t val)
{
	char addr_str[64] = "", val_str[64] = "";
	ssize_t size;

	sprintf(addr_str, "0x%lx", full_address);
	sprintf(val_str, "0x%x", val);

	size = write(debugfs->addr_fd, addr_str, strlen(addr_str) + 1);
	if (size < 0)
		return -errno;

	size = write(debugfs->data_fd, val_str, strlen(val_str) + 1);
	if (size < 0)
		return -errno;

	return 0;
}

hlthunk_public int hlthunk_debugfs_close(struct hlthunk_debugfs *debugfs)
{
	ssize_t size;
	int rc = 0;

	if (debugfs->addr_fd != -1)
		close(debugfs->addr_fd);

	if (debugfs->data_fd != -1)
		close(debugfs->data_fd);

	if (debugfs->clk_gate_fd != -1) {
		size = write(debugfs->clk_gate_fd, debugfs->clk_gate_val,
					strlen(debugfs->clk_gate_val) + 1);
		if (size < 0)
			rc = -EIO;

		close(debugfs->clk_gate_fd);
	}

	return rc;
}

hlthunk_public int hlthunk_deprecated_func1(int fd, uint64_t seq, uint64_t timeout_us,
						uint32_t *status, uint64_t *timestamp)
{
	return -EPERM;
}

hlthunk_public int hlthunk_notifier_create(int fd)
{
	struct hl_info_args args;
	int handle, rc, flags = 0;

	flags |= EFD_CLOEXEC;
	handle = eventfd(0, flags);

	if (handle == -1)
		return -errno;

	memset(&args, 0, sizeof(args));
	args.eventfd = handle;
	args.op = HL_INFO_REGISTER_EVENTFD;
	rc = hlthunk_ioctl(fd, HL_IOCTL_INFO, &args);
	if (rc) {
		close(handle);
		return rc;
	}

	return handle;
}

hlthunk_public int hlthunk_notifier_release(int fd, int handle)
{
	struct hl_info_args args;
	int rc;

	memset(&args, 0, sizeof(args));

	args.eventfd = handle;
	args.op = HL_INFO_UNREGISTER_EVENTFD;
	rc = hlthunk_ioctl(fd, HL_IOCTL_INFO, &args);
	if (rc)
		return rc;

	rc = close(handle);
	if (rc)
		return -errno;

	return 0;
}

hlthunk_public int hlthunk_notifier_recv(int fd, int handle, uint64_t *notifier_events,
				uint64_t *notifier_cnt, uint32_t flags, uint32_t timeout)
{
	int rc;
	uint64_t cnt;
	struct hl_info_args args;
	struct pollfd pollfds;

	if (!notifier_events || !notifier_cnt)
		return -EINVAL;

	*notifier_cnt = 0;

	memset(&pollfds, 0, sizeof(pollfds));
	pollfds.fd = handle;
	pollfds.events |= POLLIN;
	rc = poll(&pollfds, 1, timeout);
	if (rc < 0)
		return -errno;

	if (rc == 0)
		return 0;

	rc = read(handle, &cnt, sizeof(cnt));

       /* always expect 8-bytes */
	if (rc != sizeof(cnt))
		return -1;

	/* read the events map */
	memset(&args, 0, sizeof(args));
	args.op = HL_INFO_GET_EVENTS;
	args.return_pointer = (__u64) (uintptr_t) notifier_events;
	args.return_size    = sizeof(*notifier_events);
	rc = hlthunk_ioctl(fd, HL_IOCTL_INFO, &args);
	if (rc)
		return rc;

	*notifier_cnt = cnt;
	return 0;
}
