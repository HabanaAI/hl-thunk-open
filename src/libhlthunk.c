// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "libhlthunk.h"
#include "specs/common/pci_ids.h"

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
#include <sys/stat.h>
#include <sys/sysmacros.h>

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
struct hlthunk_functions_pointers functions_pointers_table =
	INIT_FUNCS_POINTERS_TABLE;

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
		printf("No device for the given PCI address %s\n", busid);
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
	case PCI_IDS_GAUDI:
	case PCI_IDS_GAUDI_SIMULATOR:
		return HLTHUNK_DEVICE_GAUDI;
	default:
		printf("Invalid device type 0x%x\n", device_id);
		break;
	}

	return HLTHUNK_DEVICE_INVALID;
}

hlthunk_public int hlthunk_get_pci_bus_id_from_fd(int fd, char *pci_bus_id,
							int len)
{
	char pci_bus_file_name[128], read_busid[16];
	const char *base_path = "/sys/dev/char";
	const char *pci_bus_prefix = "pci_addr";
	int rc, major_num, minor_num, pci_fd;
	struct stat fd_stat;

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
		return rc;

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
#ifndef DISABLE_PROFILER
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
#else
	printf(
		"HABANA_PROFILE is set to 1, but profiler is not supported in this build\n");
#endif
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

		hlthunk_close(ctrl_fd);

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
	hw_ip->cpld_version = hl_hw_ip.cpld_version;
	hw_ip->psoc_pci_pll_nr = hl_hw_ip.psoc_pci_pll_nr;
	hw_ip->psoc_pci_pll_nf = hl_hw_ip.psoc_pci_pll_nf;
	hw_ip->psoc_pci_pll_od = hl_hw_ip.psoc_pci_pll_od;
	hw_ip->psoc_pci_pll_div_factor = hl_hw_ip.psoc_pci_pll_div_factor;
	hw_ip->tpc_enabled_mask = hl_hw_ip.tpc_enabled_mask;
	hw_ip->dram_enabled = hl_hw_ip.dram_enabled;
	memcpy(hw_ip->cpucp_version, hl_hw_ip.cpucp_version,
		HL_INFO_VERSION_MAX_LEN);
	memcpy(hw_ip->card_name, hl_hw_ip.card_name,
		HL_INFO_CARD_NAME_MAX_LEN);
	hw_ip->module_id = hl_hw_ip.module_id;
	hw_ip->dram_page_size = hl_hw_ip.dram_page_size;
	hw_ip->first_available_interrupt_id =
		hl_hw_ip.first_available_interrupt_id;

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
	memset(&hl_dev_status, 0, sizeof(hl_dev_status));

	args.op = HL_INFO_DEVICE_STATUS;
	args.return_pointer = (__u64) (uintptr_t) &hl_dev_status;
	args.return_size = sizeof(hl_dev_status);

	rc = hlthunk_ioctl(fd, HL_IOCTL_INFO, &args);
	if (rc)
		return rc;

	return hl_dev_status.status;
}

static int hlthunk_get_hw_idle_info(int fd, uint32_t *is_idle,
					uint64_t *busy_engines_mask)
{
	struct hl_info_args args;
	struct hl_info_hw_idle hl_hw_idle;
	int rc;

	memset(&args, 0, sizeof(args));
	memset(&hl_hw_idle, 0, sizeof(hl_hw_idle));

	args.op = HL_INFO_HW_IDLE;
	args.return_pointer = (__u64) (uintptr_t) &hl_hw_idle;
	args.return_size = sizeof(hl_hw_idle);

	rc = hlthunk_ioctl(fd, HL_IOCTL_INFO, &args);
	if (rc)
		return rc;

	*is_idle = hl_hw_idle.is_idle;
	*busy_engines_mask = hl_hw_idle.busy_engines_mask_ext;

	return 0;
}

hlthunk_public bool hlthunk_is_device_idle(int fd)
{
	uint32_t is_idle;
	uint64_t mask;

	int rc;

	rc = hlthunk_get_hw_idle_info(fd, &is_idle, &mask);
	if (rc)
		return false;

	return !!is_idle;
}

hlthunk_public int hlthunk_get_busy_engines_mask(int fd, uint64_t *mask)
{
	uint32_t is_idle;
	int rc;

	rc = hlthunk_get_hw_idle_info(fd, &is_idle, mask);

	return rc;
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

hlthunk_public int hlthunk_get_device_utilization(int fd, uint32_t period_ms,
						uint32_t *rate)
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

hlthunk_public int hlthunk_get_reset_count_info(int fd,
					struct hlthunk_reset_count_info *info)
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

hlthunk_public int hlthunk_get_time_sync_info(int fd,
					struct hlthunk_time_sync_info *info)
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

	return 0;
}

hlthunk_public int hlthunk_get_cs_counters_info(int fd,
					struct hl_info_cs_counters *info)
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

hlthunk_public int hlthunk_get_pci_counters_info(int fd,
				struct hlthunk_pci_counters_info *info)
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

hlthunk_public int hlthunk_get_clk_throttle_info(int fd,
				struct hlthunk_clk_throttle_info *info)
{
	struct hl_info_args args;
	struct hl_info_clk_throttle clk_throttle;
	int rc;

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

hlthunk_public int hlthunk_get_cb_usage_count(int fd, uint64_t cb_handle,
						uint32_t *usage_cnt)
{
	union hl_cb_args args;
	int rc;

	memset(&args, 0, sizeof(args));
	args.in.op = HL_CB_OP_INFO;
	args.in.cb_handle = cb_handle;

	rc = hlthunk_ioctl(fd, HL_IOCTL_CB, &args);
	if (rc)
		return rc;

	*usage_cnt = args.out.usage_cnt;

	return 0;
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

int hlthunk_staged_command_submission_original(int fd,
						uint64_t sequence,
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
	hl_in->seq = sequence;
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

hlthunk_public int hlthunk_staged_command_submission(int fd,
						uint64_t sequence,
						struct hlthunk_cs_in *in,
						struct hlthunk_cs_out *out)
{
	return (*functions_pointers_table.fp_hlthunk_staged_command_submission)(
				fd, sequence, in, out);
}

int hlthunk_get_hw_block_original(int fd, uint64_t block_address,
					uint32_t block_size, uint64_t *handle)
{
	union hl_mem_args ioctl_args;
	int rc;

	memset(&ioctl_args, 0, sizeof(ioctl_args));
	ioctl_args.in.map_block.block_addr = block_address;
	ioctl_args.in.op = HL_MEM_OP_MAP_BLOCK;

	rc = hlthunk_ioctl(fd, HL_IOCTL_MEMORY, &ioctl_args);
	if (rc)
		return rc;

	*handle = ioctl_args.out.handle;

	return 0;
}

hlthunk_public int hlthunk_get_hw_block(int fd, uint64_t block_address,
					uint32_t block_size, uint64_t *handle)
{
	return (*functions_pointers_table.fp_hlthunk_get_hw_block)(
				fd, block_address, block_size, handle);
}

int hlthunk_signal_submission_original(int fd,
					struct hlthunk_signal_in *in,
					struct hlthunk_signal_out *out)
{
	union hl_cs_args args;
	struct hl_cs_chunk chunk_execute;
	struct hl_cs_in *hl_in;
	struct hl_cs_out *hl_out;
	int rc;

	memset(&args, 0, sizeof(args));
	memset(&chunk_execute, 0, sizeof(chunk_execute));
	chunk_execute.queue_index = in->queue_index;

	hl_in = &args.in;
	hl_in->chunks_restore = (__u64) (uintptr_t) in->chunks_restore;
	hl_in->num_chunks_restore = in->num_chunks_restore;
	hl_in->chunks_execute = (__u64) (uintptr_t) &chunk_execute;
	hl_in->num_chunks_execute = 1;
	hl_in->cs_flags = in->flags | HL_CS_FLAGS_SIGNAL;

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

hlthunk_public int hlthunk_signal_submission(int fd,
					struct hlthunk_signal_in *in,
					struct hlthunk_signal_out *out)
{
	return (*functions_pointers_table.fp_hlthunk_signal_submission)(
				fd, in, out);
}

int hlthunk_wait_for_signal_original(int fd, struct hlthunk_wait_in *in,
					struct hlthunk_wait_out *out)
{
	union hl_cs_args args;
	struct hl_cs_chunk chunk_execute;
	struct hlthunk_wait_for_signal *wait_for_signal;
	struct hl_cs_in *hl_in;
	struct hl_cs_out *hl_out;
	int rc;

	if (in->num_wait_for_signal != 1) {
		printf(
			"Currently only one wait for signal CS is supported in each ioctl\n");
		return -EINVAL;
	}

	wait_for_signal =
		(struct hlthunk_wait_for_signal *) in->hlthunk_wait_for_signal;

	if (wait_for_signal->signal_seq_nr != 1) {
		printf(
			"Currently only one signal CS seq is supported in a wait for signal CS\n");
		return -EINVAL;
	}

	memset(&args, 0, sizeof(args));
	memset(&chunk_execute, 0, sizeof(chunk_execute));
	chunk_execute.queue_index = wait_for_signal->queue_index;
	chunk_execute.signal_seq_arr =
			(__u64) (uintptr_t) wait_for_signal->signal_seq_arr;
	chunk_execute.num_signal_seq_arr = 1;

	hl_in = &args.in;
	hl_in->chunks_restore = (__u64) (uintptr_t) in->chunks_restore;
	hl_in->num_chunks_restore = in->num_chunks_restore;
	hl_in->chunks_execute = (__u64) (uintptr_t) &chunk_execute;
	hl_in->num_chunks_execute = 1;
	hl_in->cs_flags = in->flags | HL_CS_FLAGS_WAIT;

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

int hlthunk_wait_for_collective_signal_original(int fd,
		struct hlthunk_wait_in *in, struct hlthunk_wait_out *out)
{
	union hl_cs_args args;
	struct hl_cs_chunk chunk_execute;
	struct hlthunk_wait_for_signal *wait_for_signal;
	struct hl_cs_in *hl_in;
	struct hl_cs_out *hl_out;
	int rc;

	if (in->num_wait_for_signal != 1) {
		printf(
			"Currently only one wait for signal CS is supported in each ioctl\n");
		return -EINVAL;
	}

	wait_for_signal =
		(struct hlthunk_wait_for_signal *) in->hlthunk_wait_for_signal;

	if (wait_for_signal->signal_seq_nr != 1) {
		printf(
			"Currently only one signal CS seq is supported in a wait for signal CS\n");
		return -EINVAL;
	}

	memset(&args, 0, sizeof(args));
	memset(&chunk_execute, 0, sizeof(chunk_execute));
	chunk_execute.queue_index = wait_for_signal->queue_index;
	chunk_execute.signal_seq_arr =
		(__u64) (uintptr_t) wait_for_signal->signal_seq_arr;
	chunk_execute.num_signal_seq_arr = 1;
	chunk_execute.collective_engine_id =
			wait_for_signal->collective_engine_id;

	hl_in = &args.in;
	hl_in->chunks_restore = (__u64) (uintptr_t) in->chunks_restore;
	hl_in->num_chunks_restore = in->num_chunks_restore;
	hl_in->chunks_execute = (__u64) (uintptr_t) &chunk_execute;
	hl_in->num_chunks_execute = 1;
	hl_in->cs_flags = in->flags | HL_CS_FLAGS_COLLECTIVE_WAIT;

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

hlthunk_public int hlthunk_wait_for_signal(int fd,
					struct hlthunk_wait_in *in,
					struct hlthunk_wait_out *out)
{
	return (*functions_pointers_table.fp_hlthunk_wait_for_signal)(
				fd, in, out);
}

hlthunk_public int hlthunk_wait_for_collective_signal(int fd,
					struct hlthunk_wait_in *in,
					struct hlthunk_wait_out *out)
{
	return (*functions_pointers_table.fp_hlthunk_wait_for_collective_sig)(
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

hlthunk_public int hlthunk_wait_for_cs_with_timestamp(int fd, uint64_t seq,
					uint64_t timeout_us, uint32_t *status,
					uint64_t *timestamp)
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

	if (hl_out->flags & HL_WAIT_CS_STATUS_FLAG_TIMESTAMP_VLD)
		*timestamp = hl_out->timestamp_nsec;

	return rc;
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

hlthunk_public int hlthunk_device_memory_free(int fd, uint64_t handle)
{
	union hl_mem_args ioctl_args;

	memset(&ioctl_args, 0, sizeof(ioctl_args));
	ioctl_args.in.free.handle = handle;
	ioctl_args.in.op = HL_MEM_OP_FREE;

	return hlthunk_ioctl(fd, HL_IOCTL_MEMORY, &ioctl_args);
}

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

hlthunk_public uint64_t hlthunk_host_memory_map_original(int fd,
						void *host_virt_addr,
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

hlthunk_public uint64_t hlthunk_host_memory_map(int fd, void *host_virt_addr,
						uint64_t hint_addr,
						uint64_t host_size)
{
	return (*functions_pointers_table.fp_hlthunk_host_memory_map)(
			fd, host_virt_addr, hint_addr, host_size);
}

hlthunk_public int hlthunk_memory_unmap_original(int fd,
						 uint64_t device_virt_addr)
{
	union hl_mem_args ioctl_args;

	memset(&ioctl_args, 0, sizeof(ioctl_args));
	ioctl_args.in.unmap.device_virt_addr = device_virt_addr;
	ioctl_args.in.op = HL_MEM_OP_UNMAP;

	return hlthunk_ioctl(fd, HL_IOCTL_MEMORY, &ioctl_args);
}

hlthunk_public int hlthunk_memory_unmap(int fd, uint64_t device_virt_addr)
{
	return (*functions_pointers_table.fp_hlthunk_memory_unmap)(
			fd, device_virt_addr);
}

hlthunk_public int hlthunk_debug(int fd, struct hl_debug_args *debug)
{
	return hlthunk_ioctl(fd, HL_IOCTL_DEBUG, debug);
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

int hlthunk_profiler_get_trace_original(int fd, void *buffer, uint64_t *size,
					uint64_t *num_entries)
{
	return -1;
}

hlthunk_public int hlthunk_profiler_get_trace(int fd, void *buffer,
					uint64_t *size,
					uint64_t *num_entries)
{
	return (*functions_pointers_table.fp_hlthunk_profiler_get_trace)(
				fd, buffer, size, num_entries);
}

void hlthunk_profiler_destroy_original(void)
{
	pthread_mutex_lock(&global_members.profiler_init_lock);

	global_members.is_profiler_checked = false;
	struct hlthunk_functions_pointers reset_functions_pointers_table =
		INIT_FUNCS_POINTERS_TABLE;
	functions_pointers_table = reset_functions_pointers_table;

	if (global_members.shared_object_handle) {
		dlclose(global_members.shared_object_handle);
		global_members.shared_object_handle = NULL;
	}

	pthread_mutex_unlock(&global_members.profiler_init_lock);
}

hlthunk_public void hlthunk_profiler_destroy(void)
{
	(*functions_pointers_table.fp_hlthunk_profiler_destroy)();
}

hlthunk_public int hlthunk_debugfs_open(int fd,
					struct hlthunk_debugfs *debugfs)
{
	char pci_bus_id[13];
	char *path;
	char clk_gate_str[16] = "0";
	ssize_t size;
	int device_idx, rc = 0;
	int clk_gate_fd = -1, debugfs_addr_fd = -1, debugfs_data_fd = -1;

	rc = hlthunk_get_pci_bus_id_from_fd(fd,
					    pci_bus_id, sizeof(pci_bus_id));
	if (rc)
		return -ENODEV;

	device_idx =
		hlthunk_get_device_index_from_pci_bus_id(pci_bus_id);
	if (device_idx < 0)
		return -ENODEV;

	path = hlthunk_malloc(PATH_MAX);
	if (!path)
		return -ENOMEM;

	snprintf(path, PATH_MAX, "//sys/kernel/debug/habanalabs/hl%d/addr",
			device_idx);

	debugfs_addr_fd = open(path, O_WRONLY);
	if (debugfs_addr_fd == -1) {
		printf("Failed to open debugfs addr_fd (forgot sudo ?)\n");
		rc = -EPERM;
		goto err_exit;
	}

	snprintf(path, PATH_MAX, "//sys/kernel/debug/habanalabs/hl%d/data32",
			device_idx);

	debugfs_data_fd = open(path, O_RDWR);

	if (debugfs_data_fd == -1) {
		printf("Failed to open debugfs data_fd (forgot sudo ?)\n");
		rc = -EPERM;
		goto err_exit;
	}

	snprintf(path, PATH_MAX, "//sys/kernel/debug/habanalabs/hl%d/clk_gate",
			device_idx);

	clk_gate_fd = open(path, O_RDWR);

	if (clk_gate_fd == -1) {
		printf("Failed to open clk_gate_fd (forgot sudo ?)\n");
		rc = -EPERM;
		goto err_exit;
	}

	debugfs->addr_fd = debugfs_addr_fd;
	debugfs->data_fd = debugfs_data_fd;
	debugfs->clk_gate_fd = clk_gate_fd;

	size = pread(debugfs->clk_gate_fd,
		     debugfs->clk_gate_val, sizeof(debugfs->clk_gate_val), 0);
	if (size < 0)
		perror("Failed to read debugfs clk gate fd\n");

	size = write(debugfs->clk_gate_fd, clk_gate_str,
			strlen(clk_gate_str) + 1);
	if (size < 0)
		perror("Failed to write debugfs clk gate\n");

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

hlthunk_public int hlthunk_debugfs_read(struct hlthunk_debugfs *debugfs,
					uint64_t full_address, uint32_t *val)
{
	char addr_str[64] = "", value[64] = "";
	ssize_t size;

	sprintf(addr_str, "0x%lx", full_address);

	size = write(debugfs->addr_fd, addr_str, strlen(addr_str) + 1);
	if (size < 0) {
		perror("Failed to write to debugfs address fd\n");
		return -errno;
	}

	size = pread(debugfs->data_fd, value, sizeof(value), 0);
	if (size < 0) {
		perror("Failed to read from debugfs data fd\n");
		return -errno;
	}

	*val = strtoul(value, NULL, 16);
	return 0;
}

hlthunk_public int hlthunk_debugfs_write(struct hlthunk_debugfs *debugfs,
					 uint64_t full_address, uint32_t val)
{
	char addr_str[64] = "", val_str[64] = "";
	ssize_t size;

	sprintf(addr_str, "0x%lx", full_address);
	sprintf(val_str, "0x%x", val);

	size = write(debugfs->addr_fd, addr_str, strlen(addr_str) + 1);
	if (size < 0) {
		perror("Failed to write to debugfs address fd\n");
		return -errno;
	}

	size = write(debugfs->data_fd, val_str, strlen(val_str) + 1);
	if (size < 0) {
		perror("Failed to write to debugfs data fd\n");
		return -errno;
	}

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
		size = write(debugfs->clk_gate_fd,
			     debugfs->clk_gate_val,
			     strlen(debugfs->clk_gate_val) + 1);
		if (size < 0) {
			perror("Failed to write to debugfs clk_gate fd\n");
			rc = -EIO;
		}

		close(debugfs->clk_gate_fd);
	}

	return rc;
}
