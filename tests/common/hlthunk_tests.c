// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_tests.h"
#include "mersenne-twister/mersenne-twister.h"
#include "argparse.h"

#include <stdio.h>
#include <errno.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <linux/mman.h>
#include <time.h>
#include <inttypes.h>
#include <sys/ioctl.h>

#ifndef MAP_HUGE_2MB
	#define MAP_HUGE_2MB    (21 << MAP_HUGE_SHIFT)
#endif

#define FRAG_MEM_MULT 3

struct hltests_thread_params {
	const char *group_name;
	const struct CMUnitTest *tests;
	size_t num_tests;
	CMFixtureFunction group_setup;
	CMFixtureFunction group_teardown;
};

static pthread_mutex_t table_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_spinlock_t rand_lock;
static khash_t(ptr) * dev_table;

static enum hlthunk_device_name asic_name_for_testing =
						HLTHUNK_DEVICE_DONT_CARE;

static pthread_barrier_t barrier;

static int run_disabled_tests;
static const char *parser_pciaddr;
static const char *config_filename;
static int num_devices = 1;
static int legacy_mode_enabled = 1;

static char asic_names[HLTHUNK_DEVICE_MAX][20] = {
	"Goya",
	"Placeholder1",
	"Gaudi",
	"Invalid",
	"Don't care"
};

static struct hltests_module_params_info default_module_params = {
	.gaudi_huge_page_optimization = 1,
	.timeout_locked = 5,
	.reset_on_lockup = 1,
	.pldm = 0,
	.mmu_enable = 1,
	.clock_gating = 1,
	.mme_enable = 1,
	.tpc_mask = 0x3FF,
	.dram_enable = 1,
	.cpu_enable = 1,
	.reset_pcilink = 0,
	.config_pll = 0,
	.cpu_queues_enable = 1,
	.fw_loading = 0x3,
	.heartbeat = 1,
	.axi_drain = 1,
	.security_enable = 1,
	.sram_scrambler_enable = 1,
	.dram_scrambler_enable = 1,
	.dram_size_ratio = 0,
	.hbm_ecc_enable = 1,
	.reserved = 0,
	.hard_reset_on_fw_events = 1,
	.fw_loading_ext = 0
};

static struct hltests_device *get_hdev_from_fd(int fd)
{
	struct hltests_device *hdev;
	khint_t k;

	pthread_mutex_lock(&table_lock);

	k = kh_get(ptr, dev_table, fd);
	if (k == kh_end(dev_table)) {
		pthread_mutex_unlock(&table_lock);
		return NULL;
	}

	hdev = kh_val(dev_table, k);

	pthread_mutex_unlock(&table_lock);

	return hdev;
}

static int create_mem_maps(struct hltests_device *hdev)
{
	int rc;

	hdev->mem_table_host = kh_init(ptr64);
	if (!hdev->mem_table_host)
		return -ENOMEM;

	hdev->mem_table_device = kh_init(ptr64);
	if (!hdev->mem_table_device) {
		rc = -ENOMEM;
		goto delete_mem_hash;
	}

	rc = pthread_mutex_init(&hdev->mem_table_host_lock, NULL);
	if (rc)
		goto delete_device_hash;

	rc = pthread_mutex_init(&hdev->mem_table_device_lock, NULL);
	if (rc)
		goto destroy_host_lock;

	return 0;

destroy_host_lock:
	pthread_mutex_destroy(&hdev->mem_table_host_lock);
delete_device_hash:
	kh_destroy(ptr64, hdev->mem_table_device);
delete_mem_hash:
	kh_destroy(ptr64, hdev->mem_table_host);
	return rc;
}

static void destroy_mem_maps(struct hltests_device *hdev)
{
	kh_destroy(ptr64, hdev->mem_table_host);
	kh_destroy(ptr64, hdev->mem_table_device);
	pthread_mutex_destroy(&hdev->mem_table_host_lock);
	pthread_mutex_destroy(&hdev->mem_table_device_lock);
}

static int create_cb_map(struct hltests_device *hdev)
{
	int rc;

	hdev->cb_table = kh_init(ptr64);
	if (!hdev->cb_table)
		return -ENOMEM;

	rc = pthread_mutex_init(&hdev->cb_table_lock, NULL);
	if (rc)
		goto delete_hash;

	return 0;

delete_hash:
	kh_destroy(ptr64, hdev->cb_table);
	return rc;
}

static void destroy_cb_map(struct hltests_device *hdev)
{
	kh_destroy(ptr64, hdev->cb_table);
	pthread_mutex_destroy(&hdev->cb_table_lock);
}

static int hltests_init(void)
{
	int rc;

	rc = pthread_spin_init(&rand_lock, PTHREAD_PROCESS_PRIVATE);
	if (rc) {
		printf("Failed to initialize number randomizer lock [rc %d]\n",
			rc);
		return rc;
	}

	seed(time(NULL));

	dev_table = kh_init(ptr);
	if (!dev_table) {
		rc = -ENOMEM;
		printf("Failed to initialize device table [rc %d]\n", rc);
		goto free_spinlock;
	}

	return 0;

free_spinlock:
	pthread_spin_destroy(&rand_lock);

	return rc;
}

static void hltests_fini(void)
{
	if (!dev_table)
		return;

	kh_destroy(ptr, dev_table);
	pthread_spin_destroy(&rand_lock);
}

static void *hltests_thread_start(void *args)
{
	struct hltests_thread_params *params =
			(struct hltests_thread_params *) args;
	int rc;

	/*
	 * PTHREAD_BARRIER_SERIAL_THREAD is returned to one unspecified thread
	 * and zero is returned to each of the remaining threads.
	 */
	rc = pthread_barrier_wait(&barrier);
	if (rc && rc != PTHREAD_BARRIER_SERIAL_THREAD)
		return NULL;

	rc = _cmocka_run_group_tests(params->group_name,
				params->tests, params->num_tests,
				params->group_setup, params->group_teardown);
	if (rc)
		return NULL;

	return args;
}

int hltests_run_group_tests(const char *group_name,
				const struct CMUnitTest * const tests,
				const size_t num_tests,
				CMFixtureFunction group_setup,
				CMFixtureFunction group_teardown)
{
	pthread_t *thread_ids = NULL;
	struct hltests_thread_params *thread_params = NULL;
	void *retval;
	uint32_t i, num_threads = num_devices;
	int rc;

	rc = pthread_barrier_init(&barrier, NULL, num_threads);
	if (rc) {
		printf("Failed to initialize pthread barrier [rc %d]\n", rc);
		return rc;
	}

	rc = hltests_init();
	if (rc) {
		printf("Failed to initialize tests library [rc %d]\n", rc);
		goto out;
	}

	/* Allocate arrays for threads management */
	thread_ids = (pthread_t *) hlthunk_malloc(num_threads *
							sizeof(*thread_ids));
	if (!thread_ids) {
		printf("Failed to allocate memory for thread identifiers\n");
		rc = -ENOMEM;
		goto out;
	}

	thread_params = (struct hltests_thread_params *)
			hlthunk_malloc(num_threads * sizeof(*thread_params));
	if (!thread_params) {
		printf("Failed to allocate memory for thread parameters\n");
		rc = -ENOMEM;
		goto out;
	}

	/* Create and execute threads */
	for (i = 0 ; i < num_threads ; i++) {
		thread_params[i].group_name = group_name;
		thread_params[i].tests = tests;
		thread_params[i].num_tests = num_tests;
		thread_params[i].group_setup = group_setup;
		thread_params[i].group_teardown = group_teardown;

		rc = pthread_create(&thread_ids[i], NULL, hltests_thread_start,
					&thread_params[i]);
		if (rc) {
			printf("Failed to create thread %d\n", i);
			goto out;
		}
	}

	/* Wait for the termination of the threads */
	for (i = 0 ; i < num_threads ; i++) {
		rc = pthread_join(thread_ids[i], &retval);
		if (rc) {
			printf("Failed to join with thread %d\n", i);
			goto out;
		}

		if (!retval) {
			printf("Thread %d has failed\n", i);
			rc = -1;
			goto out;
		}
	}
out:
	/* Cleanup */
	hlthunk_free(thread_params);
	hlthunk_free(thread_ids);
	hltests_fini();
	pthread_barrier_destroy(&barrier);

	return rc;
}

int hltests_open(const char *busid)
{
	enum hlthunk_device_name actual_asic_type;
	struct hltests_device *hdev;
	int fd, rc;
	khint_t k;

	if (asic_name_for_testing == HLTHUNK_DEVICE_INVALID) {
		printf("Expected ASIC name is %s!!!\n",
			asic_names[asic_name_for_testing]);
		printf("Something is very wrong, exiting...\n");
		rc = -EINVAL;
		goto out;
	}

	pthread_mutex_lock(&table_lock);

	rc = fd = hlthunk_open(HLTHUNK_DEVICE_DONT_CARE, busid);
	if (fd < 0)
		goto out;

	actual_asic_type = hlthunk_get_device_name_from_fd(fd);
	if ((asic_name_for_testing != HLTHUNK_DEVICE_DONT_CARE) &&
			(asic_name_for_testing != actual_asic_type)) {

		printf("Expected to run on device %s but detected device %s\n",
				asic_names[asic_name_for_testing],
				asic_names[actual_asic_type]);
		rc = -EINVAL;
		hlthunk_close(fd);
		pthread_mutex_unlock(&table_lock);
		exit(0);
	}

	k = kh_get(ptr, dev_table, fd);
	if (k != kh_end(dev_table)) {
		/* found, just incr refcnt */
		hdev = kh_val(dev_table, k);
		hdev->refcnt++;
		goto out;
	}

	/* not found, create new device */
	hdev = hlthunk_malloc(sizeof(struct hltests_device));
	if (!hdev) {
		rc = -ENOMEM;
		goto close_device;
	}
	hdev->fd = fd;
	hdev->refcnt = 1;

	k = kh_put(ptr, dev_table, fd, &rc);
	kh_val(dev_table, k) = hdev;

	hdev->device_id = hlthunk_get_device_id_from_fd(fd);

	switch (actual_asic_type) {
	case HLTHUNK_DEVICE_GOYA:
		goya_tests_set_asic_funcs(hdev);
		break;
	case HLTHUNK_DEVICE_GAUDI:
		gaudi_tests_set_asic_funcs(hdev);
		break;
	default:
		printf("Invalid device type 0x%x\n", hdev->device_id);
		rc = -ENXIO;
		goto remove_device;
	}

	hdev->asic_funcs->dram_pool_init(hdev);

	rc = create_mem_maps(hdev);
	if (rc)
		goto remove_device;

	rc = create_cb_map(hdev);
	if (rc)
		goto destroy_mem_maps;

	pthread_mutex_unlock(&table_lock);
	return fd;

destroy_mem_maps:
	destroy_mem_maps(hdev);
remove_device:
	kh_del(ptr, dev_table, k);
	hlthunk_free(hdev);
close_device:
	hlthunk_close(fd);
out:
	pthread_mutex_unlock(&table_lock);
	return rc;
}

int hltests_close(int fd)
{
	struct hltests_device *hdev;
	khint_t k;

	pthread_mutex_lock(&table_lock);

	k = kh_get(ptr, dev_table, fd);
	if (k == kh_end(dev_table)) {
		pthread_mutex_unlock(&table_lock);
		return -ENODEV;
	}

	hdev = kh_val(dev_table, k);

	if (--hdev->refcnt) {
		pthread_mutex_unlock(&table_lock);
		return 0;
	}

	hdev->asic_funcs->dram_pool_fini(hdev);

	destroy_mem_maps(hdev);

	destroy_cb_map(hdev);

	hlthunk_close(hdev->fd);

	kh_del(ptr, dev_table, k);
	pthread_mutex_unlock(&table_lock);

	hlthunk_free(hdev);

	return 0;
}

void *hltests_cb_mmap(int fd, size_t length, off_t offset)
{
	return mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
			offset);
}

int hltests_cb_munmap(void *addr, size_t length)
{
	return munmap(addr, length);
}

static int debugfs_open(struct hltests_state *tests_state, int device_idx)
{
	int debugfs_addr_fd, debugfs_data32_fd, clk_gate_fd, debugfs_data64_fd;
	char path[PATH_MAX];
	char clk_gate_str[16] = "0";
	ssize_t size;

	snprintf(path, PATH_MAX, "//sys/kernel/debug/habanalabs/hl%d/addr",
			device_idx);

	debugfs_addr_fd = open(path, O_WRONLY);

	if (debugfs_addr_fd == -1) {
		printf("Failed to open debugfs_addr_fd (forgot sudo ?)\n");
		return -EPERM;
	}

	snprintf(path, PATH_MAX, "//sys/kernel/debug/habanalabs/hl%d/data32",
			device_idx);

	debugfs_data32_fd = open(path, O_RDWR);

	if (debugfs_data32_fd == -1) {
		close(debugfs_addr_fd);
		printf("Failed to open debugfs_data_fd (forgot sudo ?)\n");
		return -EPERM;
	}

	snprintf(path, PATH_MAX, "//sys/kernel/debug/habanalabs/hl%d/data64",
				device_idx);

	debugfs_data64_fd = open(path, O_RDWR);

	if (debugfs_data64_fd == -1) {
		close(debugfs_data32_fd);
		close(debugfs_addr_fd);
		printf("Failed to open debugfs_data64_fd (forgot sudo ?)\n");
		return -EPERM;
	}

	snprintf(path, PATH_MAX, "//sys/kernel/debug/habanalabs/hl%d/clk_gate",
			device_idx);

	clk_gate_fd = open(path, O_RDWR);

	if (clk_gate_fd == -1) {
		close(debugfs_addr_fd);
		close(debugfs_data64_fd);
		close(debugfs_data32_fd);
		printf("Failed to open clk_gate_fd (forgot sudo ?)\n");
		return -EPERM;
	}

	tests_state->debugfs.addr_fd = debugfs_addr_fd;
	tests_state->debugfs.data32_fd = debugfs_data32_fd;
	tests_state->debugfs.data64_fd = debugfs_data64_fd;
	tests_state->debugfs.clk_gate_fd = clk_gate_fd;

	size = pread(tests_state->debugfs.clk_gate_fd,
			tests_state->debugfs.clk_gate_val,
			sizeof(tests_state->debugfs.clk_gate_val), 0);
	if (size < 0)
		printf("Failed to read debugfs clk gate fd [rc %zd]\n", size);

	size = write(tests_state->debugfs.clk_gate_fd, clk_gate_str,
			strlen(clk_gate_str) + 1);
	if (size < 0)
		printf("Failed to write debugfs clk gate [rc %zd]\n", size);

	return 0;
}

static int debugfs_close(struct hltests_state *tests_state)
{
	ssize_t size;

	if ((tests_state->debugfs.addr_fd == -1) ||
		(tests_state->debugfs.data32_fd == -1) ||
		(tests_state->debugfs.data64_fd == -1) ||
		(tests_state->debugfs.clk_gate_fd == -1))
		return -EFAULT;

	size = write(tests_state->debugfs.clk_gate_fd,
			tests_state->debugfs.clk_gate_val,
			strlen(tests_state->debugfs.clk_gate_val) + 1);
	if (size < 0)
		printf("Failed to write debugfs clk gate [rc %zd]\n", size);

	close(tests_state->debugfs.clk_gate_fd);
	close(tests_state->debugfs.addr_fd);
	close(tests_state->debugfs.data32_fd);
	close(tests_state->debugfs.data64_fd);
	tests_state->debugfs.clk_gate_fd = -1;
	tests_state->debugfs.addr_fd = -1;
	tests_state->debugfs.data32_fd = -1;
	tests_state->debugfs.data64_fd = -1;

	return 0;
}

uint32_t hltests_debugfs_read(int addr_fd, int data_fd, uint64_t full_address)
{
	char addr_str[64] = "", value[64] = "";
	ssize_t size;

	sprintf(addr_str, "0x%lx", full_address);

	size = write(addr_fd, addr_str, strlen(addr_str) + 1);
	if (size < 0)
		printf("Failed to write to debugfs address fd [rc %zd]\n",
				size);

	size = pread(data_fd, value, sizeof(value), 0);
	if (size < 0)
		printf("Failed to read from debugfs data fd [rc %zd]\n", size);

	return strtoul(value, NULL, 16);
}

void hltests_debugfs_write(int addr_fd, int data_fd, uint64_t full_address,
				uint32_t val)
{
	char addr_str[64] = "", val_str[64] = "";
	ssize_t size;

	sprintf(addr_str, "0x%lx", full_address);
	sprintf(val_str, "0x%x", val);

	size = write(addr_fd, addr_str, strlen(addr_str) + 1);
	if (size < 0)
		printf("Failed to write to debugfs address fd [rc %zd]\n",
				size);

	size = write(data_fd, val_str, strlen(val_str) + 1);
	if (size < 0)
		printf("Failed to write to debugfs data fd [rc %zd]\n", size);
}

uint64_t hltests_debugfs_read64(int addr_fd, int data_fd, uint64_t full_address)
{
	char addr_str[64] = "", value[64] = "";
	ssize_t size;

	sprintf(addr_str, "0x%lx", full_address);

	size = write(addr_fd, addr_str, strlen(addr_str) + 1);
	if (size < 0)
		printf("Failed to write64 to debugfs address fd [rc %zd]\n",
				size);

	size = pread(data_fd, value, sizeof(value), 0);
	if (size < 0)
		printf("Failed to read from debugfs data fd [rc %zd]\n", size);

	return strtoul(value, NULL, 16);
}

void hltests_debugfs_write64(int addr_fd, int data_fd, uint64_t full_address,
				uint64_t val)
{
	char addr_str[64] = "", val_str[64] = "";
	ssize_t size;

	sprintf(addr_str, "0x%lx", full_address);
	sprintf(val_str, "0x%lx", val);

	size = write(addr_fd, addr_str, strlen(addr_str) + 1);
	if (size < 0)
		printf("Failed to write to debugfs address fd [rc %zd]\n",
				size);

	size = write(data_fd, val_str, strlen(val_str) + 1);
	if (size < 0)
		printf("Failed to write to debugfs data fd [rc %zd]\n", size);
}

static bool hltests_is_importer_exists(void)
{
	if (!access("/dev/hli", F_OK))
		return true;
	return false;
}

static struct hltests_state *hltests_alloc_state(void)
{
	struct hltests_state *tests_state;

	tests_state = hlthunk_malloc(sizeof(*tests_state));
	if (!tests_state)
		goto out;

	tests_state->fd = -1;
	tests_state->imp_fd = -1;
	tests_state->asic_type = HLTHUNK_DEVICE_MAX;
	tests_state->debugfs.addr_fd = -1;
	tests_state->debugfs.data32_fd = -1;
	tests_state->debugfs.data64_fd = -1;
	tests_state->debugfs.clk_gate_fd = -1;

out:
	return tests_state;
}

int hltests_setup(void **state)
{
	struct hltests_state *tests_state;
	struct hltests_module_params_info module_params;
	int rc, fd;

	tests_state = hltests_alloc_state();
	if (!tests_state)
		return -ENOMEM;

	fd = tests_state->fd = hltests_open(parser_pciaddr);
	if (fd < 0) {
		printf("Failed to open device %d\n", fd);
		rc = fd;
		goto free_state;
	}

	if (hltests_is_importer_exists()) {
		tests_state->imp_fd = open("/dev/hli", O_RDWR | O_CLOEXEC, 0);
		if (tests_state->imp_fd < 0) {
			printf("Failed to open importer %d\n",
							tests_state->imp_fd);
			rc = tests_state->imp_fd;
			goto close_fd;
		}
	}

	memset(&module_params, 0, sizeof(module_params));
	rc = hltests_get_module_params_info(fd, &module_params);
	if (rc) {
		printf("Failed to retrieve values of module parameters\n");
		goto close_imp_fd;
	}

	tests_state->mme = !!module_params.mme_enable;
	tests_state->mmu = !!module_params.mmu_enable;
	tests_state->security = !!module_params.security_enable;

	*state = tests_state;

	return 0;

close_imp_fd:
	if (tests_state->imp_fd >= 0)
		close(tests_state->imp_fd);
close_fd:
	if (hltests_close(fd))
		printf("Problem in closing FD, ignoring...\n");
free_state:
	hlthunk_free(tests_state);

	return rc;
}

int hltests_teardown(void **state)
{
	struct hltests_state *tests_state =
					(struct hltests_state *) *state;

	if (!tests_state)
		return -EINVAL;

	if (tests_state->imp_fd >= 0)
		close(tests_state->imp_fd);

	if (hltests_close(tests_state->fd))
		printf("Problem in closing FD, ignoring...\n");

	hlthunk_free(*state);

	return 0;
}

int hltests_root_setup(void **state)
{
	struct hltests_state *tests_state;
	char pci_bus_id[13];
	int rc, device_idx;

	rc = hltests_setup(state);
	if (rc)
		return rc;

	tests_state = (struct hltests_state *) *state;

	rc = hlthunk_get_pci_bus_id_from_fd(tests_state->fd, pci_bus_id,
						sizeof(pci_bus_id));
	if (rc)
		return rc;

	device_idx = hlthunk_get_device_index_from_pci_bus_id(pci_bus_id);
	if (device_idx < 0)
		return -ENODEV;

	return debugfs_open(tests_state, device_idx);
}

int hltests_root_teardown(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;

	if (!tests_state)
		return -EINVAL;

	debugfs_close(tests_state);

	return hltests_teardown(state);
}

int hltests_root_debug_setup(void **state)
{
	const char *pciaddr = hltests_get_parser_pciaddr();
	struct hltests_state *tests_state;
	int device_idx = 0, control_fd;

	tests_state = hltests_alloc_state();
	if (!tests_state)
		return -ENOMEM;

	*state = tests_state;

	if (asic_name_for_testing == HLTHUNK_DEVICE_INVALID) {
		printf("Expected ASIC name is %s!!!\n",
			asic_names[asic_name_for_testing]);
		printf("Something is very wrong, exiting...\n");
		return -EINVAL;
	}

	if (pciaddr) {
		device_idx = hlthunk_get_device_index_from_pci_bus_id(pciaddr);
		if (device_idx < 0) {
			printf("No device for the given PCI address %s\n",
				pciaddr);
			return -EINVAL;
		}
	}

	control_fd = hlthunk_open_control(device_idx, pciaddr);
	if (control_fd < 0)
		return control_fd;

	tests_state->asic_type = hlthunk_get_device_name_from_fd(control_fd);
	hlthunk_close(control_fd);

	if (asic_name_for_testing != HLTHUNK_DEVICE_DONT_CARE &&
			asic_name_for_testing != tests_state->asic_type) {
		printf("Expected to run on device %s but detected device %s\n",
			asic_names[asic_name_for_testing],
			asic_names[tests_state->asic_type]);
		hlthunk_free(*state);
		exit(0);
	}

	return debugfs_open(tests_state, device_idx);
}

int hltests_root_debug_teardown(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int rc;

	if (!tests_state)
		return -EINVAL;

	rc = debugfs_close(tests_state);

	hlthunk_free(*state);

	return rc;
}

static int hltests_ioctl(int fd, unsigned long request, void *arg)
{
	int ret;

	do {
		ret = ioctl(fd, request, arg);
	} while (ret == -1 && (errno == EINTR || errno == EAGAIN));

	return ret;
}

int hltests_get_module_params_info(int fd,
				struct hltests_module_params_info *info)
{
	if (!info)
		return -EINVAL;

	*info = default_module_params;
	return 0;
}

static void *allocate_huge_mem(uint64_t size)
{
#if defined(__powerpc__)
	int mmapFlags = MAP_SHARED | MAP_ANONYMOUS;
#else
	int mmapFlags = MAP_HUGE_2MB | MAP_HUGETLB | MAP_SHARED | MAP_ANONYMOUS;
#endif
	int prot = PROT_READ | PROT_WRITE;
	void *vaddr;

	vaddr = mmap(0, size, prot, mmapFlags, -1, 0);

	if (vaddr == MAP_FAILED) {
		printf("Failed to allocate %lu host memory with huge pages\n",
			size);
		return NULL;
	}

	return vaddr;
}

/**
 * This function allocates memory on the host and will map it to the device
 * virtual address space
 * @param fd file descriptor of the device to which the function will map
 *           the memory
 * @param size how much memory to allocate
 * @param huge whether to use huge pages for the memory allocation
 * @return pointer to the host memory. NULL is returned upon failure
 */
void *hltests_allocate_host_mem(int fd, uint64_t size, enum hltests_huge huge)
{
	struct hltests_device *hdev;
	struct hltests_memory *mem;
	khint_t k;
	int rc;

	hdev = get_hdev_from_fd(fd);
	if (!hdev)
		return NULL;

	mem = hlthunk_malloc(sizeof(struct hltests_memory));
	if (!mem)
		return NULL;

	mem->is_host = true;
	mem->is_huge = huge;
	mem->size = size;

	if (mem->is_huge)
		mem->host_ptr = allocate_huge_mem(size);
	else
		mem->host_ptr = malloc(size);

	if (!mem->host_ptr) {
		printf("Failed to allocate %lu bytes of host memory\n", size);
		goto free_mem_struct;
	}

	mem->device_virt_addr = hlthunk_host_memory_map(fd, mem->host_ptr, 0,
							size);

	if (!mem->device_virt_addr) {
		printf("Failed to map host memory to device\n");
		goto free_allocation;
	}

	pthread_mutex_lock(&hdev->mem_table_host_lock);

	k = kh_put(ptr64, hdev->mem_table_host, (uintptr_t) mem->host_ptr, &rc);
	kh_val(hdev->mem_table_host, k) = mem;

	pthread_mutex_unlock(&hdev->mem_table_host_lock);

	return (void *) mem->host_ptr;

free_allocation:
	if (mem->is_huge)
		munmap(mem->host_ptr, size);
	else
		free(mem->host_ptr);
free_mem_struct:
	hlthunk_free(mem);
	return NULL;
}

/**
 * This function allocates DRAM memory on the device and will map it to
 * the device virtual address space
 * @param fd file descriptor of the device to which the function will map
 *           the memory
 * @param size how much memory to allocate
 * @param contiguous whether the memory area will be physically contiguous
 * @return pointer to the device memory. This pointer can NOT be dereferenced
 * directly from the host. NULL is returned upon failure
 */
void *hltests_allocate_device_mem(int fd, uint64_t size,
				enum hltests_contiguous contiguous)
{
	const struct hltests_asic_funcs *asic;
	struct hltests_device *hdev;
	struct hltests_memory *mem;
	khint_t k;
	int rc;

	hdev = get_hdev_from_fd(fd);
	if (!hdev)
		return NULL;

	asic = hdev->asic_funcs;

	mem = hlthunk_malloc(sizeof(struct hltests_memory));
	if (!mem)
		return NULL;

	mem->is_host = false;
	mem->size = size;
	mem->is_pool = true;

	rc = asic->dram_pool_alloc(hdev, size, &mem->device_virt_addr);

	if (rc) {
		mem->is_pool = false;
		mem->device_handle = hlthunk_device_memory_alloc(fd, size,
								contiguous,
								false);

		if (!mem->device_handle) {
			printf(
				"Failed to allocate %lu bytes of device memory\n",
				size);
			goto free_mem_struct;
		}

		mem->device_virt_addr = hlthunk_device_memory_map(fd,
							mem->device_handle, 0);

		if (!mem->device_virt_addr) {
			printf("Failed to map device memory allocation\n");
			goto free_allocation;
		}
	}

	pthread_mutex_lock(&hdev->mem_table_device_lock);

	k = kh_put(ptr64, hdev->mem_table_device, mem->device_virt_addr, &rc);
	kh_val(hdev->mem_table_device, k) = mem;

	pthread_mutex_unlock(&hdev->mem_table_device_lock);

	return (void *) mem->device_virt_addr;

free_allocation:
	hlthunk_device_memory_free(fd, mem->device_handle);
free_mem_struct:
	hlthunk_free(mem);
	return NULL;
}

/**
 * This function frees host memory allocation which were done using
 * hltests_allocate_host_mem
 * @param fd file descriptor of the device that the host memory is mapped to
 * @param vaddr host pointer that points to the memory area
 * @return 0 for success, negative value for failure
 */
int hltests_free_host_mem(int fd, void *vaddr)
{
	struct hltests_device *hdev;
	struct hltests_memory *mem;
	khint_t k;
	int rc;

	hdev = get_hdev_from_fd(fd);
	if (!hdev)
		return -ENODEV;

	pthread_mutex_lock(&hdev->mem_table_host_lock);

	k = kh_get(ptr64, hdev->mem_table_host, (uintptr_t) vaddr);
	if (k == kh_end(hdev->mem_table_host)) {
		pthread_mutex_unlock(&hdev->mem_table_host_lock);
		return -EINVAL;
	}

	mem = kh_val(hdev->mem_table_host, k);
	kh_del(ptr64, hdev->mem_table_host, k);

	pthread_mutex_unlock(&hdev->mem_table_host_lock);

	rc = hlthunk_memory_unmap(fd, mem->device_virt_addr);
	if (rc) {
		printf("Failed to unmap host memory\n");
		return rc;
	}

	if (mem->is_huge)
		munmap(mem->host_ptr, mem->size);
	else
		free(mem->host_ptr);

	hlthunk_free(mem);

	return 0;
}

/**
 * This function frees device memory allocation which were done using
 * hltests_allocate_device_mem
 * @param fd file descriptor of the device that this memory belongs to
 * @param vaddr device VA that points to the memory area
 * @return 0 for success, negative value for failure
 */
int hltests_free_device_mem(int fd, void *vaddr)
{
	const struct hltests_asic_funcs *asic;
	struct hltests_device *hdev;
	struct hltests_memory *mem;
	khint_t k;
	int rc;

	hdev = get_hdev_from_fd(fd);
	if (!hdev)
		return -ENODEV;

	asic = hdev->asic_funcs;

	pthread_mutex_lock(&hdev->mem_table_device_lock);

	k = kh_get(ptr64, hdev->mem_table_device, (uintptr_t) vaddr);
	if (k == kh_end(hdev->mem_table_device)) {
		pthread_mutex_unlock(&hdev->mem_table_device_lock);
		return -EINVAL;
	}

	mem = kh_val(hdev->mem_table_device, k);
	kh_del(ptr64, hdev->mem_table_device, k);

	pthread_mutex_unlock(&hdev->mem_table_device_lock);

	if (mem->is_pool) {
		asic->dram_pool_free(hdev, mem->device_virt_addr,
						mem->size);
	} else {
		rc = hlthunk_memory_unmap(fd, mem->device_virt_addr);
		if (rc) {
			printf("Failed to unmap device memory\n");
			return rc;
		}

		hlthunk_device_memory_free(fd, mem->device_handle);
	}

	hlthunk_free(mem);

	return 0;
}

/**
 * This function retrieves the device VA for a host memory area that was mapped
 * to the device
 * @param fd file descriptor of the device that the host memory is mapped to
 * @param vaddr host pointer that points to the memory area
 * @return virtual address in the device VA space representing this host memory
 * area. 0 for failure
 */
uint64_t hltests_get_device_va_for_host_ptr(int fd, void *vaddr)
{
	struct hltests_device *hdev;
	struct hltests_memory *mem;
	khint_t k;

	hdev = get_hdev_from_fd(fd);
	if (!hdev)
		return 0;

	pthread_mutex_lock(&hdev->mem_table_host_lock);

	k = kh_get(ptr64, hdev->mem_table_host, (uintptr_t) vaddr);
	if (k == kh_end(hdev->mem_table_host)) {
		pthread_mutex_unlock(&hdev->mem_table_host_lock);
		return 0;
	}

	mem = kh_val(hdev->mem_table_host, k);

	pthread_mutex_unlock(&hdev->mem_table_host_lock);

	return mem->device_virt_addr;
}

/**
 * This function creates a command buffer for a specific device. It also
 * supports creating internal command buffer, which is basically a block of
 * memory on the host which is DMA'd into the device memory
 * @param fd file descriptor of the device
 * @param cb_size the size of the command buffer
 * @param is_external true if CB is for external queue, false otherwise
 * @cb_internal_sram_address the address in the sram that the internal CB will
 *                           be executed from by the CS. If this parameter is
 *                           0, the CB will be located on the host
 * @return virtual address of the CB in the user process VA space, or NULL for
 *         failure
 */
void *hltests_create_cb(int fd, uint32_t cb_size,
				enum hltests_is_external is_external,
				uint64_t cb_internal_sram_address)
{
	struct hltests_device *hdev;
	struct hltests_cb *cb;
	int rc;
	khint_t k;

	hdev = get_hdev_from_fd(fd);
	if (!hdev)
		return NULL;

	cb = hlthunk_malloc(sizeof(*cb));
	if (!cb)
		return NULL;

	cb->cb_size = cb_size;
	cb->external = is_external;

	if (is_external) {
		rc = hlthunk_request_command_buffer(fd, cb->cb_size,
							&cb->cb_handle);
		if (rc)
			goto free_cb;

		cb->ptr = hltests_cb_mmap(fd, cb->cb_size, cb->cb_handle);
		if (cb->ptr == MAP_FAILED)
			goto destroy_cb;
	} else {
		cb->ptr = hltests_allocate_host_mem(fd, cb_size, NOT_HUGE);
		if (!cb->ptr)
			goto free_cb;

		if (cb_internal_sram_address)
			cb->cb_handle = cb_internal_sram_address;
		else
			cb->cb_handle =
				hltests_get_device_va_for_host_ptr(fd, cb->ptr);
	}

	pthread_mutex_lock(&hdev->cb_table_lock);

	k = kh_put(ptr64, hdev->cb_table, (uint64_t) (uintptr_t) cb->ptr, &rc);
	kh_val(hdev->cb_table, k) = cb;

	pthread_mutex_unlock(&hdev->cb_table_lock);

	return cb->ptr;

destroy_cb:
	hlthunk_destroy_command_buffer(fd, cb->cb_handle);
free_cb:
	hlthunk_free(cb);
	return NULL;
}

int hltests_destroy_cb(int fd, void *ptr)
{
	struct hltests_device *hdev;
	struct hltests_cb *cb;
	khint_t k;

	hdev = get_hdev_from_fd(fd);
	if (!hdev)
		return -ENODEV;

	pthread_mutex_lock(&hdev->cb_table_lock);

	k = kh_get(ptr64, hdev->cb_table, (uint64_t) (uintptr_t) ptr);
	if (k == kh_end(hdev->cb_table)) {
		pthread_mutex_unlock(&hdev->cb_table_lock);
		return -EINVAL;
	}

	cb = kh_val(hdev->cb_table, k);
	kh_del(ptr64, hdev->cb_table, k);

	pthread_mutex_unlock(&hdev->cb_table_lock);

	if (cb->external) {
		hltests_cb_munmap(cb->ptr, cb->cb_size);
		hlthunk_destroy_command_buffer(fd, cb->cb_handle);
	} else {
		hltests_free_host_mem(fd, cb->ptr);
	}

	hlthunk_free(cb);

	return 0;
}

uint32_t hltests_add_packet_to_cb(void *ptr, uint32_t offset, void *pkt,
					uint32_t pkt_size)
{
	memcpy((uint8_t *) ptr + offset, pkt, pkt_size);

	return offset + pkt_size;
}

static int fill_cs_chunk(struct hltests_device *hdev,
		struct hl_cs_chunk *chunk, void *cb_ptr, uint32_t cb_size,
		uint32_t queue_index)
{
	struct hltests_cb *cb;
	khint_t k;

	pthread_mutex_lock(&hdev->cb_table_lock);

	k = kh_get(ptr64, hdev->cb_table, (uint64_t) (uintptr_t) cb_ptr);
	if (k == kh_end(hdev->cb_table)) {
		pthread_mutex_unlock(&hdev->cb_table_lock);

		/* Can't find matching handle so treat this as address */
		chunk->cb_handle = (__u64) cb_ptr;
		goto out;
	}

	cb = kh_val(hdev->cb_table, k);

	pthread_mutex_unlock(&hdev->cb_table_lock);

	chunk->cb_handle = cb->cb_handle;

out:
	chunk->queue_index = queue_index;
	chunk->cb_size = cb_size;

	return 0;
}

static int fill_cs_chunks(struct hltests_device *hdev,
			struct hl_cs_chunk *submit_arr,
			struct hltests_cs_chunk *chunks_arr,
			uint32_t num_chunks)
{
	int i, rc;

	for (i = 0 ; i < num_chunks ; i++) {
		rc = fill_cs_chunk(hdev, &submit_arr[i],
				chunks_arr[i].cb_ptr,
				chunks_arr[i].cb_size,
				chunks_arr[i].queue_index);
		if (rc)
			return rc;
	}

	return 0;
}

int hltests_submit_legacy_cs(int fd,
		struct hltests_cs_chunk *restore_arr,
		uint32_t restore_arr_size,
		struct hltests_cs_chunk *execute_arr,
		uint32_t execute_arr_size,
		uint32_t flags,
		uint64_t *seq)
{
	struct hltests_device *hdev;
	struct hl_cs_chunk *chunks_restore = NULL, *chunks_execute = NULL;
	struct hlthunk_cs_in cs_in;
	struct hlthunk_cs_out cs_out;
	uint32_t size;
	int rc = 0;

	hdev = get_hdev_from_fd(fd);
	if (!hdev)
		return -ENODEV;

	if (!restore_arr_size && !execute_arr_size)
		return 0;

	if (restore_arr_size && restore_arr) {
		size = restore_arr_size * sizeof(*chunks_restore);
		chunks_restore = hlthunk_malloc(size);
		if (!chunks_restore) {
			rc = -ENOMEM;
			goto out;
		}

		rc = fill_cs_chunks(hdev, chunks_restore, restore_arr,
				restore_arr_size);
		if (rc)
			goto free_chunks_restore;
	}

	if (execute_arr_size && execute_arr) {
		size = execute_arr_size * sizeof(*chunks_execute);
		chunks_execute = hlthunk_malloc(size);
		if (!chunks_execute) {
			rc = -ENOMEM;
			goto free_chunks_restore;
		}

		rc = fill_cs_chunks(hdev, chunks_execute, execute_arr,
				execute_arr_size);
		if (rc)
			goto free_chunks_execute;
	}

	memset(&cs_in, 0, sizeof(cs_in));
	cs_in.chunks_restore = chunks_restore;
	cs_in.chunks_execute = chunks_execute;
	cs_in.num_chunks_restore = restore_arr_size;
	cs_in.num_chunks_execute = execute_arr_size;
	cs_in.flags = flags;

	memset(&cs_out, 0, sizeof(cs_out));
	rc = hlthunk_command_submission(fd, &cs_in, &cs_out);
	if (rc)
		goto free_chunks_execute;

	if (cs_out.status != HL_CS_STATUS_SUCCESS) {
		rc = -EINVAL;
		goto free_chunks_execute;
	}

	*seq = cs_out.seq;

free_chunks_execute:
	hlthunk_free(chunks_execute);
free_chunks_restore:
	hlthunk_free(chunks_restore);
out:
	return rc;
}

int hltests_submit_cs(int fd,
		struct hltests_cs_chunk *restore_arr,
		uint32_t restore_arr_size,
		struct hltests_cs_chunk *execute_arr,
		uint32_t execute_arr_size,
		uint32_t flags,
		uint64_t *seq)
{
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	return asic->submit_cs(fd, restore_arr, restore_arr_size, execute_arr,
						execute_arr_size, flags, seq);
}

int hltests_submit_staged_cs(int fd,
		struct hltests_cs_chunk *restore_arr,
		uint32_t restore_arr_size,
		struct hltests_cs_chunk *execute_arr,
		uint32_t execute_arr_size,
		uint32_t flags,
		uint64_t staged_cs_seq,
		uint64_t *seq)
{
	struct hltests_device *hdev;
	struct hl_cs_chunk *chunks_restore = NULL, *chunks_execute = NULL;
	struct hlthunk_cs_in cs_in;
	struct hlthunk_cs_out cs_out;
	uint32_t size;
	int rc = 0;

	if (!(flags & HL_CS_FLAGS_STAGED_SUBMISSION)) {
		printf("Staged submission flags are not set");
		return -EINVAL;
	}

	hdev = get_hdev_from_fd(fd);
	if (!hdev)
		return -ENODEV;

	if (!restore_arr_size && !execute_arr_size)
		return 0;

	if (restore_arr_size && restore_arr) {
		size = restore_arr_size * sizeof(*chunks_restore);
		chunks_restore = hlthunk_malloc(size);
		if (!chunks_restore) {
			rc = -ENOMEM;
			goto out;
		}

		rc = fill_cs_chunks(hdev, chunks_restore, restore_arr,
				restore_arr_size);
		if (rc)
			goto free_chunks_restore;
	}

	if (execute_arr_size && execute_arr) {
		size = execute_arr_size * sizeof(*chunks_execute);
		chunks_execute = hlthunk_malloc(size);
		if (!chunks_execute) {
			rc = -ENOMEM;
			goto free_chunks_restore;
		}

		rc = fill_cs_chunks(hdev, chunks_execute, execute_arr,
				execute_arr_size);
		if (rc)
			goto free_chunks_execute;
	}

	memset(&cs_in, 0, sizeof(cs_in));
	cs_in.chunks_restore = chunks_restore;
	cs_in.chunks_execute = chunks_execute;
	cs_in.num_chunks_restore = restore_arr_size;
	cs_in.num_chunks_execute = execute_arr_size;
	cs_in.flags = flags;

	memset(&cs_out, 0, sizeof(cs_out));
	rc = hlthunk_staged_command_submission(fd, staged_cs_seq,
						&cs_in, &cs_out);
	if (rc)
		goto free_chunks_execute;

	if (cs_out.status != HL_CS_STATUS_SUCCESS) {
		rc = -EINVAL;
		goto free_chunks_execute;
	}

	*seq = cs_out.seq;

free_chunks_execute:
	hlthunk_free(chunks_execute);
free_chunks_restore:
	hlthunk_free(chunks_restore);
out:
	return rc;
}

int hltests_wait_for_legacy_cs(int fd, uint64_t seq, uint64_t timeout_us)
{
	uint32_t status;
	int rc;

	rc = hlthunk_wait_for_cs(fd, seq, timeout_us, &status);
	if (rc && errno != ETIMEDOUT && errno != EIO)
		return rc;

	return status;
}

int hltests_wait_for_cs(int fd, uint64_t seq, uint64_t timeout_us)
{
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	return asic->wait_for_cs(fd, seq, timeout_us);
}

int hltests_wait_for_cs_until_not_busy(int fd, uint64_t seq)
{
	int status;

	do {
		status = hltests_wait_for_cs(fd, seq,
					WAIT_FOR_CS_DEFAULT_TIMEOUT);
	} while (status == HL_WAIT_CS_STATUS_BUSY);

	return status;
}

uint32_t hltests_add_nop_pkt(int fd, void *buffer, uint32_t buf_off,
				enum hltests_eb eb, enum hltests_mb mb)
{
	const struct hltests_asic_funcs *asic =
			get_hdev_from_fd(fd)->asic_funcs;

	return asic->add_nop_pkt(buffer, buf_off, eb, mb);
}

uint32_t hltests_add_wreg32_pkt(int fd, void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	const struct hltests_asic_funcs *asic =
			get_hdev_from_fd(fd)->asic_funcs;

	return asic->add_wreg32_pkt(buffer, buf_off, pkt_info);
}

uint32_t hltests_add_arb_point_pkt(int fd, void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	const struct hltests_asic_funcs *asic =
			get_hdev_from_fd(fd)->asic_funcs;

	return asic->add_arb_point_pkt(buffer, buf_off, pkt_info);
}

uint32_t hltests_add_msg_long_pkt(int fd, void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	const struct hltests_asic_funcs *asic =
			get_hdev_from_fd(fd)->asic_funcs;

	return asic->add_msg_long_pkt(buffer, buf_off, pkt_info);
}

uint32_t hltests_add_msg_short_pkt(int fd, void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	const struct hltests_asic_funcs *asic =
			get_hdev_from_fd(fd)->asic_funcs;

	return asic->add_msg_short_pkt(buffer, buf_off, pkt_info);
}

uint32_t hltests_add_arm_monitor_pkt(int fd, void *buffer,
					uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	const struct hltests_asic_funcs *asic =
			get_hdev_from_fd(fd)->asic_funcs;

	return asic->add_arm_monitor_pkt(buffer, buf_off, pkt_info);
}

uint32_t hltests_add_write_to_sob_pkt(int fd, void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	const struct hltests_asic_funcs *asic =
			get_hdev_from_fd(fd)->asic_funcs;

	return asic->add_write_to_sob_pkt(buffer, buf_off, pkt_info);
}

uint32_t hltests_add_fence_pkt(int fd, void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	const struct hltests_asic_funcs *asic =
			get_hdev_from_fd(fd)->asic_funcs;

	return asic->add_fence_pkt(buffer, buf_off, pkt_info);
}

uint32_t hltests_add_dma_pkt(int fd, void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	const struct hltests_asic_funcs *asic =
			get_hdev_from_fd(fd)->asic_funcs;

	return asic->add_dma_pkt(buffer, buf_off, pkt_info);
}

uint32_t hltests_add_cp_dma_pkt(int fd, void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	const struct hltests_asic_funcs *asic =
			get_hdev_from_fd(fd)->asic_funcs;

	return asic->add_cp_dma_pkt(buffer, buf_off, pkt_info);
}

uint32_t hltests_add_load_and_exe_pkt(int fd, void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	const struct hltests_asic_funcs *asic =
			get_hdev_from_fd(fd)->asic_funcs;

	return asic->add_load_and_exe_pkt(buffer, buf_off, pkt_info);
}

uint32_t hltests_add_monitor_and_fence(int fd, void *buffer, uint32_t buf_off,
		struct hltests_monitor_and_fence *mon_and_fence_info)
{
	const struct hltests_asic_funcs *asic =
			get_hdev_from_fd(fd)->asic_funcs;

	return asic->add_monitor_and_fence(DCORE_MODE_FULL_CHIP, buffer,
					buf_off, mon_and_fence_info);
}

uint32_t hltests_add_arb_en_pkt(int fd, void *buffer, uint32_t buf_off,
		struct hltests_pkt_info *pkt_info,
		struct hltests_arb_info *arb_info,
		uint32_t queue_id, bool enable)
{
	const struct hltests_asic_funcs *asic =
			get_hdev_from_fd(fd)->asic_funcs;

	return asic->add_arb_en_pkt(buffer, buf_off, pkt_info,
			arb_info, queue_id, enable);
}

uint32_t hltests_get_dma_down_qid(int fd, enum hltests_stream_id stream)
{
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_dma_down_qid(DCORE_MODE_FULL_CHIP, stream);
}

uint32_t hltests_get_dma_up_qid(int fd, enum hltests_stream_id stream)
{
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_dma_up_qid(DCORE_MODE_FULL_CHIP, stream);
}

uint32_t hltests_get_ddma_qid(int fd, int dma_ch, enum hltests_stream_id stream)
{
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_ddma_qid(DCORE_MODE_FULL_CHIP, dma_ch,	stream);
}

uint8_t hltests_get_ddma_cnt(int fd)
{
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_ddma_cnt(DCORE_MODE_FULL_CHIP);
}

uint32_t hltests_get_tpc_qid(int fd, uint8_t tpc_id,
				enum hltests_stream_id stream)
{
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_tpc_qid(DCORE_MODE_FULL_CHIP, tpc_id, stream);
}

uint32_t hltests_get_mme_qid(int fd, uint8_t mme_id,
				enum hltests_stream_id stream)
{
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_mme_qid(DCORE_MODE_FULL_CHIP, mme_id, stream);
}

uint8_t hltests_get_tpc_cnt(int fd)
{
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_tpc_cnt(DCORE_MODE_FULL_CHIP);
}

uint8_t hltests_get_mme_cnt(int fd)
{
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_mme_cnt(DCORE_MODE_FULL_CHIP);
}

uint16_t hltests_get_first_avail_sob(int fd)
{
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_first_avail_sob(DCORE_MODE_FULL_CHIP);
}

uint16_t hltests_get_first_avail_mon(int fd)
{
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_first_avail_mon(DCORE_MODE_FULL_CHIP);
}

uint32_t hltests_rand_u32(void)
{
	uint32_t val;

	pthread_spin_lock(&rand_lock);
	val = rand_u32();
	pthread_spin_unlock(&rand_lock);

	return val;
}

void hltests_fill_rand_values(void *ptr, uint32_t size)
{
	uint32_t i, *p = ptr, rounddown_aligned_size, remainder, val;

	rounddown_aligned_size = size & ~(sizeof(uint32_t) - 1);
	remainder = size - rounddown_aligned_size;

	for (i = 0 ; i < rounddown_aligned_size ; i += sizeof(uint32_t), p++)
		*p = hltests_rand_u32();

	if (!remainder)
		return;

	val = hltests_rand_u32();
	for (i = 0 ; i < remainder ; i++) {
		((uint8_t *) p)[i] = (uint8_t) (val & 0xff);
		val >>= 8;
	}
}

void hltests_fill_seq_values(void *ptr, uint32_t size)
{
	uint32_t i, *p = ptr, rounddown_aligned_size, remainder, val;

	rounddown_aligned_size = size & ~(sizeof(uint32_t) - 1);
	remainder = size - rounddown_aligned_size;

	for (i = 0 ; i < rounddown_aligned_size ; i += sizeof(uint32_t), p++)
		*p = i / 4;

	if (!remainder)
		return;

	val = i / 4;
	for (i = 0 ; i < remainder ; i++) {
		((uint8_t *) p)[i] = (uint8_t) (val & 0xff);
		val >>= 8;
	}
}

int hltests_mem_compare_with_stop(void *ptr1, void *ptr2, uint64_t size,
					bool stop_on_err)
{
	uint64_t *p1 = (uint64_t *) ptr1, *p2 = (uint64_t *) ptr2;
	uint32_t err_cnt = 0, rounddown_aligned_size, remainder, i = 0;

	rounddown_aligned_size = size & ~(sizeof(uint64_t) - 1);
	remainder = size - rounddown_aligned_size;

	while (i < rounddown_aligned_size) {
		if (*p1 != *p2) {
			printf("[%p]: 0x%"PRIx64" <--> [%p]: 0x%"PRIx64"\n",
				p1, *p1, p2, *p2);
			err_cnt++;
		}

		i += sizeof(uint64_t);
		p1++;
		p2++;

		if (stop_on_err && err_cnt >= 10)
			break;
	}

	if (!remainder)
		return err_cnt;

	for (i = 0 ; i < remainder ; i++) {
		if (((uint8_t *) p1)[i] != ((uint8_t *) p2)[i]) {
			printf("[%p]: 0x%hhx <--> [%p]: 0x%hhx\n",
				(uint8_t *) p1 + i, ((uint8_t *) p1)[i],
				(uint8_t *) p2 + i, ((uint8_t *) p2)[i]);
			err_cnt++;
		}
	}

	return err_cnt;
}

int hltests_mem_compare(void *ptr1, void *ptr2, uint64_t size)
{
	return hltests_mem_compare_with_stop(ptr1, ptr2, size, true);
}

void hltests_dma_transfer(int fd, uint32_t queue_index, enum hltests_eb eb,
				enum hltests_mb mb,
				uint64_t src_addr, uint64_t dst_addr,
				uint32_t size,
				enum hltests_goya_dma_direction dma_dir)
{
	uint32_t offset = 0;
	void *ptr;
	struct hltests_pkt_info pkt_info;

	ptr = hltests_create_cb(fd, getpagesize(), EXTERNAL, 0);
	assert_non_null(ptr);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = eb;
	pkt_info.mb = mb;
	pkt_info.dma.src_addr = src_addr;
	pkt_info.dma.dst_addr = dst_addr;
	pkt_info.dma.size = size;
	pkt_info.dma.dma_dir = dma_dir;
	offset = hltests_add_dma_pkt(fd, ptr, offset, &pkt_info);

	hltests_submit_and_wait_cs(fd, ptr, offset, queue_index,
				DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_COMPLETED);
}

void hltests_dma_dram_frag_mem_test(void **state, uint64_t size)
{
	void **frag_arr;
	struct hlthunk_hw_ip_info hw_ip;
	uint32_t i, frag_arr_size, page_num, rand;
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int rc, fd = tests_state->fd;

	/* Create fragmented device physical memory.
	 * Allocate FRAG_MEM_MULT times more memory in advance and free randomly
	 * the amount of memory required for the test inside this area to create
	 * fragmentation.
	 */

	if (hltests_is_pldm(fd) && size > PLDM_MAX_DMA_SIZE_FOR_TESTING)
		skip();

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);
	page_num = size / hw_ip.dram_page_size;
	assert_int_not_equal(page_num, 0);
	frag_arr_size = page_num * FRAG_MEM_MULT;
	frag_arr = hlthunk_malloc(frag_arr_size * sizeof(*frag_arr));
	assert_non_null(frag_arr);

	for (i = 0; i < frag_arr_size; i++) {
		frag_arr[i] = hltests_allocate_device_mem(fd,
					hw_ip.dram_page_size,
					NOT_CONTIGUOUS);
		assert_non_null(frag_arr[i]);
	}

	i = 0;
	while (i < page_num) {
		rand = hltests_rand_u32() % frag_arr_size;
		while (!frag_arr[rand])
			rand = (rand + 1) % frag_arr_size;
		rc = hltests_free_device_mem(fd, frag_arr[rand]);
		assert_int_equal(rc, 0);
		frag_arr[rand] = NULL;
		i++;
	}

	hltests_dma_test(state, true, size);

	for (i = 0; i < frag_arr_size; i++) {
		if (!frag_arr[i])
			continue;
		rc = hltests_free_device_mem(fd, frag_arr[i]);
		assert_int_equal(rc, 0);
	}
	hlthunk_free(frag_arr);
}

void hltests_dma_dram_high_mem_test(void **state, uint64_t size)
{
	struct hlthunk_hw_ip_info hw_ip;
	void *device_addr;
	uint64_t alloc_size;
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int rc, fd = tests_state->fd;

	/* Allocate half size of device memory so that test allocation
	 * will begin from high memory address
	 */

	if (hltests_is_pldm(fd) && size > PLDM_MAX_DMA_SIZE_FOR_TESTING)
		skip();

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);
	alloc_size = hw_ip.dram_size / 2;
	device_addr = hltests_allocate_device_mem(fd, alloc_size,
								NOT_CONTIGUOUS);
	assert_non_null(device_addr);

	hltests_dma_test(state, true, size);

	rc = hltests_free_device_mem(fd, device_addr);
	assert_int_equal(rc, 0);
}

int hltests_dma_test(void **state, bool is_ddr, uint64_t size)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	void *device_addr, *src_ptr, *dst_ptr;
	uint64_t host_src_addr, host_dst_addr;
	uint32_t dma_dir_down, dma_dir_up;
	bool is_huge = !!((size > SZ_32K) && (size < SZ_1G));
	int rc, fd = tests_state->fd;

	if (hltests_is_pldm(fd) && size > PLDM_MAX_DMA_SIZE_FOR_TESTING)
		skip();

	/* Sanity and memory allocation */
	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (is_ddr) {
		if (!hw_ip.dram_enabled) {
			printf("DRAM is disabled so skipping test\n");
			skip();
		}

		assert_in_range(size, 1, hw_ip.dram_size);

		device_addr = hltests_allocate_device_mem(fd, size,
								NOT_CONTIGUOUS);
		assert_non_null(device_addr);

		dma_dir_down = GOYA_DMA_HOST_TO_DRAM;
		dma_dir_up = GOYA_DMA_DRAM_TO_HOST;
	} else {
		if (size > hw_ip.sram_size)
			skip();
		device_addr = (void *) (uintptr_t) hw_ip.sram_base_address;

		dma_dir_down = GOYA_DMA_HOST_TO_SRAM;
		dma_dir_up = GOYA_DMA_SRAM_TO_HOST;
	}

	src_ptr = hltests_allocate_host_mem(fd, size, is_huge);
	assert_non_null(src_ptr);
	hltests_fill_rand_values(src_ptr, size);
	host_src_addr = hltests_get_device_va_for_host_ptr(fd, src_ptr);

	dst_ptr = hltests_allocate_host_mem(fd, size, is_huge);
	assert_non_null(dst_ptr);
	memset(dst_ptr, 0, size);
	host_dst_addr = hltests_get_device_va_for_host_ptr(fd, dst_ptr);

	/* DMA: host->device */
	hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, STREAM0),
			EB_FALSE, MB_TRUE, host_src_addr,
			(uint64_t) (uintptr_t) device_addr,
			size, dma_dir_down);

	/* DMA: device->host */
	hltests_dma_transfer(fd, hltests_get_dma_up_qid(fd, STREAM0),
			EB_FALSE, MB_TRUE, (uint64_t) (uintptr_t) device_addr,
			host_dst_addr, size, dma_dir_up);

	/* Compare host memories */
	rc = hltests_mem_compare(src_ptr, dst_ptr, size);
	assert_int_equal(rc, 0);

	/* Cleanup */
	rc = hltests_free_host_mem(fd, dst_ptr);
	assert_int_equal(rc, 0);
	rc = hltests_free_host_mem(fd, src_ptr);
	assert_int_equal(rc, 0);

	if (is_ddr) {
		rc = hltests_free_device_mem(fd, device_addr);
		assert_int_equal(rc, 0);
	}

	return 0;
}

/**
 * This function submits a single command buffer for a specific queue, and
 * waits for it.
 * @param fd file descriptor of the device
 * @param cb_ptr a pointer to the command buffer
 * @param cb_size the size of the command buffer
 * @param queue_index the allocated queue for the command submission
 * @param destroy_cb true if CB should be destroyed, false otherwise
 * @return void
 */
void hltests_submit_and_wait_cs(int fd, void *cb_ptr, uint32_t cb_size,
				uint32_t queue_index,
				enum hltests_destroy_cb destroy_cb,
				int expected_val)
{
	struct hltests_cs_chunk execute_arr[1];
	uint64_t seq = 0;
	int rc;

	execute_arr[0].cb_ptr = cb_ptr;
	execute_arr[0].cb_size = cb_size;
	execute_arr[0].queue_index = queue_index;

	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, 1, 0, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, expected_val);

	if (destroy_cb) {
		rc = hltests_destroy_cb(fd, cb_ptr);
		assert_int_equal(rc, 0);
	}
}

static bool is_dev_idle_and_operational(int fd)
{
	enum hl_device_status dev_status;
	bool is_idle;
	enum hl_pci_ids device_id;

	/* TODO: Remove when is_idle function is implemented on simulator */
	device_id = hlthunk_get_device_id_from_fd(fd);
	if (device_id == PCI_IDS_GOYA_SIMULATOR ||
			device_id == PCI_IDS_GAUDI_SIMULATOR)
		is_idle = true;
	else
		is_idle = hlthunk_is_device_idle(fd);

	dev_status = hlthunk_get_device_status_info(fd);

	return (is_idle && dev_status == HL_DEVICE_STATUS_OPERATIONAL);
}

int hltests_ensure_device_operational(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hltests_module_params_info module_params;
	uint32_t timeout_locked, i;
	int fd = tests_state->fd, rc;

	if (is_dev_idle_and_operational(fd))
		return 0;

	memset(&module_params, 0, sizeof(module_params));
	rc = hltests_get_module_params_info(fd, &module_params);
	if (rc) {
		printf("Failed to retrieve values of module parameters\n");
		return errno;
	}

	timeout_locked = module_params.timeout_locked;
	if (timeout_locked > 1000)
		timeout_locked = 1000;

	for (i = 0 ; i <= timeout_locked ; i++) {
		sleep(1);
		if (is_dev_idle_and_operational(fd))
			return 0;
	}

	/* If we got here it means that something is broken */
	printf("ERROR! Something broke in the device, stop running tests\n");
	exit(-1);
}

void *hltests_mem_pool_init(uint64_t start_addr, uint64_t size, uint8_t order)
{
	struct mem_pool *mem_pool;
	uint64_t page_size;
	int rc;

	assert_in_range(order, PAGE_SHIFT_4KB, PAGE_SHIFT_16MB);

	page_size = 1ull << order;

	if (size < page_size) {
		printf("pool size should be at least one order size\n");
		return NULL;
	}

	mem_pool = calloc(1, sizeof(struct mem_pool));
	if (!mem_pool)
		return NULL;

	mem_pool->start = start_addr;
	mem_pool->page_size = page_size;
	mem_pool->pool_npages = (size + (page_size - 1)) >> order;
	mem_pool->pool = calloc(mem_pool->pool_npages, 1);
	if (!mem_pool->pool)
		goto free_struct;

	rc = pthread_mutex_init(&mem_pool->lock, NULL);
	if (rc)
		goto free_pool;

	return mem_pool;

free_pool:
	free(mem_pool->pool);
free_struct:
	free(mem_pool);

	return NULL;
}

void hltests_mem_pool_fini(void *data)
{
	struct mem_pool *mem_pool = (struct mem_pool *) data;

	pthread_mutex_destroy(&mem_pool->lock);
	free(mem_pool->pool);
	free(mem_pool);
}

int hltests_mem_pool_alloc(void *data, uint64_t size, uint64_t *addr)
{
	struct mem_pool *mem_pool = (struct mem_pool *) data;
	uint32_t needed_npages, curr_npages, i, j, k;
	bool found = false;

	needed_npages = (size + mem_pool->page_size - 1) / mem_pool->page_size;

	pthread_mutex_lock(&mem_pool->lock);

	for (i = 0 ; i < mem_pool->pool_npages ; i++) {
		for (j = i, curr_npages = 0 ; j < mem_pool->pool_npages ; j++) {
			if (mem_pool->pool[j]) {
				i = j;
				break;
			}

			curr_npages++;

			if (curr_npages == needed_npages) {
				for (k = i ; k <= j ; k++)
					mem_pool->pool[k] = 1;

				found = true;
				break;
			}
		}

		if (found) {
			/* cast to avoid int overflow */
			*addr = mem_pool->start +
					((uint64_t) i) * mem_pool->page_size;
			break;
		}

	}

	pthread_mutex_unlock(&mem_pool->lock);

	return found ? 0 : -ENOMEM;
}

void hltests_mem_pool_free(void *data, uint64_t addr, uint64_t size)
{
	struct mem_pool *mem_pool = (struct mem_pool *) data;
	uint32_t start_page, npages, i;

	start_page = (addr - mem_pool->start) / mem_pool->page_size;
	npages = (size + mem_pool->page_size - 1) / mem_pool->page_size;

	pthread_mutex_lock(&mem_pool->lock);

	for (i = start_page ; i < (start_page + npages) ; i++)
		mem_pool->pool[i] = 0;

	pthread_mutex_unlock(&mem_pool->lock);
}

void hltests_parser(int argc, const char **argv, const char * const* usage,
			enum hlthunk_device_name expected_device,
			const struct CMUnitTest * const tests, int num_tests)
{
	struct argparse argparse;
	const char *test = NULL;
	int list = 0;
	int i;

	struct argparse_option options[] = {
		OPT_HELP(),
		OPT_GROUP("Basic options"),
		OPT_BOOLEAN('l', "list", &list, "list tests"),
		OPT_BOOLEAN('d', "disabled", &run_disabled_tests,
			"run disabled tests"),
		OPT_STRING('s', "test", &test, "name of specific test to run"),
		OPT_STRING('p', "pciaddr", &parser_pciaddr,
			"pci address of device"),
		OPT_STRING('c', "config", &config_filename,
			"config filename for test(s)"),
		OPT_INTEGER('n', "ndevices", &num_devices, "number of devices"),
		OPT_BOOLEAN('m', "mode", &legacy_mode_enabled,
							"Legacy mode enabled"),
		OPT_END(),
	};

	argparse_init(&argparse, options, usage, 0);
	argparse_describe(&argparse, "\nRun tests using hl-thunk", NULL);
	argc = argparse_parse(&argparse, argc, argv);

	if (list) {
		printf("\nList of tests:");
		printf("\n-----------------\n\n");
		for (i = 0 ; i < num_tests ; i++)
			printf("%s\n", tests[i].name);
		printf("\n");
		exit(0);
	}

	asic_name_for_testing = expected_device;

	if (test)
		cmocka_set_test_filter(test);

	/*
	 * TODO:
	 * Remove when providing multiple PCI bus addresses is supported.
	 */
	if (num_devices > 1 &&  parser_pciaddr) {
		printf(
			"The '--pciaddr' and '--ndevices' options cannot coexist\n");
		exit(-1);
	}
}

const char *hltests_get_parser_pciaddr(void)
{
	return parser_pciaddr;
}

const char *hltests_get_config_filename(void)
{
	return config_filename;
}

int hltests_get_parser_run_disabled_tests(void)
{
	return run_disabled_tests;
}

int hltests_is_legacy_mode_enabled(void)
{
	return legacy_mode_enabled;
}

bool hltests_is_simulator(int fd)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);

	if (hdev->device_id == PCI_IDS_GOYA_SIMULATOR ||
		hdev->device_id == PCI_IDS_GAUDI_SIMULATOR)
		return true;

	return false;
}

bool hltests_is_goya(int fd)
{
	return (hlthunk_get_device_name_from_fd(fd) == HLTHUNK_DEVICE_GOYA);
}

bool hltests_is_gaudi(int fd)
{
	return (hlthunk_get_device_name_from_fd(fd) == HLTHUNK_DEVICE_GAUDI);
}

bool hltests_is_pldm(int fd)
{
	struct hltests_module_params_info module_params;
	int rc;

	rc = hltests_get_module_params_info(fd, &module_params);
	assert_int_equal(rc, 0);

	return !!module_params.pldm;
}

void test_sm_pingpong_common_cp(void **state, bool is_tpc,
				bool common_cb_in_host, uint8_t engine_id)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	struct hltests_cs_chunk restore_arr[1], execute_arr[3];
	struct hltests_pkt_info pkt_info;
	struct hltests_monitor_and_fence mon_and_fence_info;
	void *host_src, *host_dst, *engine_common_cb, *engine_upper_cb,
		*restore_cb, *dmadown_cb, *dmaup_cb;
	uint64_t seq = 0, host_src_device_va, host_dst_device_va,
		device_data_addr,
		engine_common_cb_sram_addr, engine_common_cb_device_va,
		engine_upper_cb_sram_addr, engine_upper_cb_device_va;
	uint32_t engine_qid, dma_size, engine_common_cb_size,
		engine_upper_cb_size, restore_cb_size, dmadown_cb_size,
		dmaup_cb_size;
	uint16_t sob[2], mon[2];
	int rc, fd = tests_state->fd;

	/* Check conditions if CB is in the host */
	if (common_cb_in_host) {

		/* This test can't run on Goya */
		if (hlthunk_get_device_name_from_fd(fd) ==
						HLTHUNK_DEVICE_GOYA) {
			printf(
				"Test is skipped. Goya's common CP can't be in host\n");
			skip();
		}

		/* This test can't run if mmu disabled */
		if (!tests_state->mmu) {
			printf(
				"Test is skipped. MMU must be enabled\n");
			skip();
		}
	}

	/* SRAM MAP (base + ):
	 * - 0x1000               : data
	 * - 0x2000               : engine's upper CB (QMAN)
	 * - 0x3000               : engine's common CB (CMDQ)
	 *
	 * NOTE:
	 * The engine's common CB can be located on the host, depending on
	 * the common_cb_in_host flag
	 *
	 * Test Description:
	 * - First DMA QMAN transfers data from host to SRAM and then signals
	 *   SOB0.
	 * - Engine QMAN process CP_DMA packet and transfer internal CB to CMDQ.
	 * - Engine CMDQ fences on SOB0, processes NOP packet, and then signals
	 *   SOB8.
	 * - Second DMA QMAN fences on SOB1 and then transfers data from SRAM to
	 *   host.
	 * - Setup CB is used to clear SOB0, 1 and to DMA the internal CBs to
	 *   SRAM.
	 */

	dma_size = 4;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (is_tpc)
		engine_qid = hltests_get_tpc_qid(fd, engine_id, STREAM0);
	else
		engine_qid = hltests_get_mme_qid(fd, engine_id, STREAM0);

	device_data_addr = hw_ip.sram_base_address + 0x1000;
	engine_upper_cb_sram_addr = hw_ip.sram_base_address + 0x2000;
	engine_common_cb_sram_addr = hw_ip.sram_base_address + 0x3000;

	/* Allocate two buffers on the host for data transfers */
	host_src = hltests_allocate_host_mem(fd, dma_size, NOT_HUGE);
	assert_non_null(host_src);
	hltests_fill_rand_values(host_src, dma_size);
	host_src_device_va = hltests_get_device_va_for_host_ptr(fd, host_src);

	host_dst = hltests_allocate_host_mem(fd, dma_size, NOT_HUGE);
	assert_non_null(host_dst);
	memset(host_dst, 0, dma_size);
	host_dst_device_va = hltests_get_device_va_for_host_ptr(fd, host_dst);

	sob[0] = hltests_get_first_avail_sob(fd);
	sob[1] = hltests_get_first_avail_sob(fd) + 1;
	mon[0] = hltests_get_first_avail_mon(fd);
	mon[1] = hltests_get_first_avail_mon(fd) + 1;

	/* Allocate memory on the host for the common CB. Either the ASIC will
	 * fetch it directly from the host, or we will download it to SRAM and
	 * the ASIC will run it from there
	 */
	engine_common_cb = hltests_allocate_host_mem(fd, 0x1000, NOT_HUGE);
	assert_non_null(engine_common_cb);
	memset(engine_common_cb, 0, 0x1000);
	engine_common_cb_device_va = hltests_get_device_va_for_host_ptr(fd,
							engine_common_cb);

	engine_common_cb_size = 0;
	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = engine_qid;
	mon_and_fence_info.cmdq_fence = true;
	mon_and_fence_info.sob_id = sob[0];
	mon_and_fence_info.mon_id = mon[0];
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.sob_val = 1;
	mon_and_fence_info.dec_fence = true;
	mon_and_fence_info.mon_payload = 1;
	engine_common_cb_size = hltests_add_monitor_and_fence(fd,
							engine_common_cb,
							engine_common_cb_size,
							&mon_and_fence_info);

	engine_common_cb_size = hltests_add_nop_pkt(fd, engine_common_cb,
							engine_common_cb_size,
							EB_FALSE, MB_TRUE);
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.write_to_sob.sob_id = sob[0] + 1;
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_ADD;
	engine_common_cb_size = hltests_add_write_to_sob_pkt(fd,
							engine_common_cb,
							engine_common_cb_size,
							&pkt_info);

	/* Upper CB for engine: CP_DMA */
	engine_upper_cb = hltests_create_cb(fd, SZ_4K, INTERNAL,
						engine_upper_cb_sram_addr);
	assert_non_null(engine_upper_cb);
	engine_upper_cb_device_va =
			hltests_get_device_va_for_host_ptr(fd, engine_upper_cb);
	engine_upper_cb_size = 0;

	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	if (common_cb_in_host)
		pkt_info.cp_dma.src_addr = engine_common_cb_device_va;
	else
		pkt_info.cp_dma.src_addr = engine_common_cb_sram_addr;
	pkt_info.cp_dma.size = engine_common_cb_size;
	engine_upper_cb_size = hltests_add_cp_dma_pkt(fd, engine_upper_cb,
						engine_upper_cb_size,
						&pkt_info);

	hltests_clear_sobs(fd, 2);

	/* Setup CB: DMA the internal CBs to SRAM */
	restore_cb =  hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	assert_non_null(restore_cb);
	restore_cb_size = 0;

	if (!common_cb_in_host) {
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_TRUE;
		pkt_info.dma.src_addr = engine_common_cb_device_va;
		pkt_info.dma.dst_addr = engine_common_cb_sram_addr;
		pkt_info.dma.size = engine_common_cb_size;
		pkt_info.dma.dma_dir = GOYA_DMA_HOST_TO_SRAM;
		restore_cb_size = hltests_add_dma_pkt(fd, restore_cb,
						restore_cb_size, &pkt_info);
	}

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.dma.src_addr = engine_upper_cb_device_va;
	pkt_info.dma.dst_addr = engine_upper_cb_sram_addr;
	pkt_info.dma.size = engine_upper_cb_size;
	pkt_info.dma.dma_dir = GOYA_DMA_HOST_TO_SRAM;
	restore_cb_size = hltests_add_dma_pkt(fd, restore_cb, restore_cb_size,
						&pkt_info);

	/* CB for first DMA QMAN:
	 * Transfer data from host to SRAM + signal SOB0.
	 */
	dmadown_cb = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	assert_non_null(dmadown_cb);
	dmadown_cb_size = 0;

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.dma.src_addr = host_src_device_va;
	pkt_info.dma.dst_addr = device_data_addr;
	pkt_info.dma.size = dma_size;
	pkt_info.dma.dma_dir = GOYA_DMA_HOST_TO_SRAM;
	dmadown_cb_size = hltests_add_dma_pkt(fd, dmadown_cb, dmadown_cb_size,
						&pkt_info);
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_FALSE;
	pkt_info.write_to_sob.sob_id = sob[0];
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_ADD;
	dmadown_cb_size = hltests_add_write_to_sob_pkt(fd, dmadown_cb,
						dmadown_cb_size, &pkt_info);

	/* CB for second DMA QMAN:
	 * Fence on SOB1 + transfer data from SRAM to host.
	 */
	dmaup_cb = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	assert_non_null(dmaup_cb);
	dmaup_cb_size = 0;
	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = hltests_get_dma_up_qid(fd, STREAM0);
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = sob[0] + 1;
	mon_and_fence_info.mon_id = mon[0] + 1;
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.sob_val = 1;
	mon_and_fence_info.dec_fence = true;
	mon_and_fence_info.mon_payload = 1;
	dmaup_cb_size = hltests_add_monitor_and_fence(fd, dmaup_cb,
				dmaup_cb_size, &mon_and_fence_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.dma.src_addr = device_data_addr;
	pkt_info.dma.dst_addr = host_dst_device_va;
	pkt_info.dma.size = dma_size;
	pkt_info.dma.dma_dir = GOYA_DMA_SRAM_TO_HOST;
	dmaup_cb_size = hltests_add_dma_pkt(fd, dmaup_cb, dmaup_cb_size,
								&pkt_info);

	/* Submit CS and wait for completion */
	restore_arr[0].cb_ptr = restore_cb;
	restore_arr[0].cb_size = restore_cb_size;
	restore_arr[0].queue_index = hltests_get_dma_down_qid(fd, STREAM0);

	execute_arr[0].cb_ptr = dmadown_cb;
	execute_arr[0].cb_size = dmadown_cb_size;
	execute_arr[0].queue_index = hltests_get_dma_down_qid(fd, STREAM0);

	execute_arr[1].cb_ptr = engine_upper_cb;
	execute_arr[1].cb_size = engine_upper_cb_size;
	execute_arr[1].queue_index = engine_qid;

	execute_arr[2].cb_ptr = dmaup_cb;
	execute_arr[2].cb_size = dmaup_cb_size;
	execute_arr[2].queue_index = hltests_get_dma_up_qid(fd, STREAM0);

	rc = hltests_submit_cs(fd, restore_arr, 1, execute_arr, 3,
					HL_CS_FLAGS_FORCE_RESTORE, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	/* Compare host memories */
	rc = hltests_mem_compare(host_src, host_dst, dma_size);
	assert_int_equal(rc, 0);

	/* Cleanup */
	rc = hltests_destroy_cb(fd, engine_upper_cb);
	assert_int_equal(rc, 0);
	rc = hltests_destroy_cb(fd, restore_cb);
	assert_int_equal(rc, 0);
	rc = hltests_destroy_cb(fd, dmadown_cb);
	assert_int_equal(rc, 0);
	rc = hltests_destroy_cb(fd, dmaup_cb);
	assert_int_equal(rc, 0);

	rc = hltests_free_host_mem(fd, engine_common_cb);
	assert_int_equal(rc, 0);
	rc = hltests_free_host_mem(fd, host_dst);
	assert_int_equal(rc, 0);
	rc = hltests_free_host_mem(fd, host_src);
	assert_int_equal(rc, 0);
}

void hltests_clear_sobs(int fd, uint16_t num_of_sobs)
{
	struct hltests_pkt_info pkt_info;
	void *cb;
	uint32_t cb_offset = 0, i;
	uint16_t first_sob = hltests_get_first_avail_sob(fd);

	cb = hltests_create_cb(fd, HL_MAX_CB_SIZE, EXTERNAL, 0);
	assert_non_null(cb);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.write_to_sob.value = 0;
	pkt_info.write_to_sob.mode = SOB_SET;
	for (i = first_sob ; i < (first_sob + num_of_sobs - 1) ; i++) {
		pkt_info.write_to_sob.sob_id = i;
		cb_offset = hltests_add_write_to_sob_pkt(fd, cb, cb_offset,
								&pkt_info);
	}
	/* only the last mb should be true */
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id = i;
	cb_offset = hltests_add_write_to_sob_pkt(fd, cb, cb_offset, &pkt_info);

	hltests_submit_and_wait_cs(fd, cb, cb_offset,
		hltests_get_dma_down_qid(fd, STREAM0),
		DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_COMPLETED);

}

double get_timediff_sec(struct timespec *begin, struct timespec *end)
{
	return (end->tv_nsec - begin->tv_nsec) / 1000000000.0 +
						(end->tv_sec  - begin->tv_sec);
}

double get_bw_gigabyte_per_sec(uint64_t bytes, struct timespec *begin,
							struct timespec *end)
{
	/*
	 * calculation conforms to GB definition:
	 * 1 GB = 1000000000 bytes (= 1000^3 B = 10^9 B)
	 */
	return ((double)(bytes) / get_timediff_sec(begin, end)) /
						(1000 * 1000 * 1000);
}
