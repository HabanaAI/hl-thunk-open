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
#include <byteswap.h>
#include <immintrin.h>


#ifndef MAP_HUGE_2MB
	#define MAP_HUGE_2MB    (21 << MAP_HUGE_SHIFT)
#endif

#define FRAG_MEM_MULT 3

#define BUILD_PATH_MAX_LENGTH	128

#define CC_CMD_SIZE		20
#define CC_QPC_SIZE		4000
#define CC_POST_MSGS		3
#define CC_SQ_MAX_ELEMENTS_NUM	64

#define CC_BBR_VALID_BIT_BURST_SIZE	0
#define CC_BBR_VALID_BIT_SQN		1
#define CC_BBR_VALID_BIT_CONG_WIN	2
#define CC_BBR_VALID_BIT_PACE_TIME	3

#define CC_SWIFT_VALID_BIT_TARGET_DELAY	0
#define CC_SWIFT_VALID_BIT_AI		1
#define CC_SWIFT_VALID_BIT_BETA		2
#define CC_SWIFT_VALID_BIT_MAX_MDF	3

#define CC_MSG_TYPE_BBR			0
#define CC_MSG_TYPE_SWIFT		1

#ifndef HLTESTS_LIB_MODE
struct hltests_thread_params {
	const char *group_name;
	const struct CMUnitTest *tests;
	size_t num_tests;
	CMFixtureFunction group_setup;
	CMFixtureFunction group_teardown;
};
#endif

static pthread_mutex_t table_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t debugfs_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_spinlock_t rand_lock;
static khash_t(ptr) * dev_table;

static long asic_mask_for_testing = HLTEST_DEVICE_MASK_DONT_CARE;

#ifndef HLTESTS_LIB_MODE
static pthread_barrier_t barrier;

static int run_disabled_tests;
static int num_devices = 1;
#endif

static int verbose_enabled;
static const char *parser_pciaddr;
static const char *config_filename;
static int legacy_mode_enabled = 1;
static uint32_t cur_seed;
static const char *build_path;
static int enable_arc_log;

char asic_names[HLTHUNK_DEVICE_MAX][20] = {
	"Goya",
	"Placeholder1",
	"Gaudi",
	"Invalid",
	"Don't care",
	"Gaudi2"
};

/* translate device name (enum) to device mask */
unsigned long device_enum_to_device_mask[HLTHUNK_DEVICE_MAX] = {
	[HLTHUNK_DEVICE_INVALID] = HLTEST_DEVICE_MASK_INVALID,
	[HLTHUNK_DEVICE_GOYA] = HLTEST_DEVICE_MASK_GOYA,
	[HLTHUNK_DEVICE_GAUDI] = HLTEST_DEVICE_MASK_GAUDI,
	[HLTHUNK_DEVICE_GAUDI2] = HLTEST_DEVICE_MASK_GAUDI2,
	[HLTHUNK_DEVICE_DONT_CARE] = HLTEST_DEVICE_MASK_DONT_CARE,
};

struct hltests_device *get_hdev_from_fd(int fd)
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

int hltests_init(void)
{
	int rc;

	rc = pthread_spin_init(&rand_lock, PTHREAD_PROCESS_PRIVATE);
	if (rc) {
		printf("Failed to initialize number randomizer lock [rc %d]\n",
			rc);
		return rc;
	}

	hltests_set_rand_seed(time(NULL));

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

void hltests_fini(void)
{
	if (!dev_table)
		return;

	kh_destroy(ptr, dev_table);
	pthread_spin_destroy(&rand_lock);
}

#ifndef HLTESTS_LIB_MODE
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
#endif

static bool hltests_is_asic_type_valid(enum hlthunk_device_name actual_asic_type)
{
	unsigned long actual_asic_mask;

	actual_asic_mask = device_enum_to_device_mask[actual_asic_type];
	if (!(asic_mask_for_testing & actual_asic_mask)) {
		printf("Expected device mask %#lx but detected device %s (%#lx)\n",
				asic_mask_for_testing,
				asic_names[actual_asic_type],
				actual_asic_mask);
		return false;
	}

	return true;
}

int hltests_control_dev_open(const char *busid)
{
	enum hlthunk_device_name actual_asic_type;
	struct hltests_device *hdev;
	int fd, rc;
	khint_t k;

	if (!asic_mask_for_testing) {
		printf("Expecting invalid ASIC!!!\n");
		printf("Something is very wrong, exiting...\n");
		rc = -EINVAL;
		goto out;
	}

	pthread_mutex_lock(&table_lock);

	rc = fd = hlthunk_open_control(0, busid);
	if (fd < 0)
		goto out;

	actual_asic_type = hlthunk_get_device_name_from_fd(fd);
	if (!hltests_is_asic_type_valid(actual_asic_type)) {
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
	case HLTHUNK_DEVICE_GAUDI2:
		gaudi2_tests_set_asic_funcs(hdev);
		break;
	default:
		printf("Invalid device type 0x%x\n", hdev->device_id);
		rc = -ENXIO;
		goto remove_device;
	}

	pthread_mutex_unlock(&table_lock);
	return fd;

remove_device:
	kh_del(ptr, dev_table, k);
	hlthunk_free(hdev);
close_device:
	hlthunk_close(fd);
out:
	pthread_mutex_unlock(&table_lock);
	return rc;
}

int hltests_control_dev_close(int fd)
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

	hlthunk_close(hdev->fd);

	kh_del(ptr, dev_table, k);
	pthread_mutex_unlock(&table_lock);

	hlthunk_free(hdev);

	return 0;
}

int hltests_open(const char *busid)
{
	enum hlthunk_device_name actual_asic_type;
	struct hltests_device *hdev;
	int fd, rc;
	khint_t k;

	if (!asic_mask_for_testing) {
		printf("Expecting invalid ASIC!!!\n");
		printf("Something is very wrong, exiting...\n");
		rc = -EINVAL;
		goto out;
	}

	pthread_mutex_lock(&table_lock);

	/* Open control device first in order to compare against asic_mask_for_testing */
	rc = fd = hlthunk_open_control_by_name(HLTHUNK_DEVICE_DONT_CARE, busid);
	if (fd < 0)
		goto out;

	actual_asic_type = hlthunk_get_device_name_from_fd(fd);
	if (!hltests_is_asic_type_valid(actual_asic_type)) {
		rc = -EINVAL;
		hlthunk_close(fd);
		pthread_mutex_unlock(&table_lock);
		exit(0);
	}
	hlthunk_close(fd);

	rc = fd = hlthunk_open(HLTHUNK_DEVICE_DONT_CARE, busid);
	if (fd < 0)
		goto out;

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
	case HLTHUNK_DEVICE_GAUDI2:
		gaudi2_tests_set_asic_funcs(hdev);
		break;
	default:
		printf("Invalid device type 0x%x\n", hdev->device_id);
		rc = -ENXIO;
		goto remove_device;
	}

	rc = hdev->asic_funcs->asic_priv_init(hdev);
	if (rc)
		goto remove_device;

	rc = create_mem_maps(hdev);
	if (rc)
		goto destroy_asic_priv;

	rc = create_cb_map(hdev);
	if (rc)
		goto destroy_mem_maps;

	pthread_mutex_unlock(&table_lock);
	return fd;

destroy_mem_maps:
	destroy_mem_maps(hdev);
destroy_asic_priv:
	hdev->asic_funcs->asic_priv_fini(hdev);
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

	hdev->asic_funcs->asic_priv_fini(hdev);

	destroy_cb_map(hdev);

	destroy_mem_maps(hdev);

	hlthunk_close(hdev->fd);

	kh_del(ptr, dev_table, k);
	pthread_mutex_unlock(&table_lock);

	hlthunk_free(hdev);

	return 0;
}

void *hltests_mmap(int fd, size_t length, off_t offset)
{
	return mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
			offset);
}

int hltests_munmap(void *addr, size_t length)
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

	pthread_mutex_lock(&debugfs_lock);

	size = write(addr_fd, addr_str, strlen(addr_str) + 1);
	if (size < 0)
		printf("Failed to write to debugfs address fd [rc %zd]\n",
				size);

	size = pread(data_fd, value, sizeof(value), 0);
	if (size < 0)
		printf("Failed to read from debugfs data fd [rc %zd]\n", size);

	pthread_mutex_unlock(&debugfs_lock);

	return strtoul(value, NULL, 16);
}

void hltests_debugfs_write(int addr_fd, int data_fd, uint64_t full_address,
				uint32_t val)
{
	char addr_str[64] = "", val_str[64] = "";
	ssize_t size;

	sprintf(addr_str, "0x%lx", full_address);
	sprintf(val_str, "0x%x", val);

	pthread_mutex_lock(&debugfs_lock);

	size = write(addr_fd, addr_str, strlen(addr_str) + 1);
	if (size < 0)
		printf("Failed to write to debugfs address fd [rc %zd]\n",
				size);

	size = write(data_fd, val_str, strlen(val_str) + 1);
	if (size < 0)
		printf("Failed to write to debugfs data fd [rc %zd]\n", size);

	pthread_mutex_unlock(&debugfs_lock);
}

uint64_t hltests_debugfs_read64(int addr_fd, int data_fd, uint64_t full_address)
{
	char addr_str[64] = "", value[64] = "";
	ssize_t size;

	sprintf(addr_str, "0x%lx", full_address);

	pthread_mutex_lock(&debugfs_lock);

	size = write(addr_fd, addr_str, strlen(addr_str) + 1);
	if (size < 0)
		printf("Failed to write64 to debugfs address fd [rc %zd]\n",
				size);

	size = pread(data_fd, value, sizeof(value), 0);
	if (size < 0)
		printf("Failed to read from debugfs data fd [rc %zd]\n", size);

	pthread_mutex_unlock(&debugfs_lock);

	return strtoul(value, NULL, 16);
}

void hltests_debugfs_write64(int addr_fd, int data_fd, uint64_t full_address,
				uint64_t val)
{
	char addr_str[64] = "", val_str[64] = "";
	ssize_t size;

	sprintf(addr_str, "0x%lx", full_address);
	sprintf(val_str, "0x%lx", val);

	pthread_mutex_lock(&debugfs_lock);

	size = write(addr_fd, addr_str, strlen(addr_str) + 1);
	if (size < 0)
		printf("Failed to write to debugfs address fd [rc %zd]\n",
				size);

	size = write(data_fd, val_str, strlen(val_str) + 1);
	if (size < 0)
		printf("Failed to write to debugfs data fd [rc %zd]\n", size);

	pthread_mutex_unlock(&debugfs_lock);
}

static struct hltests_state *hltests_alloc_state(void)
{
	struct hltests_state *tests_state;

	tests_state = hlthunk_malloc(sizeof(*tests_state));
	if (!tests_state)
		goto out;

	tests_state->fd = -1;
	tests_state->asic_type = HLTHUNK_DEVICE_MAX;
	tests_state->debugfs.addr_fd = -1;
	tests_state->debugfs.data32_fd = -1;
	tests_state->debugfs.data64_fd = -1;
	tests_state->debugfs.clk_gate_fd = -1;

out:
	return tests_state;
}

int hltests_control_dev_setup(void **state)
{
	struct hltests_state *tests_state;
	struct hltests_device *hdev;
	int rc, fd;

	tests_state = hltests_alloc_state();
	if (!tests_state)
		return -ENOMEM;

	fd = tests_state->fd = hltests_control_dev_open(parser_pciaddr);
	if (fd < 0) {
		printf("Failed to open device %d\n", fd);
		rc = fd;
		goto free_state;
	}

	hdev = get_hdev_from_fd(fd);
	if (!hdev) {
		printf("Failed to get hdev from file descriptor %d\n", fd);
		rc = -ENODEV;
		goto close_fd;
	}

	*state = tests_state;

	return 0;

close_fd:
	if (hltests_close(fd))
		printf("Problem in closing FD, ignoring...\n");
free_state:
	hlthunk_free(tests_state);

	return rc;
}

int hltests_control_dev_teardown(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;

	if (!tests_state)
		return -EINVAL;

	if (hltests_control_dev_close(tests_state->fd))
		printf("Problem in closing FD, ignoring...\n");

	hlthunk_free(*state);

	return 0;
}

uint64_t hltests_get_total_avail_device_mem(int fd)
{
	struct hlthunk_hw_ip_info hw_ip;
	int rc;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	return hw_ip.dram_size;
}

int hltests_setup_user_engines(struct hltests_state *tests_state)
{
	return 0;
}

int hltests_setup(void **state)
{
	struct hltests_state *tests_state;
	struct hltests_device *hdev;
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

	hdev = get_hdev_from_fd(fd);
	if (!hdev) {
		printf("Failed to get hdev from file descriptor %d\n", fd);
		rc = -ENODEV;
		goto close_fd;
	}

	tests_state->mme = 1;
	tests_state->mmu = 1;
	tests_state->security = 1;

	rc = hltests_setup_user_engines(tests_state);
	if (rc)
		goto close_fd;

	*state = tests_state;

	return 0;

close_fd:
	if (hltests_close(fd))
		printf("Problem in closing FD, ignoring...\n");
free_state:
	hlthunk_free(tests_state);

	return rc;
}

int hltests_teardown_user_engines(struct hltests_state *tests_state)
{
	return 0;
}

int hltests_teardown(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;

	if (!tests_state)
		return -EINVAL;

	hltests_teardown_user_engines(tests_state);

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

	if (!asic_mask_for_testing) {
		printf("Expecting invalid ASIC!!!\n");
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

	if (!hltests_is_asic_type_valid(tests_state->asic_type)) {
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
 * This function allocates memory on the host
 * @param size how much memory to allocate
 * @param huge whether to use huge pages for the memory allocation
 * @return pointer to the struct hltests_memory generated.
 * NULL is returned upon failure.
 */
struct hltests_memory *
hltests_allocate_host_mem_nomap(uint64_t size, enum hltests_huge huge)
{
	struct hltests_memory *mem;

	mem = hlthunk_malloc(sizeof(struct hltests_memory));
	if (!mem)
		return NULL;

	mem->is_host = true;
	mem->is_huge = huge;
	mem->size = size;

	if (mem->is_huge) {
		mem->host_ptr = allocate_huge_mem(size);

		/* Failed to allocate huge memory, fall-back to regular memory */
		if (!mem->host_ptr) {
			mem->is_huge = false;
			mem->host_ptr = malloc(size);
		}
	} else {
		mem->host_ptr = malloc(size);
	}

	if (!mem->host_ptr) {
		printf("Failed to allocate %lu bytes of host memory\n", size);
		goto free_mem_struct;
	}

	return mem;

free_mem_struct:
	hlthunk_free(mem);
	return NULL;
}

/**
 * This function frees host memory allocation which were done using
 * hltests_allocate_host_mem_nomap
 * @param mem pointer to the hltests_memory structure
 * @param huge whether huge pages were used for the memory allocation
 * @return 0 for success, negative value for failure
 */
int hltests_free_host_mem_nounmap(struct hltests_memory *mem,
					enum hltests_huge huge)
{
	/* contract: device_virt_addr must be released by this stage */
	assert_null(mem->device_virt_addr);

	if (mem->is_huge)
		munmap(mem->host_ptr, mem->size);
	else
		free(mem->host_ptr);

	hlthunk_free(mem);

	return 0;
}

/**
 * This function maps the host memory previously allocated by
 * hltests_allocate_host_mem_nomap to the device virtual address space.
 * @param fd file descriptor of the device to which the function will map
 *           the memory
 * @param mem pointer to the hltests_memory structure
 * @return 0 for success, negative value for failure
 */
int hltests_map_host_mem(int fd, struct hltests_memory *mem)
{
	mem->device_virt_addr = hlthunk_host_memory_map(fd, mem->host_ptr, 0,
							mem->size);
	if (!mem->device_virt_addr) {
		printf("Failed to map host memory to device\n");
		return -1;
	}

	return 0;
}

/**
 * This function unmaps the host memory previously mapped by
 * hltests_map_host_mem.
 * @param mem pointer to the hltests_memory structure
 * @param fd file descriptor of the device to which the memory was mapped
 * @return 0 for success, negative value for failure
 */
int hltests_unmap_host_mem(int fd, struct hltests_memory *mem)
{
	int rc = hlthunk_memory_unmap(fd, mem->device_virt_addr);

	mem->device_virt_addr = 0;
	return rc;
}

/**
 * This function allocates memory on the host, aligned as specified, and will
 * map it to the device virtual address space
 * @param fd file descriptor of the device to which the function will map
 *           the memory
 * @param size how much memory to allocate
 * @param huge whether to use huge pages for the memory allocation
 * @param align desired alignment in bytes, 0 meaning unaligned
 * @return pointer to the host memory. NULL is returned upon failure
 */
void *hltests_allocate_host_mem_aligned(int fd, uint64_t size,
				enum hltests_huge huge, uint64_t align)
{
	return hltests_allocate_host_mem_aligned_flags(fd, size, huge, align, 0);
}

/**
 * This function allocates memory on the host, aligned as specified, and will
 * map it to the device virtual address space, allowing to pass custom memory
 * map flags alongside.
 * @param fd file descriptor of the device to which the function will map
 *           the memory
 * @param size how much memory to allocate
 * @param huge whether to use huge pages for the memory allocation
 * @param align desired alignment in bytes, 0 meaning unaligned
 * @param flags memory map flags
 * @return pointer to the host memory. NULL is returned upon failure
 */
void *hltests_allocate_host_mem_aligned_flags(int fd, uint64_t size,
			enum hltests_huge huge, uint64_t align, uint32_t flags)
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

	if (mem->is_huge) {
		mem->host_ptr = allocate_huge_mem(size);

		/* Failed to allocate huge memory, fall-back to regular memory */
		if (!mem->host_ptr) {
			mem->is_huge = false;
			mem->host_ptr = align ? aligned_alloc(align, size) : malloc(size);
		}
	} else {
		mem->host_ptr = align ? aligned_alloc(align, size) : malloc(size);
	}

	if (!mem->host_ptr) {
		printf("Failed to allocate %lu bytes of host memory\n", size);
		goto free_mem_struct;
	}

	mem->device_virt_addr = hlthunk_host_memory_map_flags(fd, mem->host_ptr, 0,
							size, flags);

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
	return hltests_allocate_host_mem_aligned(fd, size, huge, 0);
}

/**
 * This function allocates DRAM memory on the device and will map it to
 * the device virtual address space
 * @param fd file descriptor of the device to which the function will map
 *           the memory
 * @param size how much memory to allocate
 * @param page_size what page size to use. 0 means use default page size
 * @param contiguous whether the memory area will be physically contiguous
 * @return pointer to the device memory. This pointer can NOT be dereferenced
 * directly from the host. NULL is returned upon failure
 */
void *hltests_allocate_device_mem(int fd, uint64_t size, uint64_t page_size,
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

	if (!asic->dram_pool_alloc(hdev, size, &mem->device_virt_addr))
		goto memory_allocated;

	mem->is_pool = false;

	if (!hdev->sim_dram_on_host) {
		mem->device_handle = hlthunk_device_memory_alloc(fd, size, page_size,
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
	} else {
		mem->host_ptr = malloc(size);

		if (!mem->host_ptr) {
			printf("Failed to allocate %lu bytes of host memory\n",
				size);
			goto free_mem_struct;
		}

		mem->device_virt_addr = hlthunk_host_memory_map(fd,
							mem->host_ptr, 0, size);

		if (!mem->device_virt_addr) {
			printf("Failed to map host memory to device\n");
			goto free_allocation;
		}
	}

memory_allocated:
	pthread_mutex_lock(&hdev->mem_table_device_lock);

	k = kh_put(ptr64, hdev->mem_table_device, mem->device_virt_addr, &rc);
	kh_val(hdev->mem_table_device, k) = mem;

	pthread_mutex_unlock(&hdev->mem_table_device_lock);

	return (void *) mem->device_virt_addr;

free_allocation:
	if (!hdev->sim_dram_on_host)
		hlthunk_device_memory_free(fd, mem->device_handle);
	else
		free(mem->host_ptr);
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
			printf("Failed to unmap memory\n");
			return rc;
		}

		if (!hdev->sim_dram_on_host)
			hlthunk_device_memory_free(fd, mem->device_handle);
		else
			free(mem->host_ptr);
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
 * This function retrieves the device memory handle by virtual address in the
 * device address space
 * @param fd file descriptor of the device that the host memory is mapped to
 * @param device_va virtual address in the device VA space
 * @return opaque handle representing the device memory allocation. 0 for
 * failure
 */
uint64_t hltests_get_device_handle_for_device_va(int fd, void *device_va)
{
	struct hltests_device *hdev;
	struct hltests_memory *mem;
	khint_t k;

	hdev = get_hdev_from_fd(fd);
	if (!hdev)
		return 0;

	pthread_mutex_lock(&hdev->mem_table_device_lock);

	k = kh_get(ptr64, hdev->mem_table_device, (uintptr_t) device_va);
	if (k == kh_end(hdev->mem_table_device)) {
		pthread_mutex_unlock(&hdev->mem_table_device_lock);
		return 0;
	}

	mem = kh_val(hdev->mem_table_device, k);

	pthread_mutex_unlock(&hdev->mem_table_device_lock);

	return mem->device_handle;
}

/**
 * This function creates a command buffer for a specific device. It also
 * supports creating internal command buffer, which is basically a block of
 * memory on the host which is DMA'd into the device memory
 * @param fd file descriptor of the device
 * @param cb_size the size of the command buffer
 * @param cb_type the type of the command buffer
 * @cb_internal_sram_address the address in the sram that the internal CB will
 *                           be executed from by the CS. If this parameter is
 *                           0, the CB will be located on the host
 * @return virtual address of the CB in the user process VA space, or NULL for
 *         failure
 */
void *hltests_create_cb(int fd, uint32_t cb_size, enum hltests_cb_type cb_type,
			uint64_t cb_internal_sram_address)
{
	struct hltests_device *hdev;
	struct hltests_cb *cb;
	uint64_t align;
	uint32_t suffix_size = 0;
	int rc;
	khint_t k;

	hdev = get_hdev_from_fd(fd);
	if (!hdev)
		return NULL;

	cb = hlthunk_malloc(sizeof(*cb));
	if (!cb)
		return NULL;

	if (hltests_is_legacy_mode_enabled(fd)) {
		cb->cb_size = cb_size;
	} else {
		suffix_size = hdev->asic_funcs->get_arc_cb_suffix_size();
		cb->cb_size = ALIGN_UP((cb_size + suffix_size), 64);
	}

	cb->cb_type = cb_type;

	align = hltests_is_legacy_mode_enabled(fd) ? 0 : 8;

	/* For external queues, request the kernel driver to allocate a CB only
	 * if the ASIC is Goya/Gaudi OR if MMU is disabled.
	 */
	if (cb->cb_type == CB_TYPE_KERNEL &&
			!(hltests_is_goya(fd) || hltests_is_gaudi(fd)))
		cb->cb_type = CB_TYPE_USER;

	switch (cb->cb_type) {
	case CB_TYPE_USER:
		cb->ptr = hltests_allocate_host_mem_aligned(fd, cb->cb_size, NOT_HUGE_MAP, align);
		if (!cb->ptr)
			goto free_cb;

		if (cb_internal_sram_address)
			cb->cb_handle = cb_internal_sram_address;
		else
			cb->cb_handle =
				hltests_get_device_va_for_host_ptr(fd, cb->ptr);

		break;

	case CB_TYPE_KERNEL:
	case CB_TYPE_KERNEL_MAPPED:
		if (cb->cb_type == CB_TYPE_KERNEL)
			rc = hlthunk_request_command_buffer(fd, cb->cb_size,
								&cb->cb_handle);
		else
			rc = hlthunk_request_mapped_command_buffer(fd,
						cb->cb_size, &cb->cb_handle);
		if (rc)
			goto free_cb;

		cb->ptr = hltests_mmap(fd, cb->cb_size, cb->cb_handle);
		if (cb->ptr == MAP_FAILED)
			goto destroy_cb;

		break;

	default:
		printf("Invalid CB type %d\n", cb->cb_type);
		goto free_cb;
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

	if (cb->cb_type == CB_TYPE_KERNEL ||
			cb->cb_type == CB_TYPE_KERNEL_MAPPED) {
		hltests_munmap(cb->ptr, cb->cb_size);
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

int hltests_get_cb_usage_count(int fd, void *ptr, uint32_t *usage_cnt)
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

	pthread_mutex_unlock(&hdev->cb_table_lock);

	if (cb->cb_type == CB_TYPE_USER)
		return -EINVAL;

	return hlthunk_get_cb_usage_count(fd, cb->cb_handle, usage_cnt);
}

int hltests_fill_cs_chunk(struct hltests_device *hdev,
			struct hl_cs_chunk *chunk, void *cb_ptr,
			uint32_t cb_size, uint32_t queue_index)
{
	struct hltests_cb *cb = NULL;
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
	if (!cb || cb->cb_type == CB_TYPE_USER)
		chunk->cs_chunk_flags |= HL_CS_CHUNK_FLAGS_USER_ALLOC_CB;

	return 0;
}

static int fill_cs_chunks(struct hltests_device *hdev,
			struct hl_cs_chunk *submit_arr,
			struct hltests_cs_chunk *chunks_arr,
			uint32_t num_chunks)
{
	int i, rc;

	for (i = 0 ; i < num_chunks ; i++) {
		rc = hltests_fill_cs_chunk(hdev, &submit_arr[i],
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
		uint32_t timeout,
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
	if (timeout)
		rc = hlthunk_command_submission_timeout(fd, &cs_in, &cs_out,
								timeout);
	else
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
					execute_arr_size, flags, 0, seq);
}

int hltests_submit_cs_timeout(int fd,
		struct hltests_cs_chunk *restore_arr,
		uint32_t restore_arr_size,
		struct hltests_cs_chunk *execute_arr,
		uint32_t execute_arr_size,
		uint32_t flags,
		uint32_t timeout_sec,
		uint64_t *seq)
{
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	return asic->submit_cs(fd, restore_arr, restore_arr_size, execute_arr,
					execute_arr_size, flags, timeout_sec, seq);
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

	if (flags & HL_CS_FLAGS_ENCAP_SIGNALS)
		rc = hlthunk_staged_command_submission_encaps_signals(fd,
						staged_cs_seq,
						&cs_in, &cs_out);
	else
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

int hltests_wait_for_legacy_cs_until_not_busy(int fd, uint64_t seq)
{
	int status;

	do {
		status = hltests_wait_for_legacy_cs(fd, seq,
					WAIT_FOR_CS_DEFAULT_TIMEOUT);
	} while (status == HL_WAIT_CS_STATUS_BUSY);

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
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	return asic->wait_for_cs_until_not_busy(fd, seq);
}

int hltests_wait_for_interrupt(int fd, void *addr, uint32_t target_value,
				uint32_t interrupt_id, uint64_t timeout_us)
{
	uint32_t status;
	int rc;

	rc = hlthunk_wait_for_interrupt(fd, addr, target_value, interrupt_id,
					timeout_us, &status);
	if (rc && errno != ETIMEDOUT && errno != EIO)
		return rc;

	return status;
}

int hltests_wait_for_interrupt_until_not_busy(int fd, void *addr,
				uint32_t target_value, uint32_t interrupt_id)
{
	int status;

	do {
		status = hltests_wait_for_interrupt(fd, addr, target_value,
				interrupt_id, WAIT_FOR_CS_DEFAULT_TIMEOUT);
	} while (status == HL_WAIT_CS_STATUS_BUSY);

	return status;
}

int hltests_wait_for_interrupt_by_handle(int fd, uint64_t cq_counters_handle,
				uint64_t cq_counters_offset, uint32_t target_value,
				uint32_t interrupt_id, uint64_t timeout_us)
{
	uint32_t status;
	int rc;

	rc = hlthunk_wait_for_interrupt_by_handle(fd, cq_counters_handle, cq_counters_offset,
					target_value, interrupt_id,
					timeout_us, &status);
	if (rc && errno != ETIMEDOUT && errno != EIO)
		return rc;

	return status;
}

int hltests_wait_for_interrupt_by_handle_until_not_busy(int fd, uint64_t cq_counters_handle,
				uint64_t cq_counters_offset,
				uint32_t target_value, uint32_t interrupt_id)
{
	int status;

	do {
		status = hltests_wait_for_interrupt_by_handle(fd, cq_counters_handle,
				cq_counters_offset,
				target_value,
				interrupt_id, WAIT_FOR_CS_DEFAULT_TIMEOUT);
	} while (status == HL_WAIT_CS_STATUS_BUSY);

	return status;
}

/**
 * This function submits a single command buffer for a specific queue, and
 * waits for it.
 * @param fd file descriptor of the device
 * @param cb_ptr a pointer to the command buffer
 * @param cb_size the size of the command buffer
 * @param queue_index the allocated queue for the command submission
 * @param destroy_cb true if CB should be destroyed, false otherwise
 * @param expected_val expected status of current CS (e.g., COMPLETED, BUSY, etc.)
 * @return -1 on failure, 0 on success
 */
int hltests_submit_and_wait_cs(int fd, void *cb_ptr, uint32_t cb_size,
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
 * @return -1 on failure, 0 on success
 */
int hltests_submit_and_wait_legacy_cs(int fd, void *cb_ptr, uint32_t cb_size,
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

	rc = hltests_submit_legacy_cs(fd, NULL, 0, execute_arr, 1, 0, 0, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_legacy_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, expected_val);

	if (destroy_cb) {
		rc = hltests_destroy_cb(fd, cb_ptr);
		assert_int_equal(rc, 0);
	}

	return 0;
}

uint32_t hltests_add_nop_pkt(int fd, void *buffer, uint32_t buf_off,
				struct hltests_pkt_info *pkt_info)
{
	const struct hltests_asic_funcs *asic =
			get_hdev_from_fd(fd)->asic_funcs;

	return asic->add_nop_pkt(buffer, buf_off, pkt_info);
}

uint32_t hltests_add_msg_barrier_pkt(int fd, void *buffer, uint32_t buf_off,
				struct hltests_pkt_info *pkt_info)
{
	const struct hltests_asic_funcs *asic =
			get_hdev_from_fd(fd)->asic_funcs;

	return asic->add_msg_barrier_pkt(buffer, buf_off, pkt_info);
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

uint32_t hltests_add_cb_list_pkt(int fd, void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	const struct hltests_asic_funcs *asic =
			get_hdev_from_fd(fd)->asic_funcs;

	return asic->add_cb_list_pkt(buffer, buf_off, pkt_info);
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

	return asic->add_monitor_and_fence(fd, DCORE_MODE_FULL_CHIP, buffer,
					buf_off, mon_and_fence_info);
}

uint32_t hltests_add_monitor(int fd, void *buffer, uint32_t buf_off,
		struct hltests_monitor *mon_info)
{
	const struct hltests_asic_funcs *asic =
			get_hdev_from_fd(fd)->asic_funcs;

	return asic->add_monitor(buffer, buf_off, mon_info);
}

uint64_t hltests_get_fence_addr(int fd, uint32_t qid, bool cmdq_fence)
{
	const struct hltests_asic_funcs *asic =
			get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_fence_addr(fd, qid, cmdq_fence);
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

uint32_t hltests_add_cq_config_pkt(int fd, void *buffer, uint32_t buf_off,
		struct hltests_cq_config *cq_config)
{
	const struct hltests_asic_funcs *asic =
			get_hdev_from_fd(fd)->asic_funcs;

	return asic->add_cq_config_pkt(buffer, buf_off, cq_config);
}

uint32_t hltests_get_dma_down_qid(int fd, enum hltests_stream_id stream)
{
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_dma_down_qid(fd, DCORE_MODE_FULL_CHIP, stream);
}

uint32_t hltests_get_dma_up_qid(int fd, enum hltests_stream_id stream)
{
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_dma_up_qid(fd, DCORE_MODE_FULL_CHIP, stream);
}

uint32_t hltests_get_ddma_qid(int fd, int dma_ch, enum hltests_stream_id stream)
{
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_ddma_qid(fd, DCORE_MODE_FULL_CHIP, dma_ch, stream);
}

uint8_t hltests_get_ddma_cnt(int fd)
{
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_ddma_cnt(fd, DCORE_MODE_FULL_CHIP);
}

uint32_t hltests_get_tpc_qid(int fd, uint8_t tpc_id,
				enum hltests_stream_id stream)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_tpc_qid(fd, DCORE_MODE_FULL_CHIP, tpc_id, stream);
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
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_tpc_cnt(fd, DCORE_MODE_FULL_CHIP);
}

uint8_t hltests_get_mme_cnt(int fd, bool master_slave_mode)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_mme_cnt(fd, DCORE_MODE_FULL_CHIP, master_slave_mode);
}

uint16_t hltests_get_first_avail_sob(int fd)
{
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_first_avail_sob(fd);
}

uint16_t hltests_get_first_avail_mon(int fd)
{
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_first_avail_mon(fd);
}

uint16_t hltests_get_first_avail_cq(int fd)
{
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_first_avail_cq(fd);
}

uint16_t hltests_get_first_avail_interrupt(int fd)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct hlthunk_hw_ip_info hw_ip = {};

	hlthunk_get_hw_ip_info(fd, &hw_ip);

	return hw_ip.first_available_interrupt_id + hdev->counters.reserved_interrupts;
}

uint64_t hltests_get_sob_base_addr(int fd)
{
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_sob_base_addr(fd);
}

uint64_t hltests_get_lbw_base_addr(int fd)
{
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_lbw_base_addr(fd);
}

uint16_t hltests_get_monitors_cnt_per_dcore(int fd)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_mon_cnt_per_dcore();
}

int hltests_get_stream_master_qid_arr(int fd, uint32_t **qid_arr)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_stream_master_qid_arr(qid_arr);
}

void hltests_set_rand_seed(uint32_t val)
{
	cur_seed = val;
	seed(val);
}

uint32_t hltests_rand_u32(void)
{
	uint32_t val;

	pthread_spin_lock(&rand_lock);
	val = rand_u32();
	pthread_spin_unlock(&rand_lock);

	return val;
}

bool hltests_rand_flip_coin(void)
{
	return hltests_rand_u32() & 1;
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

static void hltests_endian_swap_16_values(void *ptr, uint32_t size)
{
	uint32_t i, rounddown_aligned_size, remainder;
	uint16_t *p = ptr;

	rounddown_aligned_size = size & ~(sizeof(uint16_t) - 1);
	remainder = size - rounddown_aligned_size;

	for (i = 0 ; i < rounddown_aligned_size ; i += sizeof(uint16_t), p++)
		*p = bswap_16(*p);

	if (!remainder)
		return;

	/* There can be a remainder of only one byte */
	*((uint8_t *) p) = 0;
}

static void hltests_endian_swap_32_values(void *ptr, uint32_t size)
{
	uint32_t i, rounddown_aligned_size, remainder;
	uint32_t *p = ptr, tmp;

	rounddown_aligned_size = size & ~(sizeof(uint32_t) - 1);
	remainder = size - rounddown_aligned_size;

	for (i = 0 ; i < rounddown_aligned_size ; i += sizeof(uint32_t), p++)
		*p = bswap_32(*p);

	if (!remainder)
		return;

	tmp = 0;
	for (i = 0 ; i < remainder ; i++)
		tmp |= ((uint32_t) ((uint8_t *) p)[i]) << (i * 8);

	tmp = bswap_32(tmp);
	for (i = 0 ; i < remainder ; i++)
		((uint8_t *) p)[i] = ((uint8_t *) &tmp)[i];
}

static void hltests_endian_swap_64_values(void *ptr, uint32_t size)
{
	uint32_t i, rounddown_aligned_size, remainder;
	uint64_t *p = ptr, tmp;

	rounddown_aligned_size = size & ~(sizeof(uint64_t) - 1);
	remainder = size - rounddown_aligned_size;

	for (i = 0 ; i < rounddown_aligned_size ; i += sizeof(uint64_t), p++)
		*p = bswap_64(*p);

	if (!remainder)
		return;

	tmp = 0;
	for (i = 0 ; i < remainder ; i++)
		tmp |= ((uint64_t) ((uint8_t *) p)[i]) << (i * 8);

	tmp = bswap_64(tmp);
	for (i = 0 ; i < remainder ; i++)
		((uint8_t *) p)[i] = ((uint8_t *) &tmp)[i];
}

static uint64_t hltests_get_dram_va_hint_mask(int fd)
{
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_dram_va_hint_mask();
}

void hltests_endian_swap_values(void *ptr, uint32_t size,
				enum hltests_endian_swap endian_swap)
{
	switch (endian_swap) {
	case ENDIAN_SWAP_16:
		hltests_endian_swap_16_values(ptr, size);
		break;
	case ENDIAN_SWAP_32:
		hltests_endian_swap_32_values(ptr, size);
		break;
	case ENDIAN_SWAP_64:
		hltests_endian_swap_64_values(ptr, size);
		break;
	default:
		break;
	}
}

int hltests_mem_compare_with_stop(void *ptr1, void *ptr2, uint64_t size,
					bool stop_on_err)
{
	uint64_t *p1 = (uint64_t *) ptr1, *p2 = (uint64_t *) ptr2;
	uint64_t err_cnt = 0, rounddown_aligned_size, remainder, i = 0;

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

int hltests_dma_transfer(int fd, uint32_t queue_index, enum hltests_eb eb,
				enum hltests_mb mb,
				uint64_t src_addr, uint64_t dst_addr,
				uint32_t size,
				enum hltests_dma_direction dma_dir)
{
	uint32_t offset = 0;
	void *ptr;
	struct hltests_pkt_info pkt_info;

	ptr = hltests_create_cb(fd, 0x1000, EXTERNAL, 0);
	assert_non_null(ptr);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = queue_index;
	pkt_info.eb = eb;
	pkt_info.mb = mb;
	pkt_info.dma.src_addr = src_addr;
	pkt_info.dma.dst_addr = dst_addr;
	pkt_info.dma.size = size;
	pkt_info.dma.dma_dir = dma_dir;
	offset = hltests_add_dma_pkt(fd, ptr, offset, &pkt_info);

	return hltests_submit_and_wait_cs(fd, ptr, offset, queue_index,
				DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_COMPLETED);
}

int hltests_zero_device_memory(int fd, uint64_t dst_addr, uint32_t size,
				enum hltests_dma_direction dma_dir)
{
	uint64_t host_src_addr;
	void *src_ptr;

	src_ptr = hltests_allocate_host_mem(fd, size, HUGE_MAP);
	assert_non_null(src_ptr);

	memset(src_ptr, 0, size);
	host_src_addr = hltests_get_device_va_for_host_ptr(fd, src_ptr);

	hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, STREAM0),
				EB_FALSE, MB_TRUE, host_src_addr,
				dst_addr, size, dma_dir);

	hltests_free_host_mem(fd, src_ptr);

	return 0;
}

int hltests_dma_transfer_legacy(int fd, uint32_t queue_index,
				enum hltests_eb eb, enum hltests_mb mb,
				uint64_t src_addr, uint64_t dst_addr,
				uint32_t size,
				enum hltests_dma_direction dma_dir)
{
	uint32_t offset = 0;
	void *ptr;
	struct hltests_pkt_info pkt_info;

	ptr = hltests_create_cb(fd, 0x1000, EXTERNAL, 0);
	assert_non_null(ptr);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = eb;
	pkt_info.mb = mb;
	pkt_info.dma.src_addr = src_addr;
	pkt_info.dma.dst_addr = dst_addr;
	pkt_info.dma.size = size;
	pkt_info.dma.dma_dir = dma_dir;
	offset = hltests_add_dma_pkt(fd, ptr, offset, &pkt_info);

	return hltests_submit_and_wait_legacy_cs(fd, ptr, offset, queue_index,
				DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_COMPLETED);
}

VOID hltests_dma_dram_frag_mem_test(void **state, uint64_t size)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	uint32_t i, frag_arr_size, page_num, rand;
	struct hlthunk_hw_ip_info hw_ip;
	int rc, fd = tests_state->fd;
	uint64_t used_page_size;
	void **frag_arr;

	/* Create fragmented device physical memory.
	 * Allocate FRAG_MEM_MULT times more memory in advance and free randomly
	 * the amount of memory required for the test inside this area to create
	 * fragmentation.
	 */

	if (hltests_is_pldm(fd) && size > PLDM_MAX_DMA_SIZE_FOR_TESTING)
		skip();

	if (hltests_is_simulator(fd) && size > SZ_512M)
		skip();

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	if (hltests_is_simulator(fd) &&
			(FRAG_MEM_MULT * size) > hw_ip.dram_size) {
		printf(
			"SIM's DRAM (%lu[B]) is smaller than required allocation (%lu[B]) so skipping test\n",
			hw_ip.dram_size, FRAG_MEM_MULT * size);
		skip();
	}

	/*
	 * since in this test the device memory is allocated using the default page size
	 * we need to use it to calc number of pages
	 */
	used_page_size = hw_ip.device_mem_alloc_default_page_size;
	if (size < used_page_size) {
		printf("page size %#lx is greater than memory chunk %#lx\n", used_page_size, size);
		skip();
	}
	page_num = size / used_page_size;
	assert_int_not_equal(page_num, 0);
	frag_arr_size = page_num * FRAG_MEM_MULT;
	frag_arr = hlthunk_malloc(frag_arr_size * sizeof(*frag_arr));
	assert_non_null(frag_arr);

	for (i = 0; i < frag_arr_size; i++) {
		frag_arr[i] = hltests_allocate_device_mem(fd, used_page_size, 0, NOT_CONTIGUOUS);
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

	hltests_dma_test(state, true, size, 0);

	for (i = 0; i < frag_arr_size; i++) {
		if (!frag_arr[i])
			continue;
		rc = hltests_free_device_mem(fd, frag_arr[i]);
		assert_int_equal(rc, 0);
	}
	hlthunk_free(frag_arr);

	END_TEST;
}

VOID hltests_dma_dram_high_mem_test(void **state, uint64_t size)
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

	if (hltests_is_simulator(fd) && size > SZ_512M)
		skip();

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	alloc_size = hw_ip.dram_size / 2;

	if (hltests_is_simulator(fd) && size > alloc_size) {
		printf(
			"SIM's DRAM (%lu[B]) is smaller than required allocation (%lu[B]) so skipping test\n",
			alloc_size, size);
		skip();
	}

	device_addr = hltests_allocate_device_mem(fd, alloc_size, 0, NOT_CONTIGUOUS);
	assert_non_null(device_addr);

	hltests_dma_test(state, true, size, 0);

	rc = hltests_free_device_mem(fd, device_addr);
	assert_int_equal(rc, 0);

	END_TEST;
}

VOID hltests_dma_test_flags(void **state, bool is_ddr, uint64_t size,
				uint64_t page_size, uint32_t flags)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	void *device_addr, *src_ptr, *dst_ptr;
	uint64_t host_src_addr, host_dst_addr;
	uint32_t dma_dir_down, dma_dir_up;
	bool is_huge = !!((size > SZ_32K) && (size < SZ_1G));
	int rc, fd = tests_state->fd;

	if (hltests_is_pldm(fd) && (size > PLDM_MAX_DMA_SIZE_FOR_TESTING))
		skip();

	/* Sanity and memory allocation */
	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (is_ddr) {
		if (hltests_is_simulator(fd) && size > hw_ip.dram_size) {
			printf(
				"SIM's DRAM (%lu[B]) is smaller than required allocation (%lu[B]) so skipping test\n",
				hw_ip.dram_size, size);
			skip();
		}

		if (!hw_ip.dram_enabled) {
			if (hltests_is_gaudi2(fd) && tests_state->mmu) {
				printf("DRAM disabled, using DRAM on host\n");
			} else {
				printf("DRAM is disabled so skipping test\n");
				skip();
			}
		} else {
			assert_in_range(size, 1, hw_ip.dram_size);
		}

		device_addr = hltests_allocate_device_mem(fd, size, page_size, NOT_CONTIGUOUS);
		assert_non_null(device_addr);

		dma_dir_down = DMA_DIR_HOST_TO_DRAM;
		dma_dir_up = DMA_DIR_DRAM_TO_HOST;
	} else {
		if (size > hw_ip.sram_size)
			skip();
		device_addr = (void *) (uintptr_t) hw_ip.sram_base_address;

		dma_dir_down = DMA_DIR_HOST_TO_SRAM;
		dma_dir_up = DMA_DIR_SRAM_TO_HOST;
	}

	src_ptr = hltests_allocate_host_mem_aligned_flags(fd, size, is_huge, 0,
								flags);
	assert_non_null(src_ptr);
	hltests_fill_rand_values(src_ptr, size);
	host_src_addr = hltests_get_device_va_for_host_ptr(fd, src_ptr);

	dst_ptr = hltests_allocate_host_mem_aligned_flags(fd, size, is_huge, 0,
								flags);
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

	END_TEST;
}

VOID hltests_dma_test(void **state, bool is_ddr, uint64_t size, uint64_t page_size)
{
	END_TEST_FUNC(hltests_dma_test_flags(state, is_ddr, size, page_size, 0));
}

static int build_page_size_array(uint64_t **page_size_arr, uint8_t *arr_size, uint64_t bitmask)
{
	int i, set_idx, elem = __builtin_popcountll(bitmask);

	*page_size_arr = hlthunk_malloc(elem * sizeof(uint64_t));
	if (*page_size_arr == NULL)
		return -ENOMEM;

	for (i = 0; i < elem; i++) {
		set_idx = __builtin_ffsll(bitmask) - 1;
		(*page_size_arr)[i] = (1ULL << set_idx);
		bitmask &= ~(*page_size_arr)[i];
	}

	*arr_size = elem;
	return 0;
}

static inline void destroy_page_size_array(uint64_t *page_size_arr)
{
	hlthunk_free(page_size_arr);
}

/**
 * This test allocates device memory until all the memory was allocated.
 * @param state contains the open file descriptor.
 * @param page_size page size to use (0 means use default page size).
 * @param contiguous indicates if the allocated device memory should be
 *        contiguous or not.
 * @param mix_alloc if true use mixed allocations, otherwise use single page size.
 *
 * Note:
 * - When test is running with mixed allocation, each iteration different page size
 *   is chosen (round robin). in this case chunk size equals the page size.
 *   In this case it is expected that we will not be able to allocate the whole memory
 *   (because of memory fragmentation)
 * - Otherwise (not mixed allocation) the test is affected by the page size:
 *     # When the device dram_page_size is a power of 2 the allocated chunks are 0.5GB
 *       (because the driver reserves the first 0.5GB and we have multiples of 1GB of
 *       memory).
 *     # When the device dram_page_size is not  a power of 2, the allocated memory
 *       chunks will have the same size as the dram_page_size. This may leave some
 *       memory residues which will not be used by the test.
 *    In the above cases we expect to allocate the whole memory.
 */
VOID hltests_allocate_device_mem_until_full(void **state, uint32_t page_size,
					enum hltests_contiguous contigouos, bool mix_alloc)
{
	uint64_t total_size, num_of_chunks, i, j, page_order_bitmask, *page_size_arr, total_alloc;
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	uint32_t chunk_size, used_page_size;
	struct hlthunk_hw_ip_info hw_ip;
	int rc, fd = tests_state->fd;
	uint8_t page_size_arr_size;
	void **device_addr;
	bool error = false;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	/* initialize to avoid compiler warnings */
	page_size_arr = NULL;
	page_size_arr_size = 0;

	/*
	 * store explicitly what page size we are using for calculations
	 * (as page_size=0 means default)
	 */
	used_page_size = page_size ? page_size : hw_ip.device_mem_alloc_default_page_size;

	if (mix_alloc) {
		/* check whether mixed allocation is supported */
		rc = hlthunk_get_dev_memalloc_page_orders(fd, &page_order_bitmask);
		assert_int_equal(rc, 0);

		if (!page_order_bitmask) {
			printf("Multiple page sizes is not supported\n");
			skip();
		}
	}

	total_size = hltests_get_total_avail_device_mem(fd);
	if (mix_alloc) {
		rc = build_page_size_array(&page_size_arr, &page_size_arr_size, page_order_bitmask);
		assert_int_equal(rc, 0);
		/* we divide by page_size_arr_size later, so it mustn't be 0 */
		assert_int_not_equal(page_size_arr_size, 0);
		/* we set check size to the minimal page size so we'll "give a chance" to
		 * maximum number of allocations
		 */
		chunk_size = page_size_arr[0];
	} else if ((hw_ip.dram_page_size == 0) || IS_POWER_OF_TWO(used_page_size)) {
		chunk_size = hltests_is_simulator(fd) ? SZ_32M : SZ_512M;
		/* handle devices with dram_page_size > 32M */
		chunk_size = (chunk_size > used_page_size) ? chunk_size : used_page_size;
	} else {
		chunk_size = used_page_size;
	}

	num_of_chunks = total_size / chunk_size;
	assert_int_not_equal(num_of_chunks, 0);

	device_addr = hlthunk_malloc(num_of_chunks * sizeof(void *));
	assert_non_null(device_addr);

	total_alloc = 0;
	for (i = 0 ; i < num_of_chunks ; i++) {
		/* fix mixed allocation page size is modified each time */
		if (mix_alloc) {
			chunk_size = page_size_arr[i % page_size_arr_size];
			page_size = chunk_size;
		}
		device_addr[i] = hltests_allocate_device_mem(fd, chunk_size, page_size, contigouos);
		if (!device_addr[i])
			break;
		total_alloc += chunk_size;
	}

	/* failure criteria */
	if (mix_alloc) {
		/*
		 * we expect to be able to allocate to at least number of highest order
		 * pages that can fill the memory
		 */
		uint64_t min_chunks = total_size / page_size_arr[page_size_arr_size - 1];

		if (i < min_chunks)
			error = true;
	} else if (i < num_of_chunks) {
		error = true;
	}

	if (error || mix_alloc)
		printf("Was able to allocate %luMB out of %luMB\n",
				total_alloc / SZ_1M, total_size / SZ_1M);


	for (j = 0 ; j < i ; j++) {
		rc = hltests_free_device_mem(fd, device_addr[j]);
		assert_int_equal(rc, 0);
	}

	hlthunk_free(device_addr);
	if (mix_alloc)
		destroy_page_size_array(page_size_arr);

	if (error)
		fail();

	END_TEST;
}

int hltests_mmu_hint_address(int fd, uint64_t page_size, uint64_t ref_addr,
			     enum range_type type, bool page_aligned)
{
	uint64_t hint_addr, device_map_addr, device_map_addr_late,
		 device_handle = 0, buf_size = SZ_16K, page_off = 0;
	void *host_ptr = NULL;
	bool is_huge = false;
	int rc = 0, ret;

	/* By default, set hint address to be page aligned */
	hint_addr = (ref_addr & ~hltests_get_dram_va_hint_mask(fd)) +
			ROUND_UP(ref_addr & hltests_get_dram_va_hint_mask(fd),
					page_size);
	if (!page_aligned) {
		/* Set hint address to be non page aligned */
		hint_addr += page_size - 1;
	}

	if (type == HOST_ADDR) {
		is_huge = (page_size == SZ_2M);

		if (is_huge)
			host_ptr = allocate_huge_mem(buf_size);
		else
			host_ptr = hlthunk_malloc(buf_size);

		assert_non_null(host_ptr);

		/* In case of a regular page size, we expect a mapped address
		 * with the same offset as the host address, hence we need to
		 * save it for future comparison with the hint address.
		 */
		page_off = ((uint64_t) host_ptr) & (page_size - 1);
		device_map_addr = hlthunk_host_memory_map(fd, host_ptr,
							  hint_addr, buf_size);
	} else {
		device_handle = hlthunk_device_memory_alloc(fd, buf_size, 0,
							    NOT_CONTIGUOUS,
							    false);
		assert_non_null(device_handle);

		device_map_addr = hlthunk_device_memory_map(fd, device_handle,
							    hint_addr);
	}

	/* The expected behavior is that if hint address is page aligned, it
	 * should be equal to the device mapped address - otherwise not.
	 */
	if ((device_map_addr == hint_addr + page_off) ^ page_aligned) {
		printf("Unexpected result: MMU type %s, page_aligned %u, "
		       "page_off 0x%lx, is_huge %u, ref_addr 0x%lx, "
		       "page_size 0x%lx, hint address 0x%lx, "
		       "device_map_addr 0x%lx\n",
		       type == HOST_ADDR ? "PMMU" : "DMMU", page_aligned,
		       page_off, is_huge, ref_addr, page_size, hint_addr,
		       device_map_addr);
		rc = -1;
	}

	if (type == HOST_ADDR) {
		/* Now when the address is in use, using it as hint will not
		 * work. Validate we get a failure when hint is forced.
		 */
		device_map_addr_late = hlthunk_host_memory_map_flags(
			fd, host_ptr, hint_addr, buf_size, HL_MEM_FORCE_HINT);
		assert_null(device_map_addr_late);
	}

	ret = hlthunk_memory_unmap(fd, device_map_addr);
	assert_int_equal(ret, 0);

	if (type == HOST_ADDR) {
		if (is_huge)
			munmap(host_ptr, buf_size);
		else
			hlthunk_free(host_ptr);
	} else {
		ret = hlthunk_device_memory_free(fd, device_handle);
		assert_int_equal(ret, 0);
	}

	return rc;
}

static bool is_dev_idle_and_operational(int fd)
{
	enum hl_device_status dev_status;
	bool is_idle;

	is_idle = hlthunk_is_device_idle(fd);

	dev_status = hlthunk_get_device_status_info(fd);

	return (is_idle && dev_status == HL_DEVICE_STATUS_OPERATIONAL);
}

int hltests_ensure_device_operational(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	uint32_t timeout_locked, i;
	int fd = tests_state->fd;

	if (is_dev_idle_and_operational(fd))
		return 0;

	timeout_locked = 30000;

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

	if (!(order >= PAGE_SHIFT_4KB && order <= PAGE_SHIFT_16MB))
		return NULL;

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

void hltests_parser(int argc, const char **argv, const char * const *usage,
			unsigned long expected_device_mask
#ifndef HLTESTS_LIB_MODE
			, const struct CMUnitTest * const tests, int num_tests
#endif
			)
{
	struct argparse argparse;
#ifndef HLTESTS_LIB_MODE
	const char *test = NULL;
	int list = 0;
	int i;
#endif
	int prof = 0;

	struct argparse_option options[] = {
		OPT_HELP(),
		OPT_GROUP("Basic options"),
#ifndef HLTESTS_LIB_MODE
		OPT_BOOLEAN('l', "list", &list, "list tests"),
		OPT_BOOLEAN('d', "disabled", &run_disabled_tests, "run disabled tests"),
		OPT_STRING('s', "test", &test, "name of specific test to run"),
		OPT_INTEGER('n', "ndevices", &num_devices, "number of devices"),
#endif
		OPT_BOOLEAN('v', "verbose", &verbose_enabled, "enable verbose"),
		OPT_STRING('p', "pciaddr", &parser_pciaddr, "pci address of device"),
		OPT_STRING('c', "config", &config_filename, "config filename for test(s)"),
		OPT_BOOLEAN('f', "prof", &prof, "enable profiling for test(s)"),
		OPT_INTEGER('m', "mode", &legacy_mode_enabled, "Legacy mode enabled"),
		OPT_STRING('b', "build_path", &build_path, "Path to build directory"),
		OPT_BOOLEAN('a', "arc-log", &enable_arc_log, "enable login for arcs"),
		OPT_END(),
	};

	argparse_init(&argparse, options, usage, 0);
	argparse_describe(&argparse, "\nRun tests using hl-thunk", NULL);
	argc = argparse_parse(&argparse, argc, argv);

#ifndef HLTESTS_LIB_MODE
	if (list) {
		printf("\nList of tests:");
		printf("\n-----------------\n\n");
		for (i = 0 ; i < num_tests ; i++)
			printf("%s\n", tests[i].name);
		printf("\n");
		exit(0);
	}

	if (test)
		cmocka_set_test_filter(test);
#endif

	if (prof)
		putenv("HABANA_PROFILE=1");

	asic_mask_for_testing = expected_device_mask;

#ifndef HLTESTS_LIB_MODE
	/*
	 * TODO:
	 * Remove when providing multiple PCI bus addresses is supported.
	 */
	if (num_devices > 1 &&  parser_pciaddr) {
		printf(
			"The '--pciaddr' and '--ndevices' options cannot coexist\n");
		exit(-1);
	}
#endif
}

uint32_t hltests_get_parser_enable_arc_log(void)
{
	return enable_arc_log;
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
#ifndef HLTESTS_LIB_MODE
	return run_disabled_tests;
#else
	return 1;
#endif
}

int hltests_get_verbose_enabled(void)
{
	return verbose_enabled;
}

uint32_t hltests_get_cur_seed(void)
{
	return cur_seed;
}

const char *hltests_get_build_path(void)
{
	return build_path;
}

bool hltests_is_legacy_mode_enabled(int fd)
{
	if (hltests_is_goya(fd) || hltests_is_gaudi(fd))
		return true;

	return !!legacy_mode_enabled;
}

bool hltests_is_simulator(int fd)
{
	return false;
}

bool hltests_is_goya(int fd)
{
	return (hlthunk_get_device_name_from_fd(fd) == HLTHUNK_DEVICE_GOYA);
}

bool hltests_is_gaudi(int fd)
{
	enum hlthunk_device_name device;

	device = hlthunk_get_device_name_from_fd(fd);
	if (device == HLTHUNK_DEVICE_GAUDI)
		return true;

	return false;
}

bool hltests_is_gaudi2(int fd)
{
	return (hlthunk_get_device_name_from_fd(fd) == HLTHUNK_DEVICE_GAUDI2);
}

bool hltests_is_pldm(int fd)
{
	return false;
}

VOID test_sm_pingpong_common_cp(void **state, bool is_tpc,
				bool common_cb_in_host, uint8_t engine_id)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	struct hltests_cs_chunk restore_arr[1], execute_arr[3];
	struct hltests_pkt_info pkt_info;
	struct hltests_monitor_and_fence mon_and_fence_info;
	void *host_src, *host_dst, *engine_common_cb, *engine_upper_cb = NULL,
		*restore_cb, *dmadown_cb, *dmaup_cb;
	uint64_t seq = 0, host_src_device_va, host_dst_device_va,
		device_data_addr,
		engine_common_cb_sram_addr, engine_common_cb_device_va = 0,
		engine_upper_cb_sram_addr = 0, engine_upper_cb_device_va = 0;
	uint32_t engine_qid, dma_size, engine_common_cb_size,
		engine_upper_cb_size = 0, restore_cb_size, dmadown_cb_size,
		dmaup_cb_size;
	uint16_t sob[2], mon[2], dma_down_qid, dma_up_qid;
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

	if (!hw_ip.sram_size)
		skip();

	if (is_tpc)
		engine_qid = hltests_get_tpc_qid(fd, engine_id, STREAM0);
	else
		engine_qid = hltests_get_mme_qid(fd, engine_id, STREAM0);

	dma_down_qid = hltests_get_dma_down_qid(fd, STREAM0);
	dma_up_qid = hltests_get_dma_up_qid(fd, STREAM0);

	device_data_addr = hw_ip.sram_base_address + 0x1000;
	engine_upper_cb_sram_addr = hw_ip.sram_base_address + 0x2000;
	engine_common_cb_sram_addr = hw_ip.sram_base_address + 0x3000;

	/* Allocate two buffers on the host for data transfers */
	host_src = hltests_allocate_host_mem(fd, dma_size, NOT_HUGE_MAP);
	assert_non_null(host_src);
	hltests_fill_rand_values(host_src, dma_size);
	host_src_device_va = hltests_get_device_va_for_host_ptr(fd, host_src);

	host_dst = hltests_allocate_host_mem(fd, dma_size, NOT_HUGE_MAP);
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
	if (hltests_is_legacy_mode_enabled(fd)) {
		engine_common_cb = hltests_allocate_host_mem(fd, 0x1000, NOT_HUGE_MAP);
		assert_non_null(engine_common_cb);
		memset(engine_common_cb, 0, 0x1000);
		engine_common_cb_device_va = hltests_get_device_va_for_host_ptr(fd,
								engine_common_cb);
	} else {
		engine_common_cb = hltests_create_cb(fd, 0x1000, EXTERNAL, 0);
	}

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

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = engine_qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	engine_common_cb_size = hltests_add_nop_pkt(fd, engine_common_cb,
							engine_common_cb_size,
							&pkt_info);
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = engine_qid;
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
	if (hltests_is_legacy_mode_enabled(fd)) {
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
	}

	hltests_clear_sobs(fd, 2);

	/* Setup CB: DMA the internal CBs to SRAM */
	restore_cb =  hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	assert_non_null(restore_cb);
	restore_cb_size = 0;

	if (!common_cb_in_host) {
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.qid = dma_down_qid;
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_TRUE;
		pkt_info.dma.src_addr = engine_common_cb_device_va;
		pkt_info.dma.dst_addr = engine_common_cb_sram_addr;
		pkt_info.dma.size = engine_common_cb_size;
		pkt_info.dma.dma_dir = DMA_DIR_HOST_TO_SRAM;
		restore_cb_size = hltests_add_dma_pkt(fd, restore_cb,
						restore_cb_size, &pkt_info);
	}

	if (hltests_is_legacy_mode_enabled(fd)) {
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_TRUE;
		pkt_info.dma.src_addr = engine_upper_cb_device_va;
		pkt_info.dma.dst_addr = engine_upper_cb_sram_addr;
		pkt_info.dma.size = engine_upper_cb_size;
		pkt_info.dma.dma_dir = DMA_DIR_HOST_TO_SRAM;
		restore_cb_size = hltests_add_dma_pkt(fd, restore_cb, restore_cb_size,
							&pkt_info);
	}

	/* CB for first DMA QMAN:
	 * Transfer data from host to SRAM + signal SOB0.
	 */
	dmadown_cb = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	assert_non_null(dmadown_cb);
	dmadown_cb_size = 0;

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = dma_down_qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.dma.src_addr = host_src_device_va;
	pkt_info.dma.dst_addr = device_data_addr;
	pkt_info.dma.size = dma_size;
	pkt_info.dma.dma_dir = DMA_DIR_HOST_TO_SRAM;
	dmadown_cb_size = hltests_add_dma_pkt(fd, dmadown_cb, dmadown_cb_size,
						&pkt_info);
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = dma_down_qid;
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
	mon_and_fence_info.queue_id = dma_up_qid;
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
	pkt_info.qid = dma_up_qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.dma.src_addr = device_data_addr;
	pkt_info.dma.dst_addr = host_dst_device_va;
	pkt_info.dma.size = dma_size;
	pkt_info.dma.dma_dir = DMA_DIR_SRAM_TO_HOST;
	dmaup_cb_size = hltests_add_dma_pkt(fd, dmaup_cb, dmaup_cb_size,
								&pkt_info);

	/* Submit CS and wait for completion */
	restore_arr[0].cb_ptr = restore_cb;
	restore_arr[0].cb_size = restore_cb_size;
	restore_arr[0].queue_index = dma_down_qid;

	execute_arr[0].cb_ptr = dmadown_cb;
	execute_arr[0].cb_size = dmadown_cb_size;
	execute_arr[0].queue_index = dma_down_qid;

	execute_arr[1].cb_ptr = hltests_is_legacy_mode_enabled(fd) ?
					engine_upper_cb : engine_common_cb;
	execute_arr[1].cb_size = hltests_is_legacy_mode_enabled(fd) ?
					engine_upper_cb_size : engine_common_cb_size;
	execute_arr[1].queue_index = engine_qid;

	execute_arr[2].cb_ptr = dmaup_cb;
	execute_arr[2].cb_size = dmaup_cb_size;
	execute_arr[2].queue_index = dma_up_qid;

	rc = hltests_submit_cs(fd, restore_arr, restore_cb_size ? 1 : 0,
				execute_arr, 3, HL_CS_FLAGS_FORCE_RESTORE, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	/* Compare host memories */
	rc = hltests_mem_compare(host_src, host_dst, dma_size);
	assert_int_equal(rc, 0);

	/* Cleanup */
	if (hltests_is_legacy_mode_enabled(fd)) {
		rc = hltests_destroy_cb(fd, engine_upper_cb);
		assert_int_equal(rc, 0);
	}

	rc = hltests_destroy_cb(fd, restore_cb);
	assert_int_equal(rc, 0);
	rc = hltests_destroy_cb(fd, dmadown_cb);
	assert_int_equal(rc, 0);
	rc = hltests_destroy_cb(fd, dmaup_cb);
	assert_int_equal(rc, 0);

	if (hltests_is_legacy_mode_enabled(fd))
		rc = hltests_free_host_mem(fd, engine_common_cb);
	else
		rc = hltests_destroy_cb(fd, engine_common_cb);
	assert_int_equal(rc, 0);

	rc = hltests_free_host_mem(fd, host_dst);
	assert_int_equal(rc, 0);
	rc = hltests_free_host_mem(fd, host_src);
	assert_int_equal(rc, 0);

	END_TEST;
}

int hltests_clear_sobs_offset(int fd, uint16_t num_of_sobs, uint16_t offset)
{
	uint16_t first_sob = hltests_get_first_avail_sob(fd);
	uint32_t cb_offset = 0, i, dma_qid;
	struct hltests_pkt_info pkt_info;
	void *cb;

	cb = hltests_create_cb(fd, HL_MAX_CB_SIZE, EXTERNAL, 0);
	assert_non_null(cb);

	dma_qid = hltests_get_dma_down_qid(fd, STREAM0);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = dma_qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.write_to_sob.value = 0;
	pkt_info.write_to_sob.mode = SOB_SET;
	for (i = first_sob ; i < (first_sob + offset + num_of_sobs - 1) ; i++) {
		pkt_info.write_to_sob.sob_id = i;
		cb_offset = hltests_add_write_to_sob_pkt(fd, cb, cb_offset, &pkt_info);
	}
	/* Message Barrier should be true only in the last packet */
	pkt_info.write_to_sob.sob_id = i;
	pkt_info.mb = MB_TRUE;
	cb_offset = hltests_add_write_to_sob_pkt(fd, cb, cb_offset, &pkt_info);

	hltests_submit_and_wait_cs(fd, cb, cb_offset, dma_qid,
			DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_COMPLETED);

	return 0;
}

void hltests_clear_sobs(int fd, uint16_t num_of_sobs)
{
	hltests_clear_sobs_offset(fd, num_of_sobs, 0);
}

void *hltests_map_hw_block(int fd, uint64_t block_addr, uint32_t *block_size)
{
	uint64_t handle;
	void *ptr;
	int rc;

	if (hltests_is_simulator(fd)) {
		*block_size = 0;
		return (void *) block_addr;
	}

	rc = hlthunk_get_hw_block(fd, block_addr, block_size, &handle);
	if (rc) {
		printf(
			"Failed to retrieve a HW block handle [block_address 0x%"PRIx64", rc %d]\n",
			block_addr, rc);
		return NULL;
	}

	ptr = mmap(NULL, *block_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
			handle);
	if (ptr == MAP_FAILED) {
		printf(
			"Failed to mmap a HW block handle [block_address 0x%"PRIx64", rc %d]\n",
			block_addr, rc);
		ptr = NULL;
	}

	return ptr;
}

int hltests_unmap_hw_block(int fd, void *host_addr, uint32_t block_size)
{
	if (hltests_is_simulator(fd))
		return 0;

	return munmap(host_addr, block_size);
}

int hltests_read_lbw_mem(int fd, void *dst, void *src, uint32_t size)
{
	int num_of_regs, i;
	uint32_t *d, *s;

	/* LBW access must be aligned to 32 bits*/
	if (size % sizeof(uint32_t) != 0)
		return -EINVAL;

	num_of_regs = size / sizeof(uint32_t);
	d = dst;
	s = src;

	for (i = 0; i < num_of_regs; i++, d++, s++)
		*d = *s;

	return 0;
}

int hltests_write_lbw_mem(int fd, void *dst, void *src, uint32_t size)
{
	int num_of_regs, i;
	uint32_t *d, *s;

	/* LBW access must be aligned to 32 bits*/
	if (size % sizeof(uint32_t) != 0)
		return -EINVAL;

	_mm_sfence();
	num_of_regs = size / sizeof(uint32_t);
	d = dst;
	s = src;

	for (i = 0; i < num_of_regs; i++, d++, s++)
		*d = *s;

	return 0;
}

int hltests_read_lbw_reg(int fd, void *src, uint32_t *value)
{
	return hltests_read_lbw_mem(fd, value, src, sizeof(*value));
}

int hltests_write_lbw_reg(int fd, void *dst, uint32_t value)
{
	return hltests_write_lbw_mem(fd, dst, &value, sizeof(value));
}

/*
 * hltests_get_default_cfg - Get device specific default test
 * configuration parameters.
 *
 * @fd: Habanalabs device open file descriptor
 * @cfg: Configuration structure specific to a device test.
 * @id: Test for which default configuration is requested.
 *
 * Returns 0 on success and error on failure.
 */
int hltests_get_default_cfg(int fd, void *cfg, enum hltests_id id)
{
	const struct hltests_asic_funcs *asic_funcs =
			get_hdev_from_fd(fd)->asic_funcs;

	return asic_funcs->get_default_cfg(cfg, id);
}

double get_timediff_sec(struct timespec *begin, struct timespec *end)
{
	return (end->tv_nsec - begin->tv_nsec) / 1000000000.0 +
						(end->tv_sec  - begin->tv_sec);
}

uint32_t next_pow2(uint32_t v)
{
	v--;
	v |= v >> 1;
	v |= v >> 2;
	v |= v >> 4;
	v |= v >> 8;
	v |= v >> 16;
	v++;

	return v;
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

int hltests_get_max_pll_idx(int fd)
{
	const struct hltests_asic_funcs *asic =
			get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_max_pll_idx();
}

const char *hltests_stringify_pll_idx(int fd, uint32_t pll_idx)
{
	const struct hltests_asic_funcs *asic =
			get_hdev_from_fd(fd)->asic_funcs;

	return asic->stringify_pll_idx(pll_idx);
}

const char *hltests_stringify_pll_type(int fd, uint32_t pll_idx,
				uint8_t type_idx)
{
	const struct hltests_asic_funcs *asic =
			get_hdev_from_fd(fd)->asic_funcs;

	return asic->stringify_pll_type(pll_idx, type_idx);
}

int hltests_device_memory_export_dmabuf_fd(int fd, void *device_addr,
						uint64_t size)
{
	struct hltests_device *hdev;
	uint64_t device_handle;

	hdev = get_hdev_from_fd(fd);
	assert_non_null(hdev);

	if (hltests_is_gaudi(fd)) {
		device_handle = (uint64_t) (uintptr_t) device_addr;
	} else {
		device_handle =
			hltests_get_device_handle_for_device_va(fd,
								device_addr);
		assert_int_not_equal(device_handle, 0);
	}

	return hlthunk_device_memory_export_dmabuf_fd(fd, device_handle, size,
							O_RDWR | O_CLOEXEC);
}

int hltest_get_host_meminfo(struct hltest_host_meminfo *res)
{
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	int n_fields = 0;

	fp = fopen("/proc/meminfo", "r");
	if (!fp)
		return -1;
	memset(res, 0, sizeof(*res));

	while ((read = getline(&line, &len, fp)) != -1) {
		if (sscanf(line, "MemTotal: %lu", &res->mem_total) == 1)
			n_fields++;
		if (sscanf(line, "MemFree: %lu", &res->mem_free) == 1)
			n_fields++;
		if (sscanf(line, "MemAvailable: %lu", &res->mem_available) == 1)
			n_fields++;
		if (sscanf(line, "HugePages_Total: %lu",
			&res->hugepage_total) == 1)
			n_fields++;
		if (sscanf(line, "HugePages_Free: %lu", &res->hugepage_free) ==
		    1)
			n_fields++;
		if (sscanf(line, "Hugepagesize: %lu", &res->hugepage_size) == 1)
			n_fields++;
	}
	if (n_fields != 6)
		return -1;
	res->mem_total *= 1024;
	res->mem_free *= 1024;
	res->mem_available *= 1024;
	res->hugepage_size *= 1024;
	res->page_size = getpagesize();
	if (line)
		free(line);
	fclose(fp);
	return 0;
}

int hltests_get_async_event_id(int fd, enum hltests_async_event_id hl_tests_event_id,
				uint32_t *asic_event_id)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_async_event_id(hl_tests_event_id, asic_event_id);
}

uint32_t hltests_get_cq_patch_size(int fd, uint32_t qid)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_cq_patch_size(qid);
}

uint32_t hltests_get_max_pkt_size(int fd, bool mb, bool eb, uint32_t qid)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_max_pkt_size(fd, mb, eb, qid);
}

uint32_t hltests_add_direct_write_cq_pkt(int fd, void *buffer, uint32_t buf_off,
					struct hltests_direct_cq_write *pkt_info)
{
	const struct hltests_asic_funcs *asic =
			get_hdev_from_fd(fd)->asic_funcs;

	return asic->add_direct_write_cq_pkt(fd, buffer, buf_off, pkt_info);
}

static void *hltests_monitor_dma_thread(void *data)
{
	const struct hltests_asic_funcs *asic;
	struct monitor_dma_test *params;

	params = (struct monitor_dma_test *)data;
	asic = get_hdev_from_fd(params->fd)->asic_funcs;

	asic->monitor_dma_test_progress(params);

	return data;
}

void hltests_monitor_dma_start(struct monitor_dma_test *params)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(params->fd)->asic_funcs;
	int rc;

	if (!asic->monitor_dma_test_progress)
		return;

	pthread_cond_init(&params->cond, NULL);
	pthread_mutex_init(&params->mutex, NULL);

	rc = pthread_create(&params->tid, NULL, hltests_monitor_dma_thread, params);
	if (rc)
		printf("DMA monitor pthread_create error: %d\n", rc);
}

void hltests_monitor_dma_stop(struct monitor_dma_test *params)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(params->fd)->asic_funcs;
	int rc;

	if (!asic->monitor_dma_test_progress)
		return;

	/* signal, by means of condition variable, to the mon thread to stop  */
	pthread_mutex_lock(&params->mutex);
	pthread_cond_signal(&params->cond);
	pthread_mutex_unlock(&params->mutex);

	pthread_mutex_destroy(&params->mutex);
	pthread_cond_destroy(&params->cond);

	rc = pthread_join(params->tid, NULL);
	if (rc)
		printf("DMA monitor thread join error: %d\n", rc);
}

