// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "argparse.h"
#include "hlthunk.h"
#include "hlthunk_tests.h"
#include "mersenne-twister/mersenne-twister.h"

#include <assert.h>
#include <byteswap.h>
#include <errno.h>
#include <errno.h>
#include <fcntl.h>
#include <immintrin.h>
#include <inttypes.h>
#include <linux/mman.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <syscall.h>
#include <time.h>
#include <unistd.h>

#include <infiniband/hbldv.h>

#ifndef MAP_HUGE_2MB
	#define MAP_HUGE_2MB    (21 << MAP_HUGE_SHIFT)
#endif

#define FRAG_MEM_MULT 3

#define BUILD_PATH_MAX_LENGTH	256

#define PSOC_FREQ_GHZ		0.05

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
static int nic_port;
static int legacy_mode_enabled = 1;
static uint32_t cur_seed;
static char build_path_str[BUILD_PATH_MAX_LENGTH];
static const char *build_path;
static uint64_t hltests_capabilities_mask;
static int enable_arc_log;
static int events_listener = 1;
static uint32_t negative_tests;
static uint32_t run_mini_suite;

char asic_names[HLTHUNK_DEVICE_MAX][20] = {
	[HLTHUNK_DEVICE_INVALID] = "Invalid",
	[HLTHUNK_DEVICE_GOYA] = "Goya",
	[HLTHUNK_DEVICE_GAUDI] = "Gaudi",
	[HLTHUNK_DEVICE_GAUDI_HL2000M] = "Gaudi_HL2000M",
	[HLTHUNK_DEVICE_GRECO] = "Greco",
	[HLTHUNK_DEVICE_GAUDI2] = "Gaudi2",
	[HLTHUNK_DEVICE_GAUDI2B] = "Gaudi2B",
	[HLTHUNK_DEVICE_GAUDI2C] = "Gaudi2C",
	[HLTHUNK_DEVICE_GAUDI2D] = "Gaudi2D",
	[HLTHUNK_DEVICE_GAUDI3] = "Gaudi3",
	[HLTHUNK_DEVICE_GAUDI3D] = "Gaudi3D",
	[HLTHUNK_DEVICE_DONT_CARE] = "Don't care"
};

/* translate device name (enum) to device mask */
unsigned long device_enum_to_device_mask[HLTHUNK_DEVICE_MAX] = {
	[HLTHUNK_DEVICE_INVALID] = HLTEST_DEVICE_MASK_INVALID,
	[HLTHUNK_DEVICE_GOYA] = HLTEST_DEVICE_MASK_GOYA,
	[HLTHUNK_DEVICE_GAUDI] = HLTEST_DEVICE_MASK_GAUDI,
	[HLTHUNK_DEVICE_GAUDI_HL2000M] = HLTEST_DEVICE_MASK_GAUDI_HL2000M,
	[HLTHUNK_DEVICE_GRECO] = HLTEST_DEVICE_MASK_GRECO,
	[HLTHUNK_DEVICE_GAUDI2] = HLTEST_DEVICE_MASK_GAUDI2,
	[HLTHUNK_DEVICE_GAUDI2B] = HLTEST_DEVICE_MASK_GAUDI2B,
	[HLTHUNK_DEVICE_GAUDI2C] = HLTEST_DEVICE_MASK_GAUDI2C,
	[HLTHUNK_DEVICE_GAUDI2D] = HLTEST_DEVICE_MASK_GAUDI2D,
	[HLTHUNK_DEVICE_GAUDI3] = HLTEST_DEVICE_MASK_GAUDI3,
	[HLTHUNK_DEVICE_DONT_CARE] = HLTEST_DEVICE_MASK_DONT_CARE,
	[HLTHUNK_DEVICE_GAUDI3D] = HLTEST_DEVICE_MASK_GAUDI3D,
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
	.nic_ports_mask = 0,
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
	.cache_enabled = 0,
	.hbm_ecc_enable = 1,
	.compatibility_mode = 0,
	.hard_reset_on_fw_events = 1,
	.decoder_mask = 0,
	.rotator_mask = 0,
	.fw_loading_ext = 0
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

double get_timediff_usec(struct timespec *begin, struct timespec *end)
{
	return (end->tv_nsec - begin->tv_nsec) / 1000.0 +
						1000000.0 * (end->tv_sec  - begin->tv_sec);
}

double get_timediff_sec(struct timespec *begin, struct timespec *end)
{
	return (end->tv_nsec - begin->tv_nsec) / 1000000000.0 +
						(end->tv_sec  - begin->tv_sec);
}

static int create_mem_maps(struct hltests_device *hdev)
{
	int rc;
	bool mem_table_host_lock = false;
	bool mem_table_device_lock = false;
	bool mmap_table_lock = false;
	bool cb_table_lock = false;

	hdev->mem_table_host = kh_init(ptr64);
	if (!hdev->mem_table_host) {
		rc = -ENOMEM;
		goto cleanup;
	}

	hdev->mem_table_device = kh_init(ptr64);
	if (!hdev->mem_table_device) {
		rc = -ENOMEM;
		goto cleanup;
	}

	hdev->mmap_table = kh_init(mapping);
	if (!hdev->mmap_table) {
		rc = -ENOMEM;
		goto cleanup;
	}

	hdev->cb_table = kh_init(ptr64);
	if (!hdev->cb_table) {
		rc = -ENOMEM;
		goto cleanup;
	}

	rc = pthread_mutex_init(&hdev->mem_table_host_lock, NULL);
	if (rc)
		goto cleanup;
	else
		mem_table_host_lock = true;

	rc = pthread_mutex_init(&hdev->mem_table_device_lock, NULL);
	if (rc)
		goto cleanup;
	else
		mem_table_device_lock = true;

	rc = pthread_mutex_init(&hdev->mmap_table_lock, NULL);
	if (rc)
		goto cleanup;
	else
		mmap_table_lock = true;

	rc = pthread_mutex_init(&hdev->cb_table_lock, NULL);
	if (rc)
		goto cleanup;
	else
		cb_table_lock = true;

	return 0;

cleanup:
	if (cb_table_lock)
		pthread_mutex_destroy(&hdev->cb_table_lock);
	if (mmap_table_lock)
		pthread_mutex_destroy(&hdev->mmap_table_lock);
	if (mem_table_device_lock)
		pthread_mutex_destroy(&hdev->mem_table_device_lock);
	if (mem_table_host_lock)
		pthread_mutex_destroy(&hdev->mem_table_host_lock);
	if (hdev->cb_table)
		kh_destroy(ptr64, hdev->cb_table);
	if (hdev->mmap_table)
		kh_destroy(mapping, hdev->mmap_table);
	if (hdev->mem_table_device)
		kh_destroy(ptr64, hdev->mem_table_device);
	if (hdev->mem_table_host)
		kh_destroy(ptr64, hdev->mem_table_host);
	return rc;
}

static void destroy_mem_maps(struct hltests_device *hdev)
{
	kh_destroy(mapping, hdev->mmap_table);
	kh_destroy(ptr64, hdev->mem_table_host);
	kh_destroy(ptr64, hdev->mem_table_device);
	kh_destroy(ptr64, hdev->cb_table);
	pthread_mutex_destroy(&hdev->mmap_table_lock);
	pthread_mutex_destroy(&hdev->mem_table_host_lock);
	pthread_mutex_destroy(&hdev->mem_table_device_lock);
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

bool hltests_is_dma_dir_from_dram(enum hltests_dma_direction dir)
{
	return dir == DMA_DIR_DRAM_TO_SRAM ||
		dir == DMA_DIR_DRAM_TO_HOST ||
		dir == DMA_DIR_DRAM_TO_DRAM;
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
	struct tm ts_units_curr[num_devices], ts_units_prev[num_devices];
	struct hltests_thread_params *thread_params = NULL;
	time_t ts_curr[num_devices], ts_prev[num_devices];
	char formatted_ts[SZ_128], device_no[SZ_128];
	uint32_t i, num_threads = num_devices;
	pthread_t *thread_ids = NULL;
	int rc, diff_sec;
	void *retval;

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
		if (time(&ts_curr[i]) == -1) {
			perror("'time()' failed");
			goto out;
		}

		localtime_r(&ts_curr[i], &ts_units_curr[i]);
		strftime(formatted_ts, sizeof(formatted_ts), "%T", &ts_units_curr[i]);
		sprintf(device_no, num_threads > 1 ? "[device no. %d]" : "", i);
		printf("\n[%s]%s timestamp #1: %s\n", group_name, device_no, formatted_ts);

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

		/* Save timestamps previously sampled */
		ts_prev[i] = ts_curr[i];
		ts_units_prev[i] = ts_units_curr[i];

		if (time(&ts_curr[i]) == -1) {
			perror("'time()' failed");
			goto out;
		}

		localtime_r(&ts_curr[i], &ts_units_curr[i]);
		strftime(formatted_ts, sizeof(formatted_ts), "%T", &ts_units_curr[i]);
		sprintf(device_no, num_threads > 1 ? "[device no. %d]" : "", i);
		printf("\n[%s]%s timestamp #2: %s\n", group_name, device_no, formatted_ts);

		/* Set relative H/M/S, later to be formatted using strftime */
		diff_sec = (int)difftime(ts_curr[i], ts_prev[i]);
		ts_units_curr[i].tm_hour = diff_sec / 3600;
		diff_sec %= 3600; /* reduced whole hours */
		ts_units_curr[i].tm_min = diff_sec / 60;
		diff_sec %= 60; /* reduced whole minutes */
		ts_units_curr[i].tm_sec = diff_sec;

		strftime(formatted_ts, sizeof(formatted_ts), "%T", &ts_units_curr[i]);
		printf("[%s]%s runtime: %s\n\n", group_name, device_no, formatted_ts);

		if (rc) {
			printf("Failed to join with thread %d\n", i);
			goto out;
		}

		if (!retval || retval == PTHREAD_CANCELED) {
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
	case HLTHUNK_DEVICE_GAUDI_HL2000M:
		gaudi_tests_set_asic_funcs(hdev);
		break;
	case HLTHUNK_DEVICE_GAUDI2:
	case HLTHUNK_DEVICE_GAUDI2B:
	case HLTHUNK_DEVICE_GAUDI2C:
	case HLTHUNK_DEVICE_GAUDI2D:
		gaudi2_tests_set_asic_funcs(hdev);
		break;
	case HLTHUNK_DEVICE_GAUDI3:
	case HLTHUNK_DEVICE_GAUDI3D:
		gaudi3_tests_set_asic_funcs(hdev);
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

int wait_until_device_idle(int fd, uint32_t timeout_sec)
{
	uint64_t elapsed_usec = 0, timeout_usec = timeout_sec * USEC_PER_SEC;
	uint32_t sleep_usec = USEC_PER_MSEC;
	int rc;

	while (elapsed_usec < timeout_usec) {
		if (hlthunk_is_device_idle(fd))
			break;

		rc = usleep(sleep_usec);
		if (rc)
			return -errno;

		elapsed_usec += sleep_usec;
	}

	return elapsed_usec < timeout_usec ? 0 : -ETIMEDOUT;
}

int wait_until_device_not_in_reset(int fd)
{
	unsigned int elapsed_sec = 0, sleep_sec = 1, timeout_sec;
	int device_status;

	timeout_sec = hltests_is_pldm(fd) ? PLDM_RESET_WAIT_TIMEOUT_SEC : RESET_WAIT_TIMEOUT_SEC;

	while (elapsed_sec < timeout_sec) {
		device_status = hlthunk_get_device_status_info(fd);
		if (device_status < 0)
			return device_status;

		if (device_status != HL_DEVICE_STATUS_IN_RESET &&
				device_status != HL_DEVICE_STATUS_IN_RESET_AFTER_DEVICE_RELEASE)
			break;

		sleep(sleep_sec);
		elapsed_sec += sleep_sec;
	}

	return elapsed_sec < timeout_sec ? 0 : -ETIMEDOUT;
}

int hltests_open(const char *busid)
{
	enum hlthunk_device_name actual_asic_type;
	struct hltests_device *hdev;
	int ctrl_fd, fd, rc;
	khint_t k;

	if (!asic_mask_for_testing) {
		printf("Expecting invalid ASIC!!!\n");
		printf("Something is very wrong, exiting...\n");
		return -EINVAL;
	}

	pthread_mutex_lock(&table_lock);

	/* Open control device first in order to compare against asic_mask_for_testing */
	rc = ctrl_fd = hlthunk_open_control_by_name(HLTHUNK_DEVICE_DONT_CARE, busid);
	if (ctrl_fd < 0)
		goto out;

	actual_asic_type = hlthunk_get_device_name_from_fd(ctrl_fd);
	if (!hltests_is_asic_type_valid(actual_asic_type)) {
		rc = -EINVAL;
		hlthunk_close(ctrl_fd);
		pthread_mutex_unlock(&table_lock);
		exit(0);
	}

	/* If device is in reset, wait until reset process is done */
	rc = wait_until_device_not_in_reset(ctrl_fd);
	hlthunk_close(ctrl_fd);
	if (rc)
		goto out;

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
	hdev->device_id = hlthunk_get_device_id_from_fd(fd);

	k = kh_put(ptr, dev_table, fd, &rc);
	kh_val(dev_table, k) = hdev;

	switch (actual_asic_type) {
	case HLTHUNK_DEVICE_GOYA:
		goya_tests_set_asic_funcs(hdev);
		break;
	case HLTHUNK_DEVICE_GAUDI:
	case HLTHUNK_DEVICE_GAUDI_HL2000M:
		gaudi_tests_set_asic_funcs(hdev);
		break;
	case HLTHUNK_DEVICE_GAUDI2:
	case HLTHUNK_DEVICE_GAUDI2B:
	case HLTHUNK_DEVICE_GAUDI2C:
	case HLTHUNK_DEVICE_GAUDI2D:
		gaudi2_tests_set_asic_funcs(hdev);
		break;

	case HLTHUNK_DEVICE_GAUDI3:
	case HLTHUNK_DEVICE_GAUDI3D:
		gaudi3_tests_set_asic_funcs(hdev);
		break;
	default:
		printf("Invalid device type 0x%x\n", hdev->device_id);
		rc = -ENXIO;
		goto remove_device;
	}

	memset(&hdev->module_params, 0, sizeof(hdev->module_params));
	rc = hltests_get_module_params_info(fd, &hdev->module_params);
	if (rc) {
		printf("Failed to retrieve values of module parameters\n");
		goto remove_device;
	}

	rc = hdev->asic_funcs->asic_priv_init(hdev);
	if (rc)
		goto remove_device;

	rc = create_mem_maps(hdev);
	if (rc)
		goto destroy_asic_priv;

	pthread_mutex_unlock(&table_lock);

	return fd;

destroy_asic_priv:
	hdev->asic_funcs->asic_priv_fini(hdev);
remove_device:
	kh_del(ptr, dev_table, k);
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

	destroy_mem_maps(hdev);

	hlthunk_close(hdev->fd);

	kh_del(ptr, dev_table, k);
	pthread_mutex_unlock(&table_lock);

	hlthunk_free(hdev);

	return 0;
}

void *hltests_mmap(int fd, size_t length, off_t offset)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	void *ptr;
	int rc;
	khint_t k;

	ptr = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, offset);
	if (ptr == MAP_FAILED)
		return MAP_FAILED;

	pthread_mutex_lock(&hdev->mmap_table_lock);

	k = kh_put(mapping, hdev->mmap_table, (uintptr_t)ptr, &rc);
	if (rc < 0) {
		pthread_mutex_unlock(&hdev->mmap_table_lock);
		munmap(ptr, length);
		errno = ENOMEM;
		return MAP_FAILED;
	}
	kh_val(hdev->mmap_table, k) = length;

	pthread_mutex_unlock(&hdev->mmap_table_lock);

	return ptr;
}

int hltests_munmap(int fd, void *addr, size_t length)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	khint_t k;

	pthread_mutex_lock(&hdev->mmap_table_lock);

	k = kh_get(mapping, hdev->mmap_table, (uint64_t)(uintptr_t)addr);
	if (k == kh_end(hdev->mmap_table)) {
		pthread_mutex_unlock(&hdev->mmap_table_lock);
		errno = EINVAL;
		return -1;
	}

	if (length != kh_val(hdev->mmap_table, k)) {
		pthread_mutex_unlock(&hdev->mmap_table_lock);
		errno = ENOENT;
		return -1;
	}

	kh_del(mapping, hdev->mmap_table, k);

	pthread_mutex_unlock(&hdev->mmap_table_lock);

	return munmap(addr, length);
}

static int debugfs_open(struct hltests_state *tests_state, int device_idx)
{
	int parent_device_fd, debugfs_addr_fd, debugfs_data32_fd, clk_gate_fd, debugfs_data64_fd;
	char parent_device[16], clk_gate_str[16] = "0";
	char path[PATH_MAX];
	ssize_t size;

	snprintf(path, PATH_MAX, "/sys/class/accel/accel%d/device/parent_device", device_idx);
	parent_device_fd = open(path, O_RDONLY);
	if (parent_device_fd == -1) {
		printf("Failed to open sysfs parent_device\n");
		return -EPERM;
	}

	size = read(parent_device_fd, parent_device, sizeof(parent_device));
	if (size <= 0) {
		close(parent_device_fd);
		printf("Failed to read from sysfs parent_device, rc %zd\n", size);
		return -errno;
	}

	parent_device[strcspn(parent_device, "\n")] = '\0'; /* remove trailing newline character */
	close(parent_device_fd);

	snprintf(path, PATH_MAX, "/sys/kernel/debug/accel/%s/addr", parent_device);

	debugfs_addr_fd = open(path, O_WRONLY);

	if (debugfs_addr_fd == -1) {
		printf("Failed to open debugfs_addr_fd (forgot sudo ?)\n");
		return -EPERM;
	}

	snprintf(path, PATH_MAX, "/sys/kernel/debug/accel/%s/data32", parent_device);

	debugfs_data32_fd = open(path, O_RDWR);

	if (debugfs_data32_fd == -1) {
		close(debugfs_addr_fd);
		printf("Failed to open debugfs_data_fd (forgot sudo ?)\n");
		return -EPERM;
	}

	snprintf(path, PATH_MAX, "/sys/kernel/debug/accel/%s/data64", parent_device);

	debugfs_data64_fd = open(path, O_RDWR);

	if (debugfs_data64_fd == -1) {
		close(debugfs_data32_fd);
		close(debugfs_addr_fd);
		printf("Failed to open debugfs_data64_fd (forgot sudo ?)\n");
		return -EPERM;
	}

	snprintf(path, PATH_MAX, "/sys/kernel/debug/accel/%s/clk_gate", parent_device);

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
		printf("Failed to write to debugfs address [rc %zd]\n", size);

	size = write(data_fd, val_str, strlen(val_str) + 1);
	if (size < 0)
		printf("Failed to write to debugfs data [rc %zd]\n", size);

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

	rc = hlthunk_get_hw_ip_info(fd, &tests_state->hw_ip);
	assert_int_equal(rc, 0);

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

static void hltests_pdma_memory_free(int fd, struct hltests_pdma_db *pdma_db)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	const struct hltests_asic_funcs *asic = hdev->asic_funcs;
	uint32_t pdma_ch_cnt = asic->pdma_get_max_ch_id(fd);
	struct pdma_ch_info *ch_info = pdma_db->ch_info;
	int i;

	for (i = 0 ; i < pdma_ch_cnt ; i++)
		hltests_free_host_mem(fd, ch_info[i].submission_q);

	hlthunk_free(pdma_db->ch_info);
}

static int hltests_pdma_memory_allocate(int fd, struct hltests_pdma_db *pdma_db)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	const struct hltests_asic_funcs *asic = hdev->asic_funcs;
	uint32_t pdma_ch_cnt = asic->pdma_get_max_ch_id(fd);
	struct pdma_ch_info *ch_info;
	int i, ch_idx, rc = -ENOMEM;

	assert_int_equal(!IS_POWER_OF_TWO(PQM_PI_CI_IN_MEM_Q_SIZE), 0);
	assert_in_range(PQM_PI_CI_IN_MEM_Q_SIZE, 0, SZ_1G);

	memset(pdma_db, 0, sizeof(*pdma_db));

	pdma_db->ch_info = hlthunk_malloc(sizeof(struct pdma_ch_info) * pdma_ch_cnt);
	if (!pdma_db->ch_info)
		return rc;

	for (ch_idx = 0 ; ch_idx < pdma_ch_cnt ; ch_idx++) {
		ch_info = &pdma_db->ch_info[ch_idx];
		ch_info->submission_q_size = PQM_PI_CI_IN_MEM_Q_SIZE;
		ch_info->submission_q = hltests_allocate_host_mem_aligned(fd,
				ALIGN_UP(ch_info->submission_q_size, 8), NOT_HUGE_MAP, 8);
		if (!ch_info->submission_q)
			goto free_pqm_ch_q_mem;

		/* The low part of the pointer to the base of submission queue for PI/CI
		 * in memory mode. This address is expected to be 8B aligned.
		 */
		assert_int_equal(!IS_8B_ALIGNED((uintptr_t)ch_info->submission_q), 0);

		ch_info->submission_q_handle =
				hltests_get_device_va_for_host_ptr(fd, ch_info->submission_q);
		assert_non_null(ch_info->submission_q_handle);

		/* Submission queue of PI/CI in memory mode is expected to be 8B aligned */
		assert_int_equal(!IS_8B_ALIGNED(ch_info->submission_q_handle), 0);
	}

	return 0;

free_pqm_ch_q_mem:
	ch_info = pdma_db->ch_info;
	for (i = 0 ; i < ch_idx ; i++)
		hltests_free_host_mem(fd, ch_info[i].submission_q);

	hlthunk_free(ch_info);

	return rc;
}

int hltests_pdma_init(int fd, struct hltests_pdma_db *pdma_db)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct hlthunk_hw_ip_info hw_ip;
	int rc;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.pdma_user_owned_ch_mask)
		return 0;

	rc = hltests_pdma_memory_allocate(fd, pdma_db);
	if (rc)
		return rc;

	/* map user-owned channels to user's address space */
	rc = hdev->asic_funcs->pdma_map_lbw_blocks(fd, pdma_db);
	if (rc) {
		printf("Failed to map LBW blocks for PDMA\n");
		goto err_free_pdma_memory;
	}

	rc = hdev->asic_funcs->pdma_config_ch_blocks(fd, pdma_db);
	if (rc) {
		printf("Failed to configure PDMA channels/s\n");
		goto err_unmap_lbw_blocks;
	}

	return 0;

err_unmap_lbw_blocks:
	hdev->asic_funcs->pdma_unmap_lbw_blocks(fd, pdma_db);
err_free_pdma_memory:
	hltests_pdma_memory_free(fd, pdma_db);

	return rc;
}

void hltests_pdma_fini(int fd, struct hltests_pdma_db *pdma_db)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);

	if (!pdma_db->user_en_ch_mask)
		return;

	hdev->asic_funcs->pdma_unmap_lbw_blocks(fd, pdma_db);
	hltests_pdma_memory_free(fd, pdma_db);
}

uint64_t hltests_get_total_avail_device_mem(int fd)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct hlthunk_hw_ip_info hw_ip;
	uint64_t dram_size, num_pages;
	int rc;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	dram_size = hw_ip.dram_size;

	/*
	 * When we add dram reserved areas smaller than 32MB tests suite such
	 * as entire dram starts to fails. the reason is the hw_ip.dram_size
	 * takes into consideration those reserved areas and such tests
	 * will try to allocate the whole available memory in pages of
	 * default page size(meaning the total available memory rounded up
	 * according to the default page size). in such scenario the memory
	 * pool will have less room than the rounded up size to be allocated
	 * and then the tests will fail.
	 * To solve this we need to round down the total available size
	 * according to the default page size.
	 */
	dram_size = rounddown(dram_size, hw_ip.device_mem_alloc_default_page_size);

	if (!hltests_is_legacy_mode_enabled(fd)) {
		/*
		 * In ARC mode we allocate device memory for loading the FW
		 * In this test we should subtract this size from the entire dram size
		 * and test only the remaining part.
		 */
		num_pages = DIV_ROUND_UP(hdev->arc_db.device_mem_size,
						hw_ip.device_mem_alloc_default_page_size);
		dram_size -= (num_pages * hw_ip.device_mem_alloc_default_page_size);
	}

	return dram_size;
}

int hltests_setup_user_engines(struct hltests_state *tests_state)
{
	int rc, fd = tests_state->fd, verbose = hltests_get_verbose_enabled();
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	time_t pdma_ts, arcdb_ts, mme_dma_ts, arc_init_ts, end;

	if (hltests_is_legacy_mode_enabled(fd))
		return 0;

	memset(&hdev->arc_db, 0, sizeof(struct hltests_arc_db));

	hdev->arc_db.fw_info =
		hlthunk_malloc(sizeof(struct arc_fw_info) *
				hdev->asic_funcs->arc_get_max_cpuid());
	if (!hdev->arc_db.fw_info)
		return -ENOMEM;

	if (verbose) {
		time(&pdma_ts);
		printf("Init PDMA...");
	}

	rc = hltests_pdma_init(fd, &hdev->pdma_db);
	if (rc) {
		printf("\nFailed to allocate PDMA resources\n");
		goto free_fw_info;
	}

	if (verbose) {
		time(&arcdb_ts);
		printf("\t\t%.f seconds\n", difftime(arcdb_ts, pdma_ts));
		printf("Init ARC CQ DB...");
	}

	rc = hltests_completion_db_init(fd, &hdev->completion_db);
	if (rc) {
		printf("\nFailed to configure completion DB\n");
		goto pdma_fini;
	}

	if (verbose) {
		time(&mme_dma_ts);
		printf("\t%.f seconds\n", difftime(mme_dma_ts, arcdb_ts));
		printf("Init MME DMA...");
	}

	rc = hltests_mme_dma_init(fd);
	if (rc) {
		printf("\nFailed to init MME DMA\n");
		goto arc_cq_db_teardown;
	}


	/* Use the build path from the build phase unless it is provided at run-time */
	if (!build_path) {
		rc = hltests_set_build_path(HLTHUNK_BUILD_PATH);
		if (rc) {
			printf("\nFailed to set build path\n");
			goto arc_cq_db_teardown;
		}
	}

	if (verbose) {
		time(&arc_init_ts);
		printf("\t\t%.f seconds\n", difftime(arc_init_ts, mme_dma_ts));
		printf("Initializing ARCs...\n");
	}

	rc = hltests_arc_init(fd, &hdev->arc_db);
	if (rc) {
		printf("Failed to allocate arc memories\n");
		goto arc_cq_db_teardown;
	}

	if (verbose) {
		time(&end);
		printf("Initializing ARCs took \t%.f seconds\n", difftime(end, arc_init_ts));
	}

	return 0;

arc_cq_db_teardown:
	hltests_completion_db_teardown(fd, &hdev->completion_db);
pdma_fini:
	hltests_pdma_fini(fd, &hdev->pdma_db);
free_fw_info:
	hlthunk_free(hdev->arc_db.fw_info);

	return rc;
}

/**
 * This function waits until expected events are received and retrieve the whole received events
 * @tests_state pointer to the hltests_state structure
 * @timeout_sec timeout duration in seconds. 0 means using the default timeout value.
 * @expected_events mask of events to wait for
 * @received_events optional pointer to uint64_t to store a mask of the received events
 * @return 0 for success, negative value for failure
 */
int hltests_wait_for_events(struct hltests_state *tests_state, uint32_t timeout_sec,
				uint64_t expected_events, uint64_t *received_events)
{
	struct hltests_listener_thread_params *params = &tests_state->listener_thread_params;
	uint64_t events_to_wait_for = expected_events;
	struct timespec ts;
	int rc;

	if (!timeout_sec)
		timeout_sec = hltests_is_pldm(tests_state->fd) ?
				PLDM_EVENTS_WAIT_TIMEOUT_SEC :
				EVENTS_WAIT_TIMEOUT_SEC;

	if (received_events)
		*received_events = 0;

	rc = pthread_mutex_lock(&params->lock);
	if (rc)
		return rc;

	clock_gettime(CLOCK_REALTIME, &ts);
	ts.tv_sec += timeout_sec;

	while (events_to_wait_for) {
		/* Store all received events, either if they are part of the expected mask or not */
		if (received_events)
			*received_events |= params->notifier_events;

		/* Clear the received events from the mask of events that we wait for */
		events_to_wait_for &= ~params->notifier_events;
		params->notifier_events = 0;
		if (!events_to_wait_for)
			break;

		rc = pthread_cond_timedwait(&params->cond, &params->lock, &ts);
		if (rc) {
			pthread_mutex_unlock(&params->lock);
			/* SW-159137 TODO: this 'if' can be removed when issue is solved */
			if (rc == ETIMEDOUT && received_events && *received_events == 0) {
				char buf[128];
				int fdinfo_fd, n;

				printf("timeout, notifier events are 0x%lx\n",
							params->notifier_events);
				sprintf(buf, "/proc/%u/fdinfo/%u", params->listener_tid,
							params->handle);
				fdinfo_fd = open(buf, O_RDONLY);
				if (fdinfo_fd < 0)
					return rc;
				memset(buf, 0, sizeof(buf));
				n = read(fdinfo_fd, buf, sizeof(buf));
				buf[127] = '\0';
				printf("eventfd fdinfo (first %d bytes):\n%s\n", n, buf);
				close(fdinfo_fd);
			}
			return rc;
		}
	}

	return pthread_mutex_unlock(&params->lock);
}

static enum hltests_recovery_status hltests_get_recovery_status(struct hltests_state *tests_state)
{
	struct hltests_listener_thread_params *params = &tests_state->listener_thread_params;

	return params->recovery_status;
}

int hltests_reset_events(struct hltests_state *tests_state)
{
	struct hltests_listener_thread_params *params = &tests_state->listener_thread_params;
	int rc;

	rc = pthread_mutex_lock(&params->lock);
	if (rc)
		return rc;

	params->notifier_events = 0;
	return pthread_mutex_unlock(&params->lock);
}

static void hltests_set_recovery_status(struct hltests_state *tests_state,
					enum hltests_recovery_status recovery_status)
{
	struct hltests_listener_thread_params *params = &tests_state->listener_thread_params;

	params->recovery_status = recovery_status;
}

static void hltests_print_cs_timeout_event_info(int fd)
{
	struct hlthunk_event_record_cs_timeout cs_timeout;
	int rc;

	rc = hlthunk_get_event_record(fd, HLTHUNK_CS_TIMEOUT, &cs_timeout);
	if (rc) {
		printf("Failed to retrieve information for a CS_TIMEOUT event (%d)\n", rc);
		return;
	}

	printf("timestamp: %"PRId64"\n", cs_timeout.timestamp);
	printf("seq: %"PRIu64"\n", cs_timeout.seq);
}

static void hltests_handle_notifier_events(int fd, uint64_t notifier_events, uint64_t notifier_cnt)
{
	printf("[events listener] Received a notification: events %#"PRIx64", cnt: %"PRIu64"\n",
		notifier_events, notifier_cnt);

	if (notifier_events & HL_NOTIFIER_EVENT_CS_TIMEOUT) {
		printf("[events listener] CS_TIMEOUT\n");
		hltests_print_cs_timeout_event_info(fd);
	}

	/* TODO: use INFO IOCTL to get debug information about the events */
}

static int hltests_signal_waiting_threads(struct hltests_state *tests_state,
						uint64_t notifier_events)
{
	struct hltests_listener_thread_params *params = &tests_state->listener_thread_params;
	int rc;

	rc = pthread_mutex_lock(&params->lock);
	if (rc)
		return rc;

	params->notifier_events |= notifier_events;

	rc = pthread_cond_broadcast(&params->cond);
	if (rc) {
		pthread_mutex_unlock(&params->lock);
		return rc;
	}

	return pthread_mutex_unlock(&params->lock);
}

static void *hltests_listener_thread_func(void *args)
{
	struct hltests_state *tests_state = args;
	struct hltests_listener_thread_params *params = &tests_state->listener_thread_params;
	uint64_t notifier_events, notifier_cnt;
	int rc;
	params->listener_tid = syscall(SYS_gettid);

	/* PTHREAD_BARRIER_SERIAL_THREAD is returned to one unspecified thread and zero is returned
	 * to each of the remaining threads.
	 */
	rc = pthread_barrier_wait(&params->barrier);
	if (rc && rc != PTHREAD_BARRIER_SERIAL_THREAD) {
		printf("Failed on barrier wait from events listener thread (%d)\n", rc);
		return NULL;
	}

	while (true) {
		/* hlthunk_notifier_recv() calls internally to poll() which is a cancellation point,
		 * so pthread_cancel() will be able to terminate the thread when needed.
		 */
		rc = hlthunk_notifier_recv(tests_state->fd, params->handle, &notifier_events,
						&notifier_cnt, 0, INT_MAX);
		if (rc) {
			printf("Failed to receive a notification event (%d)\n", rc);
			return NULL;
		}

		/* TODO: a debug print to be removed when SW-159137 is solved */
		if (notifier_cnt != 1)
			printf("num of events is %lu\n", notifier_cnt);

		/* TODO: a debug print to be removed when SW-159137 is solved */
		if (notifier_events == 0)
			printf("returned with no events\n");

		/* No notification */
		if (!notifier_cnt)
			continue;

		/* Do not handle events during negative testing */
		if (!hltests_get_parser_negative_tests())
			hltests_handle_notifier_events(tests_state->fd, notifier_events,
										notifier_cnt);

		if (notifier_events & HL_NOTIFIER_EVENT_DEVICE_RESET)
			hltests_set_recovery_status(tests_state, RECOVERY_STATUS_REQUIRED);

		rc = hltests_signal_waiting_threads(tests_state, notifier_events);
		if (rc) {
			printf("Failed to signal about a notification event (%d)\n", rc);
			return NULL;
		}
	}

	return args;
}

static int hltests_start_listener_thread(struct hltests_state *tests_state)
{
	struct hltests_listener_thread_params *params = &tests_state->listener_thread_params;
	int rc, fd = tests_state->fd;

	if (!hltests_get_parser_events_listener())
		return 0;

	memset(params, 0, sizeof(*params));

	rc = pthread_barrier_init(&params->barrier, NULL, 2);
	if (rc) {
		printf("Failed to initialize barrier for listener thread (%d)\n", rc);
		return rc;
	}

	rc = pthread_cond_init(&params->cond, NULL);
	if (rc) {
		printf("Failed to initialize condition variable for listener thread (%d)\n", rc);
		goto destroy_barrier;
	}

	rc = pthread_mutex_init(&params->lock, NULL);
	if (rc) {
		printf("Failed to initialize mutex for listener thread (%d)\n", rc);
		goto destroy_cond;
	}

	params->handle = hlthunk_notifier_create(fd);
	if (params->handle < 0) {
		printf("Failed to create a notifier object (%d)\n", params->handle);
		rc = params->handle;
		goto destroy_mutex;
	}

	rc = pthread_create(&params->thread_id, NULL, hltests_listener_thread_func, tests_state);
	if (rc) {
		printf("Failed to create listener thread (%d)\n", rc);
		goto release_notifier;
	}

	/* PTHREAD_BARRIER_SERIAL_THREAD is returned to one unspecified thread and zero is returned
	 * to each of the remaining threads.
	 */
	rc = pthread_barrier_wait(&params->barrier);
	if (rc && rc != PTHREAD_BARRIER_SERIAL_THREAD) {
		printf("Failed on barrier wait while starting listener thread (%d)\n", rc);
		goto cancel_pthread;
	}

	return 0;

cancel_pthread:
	if (pthread_cancel(params->thread_id) == 0)
		pthread_join(params->thread_id, NULL);
release_notifier:
	hlthunk_notifier_release(fd, params->handle);
destroy_mutex:
	pthread_mutex_destroy(&params->lock);
destroy_cond:
	pthread_cond_destroy(&params->cond);
destroy_barrier:
	pthread_barrier_destroy(&params->barrier);
	return rc;
}

static int hltests_stop_listener_thread(struct hltests_state *tests_state)
{
	struct hltests_listener_thread_params *params = &tests_state->listener_thread_params;
	int fd = tests_state->fd;
	int rc;

	if (!hltests_get_parser_events_listener())
		return 0;

	rc = pthread_cancel(params->thread_id);
	if (rc)
		printf("failed to cancel listener thread (%d)\n", rc);
	else
		pthread_join(params->thread_id, NULL);

	rc |= hlthunk_notifier_release(fd, params->handle);
	if (rc)
		printf("failed to release eventfd (%d)\n", rc);

	pthread_mutex_destroy(&params->lock);
	pthread_cond_destroy(&params->cond);
	pthread_barrier_destroy(&params->barrier);
	return rc;
}

static int hltests_setup_common(void **state)
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

	if (hltests_is_importer_exists()) {
		tests_state->imp_fd = open("/dev/hli", O_RDWR | O_CLOEXEC, 0);
		if (tests_state->imp_fd < 0) {
			printf("Failed to open importer %d\n",
							tests_state->imp_fd);
			rc = tests_state->imp_fd;
			goto close_fd;
		}
	}

	hdev = get_hdev_from_fd(fd);
	if (!hdev) {
		printf("Failed to get hdev from file descriptor %d\n", fd);
		rc = -ENODEV;
		goto close_imp_fd;
	}

	tests_state->mme = !!hdev->module_params.mme_enable;
	tests_state->lkd_security = !!hdev->module_params.security_enable;

	rc = hltests_setup_user_engines(tests_state);
	if (rc)
		goto close_imp_fd;

	rc = hltests_start_listener_thread(tests_state);
	if (rc)
		goto teardown_user_engines;

	rc = hlthunk_get_hw_ip_info(tests_state->fd, &tests_state->hw_ip);
	if (rc)
		goto stop_listener;

	*state = tests_state;

	return 0;

stop_listener:
	hltests_stop_listener_thread(tests_state);

teardown_user_engines:
	hltests_teardown_user_engines(tests_state);

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

int hltests_teardown_user_engines(struct hltests_state *tests_state)
{
	int fd = tests_state->fd;
	struct hltests_device *hdev = get_hdev_from_fd(fd);

	if (hltests_is_legacy_mode_enabled(fd))
		return 0;

	hdev = get_hdev_from_fd(fd);
	if (!hdev) {
		printf("Failed to get hdev from file descriptor %d\n", fd);
		return -ENODEV;
	}

	hltests_arc_fini(fd, &hdev->arc_db);
	hltests_completion_db_teardown(fd, &hdev->completion_db);
	hltests_pdma_fini(fd, &hdev->pdma_db);
	hlthunk_free(hdev->arc_db.fw_info);

	return 0;
}

static int hltests_teardown_common(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int rc = 0;

	if (!tests_state)
		return -EINVAL;

	hltests_stop_listener_thread(tests_state);

	hltests_teardown_user_engines(tests_state);

	if (tests_state->imp_fd >= 0)
		close(tests_state->imp_fd);

	if (hltests_close(tests_state->fd))
		printf("Problem in closing FD, ignoring...\n");

	if (tests_state->priv)
		hlthunk_free(tests_state->priv);

	hlthunk_free(*state);

	return rc;
}

int hltests_setup(void **state)
{
	struct hltests_state *tests_state;
	char pci_bus_id[13];
	int rc, device_idx;

	rc = hltests_setup_common(state);
	if (rc)
		return rc;

	if (!can_open_debugfs(false))
		return 0;

	/* in case debugfs can be opened- open it */

	tests_state = *state;

	rc = hlthunk_get_pci_bus_id_from_fd(tests_state->fd, pci_bus_id,
						sizeof(pci_bus_id));
	if (rc)
		return rc;

	device_idx = hlthunk_get_device_index_from_pci_bus_id(pci_bus_id);
	if (device_idx < 0)
		return -ENODEV;

	return debugfs_open(tests_state, device_idx);
}

int hltests_teardown(void **state)
{
	struct hltests_state *tests_state;

	if (can_open_debugfs(false)) {
		tests_state = (struct hltests_state *) *state;

		if (!tests_state)
			return -EINVAL;

		debugfs_close(tests_state);
	}

	return hltests_teardown_common(state);
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

int hltests_get_module_params_info(int fd,
				struct hltests_module_params_info *info)
{
	struct hl_info_args args;
	struct hl_info_module_params hl_info;
	int rc;

	if (!info)
		return -EINVAL;

	memset(info, 0, sizeof(*info));

	memset(&args, 0, sizeof(args));
	memset(&hl_info, 0, sizeof(hl_info));

	args.op = HL_INFO_MODULE_PARAMS;
	args.return_pointer = (__u64) (uintptr_t) &hl_info;
	args.return_size = sizeof(hl_info);

	rc = hltests_ioctl(fd, DRM_IOCTL_HL_INFO, &args);
	if (rc) {
		*info = default_module_params;
		goto out;
	}

	info->gaudi_huge_page_optimization =
			hl_info.gaudi_huge_page_optimization;
	info->timeout_locked = hl_info.timeout_locked;
	info->reset_on_lockup = hl_info.reset_on_lockup;
	info->pldm = hl_info.pldm;
	info->mmu_enable = hl_info.mmu_enable;
	info->clock_gating = hl_info.clock_gating;
	info->mme_enable = hl_info.mme_enable;
	info->tpc_mask = hl_info.tpc_mask;
	info->nic_ports_mask = hl_info.nic_ports_mask;
	info->dram_enable = hl_info.dram_enable;
	info->cpu_enable = hl_info.cpu_enable;
	info->reset_pcilink = hl_info.reset_pcilink;
	info->config_pll = hl_info.config_pll;
	info->cpu_queues_enable = hl_info.cpu_queues_enable;
	info->fw_loading = hl_info.fw_loading;
	info->fw_loading_ext = hl_info.fw_loading_ext;
	info->heartbeat = hl_info.heartbeat;
	info->axi_drain = hl_info.axi_drain;
	info->security_enable = hl_info.security_enable;
	info->sram_scrambler_enable = hl_info.sram_scrambler_enable;
	info->dram_scrambler_enable = hl_info.dram_scrambler_enable;
	info->hbm_ecc_enable = hl_info.hbm_ecc_enable;
	info->compatibility_mode = hl_info.compatibility_mode;
	info->hard_reset_on_fw_events = hl_info.hard_reset_on_fw_events;
	info->decoder_mask = hl_info.decoder_mask;
	info->rotator_mask = hl_info.rotator_mask;
	info->dram_page_scrub = hl_info.dram_page_scrub;
	info->clock_gating_ext = hl_info.clock_gating_ext;
	info->cache_enabled = hl_info.cache_enabled;
	info->nic_lanes_per_port = hl_info.nic_lanes_per_port;
out:
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

	mem->device_virt_addr = hlthunk_host_memory_map_flags(fd, mem->host_ptr, 0, size,
									flags);

	if (!mem->device_virt_addr) {
		E("Failed to map host memory to device\n");
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

static int sim_allocate_device_mem_on_host(int fd, struct hltests_memory *mem)
{
	mem->host_ptr = hlthunk_malloc(mem->size);
	if (!mem->host_ptr) {
		E("Sim failed to allocate %#lx bytes of host memory!", mem->size);
		goto error_memory_alloc;
	}

	mem->device_virt_addr = hlthunk_host_memory_map(fd, mem->host_ptr, 0, mem->size);
	if (!mem->device_virt_addr) {
		E("Sim failed to map host memory to device!");
		goto error_memory_map;
	}

	mem->device_handle = 0;

	return 0;

error_memory_map:
	free(mem->host_ptr);

error_memory_alloc:
	return -1;
}

static int allocate_device_mem(struct hltests_device *hdev, struct hltests_memory *mem,
			       size_t page_size, enum hltests_contiguous contiguous)
{
	mem->device_handle =
		hlthunk_device_memory_alloc(hdev->fd, mem->size, page_size, contiguous, false);
	if (!mem->device_handle) {
		E("Failed to allocate %#lx bytes of device memory!", mem->size);
		goto error_memory_alloc;
	}

	mem->device_virt_addr = hlthunk_device_memory_map(hdev->fd, mem->device_handle, 0);
	if (!mem->device_virt_addr) {
		E("Failed to map device memory!");
		goto error_memory_map;
	}

	/* Memory access must go through DMA */
	mem->host_ptr = NULL;

	return 0;

error_memory_map:
	hlthunk_device_memory_free(hdev->fd, mem->device_handle);

error_memory_alloc:
	return -1;
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
	const struct hltests_memory *mem =
		hltests_allocate_device_mem_ret_mem(fd, size, page_size, contiguous);

	if (!mem)
		return NULL;

	static_assert(sizeof(void *) >= sizeof(mem->device_virt_addr),
		      "The cast to `void *` can be fatal on 32bit systems, whoever decided to return a `void *` clearly wasn't thinking straight.");
	return (void *)mem->device_virt_addr;
}

/**
 * hltests_allocate_device_mem_ret_mem() - Allocates a memory buffer on the device.
 *
 * Returns a structure containing all the information regarding the buffer.
 * If the device supports it, the buffer will be memory mapped into process memory and exposed via
 * &struct hltests_memory->host_ptr.
 *
 * @param fd file descriptor of the device to which the function will map
 *           the memory
 * @param size how much memory to allocate
 * @param page_size what page size to use. 0 means use default page size
 * @param contiguous whether the memory area will be physically contiguous
 * @return pointer to the device memory structure, NULL on failure.
 */
const struct hltests_memory *
hltests_allocate_device_mem_ret_mem(int fd, uint64_t size, uint64_t page_size,
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
	mem->is_pool = false;
	mem->size = size;

	if (!asic->dram_pool_alloc(hdev, size, &mem->device_virt_addr)) {
		mem->is_pool = true;
		rc = 0;
	} else if (hdev->sim_dram_on_host) {
		rc = sim_allocate_device_mem_on_host(fd, mem);
	} else {
		rc = allocate_device_mem(hdev, mem, page_size, contiguous);
	}

	if (rc)
		goto error_allocate_memory;

	pthread_mutex_lock(&hdev->mem_table_device_lock);

	k = kh_put(ptr64, hdev->mem_table_device, mem->device_virt_addr, &rc);
	kh_val(hdev->mem_table_device, k) = mem;

	pthread_mutex_unlock(&hdev->mem_table_device_lock);

	return mem;

error_allocate_memory:
	hlthunk_free(mem);
	return NULL;
}

/*
 * This function allocates DRAM memory on the device, using all supported page sizes and
 * will map it to the device virtual address space. The input 'size' will be divided into several
 * allocations. Each allocation will be stored inside "device_addr_arr" array's entry.
 * @param fd file descriptor of the device to which the function will map the memory
 * @param size how much memory to allocate
 * @param device_addr_arr output array, each array entry stores an allocated device address
 * @param device_addr_arr_size the size of "device_addr_arr" array
 * @param actual_arr_size the actual size of "device_addr_arr" array
 * @return 0 for success
 */
int hltests_allocate_device_mem_mix_page_size(int fd, uint64_t size,
			uint64_t *device_addr_arr, int device_addr_arr_size, int *actual_arr_size)
{
	uint64_t page_size, size_allocated = 0, *page_arr = NULL, end_device_addr = 0;
	int i = 0, next_page_size, arr_idx = 0, rc = 0;
	uint8_t page_arr_size = 0;
	void *device_addr = NULL;

	hltests_build_memalloc_page_size_array(fd, &page_arr, &page_arr_size);

	if (!page_arr || !page_arr_size)
		return -EIO;

	while (size_allocated < size) {
		for (i = 0 ; i < page_arr_size ; i++) {
			page_size = page_arr[i % page_arr_size];
			next_page_size = page_arr[(i + 1) % page_arr_size];

			if (size_allocated + page_size > size)
				page_size = page_arr[0];

			do {
				/* allocate page_size bytes */
				device_addr = hltests_allocate_device_mem(fd,
					page_size, page_size, CONTIGUOUS);

				if (!device_addr) {
					printf("Failed to allocate %ld bytes of device memory\n",
							page_size);
					rc = -ENOMEM;
					goto exit_alloc;
				}

				device_addr_arr[arr_idx] = (uint64_t)device_addr;
				arr_idx++;

				/* verify contiguous address.
				 * Do the check starting form arr_idx > 1.
				 */
				if (arr_idx > 1
					&& end_device_addr != (uint64_t)device_addr) {
					printf("Failed to alloc contiguous device memory addr\n");
					rc = -ENOMEM;
					goto exit_alloc;
				}

				size_allocated += page_size;
				end_device_addr = (uint64_t)device_addr + page_size;

				if (next_page_size < page_size)
					break;

				/* run as long as the next addr isn't aligned to next_page size */
			} while (size_allocated + page_size < size &&
					!IS_ALIGNED(end_device_addr, next_page_size));

			if (size_allocated == size)
				break;
		}
	}

exit_alloc:
	/* free the array in case of failure */
	if (rc)
		hltests_free_device_mem_mix_page_size(fd, device_addr_arr, arr_idx);

	hlthunk_free(page_arr);
	*actual_arr_size = arr_idx;
	return rc;
}

/*
 * This function frees device memory allocation array
 * @param fd file descriptor of the device to which the function will map the memory
 * @param device_addr_arr device memory allocation array
 * @param size the size of the array
 * @return 0 for success, negative value for failure
 */
int hltests_free_device_mem_mix_page_size(int fd, uint64_t *device_addr_arr, int size)
{
	int i, rc = 0;

	for (i = 0 ; i < size && !rc ; i++)
		rc = hltests_free_device_mem(fd, (void *)device_addr_arr[i]);

	return rc;
}

/*
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

static void sim_free_device_mem_on_host(int fd, struct hltests_memory *mem)
{
	if (hlthunk_memory_unmap(fd, mem->device_virt_addr))
		E("Sim failed to unmap host memory from device!");

	hlthunk_free(mem->host_ptr);
}

static void free_device_mem(struct hltests_device *hdev, struct hltests_memory *mem)
{
	if (hlthunk_memory_unmap(hdev->fd, mem->device_virt_addr))
		E("Failed to unmap device memory!");

	if (hlthunk_device_memory_free(hdev->fd, mem->device_handle))
		E("Failed to free device memory!");
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

	hdev = get_hdev_from_fd(fd);
	if (!hdev)
		return -ENODEV;

	asic = hdev->asic_funcs;

	pthread_mutex_lock(&hdev->mem_table_device_lock);

	k = kh_get(ptr64, hdev->mem_table_device, (uintptr_t)vaddr);
	if (k == kh_end(hdev->mem_table_device)) {
		pthread_mutex_unlock(&hdev->mem_table_device_lock);
		return -EINVAL;
	}

	mem = kh_val(hdev->mem_table_device, k);
	kh_del(ptr64, hdev->mem_table_device, k);

	pthread_mutex_unlock(&hdev->mem_table_device_lock);

	if (mem->is_pool) {
		asic->dram_pool_free(hdev, mem->device_virt_addr, mem->size);
	} else if (hdev->sim_dram_on_host) {
		sim_free_device_mem_on_host(fd, mem);
	} else {
		free_device_mem(hdev, mem);
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
 * This function retrieves the device memory block by virtual address in the
 * device address space
 * @param fd file descriptor of the device that the host memory is mapped to
 * @param device_va virtual address in the device VA space
 * @return struct containing memory information (handle, pva, dva, pointer). NULL for failure
 */
const struct hltests_memory *hltests_get_mem_for_device_va(int fd, void *device_va)
{
	const struct hltests_memory *mem;
	struct hltests_device *hdev;
	khint_t k;

	hdev = get_hdev_from_fd(fd);
	if (!hdev)
		return 0;

	pthread_mutex_lock(&hdev->mem_table_device_lock);

	k = kh_get(ptr64, hdev->mem_table_device, (uintptr_t) device_va);
	if (k == kh_end(hdev->mem_table_device)) {
		pthread_mutex_unlock(&hdev->mem_table_device_lock);
		errno = EINVAL;
		return NULL;
	}

	mem = kh_val(hdev->mem_table_device, k);

	pthread_mutex_unlock(&hdev->mem_table_device_lock);

	return mem;
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
	const struct hltests_memory *mem = hltests_get_mem_for_device_va(fd, device_va);

	if (!mem)
		return 0;

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
	 * if the ASIC is Goya/Gaudi.
	 */
	if (cb->cb_type == CB_TYPE_KERNEL && !(hltests_is_goya(fd) || hltests_is_gaudi(fd)))
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
		hltests_munmap(fd, cb->ptr, cb->cb_size);
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

/* cs with one cb is very common so write special helper for this */
int hltests_submit_cb(int fd,
		void *cb_ptr,
		uint32_t cb_size,
		uint32_t queue_index,
		uint32_t flags,
		uint64_t *seq)
{
	struct hltests_cs_chunk execute_arr;
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	execute_arr.cb_ptr = cb_ptr;
	execute_arr.cb_size = cb_size;
	execute_arr.queue_index = queue_index;
	return asic->submit_cs(fd, NULL, 0, &execute_arr, 1, flags, 0, seq);
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
	if (rc)
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

	assert_non_null(asic->add_write_to_sob_pkt);
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

uint32_t hltests_add_pdma_ch_bw_config_pkt(int fd, void *buffer, uint32_t buf_off,
		int qid, bool set_lbw)
{
	const struct hltests_asic_funcs *asic =
			get_hdev_from_fd(fd)->asic_funcs;

	return asic->add_pdma_ch_bw_config_pkt(fd, buffer, buf_off, qid, set_lbw);
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

uint32_t hltests_get_pdma_qid(int fd, int dma_idx)
{
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_pdma_qid(fd, dma_idx);
}

uint8_t hltests_get_pdma_ch_cnt(int fd)
{
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_pdma_ch_cnt(fd, DCORE_MODE_FULL_CHIP);
}

uint32_t hltests_pdma_config_ch_blocks(int fd)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	return asic->pdma_config_ch_blocks(fd, &hdev->pdma_db);
}

uint32_t hltests_get_tpc_qid(int fd, uint8_t tpc_id,
				enum hltests_stream_id stream)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_tpc_qid(fd, DCORE_MODE_FULL_CHIP, tpc_id, stream);
}

uint32_t hltests_get_mme_id(int fd, uint32_t qid)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_mme_id(fd, qid);
}

uint32_t hltests_get_mme_qid(int fd, uint8_t mme_id,
				enum hltests_stream_id stream)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_mme_qid(DCORE_MODE_FULL_CHIP, mme_id, stream);
}

uint32_t hltests_get_nic_qid(int fd, uint8_t nic_id,
				enum hltests_stream_id stream)
{
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_nic_qid(DCORE_MODE_FULL_CHIP, nic_id, stream);
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

	assert_non_null(asic->get_sob_base_addr);
	return asic->get_sob_base_addr(fd);
}

uint64_t hltests_get_sob_lbw_offset(int fd, uint32_t sob_idx)
{
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	assert_non_null(asic->get_sob_lbw_offset);
	return asic->get_sob_lbw_offset(fd, sob_idx);
}

uint64_t hltests_get_lbw_base_addr(int fd)
{
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	assert_non_null(asic->get_lbw_base_addr);
	return asic->get_lbw_base_addr(fd);
}

uint64_t hltests_get_any_mappable_hw_block_base_addr(int fd)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_any_mappable_hw_block_base_addr(fd);
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

void hltests_fill_rand_values(void *ptr, uint64_t size)
{
	uint64_t rounddown_aligned_size, remainder, i;
	uint32_t *p = ptr, val;

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

void hltests_fill_addr_chunk(void *ptr, uint32_t size, uint64_t addr, uint64_t chunk)
{
	uint64_t *p, chunk_template;
	uint32_t i, num_addr;

	p = ptr;
	num_addr = size / sizeof(uint64_t);
	chunk_template = (chunk & 0xffff) << 48;
	/* bits 48-63 holds the chunk index, bits 0-47 the address */
	for (i = 0 ; i < num_addr ; i++, p++) {
		*p = chunk_template | (addr & 0xffffffffffff);
		addr += sizeof(uint64_t);
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
					bool stop_on_err, uint64_t *offset)
{
	uint64_t *p1 = (uint64_t *) ptr1, *p2 = (uint64_t *) ptr2;
	uint64_t err_cnt = 0, rounddown_aligned_size, remainder, i = 0;
	uint64_t mismatch_off = ULONG_MAX;

	rounddown_aligned_size = size & ~(sizeof(uint64_t) - 1);
	remainder = size - rounddown_aligned_size;

	while (i < rounddown_aligned_size) {
		if (*p1 != *p2) {
			if (mismatch_off == ULONG_MAX)
				mismatch_off = (uint64_t)p1 - (uint64_t)ptr1;
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
		goto ret_err_cnt;

	for (i = 0 ; i < remainder ; i++) {
		if (((uint8_t *) p1)[i] != ((uint8_t *) p2)[i]) {
			if (mismatch_off == ULONG_MAX)
				mismatch_off = (uint64_t)p1 - (uint64_t)ptr1;
			printf("[%p]: 0x%hhx <--> [%p]: 0x%hhx\n",
				(uint8_t *) p1 + i, ((uint8_t *) p1)[i],
				(uint8_t *) p2 + i, ((uint8_t *) p2)[i]);
			err_cnt++;
		}
	}

ret_err_cnt:
	if (offset)
		*offset = mismatch_off;
	return err_cnt;
}

int hltests_mem_compare(void *ptr1, void *ptr2, uint64_t size)
{
	return hltests_mem_compare_with_stop(ptr1, ptr2, size, true, NULL);
}

int hltests_mem_compare_offset(void *ptr1, void *ptr2, uint64_t size, uint64_t *offset)
{
	return hltests_mem_compare_with_stop(ptr1, ptr2, size, true, offset);
}

/**
 * This function initiates a large (> 4G) DMA and waits for it to complete,
 * in addition it may measure the DMA time.
 * @param fd file descriptor of the device
 * @param queue_index the allocated queue for the command submission
 * @param eb if true- set engine barrier
 * @param mb if true- set memory barrier
 * @param src_addr source virtual address for the DMA
 * @param dst_addr destination virtual address for the DMA
 * @param size the DMA size
 * @param dma_dir the DMA direction
 * @param bw_gbps if valid pointer, the BW of the DMA op will be stored in it
 * @return 0 on success, otherwise non 0 error code
 */
int hltests_dma_transfer_large(int fd, uint32_t queue_index, enum hltests_eb eb,
				enum hltests_mb mb,
				uint64_t src_addr, uint64_t dst_addr,
				uint64_t size,
				enum hltests_dma_direction dma_dir,
				double *bw_gbps)
{
	uint32_t max_num_lin_dma_pkts_in_external_cb, num_of_cb;
	uint64_t num_dma_pkt, size_left, packet_left, seq;
	struct hltests_cs_chunk *execute_arr;
	struct hltests_pkt_info pkt_info;
	struct timespec begin, end;
	int cb_idx, pkt_idx, rc;
	void **cb_arr;

	max_num_lin_dma_pkts_in_external_cb = HL_MAX_CB_SIZE /
						hltests_get_max_pkt_size(fd, mb, eb, queue_index);
	/* for any case- avoid division by 0 */
	assert_int_not_equal(max_num_lin_dma_pkts_in_external_cb, 0);

	/* each DMA packet can transfer up to UINT32_MAX */
	num_dma_pkt = DIV_ROUND_UP_ULL(size, UINT32_MAX);

	num_of_cb = DIV_ROUND_UP(num_dma_pkt, max_num_lin_dma_pkts_in_external_cb);
	assert_in_range(num_of_cb, 1, HL_MAX_JOBS_PER_CS);

	/* allocate exec array, 1 entry per CB */
	execute_arr = hlthunk_malloc(sizeof(struct hltests_cs_chunk) * num_of_cb);
	assert_non_null(execute_arr);

	/* allocate pointer array for CBs */
	cb_arr = hlthunk_malloc(sizeof(void *) * num_of_cb);
	assert_non_null(cb_arr);

	/* allocate the CBs and assign to CB pointer array */
	for (cb_idx = 0 ; cb_idx < num_of_cb ; cb_idx++) {
		uint64_t cb_size = max_num_lin_dma_pkts_in_external_cb *
				hltests_get_max_pkt_size(fd, MB_FALSE, EB_FALSE, queue_index);

		/* Add extra bytes for (optional) CQ configuration pkt/s */
		cb_size += hltests_get_cq_patch_size(fd, queue_index);

		cb_arr[cb_idx] = hltests_create_cb(fd, cb_size, EXTERNAL, 0);
		assert_non_null(cb_arr[cb_idx]);
	}

	/* init packet field that will not be changed in the iteration */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = queue_index;
	pkt_info.eb = eb;
	pkt_info.mb = mb;
	pkt_info.dma.dma_dir = dma_dir;

	/* loop init */
	size_left = size;
	cb_idx = 0;
	packet_left = num_dma_pkt;

	while (packet_left) {
		uint32_t offset_cb, cur_pkt_num, cur_size;

		cur_pkt_num = MIN(packet_left, max_num_lin_dma_pkts_in_external_cb);
		offset_cb = 0;

		for (pkt_idx = 0 ; pkt_idx < cur_pkt_num ; pkt_idx++) {
			cur_size = MIN(size_left, UINT32_MAX);

			pkt_info.dma.src_addr = src_addr;
			pkt_info.dma.dst_addr = dst_addr;
			pkt_info.dma.size = MIN(size_left, UINT32_MAX);
			offset_cb = hltests_add_dma_pkt(fd, cb_arr[cb_idx], offset_cb, &pkt_info);

			size_left -= cur_size;
			src_addr += cur_size;
			dst_addr += cur_size;
		}

		execute_arr[cb_idx].cb_ptr = cb_arr[cb_idx];
		execute_arr[cb_idx].cb_size = offset_cb;
		execute_arr[cb_idx].queue_index = queue_index;

		cb_idx++;
		packet_left -= cur_pkt_num;
	}

	seq = 0;
	if (bw_gbps)
		clock_gettime(CLOCK_MONOTONIC_RAW, &begin);

	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, num_of_cb, 0, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	if (bw_gbps) {
		clock_gettime(CLOCK_MONOTONIC_RAW, &end);
		*bw_gbps = get_bw_gigabyte_per_sec(size, &begin, &end);
	}

	for (cb_idx = 0 ; cb_idx < num_of_cb; cb_idx++) {
		rc = hltests_destroy_cb(fd, cb_arr[cb_idx]);
		assert_int_equal(rc, 0);
	}

	hlthunk_free(cb_arr);
	hlthunk_free(execute_arr);

	return 0;
}

int hltests_dma_transfer(int fd, uint32_t queue_index, enum hltests_eb eb,
				enum hltests_mb mb,
				uint64_t src_addr, uint64_t dst_addr,
				uint32_t size,
				enum hltests_dma_direction dma_dir)
{
	return hltests_dma_transfer_large(fd, queue_index, eb, mb,
					     src_addr, dst_addr, size, dma_dir, NULL);
}

double hltests_dma_transfer_perf(int fd, struct dma_perf_transfer *transfer)
{
	uint64_t num_of_lindma_pkts, num_of_lindma_pkts_per_cb, i, j, seq = 0;
	uint32_t max_num_lin_dma_pkts_in_external_cb, offset_cb = 0;
	struct hltests_cs_chunk *execute_arr;
	struct hltests_pkt_info pkt_info;
	struct timespec begin, end;
	int rc, num_of_cb = 1;
	void **cb_arr;

	max_num_lin_dma_pkts_in_external_cb = HL_MAX_CB_SIZE /
			hltests_get_max_pkt_size(fd, MB_FALSE, EB_FALSE,
					transfer->queue_index);

	if ((hltests_is_pldm(fd) || hltests_is_simulator(fd)) &&
			hltests_get_parser_run_disabled_tests())
		num_of_lindma_pkts = 160;
	else if (hltests_is_pldm(fd))
		num_of_lindma_pkts = 1;
	else if (hltests_is_simulator(fd))
		num_of_lindma_pkts = 5;
	else
		num_of_lindma_pkts = 0x400000000ull / transfer->size;

	num_of_lindma_pkts_per_cb = num_of_lindma_pkts;

	if (num_of_lindma_pkts > max_num_lin_dma_pkts_in_external_cb) {
		num_of_lindma_pkts_per_cb = max_num_lin_dma_pkts_in_external_cb;
		/* Avoid divide by zero */
		assert_int_not_equal(num_of_lindma_pkts_per_cb, 0);

		num_of_cb = (num_of_lindma_pkts / num_of_lindma_pkts_per_cb) + 1;

		num_of_lindma_pkts = num_of_cb * num_of_lindma_pkts_per_cb;
	}

	assert_in_range(num_of_cb, 1, HL_MAX_JOBS_PER_CS);

	execute_arr = hlthunk_malloc(sizeof(struct hltests_cs_chunk) * num_of_cb);
	assert_non_null(execute_arr);

	cb_arr = hlthunk_malloc(sizeof(void *) * num_of_cb);
	assert_non_null(cb_arr);

	for (i = 0 ; i < num_of_cb ; i++) {
		uint64_t cb_size = num_of_lindma_pkts_per_cb *
				hltests_get_max_pkt_size(fd, MB_FALSE, EB_FALSE,
						transfer->queue_index);

		/* Add extra bytes for (optional) CQ configuration pkt/s */
		cb_size += hltests_get_cq_patch_size(fd, transfer->queue_index);

		cb_arr[i] = hltests_create_cb(fd, cb_size, EXTERNAL, 0);
		assert_non_null(cb_arr[i]);
	}

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = transfer->queue_index;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.dma.src_addr = transfer->src_addr;
	pkt_info.dma.dst_addr = transfer->dst_addr;
	pkt_info.dma.size = transfer->size;
	pkt_info.dma.dma_dir = transfer->dma_dir;

	for (i = 0 ; i < num_of_cb ; i++) {
		for (j = 0 ; j < num_of_lindma_pkts_per_cb ; j++)
			offset_cb = hltests_add_dma_pkt(fd, cb_arr[i], offset_cb, &pkt_info);

		execute_arr[i].cb_ptr = cb_arr[i];
		execute_arr[i].cb_size = offset_cb;
		execute_arr[i].queue_index = transfer->queue_index;

		offset_cb = 0;
	}

	clock_gettime(CLOCK_MONOTONIC_RAW, &begin);

	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, num_of_cb, 0, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	clock_gettime(CLOCK_MONOTONIC_RAW, &end);

	for (i = 0 ; i < num_of_cb; i++) {
		rc = hltests_destroy_cb(fd, cb_arr[i]);
		assert_int_equal(rc, 0);
	}

	hlthunk_free(cb_arr);
	hlthunk_free(execute_arr);

	/* return value in GB/Sec */
	return get_bw_gigabyte_per_sec(transfer->size * num_of_lindma_pkts, &begin, &end);
}

double hltests_dma_transfer_perf_bidirectional(int fd,
				struct dma_perf_transfer *host_to_device,
				struct dma_perf_transfer *device_to_host)
{
	uint64_t h2d_lindma_pkts, h2d_lindma_pkts_per_cb, i, j, d2h_lindma_pkts,
								d2h_lindma_pkts_per_cb, seq = 0;
	uint32_t max_num_lin_dma_pkts_in_external_cb, h2d_cb_offset = 0, d2h_cb_offset = 0;
	int rc, h2d_num_of_cb = 1, d2h_num_of_cb = 1;
	struct hltests_cs_chunk *execute_arr;
	struct hltests_pkt_info pkt_info;
	struct timespec begin, end;
	void **h2d_cb, **d2h_cb;

	max_num_lin_dma_pkts_in_external_cb = HL_MAX_CB_SIZE /
			hltests_get_max_pkt_size(fd, MB_FALSE, EB_FALSE,
					host_to_device->queue_index);

	/* we divide by max_num_lin_dma_pkts_in_external_cb later, so it mustn't be 0 */
	assert_int_not_equal(max_num_lin_dma_pkts_in_external_cb, 0);

	if (hltests_is_pldm(fd)) {
		h2d_lindma_pkts = 1;
		d2h_lindma_pkts = 1;
	} else if (hltests_is_simulator(fd)) {
		h2d_lindma_pkts = 5;
		d2h_lindma_pkts = 5;
	} else {
		h2d_lindma_pkts = 0x43F9B1000ull / host_to_device->size;
		d2h_lindma_pkts = 0x4A817C000ull / device_to_host->size;
	}

	h2d_lindma_pkts_per_cb = h2d_lindma_pkts;
	h2d_num_of_cb = 1;

	if (h2d_lindma_pkts > max_num_lin_dma_pkts_in_external_cb) {
		h2d_lindma_pkts_per_cb = max_num_lin_dma_pkts_in_external_cb;

		h2d_num_of_cb = (h2d_lindma_pkts / h2d_lindma_pkts_per_cb) + 1;

		h2d_lindma_pkts = h2d_num_of_cb * h2d_lindma_pkts_per_cb;
	}

	assert_in_range(h2d_num_of_cb, 1, HL_MAX_JOBS_PER_CS / 2);

	d2h_lindma_pkts_per_cb = d2h_lindma_pkts;
	d2h_num_of_cb = 1;

	if (d2h_lindma_pkts > max_num_lin_dma_pkts_in_external_cb) {
		d2h_lindma_pkts_per_cb = max_num_lin_dma_pkts_in_external_cb;
		/* Avoid divide by zero */
		assert_int_not_equal(d2h_lindma_pkts_per_cb, 0);

		d2h_num_of_cb = (d2h_lindma_pkts / d2h_lindma_pkts_per_cb) + 1;

		d2h_lindma_pkts = d2h_num_of_cb * d2h_lindma_pkts_per_cb;
	}


	assert_in_range(d2h_num_of_cb, 1, HL_MAX_JOBS_PER_CS / 2);

	execute_arr = hlthunk_malloc(sizeof(struct hltests_cs_chunk) *
					(h2d_num_of_cb + d2h_num_of_cb));
	assert_non_null(execute_arr);

	h2d_cb = hlthunk_malloc(sizeof(void *) * h2d_num_of_cb);
	assert_non_null(h2d_cb);
	d2h_cb = hlthunk_malloc(sizeof(void *) * d2h_num_of_cb);
	assert_non_null(d2h_cb);

	for (i = 0 ; i < h2d_num_of_cb ; i++) {
		uint64_t cb_size = h2d_lindma_pkts_per_cb *
				hltests_get_max_pkt_size(fd, MB_FALSE, EB_FALSE,
						host_to_device->queue_index);

		/* Add extra bytes for (optional) CQ configuration pkt/s */
		cb_size += hltests_get_cq_patch_size(fd, host_to_device->queue_index);

		h2d_cb[i] = hltests_create_cb(fd, cb_size, EXTERNAL, 0);
		assert_non_null(h2d_cb[i]);
	}

	for (i = 0 ; i < d2h_num_of_cb ; i++) {
		uint64_t cb_size = d2h_lindma_pkts_per_cb *
				hltests_get_max_pkt_size(fd, MB_FALSE, EB_FALSE,
						device_to_host->queue_index);

		/* Add extra bytes for (optional) CQ configuration pkt/s */
		cb_size += hltests_get_cq_patch_size(fd, device_to_host->queue_index);

		d2h_cb[i] = hltests_create_cb(fd, cb_size, EXTERNAL, 0);
		assert_non_null(d2h_cb[i]);
	}

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = host_to_device->queue_index;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.dma.src_addr = host_to_device->src_addr;
	pkt_info.dma.dst_addr = host_to_device->dst_addr;
	pkt_info.dma.size = host_to_device->size;
	pkt_info.dma.dma_dir = host_to_device->dma_dir;

	for (i = 0 ; i < h2d_num_of_cb ; i++) {
		for (j = 0 ; j < h2d_lindma_pkts_per_cb ; j++)
			h2d_cb_offset = hltests_add_dma_pkt(fd, h2d_cb[i],
						h2d_cb_offset, &pkt_info);

		execute_arr[i].cb_ptr = h2d_cb[i];
		execute_arr[i].cb_size = h2d_cb_offset;
		execute_arr[i].queue_index = host_to_device->queue_index;

		h2d_cb_offset = 0;
	}

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = device_to_host->queue_index;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.dma.src_addr = device_to_host->src_addr;
	pkt_info.dma.dst_addr = device_to_host->dst_addr;
	pkt_info.dma.size = device_to_host->size;
	pkt_info.dma.dma_dir = device_to_host->dma_dir;

	for (i = 0 ; i < d2h_num_of_cb ; i++) {
		for (j = 0 ; j < d2h_lindma_pkts_per_cb ; j++)
			d2h_cb_offset = hltests_add_dma_pkt(fd, d2h_cb[i],
						d2h_cb_offset, &pkt_info);

		execute_arr[h2d_num_of_cb + i].cb_ptr = d2h_cb[i];
		execute_arr[h2d_num_of_cb + i].cb_size = d2h_cb_offset;
		execute_arr[h2d_num_of_cb + i].queue_index = device_to_host->queue_index;

		d2h_cb_offset = 0;
	}

	clock_gettime(CLOCK_MONOTONIC_RAW, &begin);

	if (hltests_is_pldm(fd)) {
		/* Write on device memory first to avoid ECC error on pldm */
		rc = hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, STREAM0),
					EB_FALSE, MB_TRUE, host_to_device->src_addr,
					device_to_host->src_addr, device_to_host->size,
					host_to_device->dma_dir);
		assert_int_equal(rc, 0);
	}

	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, h2d_num_of_cb + d2h_num_of_cb, 0, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	clock_gettime(CLOCK_MONOTONIC_RAW, &end);

	for (i = 0 ; i < h2d_num_of_cb ; i++) {
		rc = hltests_destroy_cb(fd, h2d_cb[i]);
		assert_int_equal(rc, 0);
	}

	for (i = 0 ; i < d2h_num_of_cb ; i++) {
		rc = hltests_destroy_cb(fd, d2h_cb[i]);
		assert_int_equal(rc, 0);
	}

	hlthunk_free(h2d_cb);
	hlthunk_free(d2h_cb);
	hlthunk_free(execute_arr);

	/* return value in GB/Sec */
	return get_bw_gigabyte_per_sec(host_to_device->size * h2d_lindma_pkts +
			device_to_host->size * d2h_lindma_pkts, &begin, &end);
}

int hltests_zero_dram_memory(int fd, uint64_t dst_addr, uint32_t size)
{
	uint64_t host_src_addr;
	void *src_ptr;
	int rc;

	src_ptr = hltests_allocate_host_mem(fd, size, HUGE_MAP);
	assert_non_null(src_ptr);

	memset(src_ptr, 0, size);
	host_src_addr = hltests_get_device_va_for_host_ptr(fd, src_ptr);

	/* TODO: for gaudi3 we might want to use the memset option of pdma */
	rc = hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, STREAM0),
				EB_FALSE, MB_TRUE, host_src_addr, dst_addr, size,
					DMA_DIR_HOST_TO_DRAM);
	assert_int_equal(rc, 0);

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
	struct hlthunk_hw_ip_info *hw_ip;
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

	hw_ip = &tests_state->hw_ip;

	if (!hw_ip->dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	if (hltests_is_simulator(fd) &&
			(FRAG_MEM_MULT * size) > hw_ip->dram_size) {
		printf(
			"SIM's DRAM (%lu[B]) is smaller than required allocation (%lu[B]) so skipping test\n",
			hw_ip->dram_size, FRAG_MEM_MULT * size);
		skip();
	}

	/*
	 * since in this test the device memory is allocated using the default page size
	 * we need to use it to calc number of pages
	 */
	used_page_size = hw_ip->device_mem_alloc_default_page_size;
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

	hltests_dma_dram_test(state, size);

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
	void *device_addr;
	uint64_t alloc_size;
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;
	int rc, fd = tests_state->fd;

	/* Allocate half size of device memory so that test allocation
	 * will begin from high memory address
	 */

	if (hltests_is_pldm(fd) && size > PLDM_MAX_DMA_SIZE_FOR_TESTING)
		skip();

	if (hltests_is_simulator(fd) && size > SZ_512M)
		skip();

	if (!hw_ip->dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	alloc_size = hw_ip->dram_size / 2;

	if (hltests_is_simulator(fd) && size > alloc_size) {
		printf(
			"SIM's DRAM (%lu[B]) is smaller than required allocation (%lu[B]) so skipping test\n",
			alloc_size, size);
		skip();
	}

	device_addr = hltests_allocate_device_mem(fd, alloc_size, 0, NOT_CONTIGUOUS);
	assert_non_null(device_addr);

	hltests_dma_dram_test(state, size);

	rc = hltests_free_device_mem(fd, device_addr);
	assert_int_equal(rc, 0);

	END_TEST;
}

VOID hltests_dma_test_flags(void **state, bool is_ddr, uint64_t size,
				uint64_t page_size, uint32_t flags)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;
	void *device_addr, *src_ptr, *dst_ptr;
	uint64_t host_src_addr, host_dst_addr;
	uint32_t dma_dir_down, dma_dir_up;
	bool is_huge = !!((size > SZ_32K) && (size < SZ_1G));
	int rc, fd = tests_state->fd;

	if (hltests_is_pldm(fd) && (size > PLDM_MAX_DMA_SIZE_FOR_TESTING))
		skip();

	/* Sanity and memory allocation */
	if (is_ddr) {
		if (hltests_is_simulator(fd) && size > hw_ip->dram_size) {
			printf(
				"SIM's DRAM (%lu[B]) is smaller than required allocation (%lu[B]) so skipping test\n",
				hw_ip->dram_size, size);
			skip();
		}

		if (!hw_ip->dram_enabled) {
			if (hltests_is_gaudi2(fd)) {
				printf("DRAM disabled, using DRAM on host\n");
			} else {
				printf("DRAM is disabled so skipping test\n");
				skip();
			}
		} else {
			assert_in_range(size, 1, hw_ip->dram_size);
		}

		device_addr = hltests_allocate_device_mem(fd, size, page_size, NOT_CONTIGUOUS);
		assert_non_null(device_addr);

		dma_dir_down = DMA_DIR_HOST_TO_DRAM;
		dma_dir_up = DMA_DIR_DRAM_TO_HOST;
	} else {
		if (size > hw_ip->sram_size)
			skip();
		device_addr = (void *) (uintptr_t) hw_ip->sram_base_address;

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
	rc = hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, STREAM0),
			EB_FALSE, MB_TRUE, host_src_addr,
			(uint64_t) (uintptr_t) device_addr,
			size, dma_dir_down);
	assert_int_equal(rc, 0);

	/* DMA: device->host */
	rc = hltests_dma_transfer(fd, hltests_get_dma_up_qid(fd, STREAM0),
			EB_FALSE, MB_TRUE, (uint64_t) (uintptr_t) device_addr,
			host_dst_addr, size, dma_dir_up);
	assert_int_equal(rc, 0);

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

VOID hltests_dma_sram_test(void **state, uint64_t size)
{
	END_TEST_FUNC(hltests_dma_test_flags(state, false, size, 0, 0));
}

VOID hltests_dma_dram_test(void **state, uint64_t size)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	uint8_t i, page_size_arr_size;
	int fd = tests_state->fd;
	uint64_t *page_size_arr;

	CALL_HELPER_FUNC(hltests_build_memalloc_page_size_array(fd, &page_size_arr,
									&page_size_arr_size));

	if (!page_size_arr) {
		CALL_HELPER_FUNC(hltests_dma_test_flags(state, true, size, 0, 0));
		EXIT_FROM_TEST;
	}

	for (i = 0; i < page_size_arr_size; i++) {
		verbose_printf("page size: %#lx\n", page_size_arr[i]);
		CALL_HELPER_FUNC(hltests_dma_test_flags(state, true, size, page_size_arr[i], 0));
	}

	hltests_destroy_memalloc_page_size_array(page_size_arr);

	END_TEST;
}

VOID hltests_tdr_deadlock_test(void **state, bool recovery)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hltests_cs_chunk execute_arr;
	struct hltests_pkt_info pkt_info;
	uint64_t seq, expected_events;
	int fd = tests_state->fd, rc;
	uint32_t cb_size;
	void *cb_ptr;

	if (!hltests_is_legacy_mode_enabled(fd)) {
		printf("Test is irrelevant when running in ARC mode, skipping\n");
		skip();
	}

	cb_ptr = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	assert_non_null(cb_ptr);
	cb_size = 0;

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.fence.dec_val = 1;
	pkt_info.fence.gate_val = 1;
	pkt_info.fence.fence_id = 0;
	cb_size = hltests_add_fence_pkt(fd, cb_ptr, cb_size, &pkt_info);

	execute_arr.cb_ptr = cb_ptr;
	execute_arr.cb_size = cb_size;
	execute_arr.queue_index = hltests_get_dma_down_qid(fd, STREAM0);

	rc = hltests_submit_cs_timeout(fd, NULL, 0, &execute_arr, 1, 0x0,
					TEST_TDR_DEADLOCK_TIMEOUT_SEC, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_true(rc == HL_WAIT_CS_STATUS_TIMEDOUT || rc == HL_WAIT_CS_STATUS_ABORTED);

	/* Verify that the expected events are received */
	expected_events = HL_NOTIFIER_EVENT_CS_TIMEOUT | HL_NOTIFIER_EVENT_DEVICE_RESET;
	rc = hltests_wait_for_events(tests_state, 0, expected_events, NULL);
	assert_int_equal(rc, 0);

	/* Cleanup */
	rc = hltests_destroy_cb(fd, cb_ptr);
	assert_int_equal(rc, 0);

	if (!recovery)
		EXIT_FROM_TEST;

	/* Recovery */
	rc = hltests_teardown_and_setup(tests_state);
	assert_int_equal(rc, 0);

	/* Sanity check after the recovery */
	fd = tests_state->fd;
	assert_true(hlthunk_is_device_idle(fd));

	END_TEST;
}

VOID hltests_build_page_size_array(uint64_t **page_size_arr, uint8_t *arr_size, uint64_t bitmask)
{
	int i, set_idx, elem = __builtin_popcountll(bitmask);

	/* the function  should not be called with empty bitmask */
	assert_int_not_equal(elem, 0);

	*page_size_arr = hlthunk_malloc(elem * sizeof(uint64_t));
	assert_non_null(*page_size_arr);

	for (i = 0; i < elem; i++) {
		set_idx = __builtin_ffsll(bitmask) - 1;
		(*page_size_arr)[i] = (1ULL << set_idx);
		bitmask &= ~(*page_size_arr)[i];
	}

	*arr_size = elem;

	END_TEST;
}

void hltests_destroy_page_size_array(uint64_t *page_size_arr)
{
	hlthunk_free(page_size_arr);
}

VOID hltests_build_memalloc_page_size_array(int fd, uint64_t **page_size_arr,
						uint8_t *page_size_arr_size)
{
	uint64_t page_order_bitmask;
	int rc;

	/* if multi page size not supported return NULL in array */
	if (!hltests_is_gaudi3(fd)) {
		*page_size_arr = NULL;
		EXIT_FROM_TEST;
	}

	rc = hlthunk_get_dev_memalloc_page_orders(fd, &page_order_bitmask);
	assert_int_equal(rc, 0);

	END_TEST_FUNC(hltests_build_page_size_array(page_size_arr, page_size_arr_size,
							page_order_bitmask));
}

/* the function nesting redundancy is to preserve the alloc-free mirror */
void hltests_destroy_memalloc_page_size_array(uint64_t *page_size_arr)
{
	hltests_destroy_page_size_array(page_size_arr);
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
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;
	int rc, fd = tests_state->fd;
	uint8_t page_size_arr_size;
	void **device_addr;
	bool error = false;

	if (!hw_ip->dram_enabled) {
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
	used_page_size = page_size ? page_size : hw_ip->device_mem_alloc_default_page_size;

	if (mix_alloc) {
		/* check whether mixed allocation is supported */
		rc = hlthunk_get_dev_memalloc_page_orders(fd, &page_order_bitmask);
		assert_int_equal(rc, 0);

		if (!page_order_bitmask) {
			if (hltests_is_gaudi3(fd)) {
				fail();
			} else {
				printf("Multiple page sizes is not supported\n");
				skip();
			}
		}
	}

	total_size = hltests_get_total_avail_device_mem(fd);
	if (mix_alloc) {
		CALL_HELPER_FUNC(hltests_build_page_size_array(&page_size_arr, &page_size_arr_size,
					page_order_bitmask));
		/* we set check size to the minimal page size so we'll "give a chance" to
		 * maximum number of allocations
		 */
		chunk_size = page_size_arr[0];
	} else if ((hw_ip->dram_page_size == 0) || IS_POWER_OF_TWO(used_page_size)) {
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
		hltests_destroy_page_size_array(page_size_arr);

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

int hltests_teardown_and_setup(struct hltests_state *tests_state)
{
	int rc, fd = tests_state->fd;
	char pci_bus_id[13];

	rc = hlthunk_get_pci_bus_id_from_fd(fd, pci_bus_id, sizeof(pci_bus_id));
	if (rc) {
		printf("Failed to get the PCI bus ID of the device while recovering (%d)\n", rc);
		goto set_recovery_status_failed;
	}

	rc = hltests_stop_listener_thread(tests_state);
	if (rc)
		printf("Failed to stop listener thread while recovering (%d)\n", rc);

	rc = hltests_teardown_user_engines(tests_state);
	if (rc)
		printf("Failed to tear down user engines while recovering (%d)\n", rc);

	rc = hltests_close(fd);
	if (rc)
		printf("Failed to close the device while recovering (%d)\n", rc);

	fd = tests_state->fd = hltests_open(pci_bus_id);
	if (fd < 0) {
		printf("Failed to reopen the device while recovering (%d)\n", fd);
		rc = fd;
		goto set_recovery_status_failed;
	}

	rc = hltests_setup_user_engines(tests_state);
	if (rc) {
		printf("Failed to setup user engines while recovering (%d)\n", rc);
		goto close_fd;
	}

	/* Events might be received right after the listener thread starts, so clear the recovery
	 * status before starting it and check it again afterwards.
	 */
	hltests_set_recovery_status(tests_state, RECOVERY_STATUS_NOT_REQUIRED);

	rc = hltests_start_listener_thread(tests_state);
	if (rc) {
		printf("Failed to start the listener thread while recovering (%d)\n", rc);
		goto teardown_user_engines;
	}

	if (hltests_get_recovery_status(tests_state) != RECOVERY_STATUS_NOT_REQUIRED) {
		printf("Recovery is still required after performing recovery operations\n");
		rc = -EIO;
		goto teardown_user_engines;
	}

	return 0;

teardown_user_engines:
	hltests_teardown_user_engines(tests_state);
close_fd:
	hltests_close(fd);
set_recovery_status_failed:
	hltests_set_recovery_status(tests_state, RECOVERY_STATUS_FAILED);
	return rc;
}

bool hltests_is_device_idle_and_operational(int fd)
{
	return (hlthunk_is_device_idle(fd) &&
			hlthunk_get_device_status_info(fd) == HL_DEVICE_STATUS_OPERATIONAL);
}

static void hltests_destroy_all_mappings(int fd)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	void *addr;
	size_t size;
	khint_t k;

	khash_t(mapping) * table = hdev->mmap_table;

	pthread_mutex_lock(&hdev->mmap_table_lock);

	for (k = kh_begin(table) ; k != kh_end(table) ; ++k) {
		if (!kh_exist(table, k))
			continue;

		addr = (void *)kh_key(table, k);
		size = kh_val(table, k);

		kh_del(mapping, table, k);
		munmap(addr, size);
	}

	pthread_mutex_unlock(&hdev->mmap_table_lock);
}

static void hltests_destroy_all_cbs(int fd)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct hltests_cb *cb;
	khint_t k;

	khash_t(ptr64) * table = hdev->cb_table;

	pthread_mutex_lock(&hdev->cb_table_lock);

	for (k = kh_begin(table) ; k != kh_end(table) ; ++k) {
		if (!kh_exist(table, k))
			continue;

		cb = kh_val(table, k);
		kh_del(ptr64, table, k);

		if (cb->cb_type == CB_TYPE_KERNEL || cb->cb_type == CB_TYPE_KERNEL_MAPPED) {
			hltests_munmap(fd, cb->ptr, cb->cb_size);
			hlthunk_destroy_command_buffer(fd, cb->cb_handle);
		} else {
			hltests_free_host_mem(fd, cb->ptr);
		}

		hlthunk_free(cb);
	}

	pthread_mutex_unlock(&hdev->cb_table_lock);
}

static void hltests_free_all_device_mem(int fd)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct hltests_memory *mem;
	khint_t k;

	khash_t(ptr64) * table = hdev->mem_table_device;

	pthread_mutex_lock(&hdev->mem_table_device_lock);

	for (k = kh_begin(table) ; k != kh_end(table) ; ++k) {
		if (!kh_exist(table, k))
			continue;

		mem = kh_val(table, k);
		kh_del(ptr64, table, k);

		if (mem->is_pool) {
			hdev->asic_funcs->dram_pool_free(hdev, mem->device_virt_addr, mem->size);
		} else {
			hlthunk_memory_unmap(fd, mem->device_virt_addr);

			if (!hdev->sim_dram_on_host)
				hlthunk_device_memory_free(fd, mem->device_handle);
			else
				free(mem->host_ptr);
		}

		hlthunk_free(mem);
	}

	pthread_mutex_unlock(&hdev->mem_table_device_lock);
}

static void hltests_free_all_host_mem(int fd)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct hltests_memory *mem;
	khint_t k;

	khash_t(ptr64) * table = hdev->mem_table_host;

	pthread_mutex_lock(&hdev->mem_table_host_lock);

	for (k = kh_begin(table) ; k != kh_end(table) ; ++k) {
		if (!kh_exist(table, k))
			continue;

		mem = kh_val(table, k);
		kh_del(ptr64, table, k);

		hlthunk_memory_unmap(fd, mem->device_virt_addr);

		if (mem->is_huge)
			munmap(mem->host_ptr, mem->size);
		else
			free(mem->host_ptr);

		hlthunk_free(mem);
	}

	pthread_mutex_unlock(&hdev->mem_table_host_lock);
}

static int hltests_recover(struct hltests_state *tests_state)
{
	int fd = tests_state->fd;

	/* Cleanup */
	hltests_destroy_all_cbs(fd);
	hltests_destroy_all_mappings(fd);
	hltests_free_all_device_mem(fd);
	hltests_free_all_host_mem(fd);

	return hltests_teardown_and_setup(tests_state);
}

int hltests_ensure_device_operational(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hltests_device *hdev;
	uint32_t timeout_locked, i;
	bool need_recover = false;
	int fd = -1, rc;

	/* Check if need to release and reopen the device due to a previous error */
	if (hltests_get_recovery_status(tests_state) == RECOVERY_STATUS_REQUIRED) {
		need_recover = true;
		rc = hltests_recover(tests_state);
		if (rc) {
			printf("Failed to recover from error (%d)\n", rc);
			fd = tests_state->fd;
			goto err_exit;
		}
	}

	fd = tests_state->fd;

	if (hltests_is_device_idle_and_operational(fd))
		return 0;

	hdev = get_hdev_from_fd(fd);
	if (!hdev) {
		printf("Failed to get hdev from file descriptor %d\n", fd);
		goto err_exit;
	}

	timeout_locked = hdev->module_params.timeout_locked;
	if (timeout_locked > 1000)
		timeout_locked = 1000;

	for (i = 0 ; i <= timeout_locked ; i++) {
		sleep(1);
		if (hltests_is_device_idle_and_operational(fd))
			return 0;
	}

err_exit:
	/* If we got here it means that something is broken */
	printf("ERROR! device broken, status = 0x%x, (%s recovery) stop running tests\n",
		hlthunk_get_device_status_info(fd), need_recover ? "after" : "did not need");

	/* The current thread terminates itself, which leads to a full test-suite closure */
	pthread_exit(PTHREAD_CANCELED);
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
		OPT_INTEGER('i', "interface", &nic_port, "NIC interface/port"),
		OPT_INTEGER('m', "mode", &legacy_mode_enabled, "Legacy mode enabled"),
		OPT_STRING('b', "build_path", &build_path, "Path to build directory"),
		OPT_BOOLEAN('a', "arc-log", &enable_arc_log, "enable logging for arcs"),
		OPT_INTEGER('e', "events-listener", &events_listener,
				"enable driver-events listener thread"),
		OPT_BOOLEAN('x', "neg", &negative_tests, "enable negative tests"),
		OPT_BOOLEAN('g', "mini-suite", &run_mini_suite, "run minimized tests suite"),
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

void hltests_override_parser_pciaddr(const char *pciaddr)
{
	parser_pciaddr = pciaddr;
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

int hltests_set_build_path(const char *path)
{
	int ret = snprintf(build_path_str, BUILD_PATH_MAX_LENGTH, "%s", path);

	if (ret < 0 || ret >= BUILD_PATH_MAX_LENGTH)
		return -1;

	build_path = build_path_str;

	return 0;
}

int hltests_get_parser_nic_port(void)
{
	return nic_port;
}

int hltests_get_parser_events_listener(void)
{
	return events_listener;
}

uint32_t hltests_get_parser_negative_tests(void)
{
	return negative_tests;
}

uint32_t hltests_get_parser_mini_suite(void)
{
	return run_mini_suite;
}

bool hltests_is_legacy_mode_enabled(int fd)
{
	if (hltests_is_goya(fd) || hltests_is_gaudi(fd))
		return true;

	if (hltests_is_gaudi3(fd))
		return false;

	return !!legacy_mode_enabled;
}

bool hltests_is_simulator(int fd)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);

	if (hdev->device_id == PCI_IDS_GOYA_SIMULATOR ||
		hdev->device_id == PCI_IDS_GAUDI_SIMULATOR ||
		hdev->device_id == PCI_IDS_GAUDI_HL2000M_SIMULATOR ||
		hdev->device_id == PCI_IDS_GAUDI2_SIMULATOR ||
		hdev->device_id == PCI_IDS_GAUDI2_ARC_SIMULATOR ||
		hdev->device_id == PCI_IDS_GAUDI2B_SIMULATOR ||
		hdev->device_id == PCI_IDS_GAUDI2B_ARC_SIMULATOR ||
		hdev->device_id == PCI_IDS_GAUDI3_SIMULATOR ||
		hdev->device_id == PCI_IDS_GAUDI3_ARC_SIMULATOR ||
		hdev->device_id == PCI_IDS_GAUDI3_HL_338_SIMULATOR ||
		hdev->device_id == PCI_IDS_GAUDI3_HL_338_ARC_SIMULATOR ||
		hdev->device_id == PCI_IDS_GAUDI2_HL_288_SIMULATOR ||
		hdev->device_id == PCI_IDS_GAUDI2_HL_288_ARC_SIMULATOR ||
		hdev->device_id == PCI_IDS_GAUDI2D_HL_288_SIMULATOR ||
		hdev->device_id == PCI_IDS_GAUDI2D_HL_288_ARC_SIMULATOR)
		return true;

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
	if ((device == HLTHUNK_DEVICE_GAUDI) ||
			(device == HLTHUNK_DEVICE_GAUDI_HL2000M))
		return true;

	return false;
}

bool hltests_is_gaudi2(int fd)
{
	enum hlthunk_device_name device;

	device = hlthunk_get_device_name_from_fd(fd);
	if ((device == HLTHUNK_DEVICE_GAUDI2) ||
			(device == HLTHUNK_DEVICE_GAUDI2B) || (device == HLTHUNK_DEVICE_GAUDI2C) ||
			(device == HLTHUNK_DEVICE_GAUDI2D))
		return true;

	return false;
}

bool hltests_is_gaudi3(int fd)
{
	enum hlthunk_device_name device;

	device = hlthunk_get_device_name_from_fd(fd);
	if (device == HLTHUNK_DEVICE_GAUDI3 || device == HLTHUNK_DEVICE_GAUDI3D)
		return true;

	return false;
}

bool hltests_is_gaudi3d(int fd)
{
	enum hlthunk_device_name device;

	device = hlthunk_get_device_name_from_fd(fd);
	if (device == HLTHUNK_DEVICE_GAUDI3D)
		return true;

	return false;
}

bool hltests_is_gaudi_family(int fd)
{
	return (hltests_is_gaudi(fd) || hltests_is_gaudi2(fd) || hltests_is_gaudi3(fd));
}

bool hltests_is_pldm(int fd)
{
	struct hltests_module_params_info module_params;
	int rc;

	rc = hltests_get_module_params_info(fd, &module_params);
	assert_int_equal(rc, 0);

	return !!module_params.pldm;
}

VOID test_sm_pingpong_common_cp(void **state, bool is_tpc,
				bool common_cb_in_host, uint8_t engine_id)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	void *host_src, *host_dst, *engine_common_cb, *engine_upper_cb = NULL, *restore_cb,
			*dmadown_cb, *dmaup_cb, *dram_ptr = NULL;
	uint64_t seq = 0, host_src_device_va, host_dst_device_va, device_data_address = 0x0,
			engine_common_cb_address = 0x0, engine_common_cb_device_va = 0x0,
			engine_upper_cb_address = 0x0, engine_upper_cb_device_va = 0x0;
	uint32_t engine_qid, dma_size, engine_common_cb_size, engine_upper_cb_size = 0,
			restore_cb_size, dmadown_cb_size, dmaup_cb_size,
			dma_dir_down = DMA_DIR_HOST_TO_SRAM, dma_dir_up = DMA_DIR_SRAM_TO_HOST;
	struct hltests_cs_chunk restore_arr[1], execute_arr[3];
	struct hltests_monitor_and_fence mon_and_fence_info;
	uint16_t sob[2], mon[2], dma_down_qid, dma_up_qid;
	struct hltests_pkt_info pkt_info;
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;
	int rc, fd = tests_state->fd;

	/* Test Description:
	 * - First DMA QMAN transfers data from host to device and then signals SOB0.
	 * - Engine QMAN processes CP_DMA packet and transfers internal CB to CMDQ.
	 * - Engine CMDQ fences on SOB0, processes NOP packet, and then signals SOB8.
	 * - Second DMA QMAN fences on SOB1 and then transfers data from device to host.
	 * - Setup CB is used to clear SOB0/1 and to DMA the internal CBs to device.
	 *
	 * NOTE:
	 * The engine's common CB can be located on the host, depending on the "common_cb_in_host"
	 * flag.
	 */

	/* Check conditions if CB is in the host */
	if (common_cb_in_host) {
		/* This test can't run on Goya */
		if (hltests_is_goya(fd)) {
			printf("Test is skipped. Goya's common CP can't be in host\n");
			skip();
		}
	}

	if (is_tpc)
		engine_qid = hltests_get_tpc_qid(fd, engine_id, STREAM0);
	else
		engine_qid = hltests_get_mme_qid(fd, engine_id, STREAM0);

	dma_down_qid = hltests_get_dma_down_qid(fd, STREAM0);
	dma_up_qid = hltests_get_dma_up_qid(fd, STREAM0);

	/* Device addresses for data and engine's CB */
	if (hw_ip->sram_size) {
		device_data_address = hw_ip->sram_base_address + 0x1000;
		engine_upper_cb_address = hw_ip->sram_base_address + 0x2000;
		engine_common_cb_address = hw_ip->sram_base_address + 0x3000;
	} else if (hw_ip->dram_enabled) {
		dram_ptr = hltests_allocate_device_mem(fd, 0x3000, 0, CONTIGUOUS);
		assert_non_null(dram_ptr);
		device_data_address = (uint64_t) (uintptr_t) dram_ptr;
		engine_upper_cb_address = device_data_address + 0x1000;
		engine_common_cb_address = device_data_address + 0x2000;
		dma_dir_down = DMA_DIR_HOST_TO_DRAM;
		dma_dir_up = DMA_DIR_DRAM_TO_HOST;
	} else {
		printf("No device memory is available so skipping test\n");
		skip();
	}

	dma_size = 4;

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

	/* Allocate memory on host for the common CB. Either the ASIC will fetch it directly
	 * from host, or we will download it to the device and run it from there.
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
	mon_and_fence_info.mon_mode = SOB_EQUAL;
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
		engine_upper_cb = hltests_create_cb(fd, SZ_4K, INTERNAL, engine_upper_cb_address);
		assert_non_null(engine_upper_cb);
		engine_upper_cb_device_va = hltests_get_device_va_for_host_ptr(fd, engine_upper_cb);
		engine_upper_cb_size = 0;

		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_FALSE;
		if (common_cb_in_host)
			pkt_info.cp_dma.src_addr = engine_common_cb_device_va;
		else
			pkt_info.cp_dma.src_addr = engine_common_cb_address;
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
		pkt_info.dma.dst_addr = engine_common_cb_address;
		pkt_info.dma.size = engine_common_cb_size;
		pkt_info.dma.dma_dir = dma_dir_down;
		restore_cb_size = hltests_add_dma_pkt(fd, restore_cb,
						restore_cb_size, &pkt_info);
	}

	if (hltests_is_legacy_mode_enabled(fd)) {
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_TRUE;
		pkt_info.dma.src_addr = engine_upper_cb_device_va;
		pkt_info.dma.dst_addr = engine_upper_cb_address;
		pkt_info.dma.size = engine_upper_cb_size;
		pkt_info.dma.dma_dir = dma_dir_down;
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
	pkt_info.dma.dst_addr = device_data_address;
	pkt_info.dma.size = dma_size;
	pkt_info.dma.dma_dir = dma_dir_down;
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
	mon_and_fence_info.mon_mode = SOB_EQUAL;
	dmaup_cb_size = hltests_add_monitor_and_fence(fd, dmaup_cb,
				dmaup_cb_size, &mon_and_fence_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = dma_up_qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.dma.src_addr = device_data_address;
	pkt_info.dma.dst_addr = host_dst_device_va;
	pkt_info.dma.size = dma_size;
	pkt_info.dma.dma_dir = dma_dir_up;
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

	if (dram_ptr) {
		rc = hltests_free_device_mem(fd, dram_ptr);
		assert_int_equal(rc, 0);
	}

	END_TEST;
}

int hltests_clear_sobs_offset(int fd, uint16_t num_of_sobs, uint16_t offset)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;
	uint16_t first_sob = hltests_get_first_avail_sob(fd);
	uint32_t cb_offset = 0, i, dma_qid;
	struct hltests_pkt_info pkt_info;
	int rc;
	void *cb;

	if (asic->get_sob_value) {
		assert_non_null(asic->set_sob_value);

		for (i = 0; i < num_of_sobs; i++) {
			rc = asic->set_sob_value(fd, first_sob + offset + i, 0);
			assert_int_equal(rc, 0);
		}

		/* Flush writes */
		asic->get_sob_value(fd, first_sob + offset + num_of_sobs);

		return 0;
	}

	/* Use control block approach if we can't directly read/write SOBs */
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

	ptr = hltests_mmap(fd, *block_size, handle);
	if (ptr == MAP_FAILED) {
		printf(
			"Failed to mmap a HW block handle [block_address 0x%"PRIx64"]\n",
			block_addr);
		ptr = NULL;
	}

	return ptr;
}

int hltests_unmap_hw_block(int fd, void *host_addr, uint32_t block_size)
{
	if (hltests_is_simulator(fd))
		return 0;

	return hltests_munmap(fd, host_addr, block_size);
}

static int hltests_sim_read_from_lbw_mem(int fd, void *dst, uint64_t src,
						uint32_t size)
{
	struct hl_debug_params_mem_access mem_access;
	struct hl_debug_args debug;

	memset(&mem_access, 0, sizeof(mem_access));
	mem_access.cfg_address = src;
	mem_access.user_address = (uint64_t) (uintptr_t) dst;
	mem_access.size = size;

	memset(&debug, 0, sizeof(debug));
	debug.input_ptr = (uint64_t) (uintptr_t) &mem_access;
	debug.input_size = sizeof(mem_access);
	debug.op = HL_DEBUG_OP_READMEM;

	return hlthunk_debug(fd, &debug);
}

static int hltests_sim_write_to_lbw_mem(int fd, uint64_t dst, void *src,
					uint32_t size)
{
	struct hl_debug_params_mem_access mem_access;
	struct hl_debug_args debug;

	memset(&mem_access, 0, sizeof(mem_access));
	mem_access.cfg_address = dst;
	mem_access.user_address = (uint64_t) (uintptr_t) src;
	mem_access.size = size;

	memset(&debug, 0, sizeof(debug));
	debug.input_ptr = (uint64_t) (uintptr_t) &mem_access;
	debug.input_size = sizeof(mem_access);
	debug.op = HL_DEBUG_OP_MEMCPY;

	return hlthunk_debug(fd, &debug);
}

int hltests_read_lbw_mem(int fd, void *dst, void *src, uint32_t size)
{
	int num_of_regs, i;
	uint32_t *d, *s;

	/* LBW access must be aligned to 32 bits*/
	if (size % sizeof(uint32_t) != 0)
		return -EINVAL;

	if (hltests_is_simulator(fd))
		return hltests_sim_read_from_lbw_mem(fd, dst,
				(uint64_t) (uintptr_t) src, size);

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

	if (hltests_is_simulator(fd))
		return hltests_sim_write_to_lbw_mem(fd,
					(uint64_t) (uintptr_t) dst, src, size);

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

double get_bw_gigabit_from_timesync(uint64_t total_size, struct hlthunk_time_sync_info *begin,
					struct hlthunk_time_sync_info *end)
{
		double timediff_dev = (end->device_time - begin->device_time) / PSOC_FREQ_GHZ;

		/* in case of wraparound return the result to a positive value. */
		if (timediff_dev < 0)
			timediff_dev *= -1;
		return total_size * 8 / timediff_dev;
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

int hltests_device_memory_export_dmabuf_fd(int fd, void *device_addr, uint64_t size,
						uint64_t offset)
{
	uint64_t addr = (uint64_t) (uintptr_t) device_addr;
	struct hltests_device *hdev;

	hdev = get_hdev_from_fd(fd);
	assert_non_null(hdev);

	if (hltests_is_gaudi(fd)) {
		assert_int_equal(offset, 0);
		return hlthunk_device_memory_export_dmabuf_fd(fd, addr, size, 0);
	}

	return hlthunk_device_mapped_memory_export_dmabuf_fd(fd, addr, size, offset,
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

uint16_t hltests_get_cache_line_size(int fd)
{
	const struct hltests_asic_funcs *asic =
			get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_cache_line_size();
}

uint64_t hltests_get_tc_base_addr(int fd, uint32_t core_id)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_tc_base_addr(core_id);
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

void hltests_monitor_dma_start(struct monitor_dma_test *params, int fd, uint32_t qid,
				int poll_interval_sec)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;
	int rc;

	if (!asic->monitor_dma_test_progress)
		return;

	memset(params, 0, sizeof(*params));
	params->fd = fd;
	params->qid = qid;
	params->poll_interval_sec = poll_interval_sec;
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

void hltests_set_capabilities_mask(const uint64_t new_mask)
{
	hltests_capabilities_mask = new_mask;
}

uint64_t hltests_get_capabilities_mask(void)
{
	return hltests_capabilities_mask;
}

int hltests_mme_dma_init(int fd)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	const struct hltests_asic_funcs *asic = hdev->asic_funcs;

	if (asic->mme_dma_init)
		return asic->mme_dma_init(fd);
	return 0;
}

int hltests_is_mme_dma_enabled(int fd)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);

	return hdev->mme_dma_info.enable;
}

uint32_t hltests_get_mme_dma_cb_size(int fd, int num_of_lindma_pkts, uint32_t size)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	const struct hltests_asic_funcs *asic = hdev->asic_funcs;

	return asic->get_mme_dma_cb_size(fd, num_of_lindma_pkts, size);
}

uint32_t hltests_prepare_mme_dma_req(int fd, void *cb, uint32_t cb_size, uint64_t src,
					uint64_t dst, uint8_t mme_idx, uint64_t size)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	const struct hltests_asic_funcs *asic = hdev->asic_funcs;

	return asic->prepare_mme_dma_req(fd, cb, cb_size, src, dst, mme_idx, size);
}

bool can_open_debugfs(bool dbg_print)
{
	if (!access("/sys/kernel/debug", R_OK))
		return true;

	if (dbg_print)
		printf("Cannot access debugfs, maybe need to run with sudo?\n");

	return false;
}

uint32_t hltests_add_cq_db_set_cq_queue_pkt(int fd, void *buffer, uint32_t buf_off,
					struct hltests_cq_config *cq_config, uint16_t sob_id)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	const struct hltests_asic_funcs *asic = hdev->asic_funcs;

	return asic->add_cq_db_set_cq_queue_pkt(buffer, buf_off, cq_config, sob_id);
}

uint64_t hltests_get_tpc_intr_cause_reg(int fd, uint64_t tpc_idx)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	const struct hltests_asic_funcs *asic = hdev->asic_funcs;

	return asic->get_tpc_intr_cause_reg(tpc_idx);
}

uint64_t hltests_get_razwi_addr(int fd, enum err_trigger type)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	const struct hltests_asic_funcs *asic = hdev->asic_funcs;

	return asic->get_razwi_addr(type);
}

int hltests_edp_get_engines_list(int fd, uint32_t **engine_ids, uint32_t *engine_ids_size)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	const struct hltests_asic_funcs *asic = hdev->asic_funcs;

	return asic->edp_get_engines_list(fd, engine_ids, engine_ids_size);
}

uint64_t hltests_get_fw_mem_addr(int fd, uint64_t size)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	const struct hltests_asic_funcs *asic = hdev->asic_funcs;

	return asic->get_fw_mem_addr(size);
}

int hltests_set_vram_size(int fd, uint64_t vram_size, uint8_t vram_id)
{
	char pci_bus_id[13] = {}, path_vram[PATH_MAX] = {}, buf[64] = {}, vram_size_str[16] = {};
	int rc, fd_vram;
	ssize_t size;

	rc = hlthunk_get_pci_bus_id_from_fd(fd, pci_bus_id, sizeof(pci_bus_id));
	if (rc)
		return -ENODEV;

	snprintf(path_vram, PATH_MAX, "/sys/bus/pci/devices/%s/ttm/ttm0/rlimit_vram%d",
		 pci_bus_id, vram_id);

	/* Check if file exists */
	if (access(path_vram, F_OK))
		return -ENOENT;

	fd_vram = open(path_vram, O_RDWR, 0);
	if (fd_vram == -1) {
		printf("Failed to open %s\n", path_vram);
		return -errno;
	}

	size = read(fd_vram, buf, sizeof(buf));
	if (size < 0 || size >= sizeof(buf)) {
		close(fd_vram);
		return -errno;
	}

	if (vram_size != strtoul(buf, NULL, 16)) {
		snprintf(vram_size_str, sizeof(vram_size_str), "%lu", vram_size);
		size = write(fd_vram, vram_size_str, strlen(vram_size_str) + 1);
		if (size < 0) {
			printf("Failed to write to VRAM file rc %zd\n", size);
			return size;
		}
	}

	close(fd_vram);
	return 0;
}

int verbose_printf(const char *format, ...)
{
	va_list args;
	int ret;

	if (!hltests_get_verbose_enabled())
		return 0;

	va_start(args, format);
	ret = printf(format, args);
	va_end(args);

	return ret;
}
