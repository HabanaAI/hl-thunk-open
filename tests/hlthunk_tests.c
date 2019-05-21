// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_tests.h"
#include "specs/pci_ids.h"
#include "mersenne-twister.h"
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

static pthread_mutex_t table_lock = PTHREAD_MUTEX_INITIALIZER;
static khash_t(ptr) * dev_table;

static enum hlthunk_device_name asic_name_for_testing = HLTHUNK_DEVICE_INVALID;

int run_disabled_tests;
const char *parser_pciaddr;
const char *config_filename;

static char asic_names[HLTHUNK_DEVICE_INVALID][10] = {
		"Goya"
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

int hltests_init(void)
{
	if (!dev_table) {
		dev_table = kh_init(ptr);

		if (!dev_table)
			return -ENOMEM;
	}

	return 0;
}

void hltests_fini(void)
{
	if (dev_table)
		kh_destroy(ptr, dev_table);
}

enum hlthunk_device_name hltests_validate_device_name(const char *device_name)
{
	if (!device_name)
		device_name = "goya";

	if (!strcmp(device_name, "goya"))
		return HLTHUNK_DEVICE_GOYA;

	printf("Invalid device name %s\n", device_name);

	return HLTHUNK_DEVICE_INVALID;
}

int hltests_open(const char *busid)
{
	int fd, rc;
	struct hltests_device *hdev;
	khint_t k;

	pthread_mutex_lock(&table_lock);

	rc = fd = hlthunk_open(asic_name_for_testing, busid);
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

	switch (hlthunk_get_device_name_from_fd(fd)) {
	case HLTHUNK_DEVICE_GOYA:
		goya_tests_set_asic_funcs(hdev);
		break;
	default:
		printf("Invalid device type %d\n", hdev->device_id);
		rc = -ENXIO;
		goto remove_device;
	}

	hdev->asic_funcs->dram_pool_init(hdev);

	hdev->debugfs_addr_fd = -1;
	hdev->debugfs_data_fd = -1;

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

static int debugfs_open(int fd)
{
	struct hltests_device *hdev;
	int debugfs_addr_fd, debugfs_data_fd;

	hdev = get_hdev_from_fd(fd);
	if (!hdev)
		return -ENODEV;

	debugfs_addr_fd =
		open("//sys/kernel/debug/habanalabs/hl0/addr", O_WRONLY);
	debugfs_data_fd =
		open("//sys/kernel/debug/habanalabs/hl0/data32", O_RDWR);

	if ((debugfs_addr_fd == -1) || (debugfs_data_fd == -1)) {
		if (debugfs_addr_fd >= 0)
			close(debugfs_addr_fd);
		else if (debugfs_data_fd >= 0)
			close(debugfs_data_fd);
		printf("Failed to open DebugFS (Didn't run with sudo ?)\n");
		return -EPERM;
	}

	hdev->debugfs_addr_fd = debugfs_addr_fd;
	hdev->debugfs_data_fd = debugfs_data_fd;

	return 0;
}

static int debugfs_close(int fd)
{
	struct hltests_device *hdev;

	hdev = get_hdev_from_fd(fd);
	if (!hdev)
		return -ENODEV;

	if ((hdev->debugfs_addr_fd == -1) || (hdev->debugfs_data_fd == -1))
		return -EFAULT;

	close(hdev->debugfs_addr_fd);
	close(hdev->debugfs_data_fd);
	hdev->debugfs_addr_fd = -1;
	hdev->debugfs_data_fd = -1;

	return 0;
}

uint32_t hltests_debugfs_read(int fd, uint64_t full_address)
{
	struct hltests_device *hdev;
	char addr_str[64] = "", value[64] = "";
	ssize_t size;

	hdev = get_hdev_from_fd(fd);
	if (!hdev)
		return -1;

	sprintf(addr_str, "0x%lx", full_address);

	size = write(hdev->debugfs_addr_fd, addr_str, strlen(addr_str) + 1);
	if (size < 0)
		printf("Failed to write to debugfs address fd [rc %zd]\n",
				size);

	size = pread(hdev->debugfs_data_fd, value, sizeof(value), 0);
	if (size < 0)
		printf("Failed to read from debugfs data fd [rc %zd]\n", size);

	return strtoul(value, NULL, 16);
}

void hltests_debugfs_write(int fd, uint64_t full_address, uint32_t val)
{
	struct hltests_device *hdev;
	char addr_str[64] = "", val_str[64] = "";
	ssize_t size;

	hdev = get_hdev_from_fd(fd);
	if (!hdev)
		return;

	sprintf(addr_str, "0x%lx", full_address);
	sprintf(val_str, "0x%x", val);

	size = write(hdev->debugfs_addr_fd, addr_str, strlen(addr_str) + 1);
	if (size < 0)
		printf("Failed to write to debugfs address fd [rc %zd]\n",
				size);

	size = write(hdev->debugfs_data_fd, val_str, strlen(val_str) + 1);
	if (size < 0)
		printf("Failed to write to debugfs data fd [rc %zd]\n", size);
}

static int is_param_enabled(enum hltests_kmd_param param, bool *val)
{
	int fd;
	char c, path[100], *base_str = "/sys/module/habanalabs/parameters/",
			*param_str;

	memset(path, 0, sizeof(path));
	memcpy(path, base_str, strlen(base_str));

	switch (param) {
	case KMD_PARAM_MMU:
		param_str = "mmu_enable";
		break;
	case KMD_PARAM_SECURITY:
		param_str = "security_enable";
		break;
	default:
		printf("Invalid KMD parameter %d\n", param);
		return errno;
	}

	memcpy(path + strlen(base_str), param_str, strlen(param_str));

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		printf("Failed to open %s\n", path);
		return errno;
	}

	if (read(fd, &c, 1) <= 0) {
		printf("Failed to read %s\n", path);
		close(fd);
		return errno;
	}

	close(fd);

	*val = c == '1';

	return 0;
}

int hltests_setup(void **state)
{
	struct hltests_state *tests_state;
	int rc;

	tests_state = hlthunk_malloc(sizeof(struct hltests_state));
	if (!tests_state)
		return -ENOMEM;

	rc = hltests_init();
	if (rc) {
		printf("Failed to init tests library %d\n", rc);
		goto free_state;
	}

	tests_state->fd = hltests_open(parser_pciaddr);
	if (tests_state->fd < 0) {
		printf("Failed to open device %d\n", tests_state->fd);
		rc = tests_state->fd;
		goto fini_tests;
	}

	rc = is_param_enabled(KMD_PARAM_MMU, &tests_state->mmu);
	if (rc) {
		printf("Failed to detect if MMU is enabled on device %d, %d\n",
			tests_state->fd, rc);
		goto close_fd;
	}

	rc = is_param_enabled(KMD_PARAM_SECURITY, &tests_state->security);
	if (rc) {
		printf(
			"Failed to detect if security is enabled on device %d, %d\n",
			tests_state->fd, rc);
		goto close_fd;
	}

	*state = tests_state;

	seed(time(NULL));

	return 0;

close_fd:
	if (hltests_close(tests_state->fd))
		printf("Problem in closing FD, ignoring...\n");
fini_tests:
	hltests_fini();
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

	if (hltests_close(tests_state->fd))
		printf("Problem in closing FD, ignoring...\n");

	hltests_fini();

	hlthunk_free(*state);

	return 0;
}

int hltests_root_setup(void **state)
{
	struct hltests_state *tests_state;
	int rc;

	rc = hltests_setup(state);
	if (rc)
		return rc;

	tests_state = (struct hltests_state *) *state;
	return debugfs_open(tests_state->fd);
}

int hltests_root_teardown(void **state)
{
	struct hltests_state *tests_state =
					(struct hltests_state *) *state;

	if (!tests_state)
		return -EINVAL;

	debugfs_close(tests_state->fd);

	return hltests_teardown(state);
}

static void *allocate_huge_mem(uint64_t size)
{
	int mmapFlags = MAP_HUGE_2MB | MAP_HUGETLB | MAP_SHARED | MAP_ANONYMOUS;
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
void *hltests_allocate_host_mem(int fd, uint64_t size, bool huge)
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
void *hltests_allocate_device_mem(int fd, uint64_t size, bool contiguous)
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
 *                           be executed from by the CS
 * @return virtual address of the CB in the user process VA space, or NULL for
 *         failure
 */
void *hltests_create_cb(int fd, uint32_t cb_size, bool is_external,
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
		cb->ptr = hltests_allocate_host_mem(fd, cb_size, false);
		if (!cb->ptr)
			goto free_cb;
		cb->cb_handle = cb_internal_sram_address;
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
		return -EINVAL;
	}

	cb = kh_val(hdev->cb_table, k);

	pthread_mutex_unlock(&hdev->cb_table_lock);

	chunk->cb_handle = cb->cb_handle;
	chunk->queue_index = queue_index;
	chunk->cb_size = cb_size;

	return 0;
}

int hltests_submit_cs(int fd,
		struct hltests_cs_chunk *restore_arr,
		uint32_t restore_arr_size,
		struct hltests_cs_chunk *execute_arr,
		uint32_t execute_arr_size,
		bool force_restore,
		uint64_t *seq)
{
	struct hltests_device *hdev;
	struct hl_cs_chunk *chunks_restore = NULL, *chunks_execute = NULL;
	struct hlthunk_cs_in cs_in;
	struct hlthunk_cs_out cs_out;
	uint32_t size, i;
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

		for (i = 0 ; i < restore_arr_size ; i++) {
			rc = fill_cs_chunk(hdev, &chunks_restore[i],
					restore_arr[i].cb_ptr,
					restore_arr[i].cb_size,
					restore_arr[i].queue_index);
			if (rc)
				goto free_chunks_restore;
		}

	}

	if (execute_arr_size && execute_arr) {
		size = execute_arr_size * sizeof(*chunks_execute);
		chunks_execute = hlthunk_malloc(size);
		if (!chunks_execute) {
			rc = -ENOMEM;
			goto free_chunks_restore;
		}

		for (i = 0 ; i < execute_arr_size ; i++) {
			rc = fill_cs_chunk(hdev, &chunks_execute[i],
					execute_arr[i].cb_ptr,
					execute_arr[i].cb_size,
					execute_arr[i].queue_index);
			if (rc)
				goto free_chunks_execute;
		}

	}

	memset(&cs_in, 0, sizeof(cs_in));
	cs_in.chunks_restore = chunks_restore;
	cs_in.chunks_execute = chunks_execute;
	cs_in.num_chunks_restore = restore_arr_size;
	cs_in.num_chunks_execute = execute_arr_size;
	cs_in.flags = force_restore ? HL_CS_FLAGS_FORCE_RESTORE : 0x0;

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

int hltests_wait_for_cs(int fd, uint64_t seq, uint64_t timeout_us)
{
	uint32_t status;
	int rc;

	rc = hlthunk_wait_for_cs(fd, seq, timeout_us, &status);
	if (rc && errno != ETIMEDOUT && errno != EIO)
		return rc;

	return status;
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

uint32_t hltests_add_monitor_and_fence(int fd, void *buffer, uint32_t buf_off,
		struct hltests_monitor_and_fence *mon_and_fence_info)
{
	const struct hltests_asic_funcs *asic =
			get_hdev_from_fd(fd)->asic_funcs;

	return asic->add_monitor_and_fence(buffer, buf_off, mon_and_fence_info);
}

uint32_t hltests_get_dma_down_qid(int fd, enum hltests_dcore_id dcore_id,
						enum hltests_stream_id stream)
{
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_dma_down_qid(dcore_id, stream);
}

uint32_t hltests_get_dma_up_qid(int fd, enum hltests_dcore_id dcore_id,
					enum hltests_stream_id stream)
{
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_dma_up_qid(dcore_id, stream);
}

uint32_t hltests_get_dma_dram_to_sram_qid(int fd,
					enum hltests_dcore_id dcore_id,
					enum hltests_stream_id stream)
{
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_dma_dram_to_sram_qid(dcore_id, stream);
}

uint32_t hltests_get_dma_sram_to_dram_qid(int fd,
					enum hltests_dcore_id dcore_id,
					enum hltests_stream_id stream)
{
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_dma_sram_to_dram_qid(dcore_id, stream);
}

uint32_t hltests_get_tpc_qid(int fd, enum hltests_dcore_id dcore_id,
				uint8_t tpc_id,	enum hltests_stream_id stream)
{
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_tpc_qid(dcore_id, tpc_id, stream);
}

uint32_t hltests_get_mme_qid(int fd, enum hltests_dcore_id dcore_id,
				uint8_t mme_id,	enum hltests_stream_id stream)
{
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_mme_qid(dcore_id, mme_id, stream);
}

uint8_t hltests_get_tpc_cnt(int fd, uint8_t dcore_id)
{
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_tpc_cnt(dcore_id);
}

void hltests_fill_rand_values(void *ptr, uint32_t size)
{
	uint32_t i, *p = ptr, rounddown_aligned_size, remainder, val;

	rounddown_aligned_size = size & ~(sizeof(uint32_t) - 1);
	remainder = size - rounddown_aligned_size;

	for (i = 0 ; i < rounddown_aligned_size ; i += sizeof(uint32_t), p++)
		*p = rand_u32();

	if (!remainder)
		return;

	val = rand_u32();
	for (i = 0 ; i < remainder ; i++) {
		((uint8_t *) p)[i] = (uint8_t) (val & 0xff);
		val >>= 8;
	}
}

int hltests_mem_compare(void *ptr1, void *ptr2, uint64_t size)
{
	uint64_t *p1 = (uint64_t *) ptr1, *p2 = (uint64_t *) ptr2;
	uint32_t err_cnt = 0, rounddown_aligned_size, remainder, i;

	rounddown_aligned_size = size & ~(sizeof(uint64_t) - 1);
	remainder = size - rounddown_aligned_size;

	for (i = 0 ; i < rounddown_aligned_size && err_cnt < 10;
		i += sizeof(uint64_t), p1++, p2++) {
		if (*p1 != *p2) {
			printf("[%p]: 0x%"PRIx64" <--> [%p]: 0x%"PRIx64"\n",
				p1, *p1, p2, *p2);
			err_cnt++;
		}
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

void hltests_dma_transfer(int fd, uint32_t queue_index, enum hltests_eb eb,
				enum hltests_mb mb,
				uint64_t src_addr, uint64_t dst_addr,
				uint32_t size,
				enum hltests_goya_dma_direction dma_dir)
{
	uint32_t offset = 0;
	void *ptr;
	struct hltests_pkt_info pkt_info;

	ptr = hltests_create_cb(fd, getpagesize(), true, 0);
	assert_ptr_not_equal(ptr, NULL);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = eb;
	pkt_info.mb = mb;
	pkt_info.dma.src_addr = src_addr;
	pkt_info.dma.dst_addr = dst_addr;
	pkt_info.dma.size = size;
	pkt_info.dma.dma_dir = dma_dir;
	offset = hltests_add_dma_pkt(fd, ptr, offset, &pkt_info);

	hltests_submit_and_wait_cs(fd, ptr, offset, queue_index,
					true, HL_WAIT_CS_STATUS_COMPLETED);
}

int hltests_dma_test(void **state, bool is_ddr, uint64_t size)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	void *device_addr, *src_ptr, *dst_ptr;
	uint64_t host_src_addr, host_dst_addr;
	uint32_t dma_dir_down, dma_dir_up;
	bool is_huge = size > 32 * 1024;
	int rc, fd = tests_state->fd;

	/* Sanity and memory allocation */
	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (is_ddr) {
		assert_int_equal(hw_ip.dram_enabled, 1);
		assert_in_range(size, 1, hw_ip.dram_size);

		device_addr = hltests_allocate_device_mem(fd, size, false);
		assert_non_null(device_addr);

		dma_dir_down = GOYA_DMA_HOST_TO_DRAM;
		dma_dir_up = GOYA_DMA_DRAM_TO_HOST;
	} else {
		if (size < 1 || size > hw_ip.sram_size)
			return 0;
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
	hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, DCORE0, STREAM0),
			EB_FALSE, MB_TRUE, host_src_addr,
			(uint64_t) (uintptr_t) device_addr,
			size, dma_dir_down);

	/* DMA: device->host */
	hltests_dma_transfer(fd, hltests_get_dma_up_qid(fd, DCORE0, STREAM0),
				0, 1, (uint64_t) (uintptr_t) device_addr,
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
				uint32_t queue_index, bool destroy_cb,
				int expected_val)
{
	struct hltests_cs_chunk execute_arr[1];
	uint64_t seq = 0;
	int rc;

	execute_arr[0].cb_ptr = cb_ptr;
	execute_arr[0].cb_size = cb_size;
	execute_arr[0].queue_index = queue_index;

	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, 1, false, &seq);
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
	if (device_id == PCI_IDS_GOYA_SIMULATOR)
		is_idle = true;
	else
		is_idle = hlthunk_is_device_idle(fd);

	dev_status = hlthunk_get_device_status_info(fd);

	return (is_idle && dev_status == HL_DEVICE_STATUS_OPERATIONAL);
}

int hltests_ensure_device_operational(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int fd = tests_state->fd;
	int fd_for_timeout_locked, rc;
	unsigned int timeout_locked, i;
	char tmp_buff[4] = {0};

	if (is_dev_idle_and_operational(fd))
		return 0;

	fd_for_timeout_locked =
		open("/sys/module/habanalabs/parameters/timeout_locked",
								O_RDONLY);

	if (fd_for_timeout_locked < 0) {
		printf("Failed to open timeout_locked\n");
		return errno;
	}

	rc = read(fd_for_timeout_locked, &tmp_buff, sizeof(tmp_buff) - 1);
	if (rc < 0) {
		printf("Failed to read timeout_locked\n");
		close(fd_for_timeout_locked);
		return errno;
	}

	close(fd_for_timeout_locked);
	sscanf(tmp_buff, "%d", &timeout_locked);
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

void *hltests_mem_pool_init(uint64_t start_addr, uint64_t size, uint64_t order)
{
	struct mem_pool *mem_pool;
	uint64_t page_size;
	int rc;

	assert_in_range(order, PAGE_SHIFT_4KB, PAGE_SHIFT_16MB);

	page_size = 1 << order;

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
	uint32_t needed_npages, curr_npages = 0, i, j, k;
	bool found = false;

	needed_npages = (size + mem_pool->page_size - 1) / mem_pool->page_size;

	pthread_mutex_lock(&mem_pool->lock);

	for (i = 0 ; i < mem_pool->pool_npages ; i++) {
		for (j = i ; j < mem_pool->pool_npages ; j++) {
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
			*addr = mem_pool->start + i * mem_pool->page_size;
			break;
		}

	}

	pthread_mutex_unlock(&mem_pool->lock);

	return found ? 0 : -ENOMEM;
}

void hltests_mem_pool_free(void *data, uint64_t addr, uint64_t size)
{
	struct mem_pool *mem_pool = (struct mem_pool *) data;
	uint32_t start_page = (addr - mem_pool->start) / mem_pool->page_size,
			npages = size / mem_pool->page_size, i;

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
	const char *asic = NULL;
	const char *test = NULL;
	int list = 0;

	struct argparse_option options[] = {
		OPT_HELP(),
		OPT_GROUP("Basic options"),
		OPT_BOOLEAN('l', "list", &list, "list tests"),
		OPT_BOOLEAN('d', "disabled", &run_disabled_tests,
			"run disabled tests"),
		OPT_STRING('a', "asic", &asic,
			"run tests on asic (goya)"),
		OPT_STRING('s', "test", &test, "name of specific test to run"),
		OPT_STRING('p', "pciaddr", &parser_pciaddr,
			"pci address of device"),
		OPT_STRING('c', "config", &config_filename,
			"config filename for test(s)"),
		OPT_END(),
	};

	argparse_init(&argparse, options, usage, 0);
	argparse_describe(&argparse, "\nRun tests using hl-thunk", NULL);
	argc = argparse_parse(&argparse, argc, argv);

	asic_name_for_testing = hltests_validate_device_name(asic);
	if (asic_name_for_testing == HLTHUNK_DEVICE_INVALID)
		exit(-1);

	if (list) {
		printf("\nList of tests:");
		printf("\n-----------------\n\n");
		for (int i = 0 ; i < num_tests ; i++)
			printf("%s\n", tests[i].name);
		printf("\n");
		exit(0);
	}

	if ((!parser_pciaddr) && (expected_device != HLTHUNK_DEVICE_INVALID) &&
				(asic_name_for_testing != expected_device)) {
		printf("Expected to run on device %s but detected device %s\n",
				asic_names[expected_device],
				asic_names[asic_name_for_testing]);
		exit(0);
	}

	if (test)
		cmocka_set_test_filter(test);
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

bool hltests_is_simulator(int fd)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);

	if (hdev->device_id == PCI_IDS_GOYA_SIMULATOR)
		return true;

	return false;
}

bool hltests_is_goya(int fd)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);

	if (hdev->device_id == PCI_IDS_GOYA_SIMULATOR ||
			hdev->device_id == PCI_IDS_GOYA)
		return true;

	return false;
}

void test_sm_pingpong_cmdq(void **state, bool is_tpc)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	struct hltests_cs_chunk restore_arr[1], execute_arr[3];
	struct hltests_pkt_info pkt_info;
	struct hltests_monitor_and_fence mon_and_fence_info;
	void *host_src, *host_dst, *engine_cmdq_cb, *engine_qman_cb,
		*restore_cb, *dmadown_cb, *dmaup_cb;
	uint64_t seq = 0, host_src_device_va, host_dst_device_va,
		device_data_addr,
		engine_cmdq_cb_sram_addr, engine_cmdq_cb_device_va,
		engine_qman_cb_sram_addr, engine_qman_cb_device_va;
	uint32_t engine_qid, dma_size, page_size, engine_cmdq_cb_size,
		engine_qman_cb_size, restore_cb_size, dmadown_cb_size,
		dmaup_cb_size;
	int rc, fd = tests_state->fd;

	memset(&pkt_info, 0, sizeof(pkt_info));

	/* SRAM MAP (base + ):
	 * - 0x1000               : data
	 * - 0x2000               : engine's internal CB (QMAN)
	 * - 0x3000               : engine's internal CB (CMDQ)
	 *
	 * Test Description:
	 * - First DMA QMAN transfers data from host to SRAM and then signals
	 *   SOB0.
	 * - Engine QMAN process CP_DMA packet and transfer internal CB to CMDQ.
	 * - Engine CMDQ fences on SOB0, processes NOP packet, and then signals
	 *   SOB8.
	 * - Second DMA QMAN fences on SOB8 and then transfers data from SRAM to
	 *   host.
	 * - Setup CB is used to clear SOB 0, 8 and to DMA the internal CBs to
	 *   SRAM.
	 */

	dma_size = 4;
	page_size = sysconf(_SC_PAGESIZE);
	assert_in_range(page_size, PAGE_SIZE_4KB, PAGE_SIZE_64KB);

	/* Set engine queue ID and SRAM addresses */
	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (is_tpc) {
		/* Find first available TPC */
		uint8_t tpc_id, tpc_cnt;

		tpc_cnt = hltests_get_tpc_cnt(fd, 0);
		for (tpc_id = 0;
			(!(hw_ip.tpc_enabled_mask & (0x1 << tpc_id))) &&
			(tpc_id < tpc_cnt);)
			tpc_id++;

		assert_in_range(tpc_id, 0, tpc_cnt - 1);
		engine_qid = hltests_get_tpc_qid(fd, DCORE0, tpc_id, STREAM0);
	} else {
		engine_qid = hltests_get_mme_qid(fd, DCORE0, 0, STREAM0);
	}

	device_data_addr = hw_ip.sram_base_address + 0x1000;
	engine_qman_cb_sram_addr = hw_ip.sram_base_address + 0x2000;
	engine_cmdq_cb_sram_addr = hw_ip.sram_base_address + 0x3000;

	/* Allocate two buffers on the host for data transfers */
	host_src = hltests_allocate_host_mem(fd, dma_size, false);
	assert_non_null(host_src);
	hltests_fill_rand_values(host_src, dma_size);
	host_src_device_va = hltests_get_device_va_for_host_ptr(fd, host_src);

	host_dst = hltests_allocate_host_mem(fd, dma_size, false);
	assert_non_null(host_dst);
	memset(host_dst, 0, dma_size);
	host_dst_device_va = hltests_get_device_va_for_host_ptr(fd, host_dst);

	/* Internal CB for engine CMDQ: fence on SOB0 + NOP + signal SOB8 */
	engine_cmdq_cb = hltests_create_cb(fd, page_size, false,
						engine_cmdq_cb_sram_addr);
	assert_ptr_not_equal(engine_cmdq_cb, NULL);
	engine_cmdq_cb_device_va = hltests_get_device_va_for_host_ptr(fd,
								engine_cmdq_cb);
	engine_cmdq_cb_size = 0;
	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.dcore_id = 0;
	mon_and_fence_info.queue_id = engine_qid;
	mon_and_fence_info.cmdq_fence = true;
	mon_and_fence_info.sob_id = 0;
	mon_and_fence_info.mon_id = 0;
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.target_val = 1;
	mon_and_fence_info.dec_val = 1;
	engine_cmdq_cb_size = hltests_add_monitor_and_fence(fd, engine_cmdq_cb,
							engine_cmdq_cb_size,
							&mon_and_fence_info);

	engine_cmdq_cb_size = hltests_add_nop_pkt(fd, engine_cmdq_cb,
							engine_cmdq_cb_size,
							EB_FALSE, MB_TRUE);
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.write_to_sob.sob_id = 8;
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_ADD;
	engine_cmdq_cb_size = hltests_add_write_to_sob_pkt(fd, engine_cmdq_cb,
							engine_cmdq_cb_size,
							&pkt_info);

	/* Internal CB for engine QMAN: CP_DMA */
	engine_qman_cb = hltests_create_cb(fd, page_size, false,
						engine_qman_cb_sram_addr);
	assert_ptr_not_equal(engine_qman_cb, NULL);
	engine_qman_cb_device_va = hltests_get_device_va_for_host_ptr(fd,
								engine_qman_cb);
	engine_qman_cb_size = 0;

	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.cp_dma.src_addr = engine_cmdq_cb_sram_addr;
	pkt_info.cp_dma.size = engine_cmdq_cb_size;
	engine_qman_cb_size = hltests_add_cp_dma_pkt(fd, engine_qman_cb,
						engine_qman_cb_size, &pkt_info);

	/* Setup CB: Clear SOB 0, 8 + DMA the internal CBs to SRAM */
	restore_cb =  hltests_create_cb(fd, page_size, true, 0);
	assert_ptr_not_equal(restore_cb, NULL);
	restore_cb_size = 0;

	hltests_clear_sobs(fd, DCORE0, 2);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.dma.src_addr = engine_cmdq_cb_device_va;
	pkt_info.dma.dst_addr = engine_cmdq_cb_sram_addr;
	pkt_info.dma.size = engine_cmdq_cb_size;
	pkt_info.dma.dma_dir = GOYA_DMA_HOST_TO_SRAM;
	restore_cb_size = hltests_add_dma_pkt(fd, restore_cb, restore_cb_size,
						&pkt_info);

	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.dma.src_addr = engine_qman_cb_device_va;
	pkt_info.dma.dst_addr = engine_qman_cb_sram_addr;
	pkt_info.dma.size = engine_qman_cb_size;
	pkt_info.dma.dma_dir = GOYA_DMA_HOST_TO_SRAM;
	restore_cb_size = hltests_add_dma_pkt(fd, restore_cb, restore_cb_size,
						&pkt_info);

	/* CB for first DMA QMAN:
	 * Transfer data from host to SRAM + signal SOB0.
	 */
	dmadown_cb = hltests_create_cb(fd, page_size, true, 0);
	assert_ptr_not_equal(dmadown_cb, NULL);
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
	pkt_info.write_to_sob.sob_id = 0;
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_ADD;
	dmadown_cb_size = hltests_add_write_to_sob_pkt(fd, dmadown_cb,
						dmadown_cb_size, &pkt_info);

	/* CB for second DMA QMAN:
	 * Fence on SOB8 + transfer data from SRAM to host.
	 */
	dmaup_cb = hltests_create_cb(fd, page_size, true, 0);
	assert_ptr_not_equal(dmaup_cb, NULL);
	dmaup_cb_size = 0;
	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.dcore_id = 0;
	mon_and_fence_info.queue_id = hltests_get_dma_up_qid(fd,
							DCORE0, STREAM0);
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = 8;
	mon_and_fence_info.mon_id = 1;
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.target_val = 1;
	mon_and_fence_info.dec_val = 1;
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
	restore_arr[0].queue_index = hltests_get_dma_down_qid(fd,
							DCORE0, STREAM0);

	execute_arr[0].cb_ptr = dmadown_cb;
	execute_arr[0].cb_size = dmadown_cb_size;
	execute_arr[0].queue_index = hltests_get_dma_down_qid(fd,
							DCORE0, STREAM0);

	execute_arr[1].cb_ptr = engine_qman_cb;
	execute_arr[1].cb_size = engine_qman_cb_size;
	execute_arr[1].queue_index = engine_qid;

	execute_arr[2].cb_ptr = dmaup_cb;
	execute_arr[2].cb_size = dmaup_cb_size;
	execute_arr[2].queue_index = hltests_get_dma_up_qid(fd,
							DCORE0, STREAM0);

	rc = hltests_submit_cs(fd, restore_arr, 1, execute_arr, 3, true, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	/* Compare host memories */
	rc = hltests_mem_compare(host_src, host_dst, dma_size);
	assert_int_equal(rc, 0);

	/* Cleanup */
	rc = hltests_destroy_cb(fd, engine_cmdq_cb);
	assert_int_equal(rc, 0);
	rc = hltests_destroy_cb(fd, engine_qman_cb);
	assert_int_equal(rc, 0);
	rc = hltests_destroy_cb(fd, restore_cb);
	assert_int_equal(rc, 0);
	rc = hltests_destroy_cb(fd, dmadown_cb);
	assert_int_equal(rc, 0);
	rc = hltests_destroy_cb(fd, dmaup_cb);
	assert_int_equal(rc, 0);

	rc = hltests_free_host_mem(fd, host_dst);
	assert_int_equal(rc, 0);
	rc = hltests_free_host_mem(fd, host_src);
	assert_int_equal(rc, 0);
}

void hltests_clear_sobs(int fd, enum hltests_dcore_id dcore_id,
						uint32_t num_of_sobs)
{
	struct hltests_pkt_info pkt_info;
	void *cb;
	uint32_t cb_offset = 0, i;

	cb = hltests_create_cb(fd,  MSG_LONG_SIZE * num_of_sobs, true, 0);
	assert_non_null(cb);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.write_to_sob.value = 0;
	pkt_info.write_to_sob.mode = SOB_SET;
	for (i = 0 ; i < num_of_sobs - 1 ; i++) {
		pkt_info.write_to_sob.sob_id = i;
		cb_offset = hltests_add_write_to_sob_pkt(fd, cb, cb_offset,
								&pkt_info);
	}
	/* only the last mb should be true */
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id = i;
	cb_offset = hltests_add_write_to_sob_pkt(fd, cb, cb_offset, &pkt_info);

	hltests_submit_and_wait_cs(fd, cb, cb_offset,
		hltests_get_dma_down_qid(fd, dcore_id, STREAM0),
		true, HL_WAIT_CS_STATUS_COMPLETED);

}
