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

#include "hlthunk_tests.h"
#include "specs/pci_ids.h"
#include "mersenne-twister.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

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

#include <setjmp.h>
#include <cmocka.h>

typedef struct {
	pthread_mutex_t lock;
	uint64_t start;
	uint32_t page_size;
	uint32_t pool_npages;
	uint8_t *pool;
} mem_pool_t;

static pthread_mutex_t table_lock = PTHREAD_MUTEX_INITIALIZER;
static khash_t(ptr) *dev_table;

static struct hltests_device* get_hdev_from_fd(int fd)
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

enum hlthunk_device_name hltests_get_device_name(void)
{
	char *device_name = getenv("HLTHUNK_DEVICE_NAME");
	if (!device_name)
		device_name = "Goya";

	if (!strcmp(device_name, "Goya"))
		return HLTHUNK_DEVICE_GOYA;

	printf("Invalid device name %s\n", device_name);

	return HLTHUNK_DEVICE_INVALID;
}

int hltests_open(const char *busid)
{
	int fd, rc;
	struct hltests_device *hdev;
	enum hl_pci_ids device_id;
	khint_t k;

	pthread_mutex_lock(&table_lock);

	rc = fd = hlthunk_open(hltests_get_device_name(), busid);
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

	device_id = hlthunk_get_device_id_from_fd(fd);

	switch (device_id) {
	case PCI_IDS_GOYA:
		goya_tests_set_asic_funcs(hdev);
		break;
	default:
		printf("Invalid device type %d\n", device_id);
		rc = -ENXIO;
		goto remove_device;
		break;
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

void* hltests_cb_mmap(int fd, size_t length, off_t offset)
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

	tests_state->fd = hltests_open(NULL);
	if (tests_state->fd < 0) {
		printf("Failed to open device %d\n", tests_state->fd);
		rc = tests_state->fd;
		goto fini_tests;
	}

	*state = tests_state;

	seed(time(NULL));

	return 0;

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

static void* allocate_huge_mem(uint64_t size)
{
	int mmapFlags = MAP_HUGE_2MB | MAP_HUGETLB | MAP_SHARED | MAP_ANONYMOUS;
	int prot = PROT_READ | PROT_WRITE;
	void *vaddr;

	vaddr = mmap(0, size, prot, mmapFlags, -1, 0);

	if (vaddr == MAP_FAILED) {
		printf("Failed to allocate %lu of host memory with huge pages\n",
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
void* hltests_allocate_host_mem(int fd, uint64_t size, bool huge)
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
 * @return pointer to the device memory. This pointer can NOT be dereferenced
 * directly from the host. NULL is returned upon failure
 */
void* hltests_allocate_device_mem(int fd, uint64_t size)
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

	if (!asic->dram_pool_alloc(hdev, size, &mem->device_virt_addr)) {
		mem->is_pool = true;
	} else {
		mem->is_pool = false;
		mem->device_handle = hlthunk_device_memory_alloc(fd, size,
								false,
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
void* hltests_create_cb(int fd, uint32_t cb_size, bool is_external,
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

int _hltests_wait_for_cs(int fd, uint64_t seq, uint64_t timeout_us,
				uint32_t expected_status)
{
	uint32_t status;
	int rc;

	rc = hlthunk_wait_for_cs(fd, seq, timeout_us, &status);
	if (rc)
		return rc;

	if (status != expected_status)
		return -EINVAL;

	return 0;
}

int hltests_wait_for_cs(int fd, uint64_t seq)
{
	return _hltests_wait_for_cs(fd, seq, WAIT_FOR_CS_DEFAULT_TIMEOUT,
					HL_WAIT_CS_STATUS_COMPLETED);
}

uint32_t hltests_add_nop_pkt(int fd, void *buffer, uint32_t buf_off,
					bool eb, bool mb)
{
	const struct hltests_asic_funcs *asic =
			get_hdev_from_fd(fd)->asic_funcs;

	return asic->add_nop_pkt(buffer, buf_off, eb, mb);
}

uint32_t hltests_add_msg_long_pkt(int fd, void *buffer, uint32_t buf_off,
					bool eb, bool mb, uint64_t address,
					uint32_t value)
{
	const struct hltests_asic_funcs *asic =
			get_hdev_from_fd(fd)->asic_funcs;

	return asic->add_msg_long_pkt(buffer, buf_off, eb, mb, address, value);
}

uint32_t hltests_add_msg_short_pkt(int fd, void *buffer, uint32_t buf_off,
					bool eb, bool mb, uint8_t base,
					uint16_t address, uint32_t value)
{
	const struct hltests_asic_funcs *asic =
			get_hdev_from_fd(fd)->asic_funcs;

	return asic->add_msg_short_pkt(buffer, buf_off, eb, mb, base, address,
					value);
}

uint32_t hltests_add_arm_monitor_pkt(int fd, void *buffer,
					uint32_t buf_off, bool eb, bool mb,
					uint16_t address, uint32_t value,
					uint8_t mon_mode, uint16_t sync_val,
					uint16_t sync_id)
{
	const struct hltests_asic_funcs *asic =
			get_hdev_from_fd(fd)->asic_funcs;

	return asic->add_arm_monitor_pkt(buffer, buf_off, eb, mb, address,
					value, mon_mode, sync_val, sync_id);
}

uint32_t hltests_add_write_to_sob_pkt(int fd, void *buffer, uint32_t buf_off,
					bool eb, bool mb, uint16_t sob_id,
					uint16_t value, uint8_t mode)
{
	const struct hltests_asic_funcs *asic =
			get_hdev_from_fd(fd)->asic_funcs;

	return asic->add_write_to_sob_pkt(buffer, buf_off, eb, mb, sob_id,
						value, mode);
}

uint32_t hltests_add_set_sob_pkt(int fd, void *buffer, uint32_t buf_off,
					bool eb, bool mb, uint8_t dcore_id,
					uint16_t sob_id, uint32_t value)
{
	const struct hltests_asic_funcs *asic =
			get_hdev_from_fd(fd)->asic_funcs;

	return asic->add_set_sob_pkt(buffer, buf_off, eb, mb, dcore_id, sob_id,
					value);
}

uint32_t hltests_add_fence_pkt(int fd, void *buffer, uint32_t buf_off,
					bool eb, bool mb, uint8_t dec_val,
					uint8_t gate_val, uint8_t fence_id)
{
	const struct hltests_asic_funcs *asic =
			get_hdev_from_fd(fd)->asic_funcs;

	return asic->add_fence_pkt(buffer, buf_off, eb, mb, dec_val, gate_val,
					fence_id);
}

uint32_t hltests_add_dma_pkt(int fd, void *buffer, uint32_t buf_off,
				bool eb, bool mb, uint64_t src_addr,
				uint64_t dst_addr, uint32_t size,
				enum hltests_goya_dma_direction dma_dir)
{
	const struct hltests_asic_funcs *asic =
			get_hdev_from_fd(fd)->asic_funcs;

	return asic->add_dma_pkt(buffer, buf_off, eb, mb, src_addr, dst_addr,
					size, dma_dir);
}

uint32_t hltests_add_cp_dma_pkt(int fd, void *buffer, uint32_t buf_off,
				bool eb, bool mb, uint64_t src_addr,
				uint32_t size)
{
	const struct hltests_asic_funcs *asic =
			get_hdev_from_fd(fd)->asic_funcs;

	return asic->add_cp_dma_pkt(buffer, buf_off, eb, mb, src_addr, size);
}

uint32_t hltests_add_monitor_and_fence(int fd, void *buffer, uint32_t buf_off,
					uint8_t dcore_id, uint8_t queue_id,
					bool cmdq_fence, uint32_t so_id,
					uint32_t mon_id, uint64_t mon_address)
{
	const struct hltests_asic_funcs *asic =
			get_hdev_from_fd(fd)->asic_funcs;

	return asic->add_monitor_and_fence(buffer, buf_off, dcore_id, queue_id,
						cmdq_fence, so_id, mon_id,
						mon_address);
}

uint32_t hltests_get_dma_down_qid(int fd, uint8_t dcore_id, uint8_t stream)
{
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_dma_down_qid(dcore_id, stream);
}

uint32_t hltests_get_dma_up_qid(int fd, uint8_t dcore_id, uint8_t stream)
{
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_dma_up_qid(dcore_id, stream);
}

uint32_t hltests_get_dma_dram_to_sram_qid(int fd, uint8_t dcore_id,
						uint8_t stream)
{
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_dma_dram_to_sram_qid(dcore_id, stream);
}

uint32_t hltests_get_dma_sram_to_dram_qid(int fd, uint8_t dcore_id,
						uint8_t stream)
{
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_dma_sram_to_dram_qid(dcore_id, stream);
}

uint32_t hltests_get_tpc_qid(int fd, uint8_t dcore_id, uint8_t tpc_id,
				uint8_t stream)
{
	const struct hltests_asic_funcs *asic =
				get_hdev_from_fd(fd)->asic_funcs;

	return asic->get_tpc_qid(dcore_id, tpc_id, stream);
}

uint32_t hltests_get_mme_qid(int fd, uint8_t dcore_id, uint8_t mme_id,
				uint8_t stream)
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

	for (i = 0 ; i < rounddown_aligned_size && err_cnt < 10 ;
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

void hltests_dma_transfer(int fd, uint32_t queue_index, bool eb, bool mb,
				uint64_t src_addr, uint64_t dst_addr,
				uint32_t size,
				enum hltests_goya_dma_direction dma_dir)
{
	uint32_t offset = 0;
	void *ptr;

	ptr = hltests_create_cb(fd, getpagesize(), true, 0);
	assert_ptr_not_equal(ptr, NULL);

	offset = hltests_add_dma_pkt(fd, ptr, offset, eb, mb, src_addr,
						dst_addr, size, dma_dir);

	hltests_submit_and_wait_cs(fd, ptr, offset, queue_index, true);
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

		device_addr = hltests_allocate_device_mem(fd, size);
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
	hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, 0, 0), 0, 1,
			host_src_addr, (uint64_t) (uintptr_t) device_addr,
			size, dma_dir_down);

	/* DMA: device->host */
	hltests_dma_transfer(fd, hltests_get_dma_up_qid(fd, 0, 0), 0, 1,
				(uint64_t) (uintptr_t) device_addr,
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
				uint32_t queue_index, bool destroy_cb)
{
	struct hltests_cs_chunk execute_arr[1];
	uint64_t seq = 0;
	int rc;

	execute_arr[0].cb_ptr = cb_ptr;
	execute_arr[0].cb_size = cb_size;
	execute_arr[0].queue_index = queue_index;

	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, 1, false, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_cs(fd, seq);
	assert_int_equal(rc, 0);

	if (destroy_cb) {
		rc = hltests_destroy_cb(fd, cb_ptr);
		assert_int_equal(rc, 0);
	}
}

static bool is_dev_idle_and_operational(int fd)
{
	enum hl_device_status dev_status;
	bool is_idle;

	is_idle = hlthunk_is_device_idle(fd);
	dev_status = hlthunk_get_device_status_info(fd);

	return (is_idle && dev_status == HL_DEVICE_STATUS_OPERATIONAL);
}

int hl_tests_ensure_device_operational(void **state)
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
	for (i = 0 ; i <= timeout_locked ; i++) {
		sleep(1);
		if (is_dev_idle_and_operational(fd))
			return 0;
	}

	/*if we got here it means that something is broken*/
	exit(-1);
}

void *hltests_mem_pool_init(uint64_t start_addr, uint64_t size, uint64_t order)
{
	mem_pool_t *mem_pool;
	uint64_t page_size;
	int rc;

	page_size = 1 << order;

	if (size < page_size) {
		printf("pool size should be at least one order size\n");
		return NULL;
	}

	mem_pool = calloc(1, sizeof(mem_pool_t));
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
	mem_pool_t *mem_pool = (mem_pool_t *) data;
	pthread_mutex_destroy(&mem_pool->lock);
	free(mem_pool->pool);
	free(mem_pool);
}

int hltests_mem_pool_alloc(void *data, uint64_t size, uint64_t *addr)
{
	mem_pool_t *mem_pool = (mem_pool_t *) data;
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
	mem_pool_t *mem_pool = (mem_pool_t *) data;
	uint32_t start_page = (addr - mem_pool->start) / mem_pool->page_size,
			npages = size / mem_pool->page_size, i;

	pthread_mutex_lock(&mem_pool->lock);

	for (i = start_page ; i < (start_page + npages) ; i++)
		mem_pool->pool[i] = 0;

	pthread_mutex_unlock(&mem_pool->lock);
}
