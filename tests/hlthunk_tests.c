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
#include "hlthunk.h"
#include "specs/pci_ids.h"

#include <stdio.h>
#include <errno.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <linux/mman.h>

static pthread_mutex_t table_lock = PTHREAD_MUTEX_INITIALIZER;
static khash_t(ptr) *dev_table;

static struct hlthunk_tests_device* get_hdev_from_fd(int fd)
{
	khint_t k;

	k = kh_get(ptr, dev_table, fd);
	if (k == kh_end(dev_table))
		return NULL;

	return kh_val(dev_table, k);
}

static int create_mem_maps(struct hlthunk_tests_device *hdev)
{
	int rc;

	hdev->mem_table_host = kh_init(ptr64);
	if (!hdev->mem_table_host)
		return -ENOMEM;

	hdev->mem_table_device = kh_init(ptr64);
	if (!hdev->mem_table_device)
		goto delete_mem_hash;

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

static void destroy_mem_maps(struct hlthunk_tests_device *hdev)
{
	kh_destroy(ptr64, hdev->mem_table_host);
	kh_destroy(ptr64, hdev->mem_table_device);
	pthread_mutex_destroy(&hdev->mem_table_host_lock);
	pthread_mutex_destroy(&hdev->mem_table_device_lock);
}

static int create_cb_map(struct hlthunk_tests_device *hdev)
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

static void destroy_cb_map(struct hlthunk_tests_device *hdev)
{
	kh_destroy(ptr64, hdev->cb_table);
	pthread_mutex_destroy(&hdev->cb_table_lock);
}

int hlthunk_tests_init(void)
{
	if (!dev_table) {
		dev_table = kh_init(ptr);

		if (!dev_table)
			return -ENOMEM;
	}

	return 0;
}

void hlthunk_tests_fini(void)
{
	if (dev_table)
		kh_destroy(ptr, dev_table);
}

int hlthunk_tests_open(const char *busid)
{
	int fd, rc;
	struct hlthunk_tests_device *hdev;
	enum hl_pci_ids device_type;
	khint_t k;

	pthread_mutex_lock(&table_lock);

	rc = fd = hlthunk_open(busid);
	if (fd < 0)
		goto out;

	hdev = get_hdev_from_fd(fd);
	if (hdev) {
		/* found, just incr refcnt */
		hdev->refcnt++;
		goto out;
	}

	/* not found, create new device */
	hdev = hlthunk_malloc(sizeof(struct hlthunk_tests_device));
	if (!hdev) {
		rc = -ENOMEM;
		goto close_device;
	}
	hdev->fd = fd;
	k = kh_put(ptr, dev_table, fd, &rc);
	kh_val(dev_table, k) = hdev;

	device_type = hlthunk_get_device_type_from_fd(fd);

	switch (device_type) {
	case PCI_IDS_GOYA:
		goya_tests_set_asic_funcs(hdev);
		break;
	default:
		printf("Invalid device type %d\n", device_type);
		rc = -ENXIO;
		goto remove_device;
		break;
	}

	hdev->debugfs_addr_fd = -1;
	hdev->debugfs_data_fd = -1;

	rc = pthread_mutex_init(&hdev->refcnt_lock, NULL);
	if (rc)
		goto remove_device;

	rc = create_mem_maps(hdev);
	if (rc)
		goto destroy_refcnt_lock;

	rc = create_cb_map(hdev);
	if (rc)
		goto destroy_mem_maps;

	pthread_mutex_unlock(&table_lock);
	return fd;

destroy_mem_maps:
	destroy_mem_maps(hdev);
destroy_refcnt_lock:
	pthread_mutex_destroy(&hdev->refcnt_lock);
remove_device:
	kh_del(ptr, dev_table, k);
	hlthunk_free(hdev);
close_device:
	hlthunk_close(fd);
out:
	pthread_mutex_unlock(&table_lock);
	return rc;
}

int hlthunk_tests_close(int fd)
{
	struct hlthunk_tests_device *hdev;
	khint_t k;

	hdev = get_hdev_from_fd(fd);
	if (!hdev)
		return -ENODEV;

	pthread_mutex_lock(&hdev->refcnt_lock);
	if (--hdev->refcnt) {
		pthread_mutex_unlock(&hdev->refcnt_lock);
		return 0;
	}
	pthread_mutex_unlock(&hdev->refcnt_lock);

	destroy_mem_maps(hdev);

	destroy_cb_map(hdev);

	pthread_mutex_destroy(&hdev->refcnt_lock);

	hlthunk_close(hdev->fd);

	pthread_mutex_lock(&table_lock);
	k = kh_get(ptr, dev_table, fd);
	kh_del(ptr, dev_table, k);
	pthread_mutex_unlock(&table_lock);

	hlthunk_free(hdev);

	return 0;
}

void* hlthunk_tests_cb_mmap(int fd, size_t length, off_t offset)
{
	return mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
			offset);
}

int hlthunk_tests_cb_munmap(void *addr, size_t length)
{
	return munmap(addr, length);
}

static int debugfs_open(int fd)
{
	struct hlthunk_tests_device *hdev;
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
	struct hlthunk_tests_device *hdev;

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

uint32_t hlthunk_tests_debugfs_read(int fd, uint64_t full_address)
{
	struct hlthunk_tests_device *hdev;
	char addr_str[64] = {0}, value[64] = {0};
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

void hlthunk_tests_debugfs_write(int fd, uint64_t full_address, uint32_t val)
{
	struct hlthunk_tests_device *hdev;
	char addr_str[64] = {0}, val_str[64] = {0};
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

int hlthunk_tests_setup(void **state)
{
	struct hlthunk_tests_state *tests_state;
	int rc;

	tests_state = hlthunk_malloc(sizeof(struct hlthunk_tests_state));
	if (!tests_state)
		return -ENOMEM;

	rc = hlthunk_tests_init();
	if (rc) {
		printf("Failed to init tests library %d\n", rc);
		goto free_state;
	}

	tests_state->fd = hlthunk_tests_open(NULL);
	if (tests_state->fd < 0) {
		printf("Failed to open device %d\n", tests_state->fd);
		rc = tests_state->fd;
		goto fini_tests;
	}

	*state = tests_state;

	return 0;

fini_tests:
	hlthunk_tests_fini();
free_state:
	hlthunk_free(tests_state);
	return rc;
}

int hlthunk_tests_teardown(void **state)
{
	struct hlthunk_tests_state *tests_state =
					(struct hlthunk_tests_state *) *state;

	if (!tests_state)
		return -EINVAL;

	if (hlthunk_tests_close(tests_state->fd))
		printf("Problem in closing FD, ignoring...\n");

	hlthunk_tests_fini();

	hlthunk_free(*state);

	return 0;
}

int hlthunk_tests_root_setup(void **state)
{
	struct hlthunk_tests_state *tests_state;
	int rc;

	rc = hlthunk_tests_setup(state);
	if (rc)
		return rc;

	tests_state = (struct hlthunk_tests_state *) *state;
	return debugfs_open(tests_state->fd);
}

int hlthunk_tests_root_teardown(void **state)
{
	struct hlthunk_tests_state *tests_state =
					(struct hlthunk_tests_state *) *state;

	if (!tests_state)
		return -EINVAL;

	debugfs_close(tests_state->fd);

	return hlthunk_tests_teardown(state);
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
void* hlthunk_tests_allocate_host_mem(int fd, uint64_t size, bool huge)
{
	struct hlthunk_tests_device *hdev;
	struct hlthunk_tests_memory *mem;
	khint_t k;
	int rc;

	hdev = get_hdev_from_fd(fd);
	if (!hdev)
		return NULL;

	mem = hlthunk_malloc(sizeof(struct hlthunk_tests_memory));
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
 * @return pointer to the device memory. This pointer can NOT be derefenced
 * directly from the host. NULL is returned upon failure
 */
void* hlthunk_tests_allocate_device_mem(int fd, uint64_t size)
{
	struct hlthunk_tests_device *hdev;
	struct hlthunk_tests_memory *mem;
	khint_t k;
	int rc;

	hdev = get_hdev_from_fd(fd);
	if (!hdev)
		return NULL;

	mem = hlthunk_malloc(sizeof(struct hlthunk_tests_memory));
	if (!mem)
		return NULL;

	mem->is_host = false;
	mem->size = size;

	mem->device_handle = hlthunk_device_memory_alloc(fd, size, false,
							false);

	if (!mem->device_handle) {
		printf("Failed to allocate %lu bytes of device memory\n", size);
		goto free_mem_struct;
	}

	mem->device_virt_addr = hlthunk_device_memory_map(fd,
							mem->device_handle, 0);

	if (!mem->device_virt_addr) {
		printf("Failed to map device memory allocation\n");
		goto free_allocation;
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
 * hlthunk_tests_allocate_host_mem
 * @param fd file descriptor of the device that the host memory is mapped to
 * @param vaddr host pointer that points to the memory area
 * @return 0 for success, negative value for failure
 */
int hlthunk_tests_free_host_mem(int fd, void *vaddr)
{
	struct hlthunk_tests_device *hdev;
	struct hlthunk_tests_memory *mem;
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
 * hlthunk_tests_allocate_device_mem
 * @param fd file descriptor of the device that this memory belongs to
 * @param vaddr device VA that points to the memory area
 * @return 0 for success, negative value for failure
 */
int hlthunk_tests_free_device_mem(int fd, void *vaddr)
{
	struct hlthunk_tests_device *hdev;
	struct hlthunk_tests_memory *mem;
	khint_t k;
	int rc;

	hdev = get_hdev_from_fd(fd);
	if (!hdev)
		return -ENODEV;

	pthread_mutex_lock(&hdev->mem_table_device_lock);

	k = kh_get(ptr64, hdev->mem_table_device, (uintptr_t) vaddr);
	if (k == kh_end(hdev->mem_table_device)) {
		pthread_mutex_unlock(&hdev->mem_table_device_lock);
		return -EINVAL;
	}

	mem = kh_val(hdev->mem_table_device, k);
	kh_del(ptr64, hdev->mem_table_device, k);

	pthread_mutex_unlock(&hdev->mem_table_device_lock);

	rc = hlthunk_memory_unmap(fd, mem->device_virt_addr);
	if (rc) {
		printf("Failed to unmap device memory\n");
		return rc;
	}

	hlthunk_device_memory_free(fd, mem->device_handle);

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
uint64_t hlthunk_tests_get_device_va_for_host_ptr(int fd, void *vaddr)
{
	struct hlthunk_tests_device *hdev;
	struct hlthunk_tests_memory *mem;
	khint_t k;

	hdev = get_hdev_from_fd(fd);
	if (!hdev)
		return 0;

	k = kh_get(ptr64, hdev->mem_table_host, (uintptr_t) vaddr);
	if (k == kh_end(hdev->mem_table_host))
		return 0;

	mem = kh_val(hdev->mem_table_host, k);

	return mem->device_virt_addr;
}

void *hlthunk_tests_create_cb(int fd, uint32_t cb_size, bool is_external)
{
	struct hlthunk_tests_device *hdev;
	struct hlthunk_tests_cb *cb;
	int rc;
	khint_t k;

	hdev = get_hdev_from_fd(fd);
	if (!hdev)
		return NULL;

	cb = hlthunk_malloc(sizeof(*cb));
	if (!cb)
		return NULL;

	// TODO: Add handling of CB for internal queues.

	cb->cb_size = cb_size;
	rc = hlthunk_request_command_buffer(fd, cb->cb_size, &cb->cb_handle);
	if (rc)
		goto free_cb;

	cb->ptr = hlthunk_tests_cb_mmap(fd, cb->cb_size, cb->cb_handle);
	if (cb->ptr == MAP_FAILED)
		goto destroy_cb;

	cb->is_external = is_external;

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

int hlthunk_tests_destroy_cb(int fd, void *ptr)
{
	struct hlthunk_tests_device *hdev;
	struct hlthunk_tests_cb *cb;
	int rc;
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

	rc = hlthunk_tests_cb_munmap(cb->ptr, cb->cb_size);
	if (rc)
		return rc;

	rc = hlthunk_destroy_command_buffer(fd, cb->cb_handle);
	if (rc)
		return rc;

	hlthunk_free(cb);

	return 0;
}

uint32_t hlthunk_tests_add_packet_to_cb(void *ptr, uint32_t offset, void *pkt,
					uint32_t pkt_size)
{
	memcpy((uint8_t *) ptr + offset, pkt, pkt_size);

	return offset + pkt_size;
}

static int fill_cs_chunk(struct hlthunk_tests_device *hdev,
		struct hl_cs_chunk *chunk, void *cb_ptr, uint32_t cb_size,
		uint32_t queue_index)
{
	struct hlthunk_tests_cb *cb;
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

int hlthunk_tests_submit_cs(int fd,
		struct hlthunk_tests_cs_chunk *restore_arr,
		uint32_t restore_arr_size,
		struct hlthunk_tests_cs_chunk *execute_arr,
		uint32_t execute_arr_size,
		bool force_restore,
		uint64_t *seq)
{
	struct hlthunk_tests_device *hdev;
	struct hl_cs_chunk *chunks_restore = NULL, *chunks_execute = NULL;
	struct hlthunk_cs_in cs_in = {};
	struct hlthunk_cs_out cs_out = {};
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

	cs_in.chunks_restore = chunks_restore;
	cs_in.chunks_execute = chunks_execute;
	cs_in.num_chunks_restore = restore_arr_size;
	cs_in.num_chunks_execute = execute_arr_size;
	cs_in.flags = force_restore ? HL_CS_FLAGS_FORCE_RESTORE : 0x0;

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

int hlthunk_tests_wait_for_cs(int fd, uint64_t seq, uint64_t timeout_us)
{
	uint32_t status;
	int rc;

	rc = hlthunk_wait_for_cs(fd, seq, timeout_us, &status);
	if (rc)
		return rc;

	if (status != HL_WAIT_CS_STATUS_COMPLETED)
		return -EINVAL;

	return 0;
}

uint32_t hlthunk_tests_add_nop_pkt(int fd, void *buffer, uint32_t buf_off,
					bool eb, bool mb)
{
	const struct hlthunk_tests_asic_funcs *asic =
			get_hdev_from_fd(fd)->asic_funcs;

	return asic->add_nop_pkt(buffer, buf_off, eb, mb);
}

uint32_t hlthunk_tests_add_msg_long_pkt(int fd, void *buffer, uint32_t buf_off,
					bool eb, bool mb, uint64_t address,
					uint32_t value)
{
	const struct hlthunk_tests_asic_funcs *asic =
			get_hdev_from_fd(fd)->asic_funcs;

	return asic->add_msg_long_pkt(buffer, buf_off, eb, mb, address, value);
}
