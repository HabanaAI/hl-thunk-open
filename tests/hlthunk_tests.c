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

#include "khash.h"
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

static pthread_mutex_t table_lock = PTHREAD_MUTEX_INITIALIZER;
KHASH_MAP_INIT_INT(ptr, void*)
static khash_t(ptr) *dev_table;

static struct hlthunk_tests_device* get_hdev_from_fd(int fd)
{
	khint_t k;

	k = kh_get(ptr, dev_table, fd);
	if (k == kh_end(dev_table))
		return NULL;

	return kh_val(dev_table, k);
}

static int create_mem_map(struct hlthunk_tests_device *hdev)
{
	/*hdev->mem_table = hlthunk_hash_create();
	if (!hdev->mem_table)
		return -ENOMEM;
*/
	return 0;
}

static void destroy_mem_map(struct hlthunk_tests_device *hdev)
{
	/*if (hdev->mem_table)
		hlthunk_hash_destroy(dev_table);*/
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
	struct hlthunk_tests_device *hdev = NULL;
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

	rc = create_mem_map(hdev);
	if (rc)
		goto destroy_refcnt_lock;

	pthread_mutex_unlock(&table_lock);
	return fd;

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
	struct hlthunk_tests_device *hdev = NULL;
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

	destroy_mem_map(hdev);

	pthread_mutex_destroy(&hdev->refcnt_lock);

	hlthunk_close(hdev->fd);

	pthread_mutex_lock(&table_lock);
	k = kh_get(ptr, dev_table, fd);
	kh_del(ptr, dev_table, k);
	pthread_mutex_unlock(&table_lock);

	hlthunk_free(hdev);

	return 0;
}

void* hlthunk_tests_mmap(int fd, size_t length, off_t offset)
{
	return mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
			offset);
}

int hlthunk_tests_munmap(void *addr, size_t length)
{
	return munmap(addr, length);
}

static int debugfs_open(int fd)
{
	struct hlthunk_tests_device *hdev = NULL;
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
	struct hlthunk_tests_device *hdev = NULL;

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
	struct hlthunk_tests_device *hdev = NULL;
	char addr_str[64] = {0}, value[64] = {0};

	hdev = get_hdev_from_fd(fd);
	if (!hdev)
		return -1;

	sprintf(addr_str, "0x%lx", full_address);

	write(hdev->debugfs_addr_fd, addr_str, strlen(addr_str) + 1);
	pread(hdev->debugfs_data_fd, value, sizeof(value), 0);

	return strtoul(value, NULL, 16);
}

void hlthunk_tests_debugfs_write(int fd, uint64_t full_address, uint32_t val)
{
	struct hlthunk_tests_device *hdev = NULL;
	char addr_str[64] = {0}, val_str[64] = {0};

	hdev = get_hdev_from_fd(fd);
	if (!hdev)
		return;

	sprintf(addr_str, "0x%lx", full_address);
	sprintf(val_str, "0x%x", val);

	write(hdev->debugfs_addr_fd, addr_str, strlen(addr_str) + 1);
	write(hdev->debugfs_data_fd, val_str, strlen(val_str) + 1);
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

void *hlthunk_tests_allocate_host_mem(int fd, uint64_t size, bool huge)
{
	return NULL;
}

void *hlthunk_tests_allocate_device_mem(int fd, uint64_t size)
{
	return NULL;
}

void hlthunk_tests_free_host_mem(int fd, void *vaddr)
{

}

void hlthunk_tests_free_device_mem(int fd, void *vaddr)
{

}
