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

static pthread_mutex_t table_lock = PTHREAD_MUTEX_INITIALIZER;
static void* dev_table;

int hlthunk_tests_init(void)
{
	if (!dev_table)
		dev_table = hlthunk_hash_create();

	if (!dev_table)
		return -ENOMEM;

	return 0;
}

void hlthunk_tests_fini(void)
{
	if (dev_table)
		hlthunk_hash_destroy(dev_table);
}

int hlthunk_tests_open(const char *busid)
{
	int fd, rc;
	struct hlthunk_tests_device *hdev = NULL;
	enum hl_pci_ids device_type;

	pthread_mutex_lock(&table_lock);

	fd = hlthunk_open(busid);
	if (fd < 0) {
		rc = fd;
		goto out_err;
	}

	if (hlthunk_hash_lookup(dev_table, fd, (void **) &hdev)) {
		/* not found, create new device */
		hdev = hlthunk_malloc(sizeof(struct hlthunk_tests_device));
		if (!hdev) {
			rc = -ENOMEM;
			goto close_device;
		}
		hdev->fd = fd;
		hlthunk_hash_insert(dev_table, hdev->fd, hdev);
	} else {
		/* found, just incr refcnt */
		atomic_inc(&hdev->refcnt);
		goto out;
	}

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

out:
	pthread_mutex_unlock(&table_lock);
	return fd;

remove_device:
	hlthunk_hash_delete(dev_table, hdev->fd);
	hlthunk_free(hdev);
close_device:
	hlthunk_close(fd);
out_err:
	pthread_mutex_unlock(&table_lock);
	return rc;
}

int hlthunk_tests_close(int fd)
{
	struct hlthunk_tests_device *hdev = NULL;

	if (hlthunk_hash_lookup(dev_table, fd, (void **) &hdev))
		return -ENODEV;

	if (!atomic_dec_and_test(&hdev->refcnt))
		return 0;

	hlthunk_close(hdev->fd);

	pthread_mutex_lock(&table_lock);
	hlthunk_hash_delete(dev_table, hdev->fd);
	pthread_mutex_unlock(&table_lock);

	hlthunk_free(hdev);

	return 0;
}

void *hlthunk_tests_mmap(int fd, size_t length, off_t offset)
{
	return mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
			offset);
}

int hlthunk_tests_munmap(void *addr, size_t length)
{
	return munmap(addr, length);
}
