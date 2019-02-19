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

#ifndef HLTHUNK_TESTS_H
#define HLTHUNK_TESTS_H

#include <stdint.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <stdbool.h>

struct hlthunk_tests_state {
	int fd;
};

struct hlthunk_tests_asic_funcs {
	uint32_t (*add_monitor_and_fence)(uint8_t *cb, uint8_t queue_id,
					bool cmdq_fence, uint32_t so_id,
					uint32_t mon_id, uint64_t mon_address);
};

struct hlthunk_tests_memory {
	uint64_t device_handle;
	bool is_huge;
	bool is_host;
};

struct hlthunk_tests_device {
	const struct hlthunk_tests_asic_funcs *asic_funcs;
	void* mem_table;
	pthread_mutex_t mem_table_lock;
	int fd;
	int refcnt;
	pthread_mutex_t refcnt_lock;
	int debugfs_addr_fd;
	int debugfs_data_fd;
};

int hlthunk_tests_init(void);
void hlthunk_tests_fini(void);
int hlthunk_tests_open(const char *busid);
int hlthunk_tests_close(int fd);

void* hlthunk_tests_mmap(int fd, size_t len, off_t offset);
int hlthunk_tests_munmap(void *addr, size_t length);

int hlthunk_tests_debugfs_open(int fd);
int hlthunk_tests_debugfs_close(int fd);
uint32_t hlthunk_tests_debugfs_read(int fd, uint64_t full_address);
void hlthunk_tests_debugfs_write(int fd, uint64_t full_address, uint32_t val);

int hlthunk_tests_setup(void **state);
int hlthunk_tests_teardown(void **state);
int hlthunk_tests_root_setup(void **state);
int hlthunk_tests_root_teardown(void **state);

void goya_tests_set_asic_funcs(struct hlthunk_tests_device *hdev);

#endif /* HLTHUNK_TESTS_H */
