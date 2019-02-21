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

#include "khash.h"

#include <stdint.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <stdbool.h>

KHASH_MAP_INIT_INT(ptr, void*)
KHASH_MAP_INIT_INT64(ptr64, void*)

#define WAIT_FOR_CS_DEFAULT_TIMEOUT	1000000 /* 1 sec */

/* Must be an exact copy of goya_dma_direction for the no mmu mode to work
 * This structure is relevant only for Goya. In Gaudi and above, we don't need
 * the user to hint us about the direction
 */
enum hlthunk_tests_goya_dma_direction {
	GOYA_DMA_HOST_TO_DRAM,
	GOYA_DMA_HOST_TO_SRAM,
	GOYA_DMA_DRAM_TO_SRAM,
	GOYA_DMA_SRAM_TO_DRAM,
	GOYA_DMA_SRAM_TO_HOST,
	GOYA_DMA_DRAM_TO_HOST,
	GOYA_DMA_DRAM_TO_DRAM,
	GOYA_DMA_SRAM_TO_SRAM,
	GOYA_DMA_ENUM_MAX
};

struct hlthunk_tests_state {
	int fd;
};

struct hlthunk_tests_asic_funcs {
	uint32_t (*add_monitor_and_fence)(uint8_t *cb, uint8_t queue_id,
					bool cmdq_fence, uint32_t so_id,
					uint32_t mon_id, uint64_t mon_address);
	uint32_t (*add_nop_pkt)(void *buffer, uint32_t buf_off, bool eb,
				bool mb);
	uint32_t (*add_msg_long_pkt)(void *buffer, uint32_t buf_off, bool eb,
					bool mb, uint64_t address,
					uint32_t value);
	uint32_t (*add_msg_short_pkt)(void *buffer, uint32_t buf_off, bool eb,
					bool mb, uint16_t address,
					uint32_t value);
	uint32_t (*add_fence_pkt)(void *buffer, uint32_t buf_off, bool eb,
					bool mb, uint8_t dec_val,
					uint8_t gate_val, uint8_t fence_id);
	uint32_t (*add_dma_pkt)(void *buffer, uint32_t buf_off, bool eb,
				bool mb, uint64_t src_addr,
				uint64_t dst_addr, uint32_t size,
				enum hlthunk_tests_goya_dma_direction dma_dir);
};

struct hlthunk_tests_memory {
	union {
		uint64_t device_handle;
		void *host_ptr;
	};
	uint64_t device_virt_addr;
	uint64_t size;
	bool is_huge;
	bool is_host;
};

struct hlthunk_tests_cb {
	void *ptr;
	uint64_t cb_handle;
	uint32_t cb_size;
	bool is_external;
};

struct hlthunk_tests_cs_chunk {
	void *cb_ptr;
	uint32_t cb_size;
	uint32_t queue_index;
};

struct hlthunk_tests_device {
	const struct hlthunk_tests_asic_funcs *asic_funcs;
	khash_t(ptr64) *mem_table_host;
	pthread_mutex_t mem_table_host_lock;
	khash_t(ptr64) *mem_table_device;
	pthread_mutex_t mem_table_device_lock;
	khash_t(ptr64) *cb_table;
	pthread_mutex_t cb_table_lock;
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

void* hlthunk_tests_cb_mmap(int fd, size_t len, off_t offset);
int hlthunk_tests_cb_munmap(void *addr, size_t length);

int hlthunk_tests_debugfs_open(int fd);
int hlthunk_tests_debugfs_close(int fd);
uint32_t hlthunk_tests_debugfs_read(int fd, uint64_t full_address);
void hlthunk_tests_debugfs_write(int fd, uint64_t full_address, uint32_t val);

void* hlthunk_tests_allocate_host_mem(int fd, uint64_t size, bool huge);
void* hlthunk_tests_allocate_device_mem(int fd, uint64_t size);
int hlthunk_tests_free_host_mem(int fd, void *vaddr);
int hlthunk_tests_free_device_mem(int fd, void *vaddr);
uint64_t hlthunk_tests_get_device_va_for_host_ptr(int fd, void *vaddr);

void *hlthunk_tests_create_cb(int fd, uint32_t cb_size, bool is_external);
int hlthunk_tests_destroy_cb(int fd, void *ptr);
uint32_t hlthunk_tests_add_packet_to_cb(void *ptr, uint32_t offset, void *pkt,
					uint32_t pkt_size);

uint32_t hlthunk_tests_add_nop_pkt(int fd, void *buffer, uint32_t buf_off,
					bool eb, bool mb);
uint32_t hlthunk_tests_add_msg_long_pkt(int fd, void *buffer, uint32_t buf_off,
					bool eb, bool mb, uint64_t address,
					uint32_t value);
uint32_t hlthunk_tests_add_msg_short_pkt(int fd, void *buffer, uint32_t buf_off,
					bool eb, bool mb, uint16_t address,
					uint32_t value);
uint32_t hlthunk_tests_add_fence_pkt(int fd, void *buffer, uint32_t buf_off,
					bool eb, bool mb, uint8_t dec_val,
					uint8_t gate_val, uint8_t fence_id);

uint32_t hlthunk_tests_add_dma_pkt(int fd, void *buffer, uint32_t buf_off,
				bool eb, bool mb, uint64_t src_addr,
				uint64_t dst_addr, uint32_t size,
				enum hlthunk_tests_goya_dma_direction dma_dir);

int hlthunk_tests_submit_cs(int fd, struct hlthunk_tests_cs_chunk *restore_arr,
				uint32_t restore_arr_size,
				struct hlthunk_tests_cs_chunk *execute_arr,
				uint32_t execute_arr_size, bool force_restore,
				uint64_t *seq);

int hlthunk_tests_wait_for_cs(int fd, uint64_t seq, uint64_t timeout_us);

int hlthunk_tests_setup(void **state);
int hlthunk_tests_teardown(void **state);
int hlthunk_tests_root_setup(void **state);
int hlthunk_tests_root_teardown(void **state);

void hlthunk_tests_fill_rand_values(void *ptr, uint32_t size);

void goya_tests_set_asic_funcs(struct hlthunk_tests_device *hdev);

#endif /* HLTHUNK_TESTS_H */
