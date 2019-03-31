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

#include "hlthunk.h"
#include "khash.h"

#include <stdint.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <stdbool.h>

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#define WAIT_FOR_CS_DEFAULT_TIMEOUT	5000000 /* 5 sec */

#define DMA_1KB_INC_SRAM(func_name, state, size) \
	void func_name(void **state) { hltests_dma_test(state, false, size); }
#define DMA_1KB_INC_DRAM(func_name, state, size) \
	void func_name(void **state) { hltests_dma_test(state, true, size); }

KHASH_MAP_INIT_INT(ptr, void*)
KHASH_MAP_INIT_INT64(ptr64, void*)

/* Must be an exact copy of goya_dma_direction for the no mmu mode to work
 * This structure is relevant only for Goya. In Gaudi and above, we don't need
 * the user to hint us about the direction
 */
enum hltests_goya_dma_direction {
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

struct hltests_state {
	int fd;
	bool mmu;
};

struct hltests_device {
	const struct hltests_asic_funcs *asic_funcs;
	khash_t(ptr64) *mem_table_host;
	pthread_mutex_t mem_table_host_lock;
	khash_t(ptr64) *mem_table_device;
	pthread_mutex_t mem_table_device_lock;
	khash_t(ptr64) *cb_table;
	pthread_mutex_t cb_table_lock;
	void *priv;
	int fd;
	int refcnt;
	int debugfs_addr_fd;
	int debugfs_data_fd;
};

struct hltests_asic_funcs {
	uint32_t (*add_monitor_and_fence)(void *buffer, uint32_t buf_off,
					uint8_t dcore_id, uint8_t queue_id,
					bool cmdq_fence, uint32_t so_id,
					uint32_t mon_id, uint64_t mon_address);
	uint32_t (*add_nop_pkt)(void *buffer, uint32_t buf_off, bool eb,
				bool mb);
	uint32_t (*add_msg_long_pkt)(void *buffer, uint32_t buf_off, bool eb,
					bool mb, uint64_t address,
					uint32_t value);
	uint32_t (*add_msg_short_pkt)(void *buffer, uint32_t buf_off, bool eb,
					bool mb, uint8_t base, uint16_t address,
					uint32_t value);
	uint32_t (*add_arm_monitor_pkt)(void *buffer, uint32_t buf_off, bool eb,
					bool mb, uint16_t address,
					uint32_t value, uint8_t mon_mode,
					uint16_t sync_val, uint16_t sync_id);
	uint32_t (*add_write_to_sob_pkt)(void *buffer, uint32_t buf_off,
					bool eb, bool mb, uint16_t sob_id,
					uint16_t value, uint8_t mode);
	uint32_t (*add_set_sob_pkt)(void *buffer, uint32_t buf_off, bool eb,
					bool mb, uint8_t dcore_id,
					uint16_t sob_id, uint32_t value);
	uint32_t (*add_fence_pkt)(void *buffer, uint32_t buf_off, bool eb,
					bool mb, uint8_t dec_val,
					uint8_t gate_val, uint8_t fence_id);
	uint32_t (*add_dma_pkt)(void *buffer, uint32_t buf_off, bool eb,
				bool mb, uint64_t src_addr,
				uint64_t dst_addr, uint32_t size,
				enum hltests_goya_dma_direction dma_dir);
	uint32_t (*add_cp_dma_pkt)(void *buffer, uint32_t buf_off, bool eb,
					bool mb, uint64_t src_addr,
					uint32_t size);
	uint32_t (*get_dma_down_qid)(uint8_t dcore_id, uint8_t stream);
	uint32_t (*get_dma_up_qid)(uint8_t dcore_id, uint8_t stream);
	uint32_t (*get_dma_dram_to_sram_qid)(uint8_t dcore_id, uint8_t stream);
	uint32_t (*get_dma_sram_to_dram_qid)(uint8_t dcore_id, uint8_t stream);
	uint32_t (*get_tpc_qid)(uint8_t dcore_id, uint8_t tpc_id,
				uint8_t stream);
	uint32_t (*get_mme_qid)(uint8_t dcore_id, uint8_t mme_id,
				uint8_t stream);
	uint8_t (*get_tpc_cnt)(uint8_t dcore_id);
	void (*dram_pool_init)(struct hltests_device *hdev);
	void (*dram_pool_fini)(struct hltests_device *hdev);
	int (*dram_pool_alloc)(struct hltests_device *hdev, uint64_t size,
				uint64_t *return_addr);
	void (*dram_pool_free)(struct hltests_device *hdev, uint64_t addr,
				uint64_t size);
};

struct hltests_memory {
	union {
		uint64_t device_handle;
		void *host_ptr;
	};
	uint64_t device_virt_addr;
	uint64_t size;
	bool is_huge;
	bool is_host;
	bool is_pool;
};

struct hltests_cb {
	void *ptr;
	uint64_t cb_handle;
	uint32_t cb_size;
	bool external;
};

struct hltests_cs_chunk {
	void *cb_ptr;
	uint32_t cb_size;
	uint32_t queue_index;
};

void hltests_parser(int argc, const char **argv, const char * const* usage,
			enum hlthunk_device_name expected_device,
			const struct CMUnitTest * tests, int num_tests);
int hltests_init(void);
void hltests_fini(void);
int hltests_open(const char *busid);
int hltests_close(int fd);

enum hlthunk_device_name hltests_validate_device_name(const char *device_name);

void* hltests_cb_mmap(int fd, size_t len, off_t offset);
int hltests_cb_munmap(void *addr, size_t length);

int hltests_debugfs_open(int fd);
int hltests_debugfs_close(int fd);
uint32_t hltests_debugfs_read(int fd, uint64_t full_address);
void hltests_debugfs_write(int fd, uint64_t full_address, uint32_t val);

void* hltests_allocate_host_mem(int fd, uint64_t size, bool huge);
void* hltests_allocate_device_mem(int fd, uint64_t size);
int hltests_free_host_mem(int fd, void *vaddr);
int hltests_free_device_mem(int fd, void *vaddr);
uint64_t hltests_get_device_va_for_host_ptr(int fd, void *vaddr);

void* hltests_create_cb(int fd, uint32_t cb_size, bool is_external,
				uint64_t cb_internal_sram_address);
int hltests_destroy_cb(int fd, void *ptr);
uint32_t hltests_add_packet_to_cb(void *ptr, uint32_t offset, void *pkt,
					uint32_t pkt_size);

int hltests_submit_cs(int fd, struct hltests_cs_chunk *restore_arr,
				uint32_t restore_arr_size,
				struct hltests_cs_chunk *execute_arr,
				uint32_t execute_arr_size, bool force_restore,
				uint64_t *seq);

int hltests_setup(void **state);
int hltests_teardown(void **state);
int hltests_root_setup(void **state);
int hltests_root_teardown(void **state);

void hltests_fill_rand_values(void *ptr, uint32_t size);

int hltests_mem_compare(void *ptr1, void *ptr2, uint64_t size);

void hltests_dma_transfer(int fd, uint32_t queue_index, bool eb, bool mb,
				uint64_t src_addr, uint64_t dst_addr,
				uint32_t size,
				enum hltests_goya_dma_direction dma_dir);

int hltests_dma_test(void **state, bool is_ddr, uint64_t size);

int hltests_wait_for_cs(int fd, uint64_t seq, uint64_t timeout_us);
int hltests_wait_for_cs_until_not_busy(int fd, uint64_t seq);

void hltests_submit_and_wait_cs(int fd, void *cb_ptr, uint32_t cb_size,
				uint32_t queue_index, bool destroy_cb);

int hl_tests_ensure_device_operational(void **state);

/* Generic memory addresses pool */
void *hltests_mem_pool_init(uint64_t start_addr, uint64_t size, uint64_t order);
void hltests_mem_pool_fini(void *data);
int hltests_mem_pool_alloc(void *data, uint64_t size, uint64_t *addr);
void hltests_mem_pool_free(void *data, uint64_t addr, uint64_t size);

/* ASIC functions */
uint32_t hltests_add_nop_pkt(int fd, void *buffer, uint32_t buf_off,
					bool eb, bool mb);
uint32_t hltests_add_msg_long_pkt(int fd, void *buffer, uint32_t buf_off,
					bool eb, bool mb, uint64_t address,
					uint32_t value);
uint32_t hltests_add_msg_short_pkt(int fd, void *buffer, uint32_t buf_off,
					bool eb, bool mb, uint8_t base,
					uint16_t address, uint32_t value);
uint32_t hltests_add_arm_monitor_pkt(int fd, void *buffer,
					uint32_t buf_off, bool eb, bool mb,
					uint16_t address, uint32_t value,
					uint8_t mon_mode, uint16_t sync_val,
					uint16_t sync_id);

uint32_t hltests_add_write_to_sob_pkt(int fd, void *buffer, uint32_t buf_off,
					bool eb, bool mb, uint16_t sob_id,
					uint16_t value, uint8_t mode);

uint32_t hltests_add_set_sob_pkt(int fd, void *buffer, uint32_t buf_off,
					bool eb, bool mb, uint8_t dcore_id,
					uint16_t sob_id, uint32_t value);

uint32_t hltests_add_fence_pkt(int fd, void *buffer, uint32_t buf_off,
					bool eb, bool mb, uint8_t dec_val,
					uint8_t gate_val, uint8_t fence_id);

uint32_t hltests_add_dma_pkt(int fd, void *buffer, uint32_t buf_off,
				bool eb, bool mb, uint64_t src_addr,
				uint64_t dst_addr, uint32_t size,
				enum hltests_goya_dma_direction dma_dir);

uint32_t hltests_add_cp_dma_pkt(int fd, void *buffer, uint32_t buf_off,
				bool eb, bool mb, uint64_t src_addr,
				uint32_t size);

uint32_t hltests_add_monitor_and_fence(int fd, void *buffer, uint32_t buf_off,
					uint8_t dcore_id, uint8_t queue_id,
					bool cmdq_fence, uint32_t so_id,
					uint32_t mon_id, uint64_t mon_address);

uint32_t hltests_get_dma_down_qid(int fd, uint8_t dcore_id, uint8_t stream);
uint32_t hltests_get_dma_up_qid(int fd, uint8_t dcore_id, uint8_t stream);
uint32_t hltests_get_dma_dram_to_sram_qid(int fd, uint8_t dcore_id,
						uint8_t stream);
uint32_t hltests_get_dma_sram_to_dram_qid(int fd, uint8_t dcore_id,
						uint8_t stream);
uint32_t hltests_get_tpc_qid(int fd, uint8_t dcore_id, uint8_t tpc_id,
				uint8_t stream);
uint32_t hltests_get_mme_qid(int fd, uint8_t dcore_id, uint8_t mme_id,
				uint8_t stream);
uint8_t hltests_get_tpc_cnt(int fd, uint8_t dcore_id);

void goya_tests_set_asic_funcs(struct hltests_device *hdev);

#endif /* HLTHUNK_TESTS_H */
