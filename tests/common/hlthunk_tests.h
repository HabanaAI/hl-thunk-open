/* SPDX-License-Identifier: MIT
 *
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 *
 */

#ifndef HLTHUNK_TESTS_H
#define HLTHUNK_TESTS_H

#include "uapi/hlthunk.h"
#include "khash.h"
#include "specs/common/pci_ids.h"

#include <stdint.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <stdbool.h>

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#define ARRAY_SIZE(arr)			(sizeof(arr) / sizeof((arr)[0]))

#define WAIT_FOR_CS_DEFAULT_TIMEOUT	5000000 /* 5 sec */

#define SZ_1K				0x00000400
#define SZ_2K				0x00000800
#define SZ_4K				0x00001000
#define SZ_8K				0x00002000
#define SZ_16K				0x00004000
#define SZ_32K				0x00008000
#define SZ_64K				0x00010000
#define SZ_128K				0x00020000
#define SZ_256K				0x00040000
#define SZ_512K				0x00080000

#define SZ_1M				0x00100000
#define SZ_2M				0x00200000
#define SZ_4M				0x00400000
#define SZ_8M				0x00800000
#define SZ_16M				0x01000000
#define SZ_32M				0x02000000
#define SZ_64M				0x04000000
#define SZ_128M				0x08000000
#define SZ_256M				0x10000000
#define SZ_512M				0x20000000

#define SZ_1G				0x40000000
#define SZ_2G				0x80000000

#define SZ_4G				0x100000000ULL
#define SZ_8G				0x200000000ULL
#define SZ_16G				0x400000000ULL
#define SZ_32G				0x800000000ULL

#define PAGE_SHIFT_4KB			12
#define PAGE_SHIFT_2MB			21
#define PAGE_SHIFT_16MB			24

#define DMA_TEST_INC_SRAM(func_name, state, size) \
	void func_name(void **state) { hltests_dma_test(state, false, size); }
#define DMA_TEST_INC_DRAM(func_name, state, size) \
	void func_name(void **state) { hltests_dma_test(state, true, size); }
#define DMA_TEST_INC_DRAM_FRAG(func_name, state, size) \
	void func_name(void **state) \
	{ hltests_dma_dram_frag_mem_test(state, size); }
#define DMA_TEST_INC_DRAM_HIGH(func_name, state, size) \
	void func_name(void **state) \
	{ hltests_dma_dram_high_mem_test(state, size); }
#define RREG32(full_address) \
		hltests_debugfs_read(tests_state->debugfs.addr_fd, \
			tests_state->debugfs.data32_fd, full_address)
#define WREG32(full_address, val) \
		hltests_debugfs_write(tests_state->debugfs.addr_fd, \
			tests_state->debugfs.data32_fd, full_address, val)
#define RREG64(full_address) \
		hltests_debugfs_read64(tests_state->debugfs.addr_fd, \
			tests_state->debugfs.data64_fd, full_address)
#define WREG64(full_address, val) \
		hltests_debugfs_write64(tests_state->debugfs.addr_fd, \
			tests_state->debugfs.data64_fd, full_address, val)

#define PLDM_MAX_DMA_SIZE_FOR_TESTING SZ_1M

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

/* Should be removed when a more appropriate enum is defined in habanalabs.h */
enum hltests_dcore_separation_mode {
	DCORE_MODE_FULL_CHIP,
	DCORE_MODE_ENUM_MAX
};

enum hltests_eb {
	EB_FALSE = 0,
	EB_TRUE
};

enum hltests_mb {
	MB_FALSE = 0,
	MB_TRUE
};

enum mon_mode {
	GREATER_OR_EQUAL = 0,
	EQUAL,
};

enum hl_tests_write_to_sob_mod {
	SOB_SET = 0,
	SOB_ADD
};

enum hl_tests_size_desc {
	ENTRY_SIZE_16B = 0,
	ENTRY_SIZE_32B
};

enum hl_tests_load_dst {
	DST_PREDICATES = 0,
	DST_SCALARS
};

enum hl_tests_predicates_map {
	PMAP_NON_CONSECUTIVE = 0,
	PMAP_CONSECUTIVE
};

enum hl_tests_exe_type {
	ETYPE_ALL_OR_LOWER_RF = 0,
	ETYPE_UPPER_RF
};

enum hltests_stream_id {
	STREAM0 = 0,
	STREAM1,
	STREAM2,
	STREAM3,
	NUM_OF_STREAMS
};

enum hltests_is_external {
	INTERNAL = 0,
	EXTERNAL
};

enum hltests_destroy_cb {
	DESTROY_CB_FALSE = 0,
	DESTROY_CB_TRUE
};

enum hltests_huge {
	NOT_HUGE = 0,
	HUGE
};

enum hltests_contiguous {
	NOT_CONTIGUOUS = 0,
	CONTIGUOUS
};

enum hltests_dma_perf_test_results {
	DMA_PERF_HOST2DRAM,
	DMA_PERF_HOST2SRAM,
	DMA_PERF_DRAM2SRAM_SINGLE_CH,
	DMA_PERF_SRAM2DRAM_SINGLE_CH,
	DMA_PERF_DRAM2DRAM_SINGLE_CH,
	DMA_PERF_DRAM2SRAM_MULTI_CH,
	DMA_PERF_SRAM2DRAM_MULTI_CH,
	DMA_PERF_DRAM2DRAM_MULTI_CH,
	DMA_PERF_SRAM_DRAM_BIDIR_FULL_CH,
	DMA_PERF_DRAM2SRAM_5_CH,
	DMA_PERF_SRAM2HOST,
	DMA_PERF_DRAM2HOST,
	DMA_PERF_HOST_SRAM_BIDIR,
	DMA_PERF_HOST_DRAM_BIDIR,
	DMA_PERF_RESULTS_MAX
};

struct hltests_debugfs {
	int addr_fd;
	int data32_fd;
	int data64_fd;
	int clk_gate_fd;
	char clk_gate_val[32];
};

struct hltests_device {
	const struct hltests_asic_funcs *asic_funcs;

	khash_t(ptr64) * mem_table_host;

	pthread_mutex_t mem_table_host_lock;

	khash_t(ptr64) * mem_table_device;

	pthread_mutex_t mem_table_device_lock;

	khash_t(ptr64) * cb_table;

	pthread_mutex_t cb_table_lock;
	void *priv;
	int fd;
	int refcnt;
	enum hl_pci_ids device_id;
};

struct hltests_state {
	double perf_outcomes[DMA_PERF_RESULTS_MAX];
	struct hltests_debugfs debugfs;
	int fd;
	int imp_fd;
	bool mme;
	bool mmu;
	bool security;
	enum hlthunk_device_name asic_type;
};

struct hltests_pkt_info {

	enum hltests_eb eb;
	enum hltests_mb mb;
	uint8_t pred;
	union {
		struct {
			uint32_t value;
			uint16_t reg_addr;
		} wreg32;
		struct {
			uint8_t priority;
			bool release;
		} arb_point;
		struct {
			uint64_t address;
			uint32_t value;
		} msg_long;
		struct {
			uint8_t base;
			uint16_t address;
			uint32_t value;
		} msg_short;
		struct {
			uint16_t address;
			enum mon_mode mon_mode;
			uint16_t sob_val;
			uint16_t sob_id;
		} arm_monitor;
		struct {
			uint16_t sob_id;
			uint16_t value;
			enum hl_tests_write_to_sob_mod mode;
		} write_to_sob;
		struct {
			uint8_t dec_val;
			uint8_t gate_val;
			uint8_t fence_id;
		} fence;
		struct {
			uint64_t src_addr;
			uint64_t dst_addr;
			uint32_t size;
			enum hltests_goya_dma_direction dma_dir;
			bool memset;
		} dma;
		struct {
			uint64_t src_addr;
			uint32_t size;
			uint8_t upper_cp;
		} cp_dma;
		struct {
			uint64_t src_addr;
			uint8_t load;
			uint8_t exe;
			enum hl_tests_load_dst load_dst;
			enum hl_tests_predicates_map pred_map;
			enum hl_tests_exe_type exe_type;
		} load_and_exe;
	};
};

struct hltests_monitor_and_fence {
	uint64_t mon_address;
	uint32_t mon_payload;
	bool cmdq_fence;
	bool dec_fence; /* decrement the fence once it reaches the gate value */
	bool no_fence; /* true to avoid adding the fence packet */
	uint16_t sob_id;
	uint16_t mon_id;
	uint16_t sob_val;
	uint8_t queue_id;
};

enum hltests_arb {
	ARB_PRIORITY = 0,
	ARB_WRR
};

struct hltests_arb_info {
	enum hltests_arb arb;
	union {
		uint32_t weight[NUM_OF_STREAMS];
		uint32_t priority[NUM_OF_STREAMS];
	};
	uint32_t arb_mst_quiet_val;
};

struct hltests_cs_chunk {
	void *cb_ptr;
	uint32_t cb_size;
	uint32_t queue_index;
};

struct hltests_asic_funcs {
	uint32_t (*add_arb_en_pkt)(void *buffer, uint32_t buf_off,
			struct hltests_pkt_info *pkt_info,
			struct hltests_arb_info *arb_info,
			uint32_t queue_id, bool enable);
	uint32_t (*add_monitor_and_fence)(
			enum hltests_dcore_separation_mode dcore_sep_mode,
			void *buffer, uint32_t buf_off,
			struct hltests_monitor_and_fence *mon_and_fence);
	uint32_t (*add_nop_pkt)(void *buffer, uint32_t buf_off, bool eb,
				bool mb);
	uint32_t (*add_wreg32_pkt)(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info);
	uint32_t (*add_arb_point_pkt)(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info);
	uint32_t (*add_msg_long_pkt)(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info);
	uint32_t (*add_msg_short_pkt)(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info);
	uint32_t (*add_arm_monitor_pkt)(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info);
	uint32_t (*add_write_to_sob_pkt)(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info);
	uint32_t (*add_fence_pkt)(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info);
	uint32_t (*add_dma_pkt)(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info);
	uint32_t (*add_cp_dma_pkt)(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info);
	uint32_t (*add_load_and_exe_pkt)(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info);
	uint32_t (*get_dma_down_qid)(
			enum hltests_dcore_separation_mode dcore_sep_mode,
			enum hltests_stream_id stream);
	uint32_t (*get_dma_up_qid)(
			enum hltests_dcore_separation_mode dcore_sep_mode,
			enum hltests_stream_id stream);
	uint32_t (*get_ddma_qid)(
			enum hltests_dcore_separation_mode dcore_sep_mode,
			int dma_ch,
			enum hltests_stream_id stream);
	uint8_t (*get_ddma_cnt)(
			enum hltests_dcore_separation_mode dcore_sep_mode);
	uint32_t (*get_tpc_qid)(
			enum hltests_dcore_separation_mode dcore_sep_mode,
			uint8_t tpc_id, enum hltests_stream_id stream);
	uint32_t (*get_mme_qid)(
			enum hltests_dcore_separation_mode dcore_sep_mode,
			uint8_t mme_id,	enum hltests_stream_id stream);
	uint8_t (*get_tpc_cnt)(
			enum hltests_dcore_separation_mode dcore_sep_mode);
	uint8_t (*get_mme_cnt)(
			enum hltests_dcore_separation_mode dcore_sep_mode);
	uint16_t (*get_first_avail_sob)(
			enum hltests_dcore_separation_mode dcore_sep_mode);
	uint16_t (*get_first_avail_mon)(
			enum hltests_dcore_separation_mode dcore_sep_mode);
	void (*dram_pool_init)(struct hltests_device *hdev);
	void (*dram_pool_fini)(struct hltests_device *hdev);
	int (*dram_pool_alloc)(struct hltests_device *hdev, uint64_t size,
				uint64_t *return_addr);
	void (*dram_pool_free)(struct hltests_device *hdev, uint64_t addr,
				uint64_t size);
	int (*submit_cs)(int fd, struct hltests_cs_chunk *restore_arr,
				uint32_t restore_arr_size,
				struct hltests_cs_chunk *execute_arr,
				uint32_t execute_arr_size,
				uint32_t flags, uint64_t *seq);
	int (*wait_for_cs)(int fd, uint64_t seq, uint64_t timeout_us);
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

struct mem_pool {
	pthread_mutex_t lock;
	uint64_t start;
	uint32_t page_size;
	uint32_t pool_npages;
	uint8_t *pool;
};

struct hltests_module_params_info {
	uint64_t tpc_mask;
	uint32_t gaudi_huge_page_optimization;
	uint32_t timeout_locked;
	uint32_t reset_on_lockup;
	uint32_t pldm;
	uint32_t mmu_enable;
	uint32_t clock_gating;
	uint32_t mme_enable;
	uint32_t dram_enable;
	uint32_t cpu_enable;
	uint32_t reset_pcilink;
	uint32_t config_pll;
	uint32_t cpu_queues_enable;
	uint32_t fw_loading;
	uint32_t heartbeat;
	uint32_t axi_drain;
	uint32_t security_enable;
	uint32_t sram_scrambler_enable;
	uint32_t dram_scrambler_enable;
	uint32_t dram_size_ratio;
	uint32_t hbm_ecc_enable;
	uint32_t reserved;
	uint32_t hard_reset_on_fw_events;
	uint32_t fw_loading_ext;
};

void hltests_parser(int argc, const char **argv, const char * const* usage,
			enum hlthunk_device_name expected_device,
			const struct CMUnitTest * const tests, int num_tests);
const char *hltests_get_parser_pciaddr(void);
const char *hltests_get_config_filename(void);
int hltests_get_parser_run_disabled_tests(void);
int hltests_is_legacy_mode_enabled(void);
bool hltests_is_simulator(int fd);
bool hltests_is_goya(int fd);
bool hltests_is_gaudi(int fd);
bool hltests_is_pldm(int fd);

int hltests_run_group_tests(const char *group_name,
				const struct CMUnitTest * const tests,
				const size_t num_tests,
				CMFixtureFunction group_setup,
				CMFixtureFunction group_teardown);

int hltests_open(const char *busid);
int hltests_close(int fd);

void *hltests_cb_mmap(int fd, size_t len, off_t offset);
int hltests_cb_munmap(void *addr, size_t length);

int hltests_debugfs_open(int fd);
int hltests_debugfs_close(int fd);

uint32_t hltests_debugfs_read(int addr_fd, int data_fd, uint64_t full_address);
void hltests_debugfs_write(int addr_fd, int data_fd, uint64_t full_address,
				uint32_t val);
uint64_t hltests_debugfs_read64(int addr_fd, int data_fd, uint64_t full_address);
void hltests_debugfs_write64(int addr_fd, int data_fd, uint64_t full_address,
				uint64_t val);

void *hltests_allocate_host_mem(int fd, uint64_t size, enum hltests_huge huge);
void *hltests_allocate_device_mem(int fd, uint64_t size,
				enum hltests_contiguous contiguous);
int hltests_free_host_mem(int fd, void *vaddr);
int hltests_free_device_mem(int fd, void *vaddr);
uint64_t hltests_get_device_va_for_host_ptr(int fd, void *vaddr);

void *hltests_create_cb(int fd, uint32_t cb_size,
				enum hltests_is_external is_external,
				uint64_t cb_internal_sram_address);
int hltests_destroy_cb(int fd, void *ptr);
uint32_t hltests_add_packet_to_cb(void *ptr, uint32_t offset, void *pkt,
					uint32_t pkt_size);

int hltests_submit_cs(int fd, struct hltests_cs_chunk *restore_arr,
				uint32_t restore_arr_size,
				struct hltests_cs_chunk *execute_arr,
				uint32_t execute_arr_size,
				uint32_t flags,
				uint64_t *seq);
int hltests_submit_legacy_cs(int fd, struct hltests_cs_chunk *restore_arr,
				uint32_t restore_arr_size,
				struct hltests_cs_chunk *execute_arr,
				uint32_t execute_arr_size,
				uint32_t flags,
				uint64_t *seq);
int hltests_submit_staged_cs(int fd, struct hltests_cs_chunk *restore_arr,
				uint32_t restore_arr_size,
				struct hltests_cs_chunk *execute_arr,
				uint32_t execute_arr_size,
				uint32_t flags,
				uint64_t staged_cs_seq,
				uint64_t *seq);
int hltests_wait_for_legacy_cs(int fd, uint64_t seq, uint64_t timeout_us);

int hltests_setup(void **state);
int hltests_teardown(void **state);
int hltests_root_setup(void **state);
int hltests_root_teardown(void **state);
int hltests_root_debug_setup(void **state);
int hltests_root_debug_teardown(void **state);

int hltests_get_module_params_info(int fd,
				struct hltests_module_params_info *info);

uint32_t hltests_rand_u32(void);
void hltests_fill_rand_values(void *ptr, uint32_t size);
void hltests_fill_seq_values(void *ptr, uint32_t size);

int hltests_mem_compare_with_stop(void *ptr1, void *ptr2, uint64_t size, bool
			stop_on_err);
int hltests_mem_compare(void *ptr1, void *ptr2, uint64_t size);

void hltests_dma_transfer(int fd, uint32_t queue_index, enum hltests_eb eb,
				enum hltests_mb mb,
				uint64_t src_addr, uint64_t dst_addr,
				uint32_t size,
				enum hltests_goya_dma_direction dma_dir);

int hltests_dma_test(void **state, bool is_ddr, uint64_t size);

int hltests_wait_for_cs(int fd, uint64_t seq, uint64_t timeout_us);
int hltests_wait_for_cs_until_not_busy(int fd, uint64_t seq);

void hltests_submit_and_wait_cs(int fd, void *cb_ptr, uint32_t cb_size,
				uint32_t queue_index,
				enum hltests_destroy_cb destroy_cb,
				int expected_val);

void hltests_dma_dram_frag_mem_test(void **state, uint64_t size);

void hltests_dma_dram_high_mem_test(void **state, uint64_t size);

int hltests_ensure_device_operational(void **state);

void test_sm_pingpong_common_cp(void **state, bool is_tpc,
				bool common_cb_in_host, uint8_t tpc_id);

void hltests_clear_sobs(int fd, uint16_t num_of_sobs);

/* Generic memory addresses pool */
void *hltests_mem_pool_init(uint64_t start_addr, uint64_t size, uint8_t order);
void hltests_mem_pool_fini(void *data);
int hltests_mem_pool_alloc(void *data, uint64_t size, uint64_t *addr);
void hltests_mem_pool_free(void *data, uint64_t addr, uint64_t size);

/* ASIC functions */
uint32_t hltests_add_nop_pkt(int fd, void *buffer, uint32_t buf_off,
				enum hltests_eb eb, enum hltests_mb mb);

uint32_t hltests_add_wreg32_pkt(int fd, void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info);

uint32_t hltests_add_arb_point_pkt(int fd, void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info);

uint32_t hltests_add_msg_long_pkt(int fd, void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info);

uint32_t hltests_add_msg_short_pkt(int fd, void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info);

uint32_t hltests_add_arm_monitor_pkt(int fd, void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info);

uint32_t hltests_add_write_to_sob_pkt(int fd, void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info);

uint32_t hltests_add_fence_pkt(int fd, void *buffer, uint32_t buf_off,
				struct hltests_pkt_info *pkt_info);

uint32_t hltests_add_dma_pkt(int fd, void *buffer, uint32_t buf_off,
				struct hltests_pkt_info *pkt_info);

uint32_t hltests_add_cp_dma_pkt(int fd, void *buffer, uint32_t buf_off,
				struct hltests_pkt_info *pkt_info);

uint32_t hltests_add_load_and_exe_pkt(int fd, void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info);

uint32_t hltests_add_monitor_and_fence(int fd, void *buffer, uint32_t buf_off,
		struct hltests_monitor_and_fence *mon_and_fence_info);
uint32_t hltests_add_arb_en_pkt(int fd, void *buffer, uint32_t buf_off,
		struct hltests_pkt_info *pkt_info,
		struct hltests_arb_info *arb_info,
		uint32_t queue_id, bool enable);
uint32_t hltests_get_dma_down_qid(int fd, enum hltests_stream_id stream);
uint32_t hltests_get_dma_up_qid(int fd, enum hltests_stream_id stream);
uint32_t hltests_get_ddma_qid(int fd, int dma_ch,
					enum hltests_stream_id stream);
uint8_t hltests_get_ddma_cnt(int fd);
uint32_t hltests_get_tpc_qid(int fd, uint8_t tpc_id,
				enum hltests_stream_id stream);
uint32_t hltests_get_mme_qid(int fd, uint8_t mme_id,
				enum hltests_stream_id stream);
uint8_t hltests_get_tpc_cnt(int fd);
uint8_t hltests_get_mme_cnt(int fd);
uint16_t hltests_get_first_avail_sob(int fd);
uint16_t hltests_get_first_avail_mon(int fd);

void goya_tests_set_asic_funcs(struct hltests_device *hdev);
void gaudi_tests_set_asic_funcs(struct hltests_device *hdev);


double get_timediff_sec(struct timespec *begin, struct timespec *end);
double get_bw_gigabyte_per_sec(uint64_t bytes, struct timespec *begin,
							struct timespec *end);
#endif /* HLTHUNK_TESTS_H */
