/* SPDX-License-Identifier: MIT
 *
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 *
 */

#ifndef HLTHUNK_TESTS_H
#define HLTHUNK_TESTS_H

#include "misc/habanalabs.h"
#include "hlthunk.h"
#include "khash.h"
#include "pci_ids.h"

#include <stdint.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <stdbool.h>

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#ifndef HLTESTS_LIB_MODE
#include <cmocka.h>
#endif

#ifdef HLTESTS_LIB_MODE

#define VOID int
#define END_TEST return 0
#define END_TEST_FUNC(a) return (a)
#define EXIT_FROM_TEST return 0
#define CALL_HELPER_FUNC(func) \
		do { int _rc = (func); if (_rc) return _rc; } while (0)

#define fail() return -1
#define skip() return 0

#define fail_msg(fmt, ...) do { printf(fmt, ##__VA_ARGS__); return -1; } while (0)
#define print_message(fmt, ...) printf(fmt, ##__VA_ARGS__)
#define print_error(fmt, ...) printf(fmt, ##__VA_ARGS__)

#define assert_null(p) if (p) return -1
#define assert_non_null(p) if (!(p)) return -1

#define assert_int_equal(a, b) if ((a) != (b)) return -1
#define assert_int_not_equal(a, b) if ((a) == (b)) return -1

#define assert_ptr_not_equal(p, v) if ((p) == (v)) return -1

#define assert_in_range(a, min, max) if (!((a) >= (min) && (a) <= (max))) return -1
#define assert_not_in_range(a, min, max) if ((a) >= (min) && (a) <= (max)) return -1

#define assert_true(a) if (!(a)) return -1
#define assert_false(a) if (a) return -1

#define fail_ret_ptr() return NULL

#define fail_msg_ret_ptr(fmt, ...) printf(fmt, ##__VA_ARGS__); return NULL

#define assert_null_ret_ptr(p) if (p) return NULL
#define assert_non_null_ret_ptr(p) if (!(p)) return NULL

#define assert_int_equal_ret_ptr(a, b) if ((a) != (b)) return NULL
#define assert_int_not_equal_ret_ptr(a, b) if ((a) == (b)) return NULL

#define assert_ptr_not_equal_ret_ptr(p, v) if ((p) == (v)) return NULL

#define assert_in_range_ret_ptr(a, min, max) \
		if (!((a) >= (min) && (a) <= (max))) \
			return NULL

#define assert_not_in_range_ret_ptr(a, min, max) \
		if ((a) >= (min) && (a) <= (max)) \
			return NULL

#define assert_true_ret_ptr(a) if (!(a)) return NULL
#define assert_false_ret_ptr(a) if (a) return NULL

#else

#define VOID void
#define END_TEST
#define END_TEST_FUNC(a) (a)
#define EXIT_FROM_TEST return
#define CALL_HELPER_FUNC(func) (func)

#define fail_ret_ptr() fail()

#define fail_msg_ret_ptr(fmt, ...) fail_msg(fmt, ...)

#define assert_null_ret_ptr(p) assert_null((p))
#define assert_non_null_ret_ptr(p) assert_non_null((p))

#define assert_int_equal_ret_ptr(a, b) assert_int_equal((a), (b))
#define assert_int_not_equal_ret_ptr(a, b) assert_int_not_equal((a), (b))

#define assert_ptr_not_equal_ret_ptr(p, v) assert_ptr_not_equal((p), (v))

#define assert_in_range_ret_ptr(a, min, max) assert_in_range((a), (min), (max))

#define assert_not_in_range_ret_ptr(a, min, max) \
			assert_not_in_range((a), (min), (max))

#define assert_true_ret_ptr(a) assert_true((a))
#define assert_false_ret_ptr(a) assert_false((a))

#endif

#ifdef HLTHUNK_TESTS_SANITIZER
#undef skip
#define skip() EXIT_FROM_TEST
#endif

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
	NOT_HUGE_MAP = 0,
	HUGE_MAP
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
	DMA_PERF_ALL2ALL_SUPER_STRESS,
	DMA_PERF_RESULTS_MAX
};

enum hltests_random {
	NOT_RANDOM = 0,
	RANDOM
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
	enum hlthunk_device_name asic_type;
};

enum sync_mng_base {
	SYNC_MNG_BASE_ES,
	SYNC_MNG_BASE_WS,
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
			enum sync_mng_base base;
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
	int (*dram_pool_init)(struct hltests_device *hdev);
	void (*dram_pool_fini)(struct hltests_device *hdev);
	int (*dram_pool_alloc)(struct hltests_device *hdev, uint64_t size,
				uint64_t *return_addr);
	void (*dram_pool_free)(struct hltests_device *hdev, uint64_t addr,
				uint64_t size);
	int (*submit_cs)(int fd, struct hltests_cs_chunk *restore_arr,
				uint32_t restore_arr_size,
				struct hltests_cs_chunk *execute_arr,
				uint32_t execute_arr_size,
				uint32_t flags, uint32_t timeout,
				uint64_t *seq);
	int (*wait_for_cs)(int fd, uint64_t seq, uint64_t timeout_us);
	int (*get_max_pll_idx)(void);
	const char *(*stringify_pll_idx)(uint32_t pll_idx);
	const char *(*stringify_pll_type)(uint32_t pll_idx, uint8_t type_idx);
	uint32_t (*get_sob_id)(uint32_t base_addr_off);
	uint16_t (*get_mon_cnt_per_dcore)(void);
	int (*get_stream_master_qid_arr)(uint32_t **qid_arr);
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

struct hltest_host_meminfo {
	uint64_t mem_total;
	uint64_t mem_free;
	uint64_t mem_available;
	uint64_t page_size;
	uint64_t hugepage_total;
	uint64_t hugepage_free;
	uint64_t hugepage_size;
};

struct mem_pool {
	pthread_mutex_t lock;
	uint64_t start;
	uint32_t page_size;
	uint32_t pool_npages;
	uint8_t *pool;
};

extern char asic_names[HLTHUNK_DEVICE_MAX][20];

void hltests_parser(int argc, const char **argv, const char * const*usage,
			enum hlthunk_device_name expected_device
#ifndef HLTESTS_LIB_MODE
			, const struct CMUnitTest * const tests, int num_tests
#endif
			);

const char *hltests_get_parser_pciaddr(void);
const char *hltests_get_config_filename(void);
int hltests_get_parser_run_disabled_tests(void);
int hltests_get_verbose_enabled(void);
uint32_t hltests_get_cur_seed(void);
char *hltests_get_build_path(void);
bool hltests_is_legacy_mode_enabled(void);
bool hltests_is_goya(int fd);
bool hltests_is_gaudi(int fd);

#ifndef HLTESTS_LIB_MODE
int hltests_run_group_tests(const char *group_name,
				const struct CMUnitTest * const tests,
				const size_t num_tests,
				CMFixtureFunction group_setup,
				CMFixtureFunction group_teardown);
#endif

int hltests_control_dev_open(const char *busid);
int hltests_control_dev_close(int fd);
int hltests_open(const char *busid);
int hltests_close(int fd);

void *hltests_cb_mmap(int fd, size_t len, off_t offset);
int hltests_cb_munmap(void *addr, size_t length);

uint32_t hltests_debugfs_read(int addr_fd, int data_fd, uint64_t full_address);
void hltests_debugfs_write(int addr_fd, int data_fd, uint64_t full_address,
				uint32_t val);
uint64_t hltests_debugfs_read64(int addr_fd, int data_fd, uint64_t full_address);
void hltests_debugfs_write64(int addr_fd, int data_fd, uint64_t full_address,
				uint64_t val);
struct hltests_memory *
hltests_allocate_host_mem_nomap(uint64_t size, enum hltests_huge huge);
int hltests_free_host_mem_nounmap(struct hltests_memory *mem,
					enum hltests_huge huge);
int hltests_map_host_mem(int fd, struct hltests_memory *mem);
int hltests_unmap_host_mem(int fd, struct hltests_memory *mem);
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
int hltests_submit_cs_timeout(int fd, struct hltests_cs_chunk *restore_arr,
				uint32_t restore_arr_size,
				struct hltests_cs_chunk *execute_arr,
				uint32_t execute_arr_size,
				uint32_t flags,
				uint32_t timeout,
				uint64_t *seq);
int hltests_submit_legacy_cs(int fd, struct hltests_cs_chunk *restore_arr,
				uint32_t restore_arr_size,
				struct hltests_cs_chunk *execute_arr,
				uint32_t execute_arr_size,
				uint32_t flags, uint32_t timeout,
				uint64_t *seq);
int hltests_submit_staged_cs(int fd, struct hltests_cs_chunk *restore_arr,
				uint32_t restore_arr_size,
				struct hltests_cs_chunk *execute_arr,
				uint32_t execute_arr_size,
				uint32_t flags,
				uint64_t staged_cs_seq,
				uint64_t *seq);
int hltests_wait_for_legacy_cs(int fd, uint64_t seq, uint64_t timeout_us);
int hltests_submit_and_wait_cs(int fd, void *cb_ptr, uint32_t cb_size,
				uint32_t queue_index,
				enum hltests_destroy_cb destroy_cb,
				int expected_val);

int hltests_control_dev_setup(void **state);
int hltests_control_dev_teardown(void **state);
int hltests_setup(void **state);
int hltests_teardown(void **state);
int hltests_root_setup(void **state);
int hltests_root_teardown(void **state);
int hltests_root_debug_setup(void **state);
int hltests_root_debug_teardown(void **state);

uint32_t hltests_rand_u32(void);
bool hltests_rand_flip_coin(void);
void hltests_fill_rand_values(void *ptr, uint32_t size);
void hltests_fill_seq_values(void *ptr, uint32_t size);

int hltests_mem_compare_with_stop(void *ptr1, void *ptr2, uint64_t size, bool
			stop_on_err);
int hltests_mem_compare(void *ptr1, void *ptr2, uint64_t size);

int hltests_dma_transfer(int fd, uint32_t queue_index, enum hltests_eb eb,
				enum hltests_mb mb,
				uint64_t src_addr, uint64_t dst_addr,
				uint32_t size,
				enum hltests_goya_dma_direction dma_dir);

int hltests_zero_device_memory(int fd, uint64_t dst_addr, uint32_t size,
				enum hltests_goya_dma_direction dma_dir);

VOID hltests_dma_test(void **state, bool is_ddr, uint64_t size);

int hltests_wait_for_cs(int fd, uint64_t seq, uint64_t timeout_us);
int hltests_wait_for_cs_until_not_busy(int fd, uint64_t seq);

VOID hltests_dma_dram_frag_mem_test(void **state, uint64_t size);

VOID hltests_dma_dram_high_mem_test(void **state, uint64_t size);

int hltests_ensure_device_operational(void **state);

VOID test_sm_pingpong_common_cp(void **state, bool is_tpc,
				bool common_cb_in_host, uint8_t tpc_id);

int hltests_clear_sobs(int fd, uint16_t num_of_sobs);
void hltests_clear_sobs_offset(int fd, uint16_t num_of_sobs, uint16_t offset);

void *hltests_map_hw_block(int fd, uint64_t block_addr, uint32_t *block_size);
int hltests_unmap_hw_block(int fd, void *host_addr, uint32_t block_size);

int hltests_read_lbw_mem(int fd, void *dst, void *src, uint32_t size);
int hltests_write_lbw_mem(int fd, void *dst, void *src, uint32_t size);
int hltests_read_lbw_reg(int fd, void *src, uint32_t *value);
int hltests_write_lbw_reg(int fd, void *dst, uint32_t value);

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
uint16_t hltests_get_first_avail_interrupt(int fd);
uint32_t hltests_get_sob_id(int fd, uint32_t base_addr_off);
uint16_t hltests_get_monitors_cnt_per_dcore(int fd);
int hltests_get_stream_master_qid_arr(int fd, uint32_t **qid_arr);

void goya_tests_set_asic_funcs(struct hltests_device *hdev);
void gaudi_tests_set_asic_funcs(struct hltests_device *hdev);


double get_timediff_sec(struct timespec *begin, struct timespec *end);
double get_bw_gigabyte_per_sec(uint64_t bytes, struct timespec *begin,
							struct timespec *end);
int hltests_get_max_pll_idx(int fd);
const char *hltests_stringify_pll_idx(int fd, uint32_t pll_idx);
const char *hltests_stringify_pll_type(int fd, uint32_t pll_idx,
				uint8_t type_idx);

void hltests_set_rand_seed(uint32_t val);

int hltest_get_host_meminfo(struct hltest_host_meminfo *res);

int hltests_init(void);
void hltests_fini(void);

/* Tests */
VOID test_hbm_read_temperature(void **state);
VOID test_hbm_read_interrupts(void **state);
VOID test_print_asic_rev(void **state);
VOID test_read_every_4KB_registers_block(void **state);
VOID test_read_through_pci(void **state);
VOID test_tpc_corner_with_inbound_pci_hbw(void **state);
VOID rate_limiter_init(struct hltests_state *tests_state);
VOID activate_all2all_dma_channels(void **state, uint64_t *dram_addr,
					uint32_t dma_size,
					struct hlthunk_hw_ip_info *hw_ip);
VOID test_dma_all2all_stress(void **state);
VOID test_dma_all2all_stress_minimum_host_memory(void **state);
VOID activate_super_stress_dma_channels(void **state,
					struct hlthunk_hw_ip_info *hw_ip,
					int num_of_iterations);
VOID test_dma_all2all_super_stress(void **state);
VOID test_mme_basic_conv(void **state);
VOID test_conn_alloc_destroy(void **state);
VOID test_conn_set_context(void **state);
VOID test_gaudi_dma_all2all(void **state);
VOID test_strided_dma(void **state);
VOID test_threads(void **state, uint32_t num_of_threads,
				uint32_t num_of_iter, void *(*func)(void *));
VOID test_wq_threads(void **state);
VOID test_conn_threads(void **state, uint32_t num_of_threads,
				uint32_t num_of_iter);
VOID test_conn_1_thread(void **state);
VOID test_conn_8_threads(void **state);
VOID test_conn_512_threads(void **state);
VOID test_conn_1023_threads(void **state);
VOID test_print_ips_macs(void **state);
VOID test_qman_write_to_protected_register(void **state, bool is_tpc);
VOID test_debugfs_sram_read_write(void **state);
VOID test_write_to_cfg_space(void **state);
VOID test_tpc_qman_write_to_protected_register(void **state);
VOID test_mme_qman_write_to_protected_register(void **state);
VOID test_write_to_mmTPC_PLL_CLK_RLX_0_from_qman(void **state);
VOID test_dma_4_queues_goya(void **state);
VOID test_axi_drain_functionality(void **state);
VOID test_fence_cnt_cleanup_on_ctx_switch(void **state);
VOID handle_block_security_violations(struct hltests_state *tests_state,
					     int raw, int col,
					     const uint64_t array[raw][col],
					     uint64_t mask);
VOID test_check_for_security_violations(void **state);
VOID inc_sobs(int fd, uint16_t first_sob, uint16_t num_of_sobs);
VOID test_deny_access_to_secured_sobjs(void **state);
VOID test_deny_mon_access_to_secured_area(void **state);
VOID test_deny_access_to_secured_monitors(void **state);
VOID test_tdr_deadlock(void **state);
VOID test_endless_memory_ioctl(void **state);
VOID test_dma_custom(void **state);
VOID test_transfer_bigger_than_alloc(void **state);
VOID test_map_custom(void **state);
VOID test_loop_map_work_unmap(void **state);
VOID test_duplicate_file_descriptor(void **state);
VOID test_page_miss(void **state);
VOID test_register_security(void **state);
VOID test_open_by_busid(void **state);
VOID test_open_twice(void **state);
VOID test_open_by_module_id(void **state);
VOID test_open_close_without_ioctl(void **state);
VOID test_close_without_releasing_debug(void **state);
VOID test_open_and_print_pci_bdf(void **state);
VOID test_sm(void **state, bool is_tpc, bool is_wait, uint8_t engine_id);
VOID test_sm_pingpong_upper_cp(void **state, bool is_tpc,
				bool upper_cb_in_host, uint8_t engine_id);
VOID test_sm_tpc(void **state);
VOID test_sm_mme(void **state);
VOID test_sm_pingpong_tpc_upper_cp_from_sram(void **state);
VOID test_sm_pingpong_mme_upper_cp_from_sram(void **state);
VOID test_sm_pingpong_tpc_upper_cp_from_host(void **state);
VOID test_sm_pingpong_mme_upper_cp_from_host(void **state);
VOID test_sm_pingpong_tpc_common_cp_from_sram(void **state);
VOID test_sm_pingpong_mme_common_cp_from_sram(void **state);
VOID test_sm_pingpong_tpc_common_cp_from_host(void **state);
VOID test_sm_pingpong_mme_common_cp_from_host(void **state);
VOID test_sm_sob_cleanup_on_ctx_switch(void **state);
VOID test_sm_monitor_set_sram(void **state);
VOID test_sm_monitor_set_hostmem(void **state);
VOID test_signal_wait(void **state);
VOID test_signal_wait_parallel(void **state);
VOID test_signal_collective_wait_parallel(void **state);
VOID test_signal_wait_dma(void **state);
VOID test_sm_long_mode(void **state);
VOID test_signal_collective_wait_dma(void **state);
VOID test_print_hw_ip_info(void **state);
VOID print_engine_name(int fd, uint32_t engine_id);
VOID test_print_hw_idle_info(void **state);
VOID test_print_dram_usage_info_no_stop(void **state);
VOID test_print_device_utilization_no_stop(void **state);
VOID test_print_clk_rate(void **state);
VOID test_print_reset_count(void **state);
VOID test_print_time_sync_info(void **state);
VOID test_print_hlthunk_version(void **state);
VOID test_print_cs_drop_statistics(void **state);
VOID test_print_pci_counters(void **state);
VOID test_print_clk_throttling_reason(void **state);
VOID test_print_total_energy_consumption(void **state);
VOID print_events_counters(void **state, bool aggregate);
VOID test_print_events_counters(void **state);
VOID test_print_events_counters_aggregate(void **state);
VOID test_print_pci_bdf(void **state);
VOID test_print_pll_info(void **state);
VOID test_print_hw_asic_status(void **state);
VOID test_dma_entire_sram_random(void **state);
VOID test_host_sram_perf(void **state);
VOID test_sram_host_perf(void **state);
VOID test_host_dram_perf(void **state);
VOID test_dram_host_perf(void **state);
VOID test_sram_dram_single_ch_perf(void **state);
VOID test_dram_sram_single_ch_perf(void **state);
VOID test_dram_dram_single_ch_perf(void **state);
VOID test_sram_dram_multi_ch_perf(void **state);
VOID test_dram_sram_multi_ch_perf(void **state);
VOID test_dram_dram_multi_ch_perf(void **state);
VOID test_sram_dram_bidirectional_full_multi_ch_perf(void **state);
VOID test_dram_sram_5ch_perf(void **state);
VOID test_host_sram_bidirectional_perf(void **state);
VOID test_host_dram_bidirectional_perf(void **state);
VOID test_map_bigger_than_4GB(void **state);
VOID allocate_device_mem_until_full(void **state,
					enum hltests_contiguous contigouos);
VOID alloc_device_mem_scrubbed(void **state,
		enum hltests_contiguous contigouos);
VOID test_alloc_device_mem_until_full(void **state);
VOID test_alloc_device_mem_until_full_contiguous(void **state);
VOID test_alloc_device_mem_scrubbed(void **state);
VOID test_alloc_device_mem_scrubbed_contiguous(void **state);
VOID test_submit_after_unmap(void **state);
VOID test_submit_and_close(void **state);
VOID test_hint_addresses(void **state);
VOID test_dmmu_hint_address(void **state);
VOID test_pmmu_hint_address(void **state, bool is_huge);
VOID test_pmmu_hint_address_regular_page(void **state);
VOID test_pmmu_hint_address_huge_page(void **state);
VOID test_dma_threads(void **state, uint32_t num_of_threads);
VOID test_dma_8_threads(void **state);
VOID test_dma_64_threads(void **state);
VOID test_dma_512_threads(void **state);
VOID dma_4_queues(void **state, bool sram_only);
VOID test_dma_4_queues(void **state);
VOID test_dma_4_queues_sram_only(void **state);
VOID test_lbw_scan(void **state);
VOID test_debug_mode(void **state);
VOID hltest_bench_host_map_expected(struct hltests_state *tests_state,
					uint64_t n_allocs, uint64_t alloc_size,
					enum hltests_huge huge,
					uint64_t n_maps, uint64_t n_unmaps,
					enum hltests_random random,
					uint32_t n_iter,
					bool disabled_test,
					bool validate_exp,
					const char *test_name);
VOID test_bench_mappings_custom(void **state);
VOID submit_cs_nop(void **state, int num_of_pqe,
				uint16_t wait_after_submit_cnt);
VOID test_cs_nop(void **state);
VOID test_cs_nop_16PQE(void **state);
VOID test_cs_nop_32PQE(void **state);
VOID test_cs_nop_48PQE(void **state);
VOID test_cs_nop_64PQE(void **state);
VOID test_and_measure_wait_after_submit_cs_nop(void **state);
VOID test_and_measure_wait_after_64_submit_cs_nop(void **state);
VOID test_and_measure_wait_after_256_submit_cs_nop(void **state);
VOID test_cs_msg_long(void **state);
VOID test_cs_msg_long_2000(void **state);
VOID test_cs_two_streams_with_fence(void **state);
VOID hltests_cs_two_streams_arb_point(int fd,
					     struct hltests_arb_info *arb_info,
					     uint64_t *host_data_va,
					     uint64_t *device_data_addr,
					     uint16_t sob_id,
					     uint16_t *mon_id,
					     uint32_t dma_size,
					     bool ds_direction);
VOID test_cs_two_streams_with_arb(void **state);
VOID test_cs_two_streams_with_priority_arb(void **state);
VOID test_cs_two_streams_with_wrr_arb(void **state);
VOID test_cs_cq_wrap_around(void **state);
VOID test_cs_load_predicates(void **state, bool is_consecutive_map);
VOID test_cs_load_pred_non_consecutive_map(void **state);
VOID test_cs_load_pred_consecutive_map(void **state);
VOID load_scalars_and_exe_4_rfs(int fd, uint64_t scalar_buf_sram_addr,
					uint64_t cb_sram_addr,
					uint64_t msg_long_dst_sram_addr,
					uint64_t host_data_device_va,
					bool is_separate_exe);
VOID load_scalars_and_exe_2_rfs(int fd, uint64_t scalar_buf_sram_addr,
					uint64_t cb_sram_addr, uint16_t sob0,
					uint16_t mon0, bool is_upper_rfs,
					bool is_separate_exe);
VOID test_cs_load_scalars_exe_2_rfs(void **state, bool is_upper_rfs);
VOID test_cs_load_scalars_exe_lower_2_rfs(void **state);
VOID test_cs_load_scalars_exe_upper_2_rfs(void **state);
VOID test_cs_cb_list(void **state);
VOID test_cs_cb_list_with_parallel_pqe(void **state);
VOID test_cs_drop(void **state);
VOID test_wait_for_cs_with_timestamp(void **state);
VOID test_staged_submission_256_threads(void **state);
VOID test_wait_for_interrupt(void **state);
VOID dma_entire_dram_random(void **state, uint64_t zone_size,
			uint64_t dma_size);
VOID test_dma_entire_dram_random_256KB(void **state);
VOID test_dma_entire_dram_random_512KB(void **state);
VOID test_dma_entire_dram_random_1MB(void **state);
VOID test_dma_entire_dram_random_2MB(void **state);
VOID cb_create_mmap_unmap_destroy(void **state, uint32_t size,
					bool unmap, bool destroy);
VOID test_cb_mmap(void **state);
VOID test_cb_unaligned_size(void **state);
VOID test_cb_small_unaligned_odd_size(void **state);
VOID test_cb_unaligned_odd_size(void **state);
VOID test_cb_skip_unmap(void **state);
VOID test_cb_skip_unmap_and_destroy(void **state);
VOID test_cb_unalign(void **state);
VOID submit_unalign_device_common_cb(int fd, void *upper_cb,
				uint64_t host_buf_va, int offset,
				bool sram_test);
VOID submit_unalign_host_common_cb(int fd, void *upper_cb,
				uint64_t host_buf_va, int offset);
VOID test_common_cb_unalign(void **state);
VOID test_cb_kernel_mapped(void **state);
VOID test_error_injection_endless_command(void **state);
VOID test_error_injection_non_fatal_event(void **state);
VOID test_error_injection_fatal_event(void **state);
VOID test_error_injection_heartbeat(void **state);
VOID test_error_injection_thermal_event(void **state);
VOID test_dma_all2all_dram2sram(void **state);
VOID test_dma_all2all_dram2dram(void **state);

#endif /* HLTHUNK_TESTS_H */
