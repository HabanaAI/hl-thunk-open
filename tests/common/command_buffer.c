// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_tests.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include <limits.h>
#include <stdio.h>
#include <errno.h>

#define UNALIGN_OFFSET 8
#define NUM_OF_PKTS    4
/* number of msg_long packets and single msg_short (signal SOB) */
#define CB_LEN         (NUM_OF_PKTS * 16 + 8)

VOID cb_create_mmap_unmap_destroy(void **state, uint32_t size,
					bool unmap, bool destroy)
{
	struct hltests_state *tests_state =
					(struct hltests_state *) *state;
	uint64_t cb_handle;
	void *ptr;
	int rc;

	rc = hlthunk_request_command_buffer(tests_state->fd, size, &cb_handle);
	assert_int_equal(rc, 0);

	ptr = hltests_mmap(tests_state->fd, size, cb_handle);
	assert_ptr_not_equal(ptr, MAP_FAILED);

	if (unmap) {
		rc = hltests_munmap(ptr, size);
		assert_int_equal(rc, 0);
	}

	if (destroy) {
		rc = hlthunk_destroy_command_buffer(tests_state->fd, cb_handle);
		assert_int_equal(rc, 0);
	}

	END_TEST;
}

VOID test_cb_mmap(void **state)
{
	END_TEST_FUNC(cb_create_mmap_unmap_destroy(state, 0x100000, true,
								true));
}

VOID test_cb_unaligned_size(void **state)
{
	END_TEST_FUNC(cb_create_mmap_unmap_destroy(state, 5000, true, true));
}

VOID test_cb_small_unaligned_odd_size(void **state)
{
	END_TEST_FUNC(cb_create_mmap_unmap_destroy(state, 77, true, true));
}

VOID test_cb_unaligned_odd_size(void **state)
{
	END_TEST_FUNC(cb_create_mmap_unmap_destroy(state, 92517, true, true));
}

VOID test_cb_skip_unmap(void **state)
{
	END_TEST_FUNC(cb_create_mmap_unmap_destroy(state, 92517, false, true));
}

VOID test_cb_skip_unmap_and_destroy(void **state)
{
	END_TEST_FUNC(cb_create_mmap_unmap_destroy(state, 92517, false,
								false));
}

static int submit_unalign_device_cb(int fd, uint64_t host_buf_va,
					int offset, bool sram_test)
{
	int rc, i;
	uint32_t cb_size = 0;
	uint64_t addr, cb_device_va, sram_addr;
	struct hltests_pkt_info pkt_info;
	struct hlthunk_hw_ip_info hw_ip;
	void *device_addr, *cb;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (sram_test)
		sram_addr = hw_ip.sram_base_address + offset;
	else
		sram_addr = 0;

	cb = hltests_create_cb(fd, CB_LEN, INTERNAL, sram_addr);
	assert_non_null(cb);

	for (i = 0 ; i < NUM_OF_PKTS ; i++) {
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_TRUE;
		pkt_info.mb = MB_TRUE;
		addr = host_buf_va + (i * sizeof(uint32_t));
		pkt_info.msg_long.address = addr;
		pkt_info.msg_long.value = 0x0ded0000 + i;
		cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);
	}

	cb_device_va = hltests_get_device_va_for_host_ptr(fd, cb);
	if (sram_test) {
		device_addr = (void *) (uintptr_t) sram_addr;
	} else {
		/* DRAM: Allocate cb size plus the size of the unalign
		 * offset. Make the host cb pointer to be unaligned
		 */
		device_addr = hltests_allocate_device_mem(fd, CB_LEN + offset, 0, CONTIGUOUS);

		device_addr = (uint8_t *) device_addr + offset;
	}
	/* In SRAM or DRAM tests: in order to create the cb
	 * inside the device memory, do a dma transfer that transfer
	 * the cb info, into the device memory.
	 * DMA: host->device
	 */
	hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, STREAM0),
				EB_FALSE, MB_TRUE,
				cb_device_va,
				(uint64_t) device_addr,
				CB_LEN,
				DMA_DIR_HOST_TO_SRAM);

	if (sram_test) {
		hltests_submit_and_wait_cs(fd, cb, cb_size,
				hltests_get_ddma_qid(fd, 0, STREAM0),
				DESTROY_CB_FALSE, HL_WAIT_CS_STATUS_COMPLETED);
	} else {
		/* only gaudi2 supports DRAM unaligned CB */
		int expected_status = hltests_is_gaudi2(fd) ?
						HL_WAIT_CS_STATUS_COMPLETED :
						HL_WAIT_CS_STATUS_ABORTED;

		/* in DRAM: use the DRAM address which stores the
		 * CB that copied via dma transfer
		 */
		hltests_submit_and_wait_cs(fd, (void *)device_addr, cb_size,
				hltests_get_ddma_qid(fd, 0, STREAM0),
				DESTROY_CB_FALSE, expected_status);
	}

	rc = hltests_destroy_cb(fd, cb);
	assert_int_equal(rc, 0);

	if (!sram_test) {
		device_addr = (uint8_t *) device_addr - offset;
		hltests_free_device_mem(fd, device_addr);
	}

	return 0;
}

static int submit_unalign_host_cb(int fd, uint64_t host_buf_va,
							int offset)
{
	int rc, i;
	uint32_t cb_size = 0;
	uint64_t addr, cb_device_va;
	struct hltests_pkt_info pkt_info;
	void *cb;

	/* Allocate cb size plus the size of the unalign offset.
	 * Make the host cb pointer to be unaligned
	 */
	cb = hltests_allocate_host_mem(fd, CB_LEN + offset, NOT_HUGE_MAP);
	assert_non_null(cb);

	cb_device_va = hltests_get_device_va_for_host_ptr(fd, cb);
	assert_non_null(cb_device_va);

	cb = (uint8_t *) cb + offset;
	cb_device_va = cb_device_va + offset;

	for (i = 0 ; i < NUM_OF_PKTS ; i++) {
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_TRUE;
		pkt_info.mb = MB_TRUE;
		addr = host_buf_va + (i * sizeof(uint32_t));
		pkt_info.msg_long.address = addr;
		pkt_info.msg_long.value = 0x0ded0000 + i;
		cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);
	}

	hltests_submit_and_wait_cs(fd, (void *)cb_device_va, cb_size,
				hltests_get_ddma_qid(fd, 0, STREAM0),
				DESTROY_CB_FALSE, HL_WAIT_CS_STATUS_COMPLETED);

	/* Resume the original address of host cb */
	cb = (uint8_t *) cb - offset;
	rc = hltests_free_host_mem(fd, cb);
	assert_int_equal(rc, 0);

	return 0;
}

VOID test_cb_unalign(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	void *host_buf;
	uint32_t cmp_buf[NUM_OF_PKTS];
	int rc, i, len = sizeof(cmp_buf), fd = tests_state->fd;
	uint64_t host_buf_va;

	if (!hltests_is_legacy_mode_enabled(fd)) {
		printf("Test is not relevant in ARC mode, skipping\n");
		skip();
	}

	if (!tests_state->mmu) {
		printf("MMU must be enabled for this test, skipping.\n");
		skip();
	}

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.sram_size)
		skip();

	/* Test only asic which supports unaligned cb */
	if (hltests_is_goya(fd) || hltests_is_gaudi(fd)) {
		printf("Test is supported on Greco and above, skipping.\n");
		skip();
	}

	/* Prepare the buf that will be compared to host_buf */
	for (i = 0 ; i < NUM_OF_PKTS ; i++)
		cmp_buf[i] = 0x0ded0000 + i;

	host_buf = hltests_allocate_host_mem(fd, len, NOT_HUGE_MAP);
	assert_non_null(host_buf);

	host_buf_va = hltests_get_device_va_for_host_ptr(fd, host_buf);
	assert_non_null(host_buf_va);

	/* Test unaligned CB in HOST memory */
	memset(host_buf, 0, len);
	submit_unalign_host_cb(fd, host_buf_va, UNALIGN_OFFSET);
	rc = hltests_mem_compare(cmp_buf, host_buf, len);
	assert_int_equal(rc, 0);

	/* Test unaligned CB in SRAM */
	memset(host_buf, 0, len);
	submit_unalign_device_cb(fd, host_buf_va, UNALIGN_OFFSET, true);
	rc = hltests_mem_compare(cmp_buf, host_buf, len);
	assert_int_equal(rc, 0);

	/* Test unaligned CB in DRAM. Gaudi2 should be able to
	 * execute a CB that stored in none aligned DRAM address
	 */
	if (hltests_is_gaudi2(fd)) {
		memset(host_buf, 0, len);
		submit_unalign_device_cb(fd, host_buf_va,
					UNALIGN_OFFSET, false);

		rc = hltests_mem_compare(cmp_buf, host_buf, len);
		assert_int_equal(rc, 0);
	}

	rc = hltests_free_host_mem(fd, host_buf);
	assert_int_equal(rc, 0);

	END_TEST;
}

VOID submit_unalign_device_common_cb(int fd, void *upper_cb,
				uint64_t host_buf_va, int offset,
				bool sram_test)
{
	uint64_t addr, cb_device_va, upper_cb_device_va, sram_addr;
	struct hltests_monitor_and_fence mon_and_fence_info;
	uint16_t sob_signal_upper_cb, mon_lower_cb;
	struct hltests_pkt_info pkt_info;
	struct hlthunk_hw_ip_info hw_ip;
	void *device_addr, *common_cb;
	uint32_t cb_size = 0;
	int rc, i;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (sram_test)
		sram_addr = hw_ip.sram_base_address + offset;
	else
		sram_addr = 0;

	sob_signal_upper_cb = hltests_get_first_avail_sob(fd);
	mon_lower_cb = hltests_get_first_avail_mon(fd);

	/* Clear SOB before we start */
	hltests_clear_sobs(fd, 1);

	upper_cb_device_va = hltests_get_device_va_for_host_ptr(fd,
							upper_cb);

	assert_non_null(upper_cb_device_va);

	common_cb = hltests_create_cb(fd, CB_LEN, INTERNAL, sram_addr);
	assert_non_null(common_cb);

	for (i = 0 ; i < NUM_OF_PKTS ; i++) {
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_TRUE;
		pkt_info.mb = MB_TRUE;
		addr = host_buf_va + (i * sizeof(uint32_t));
		pkt_info.msg_long.address = addr;
		pkt_info.msg_long.value = 0x0ded0000 + i;
		cb_size = hltests_add_msg_long_pkt(fd, common_cb,
						cb_size, &pkt_info);
	}

	/* add packet to signal upper CB once writes done */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.mode = SOB_ADD;
	pkt_info.write_to_sob.sob_id = sob_signal_upper_cb;
	pkt_info.write_to_sob.value = 1;
	cb_size = hltests_add_write_to_sob_pkt(fd, common_cb, cb_size,
								&pkt_info);

	cb_device_va = hltests_get_device_va_for_host_ptr(fd, common_cb);
	if (sram_test) {
		device_addr = (void *) (uintptr_t) sram_addr;
	} else {
		/* DRAM: Allocate cb size plus the size of the unalign
		 * offset. Make the host cb pointer to be unaligned
		 */
		device_addr = hltests_allocate_device_mem(fd, CB_LEN + offset, 0, CONTIGUOUS);

		device_addr = (uint8_t *) device_addr + offset;
	}
	/* In SRAM or DRAM tests: in order to create the cb
	 * inside the device memory, do a dma transfer that transfer
	 * the cb info, into the device memory.
	 * DMA: host->device
	 */
	hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, STREAM0),
				EB_FALSE, MB_TRUE,
				cb_device_va,
				(uint64_t) device_addr,
				CB_LEN,
				DMA_DIR_HOST_TO_SRAM);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.cp_dma.src_addr = (uint64_t) device_addr;
	pkt_info.cp_dma.size = cb_size;
	cb_size = 0;
	cb_size = hltests_add_cp_dma_pkt(fd, upper_cb,
					cb_size, &pkt_info);

	/* Add monitor to wait for PDMA0 to finish the down DMA job */
	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = hltests_get_ddma_qid(fd, 0, STREAM0);
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = sob_signal_upper_cb;
	mon_and_fence_info.mon_id = mon_lower_cb;
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.sob_val = 1;
	mon_and_fence_info.dec_fence = true;
	mon_and_fence_info.mon_payload = 1;
	cb_size = hltests_add_monitor_and_fence(fd, upper_cb, cb_size,
							&mon_and_fence_info);

	/* in DRAM: use the DRAM address which stores the
	 * CB that copied via dma transfer
	 */
	hltests_submit_and_wait_cs(fd, (void *)upper_cb_device_va, cb_size,
				hltests_get_ddma_qid(fd, 0, STREAM0),
				DESTROY_CB_FALSE, HL_WAIT_CS_STATUS_COMPLETED);

	rc = hltests_destroy_cb(fd, common_cb);
	assert_int_equal(rc, 0);

	if (!sram_test) {
		device_addr = (uint8_t *) device_addr - offset;
		hltests_free_device_mem(fd, device_addr);
	}

	END_TEST;
}

VOID submit_unalign_host_common_cb(int fd, void *upper_cb,
				uint64_t host_buf_va, int offset)
{
	struct hltests_monitor_and_fence mon_and_fence_info;
	uint64_t addr, cb_device_va, upper_cb_device_va;
	uint16_t sob_signal_upper_cb, mon_lower_cb;
	struct hltests_pkt_info pkt_info;
	uint32_t cb_size = 0;
	int rc, i;
	void *cb;

	sob_signal_upper_cb = hltests_get_first_avail_sob(fd);
	mon_lower_cb = hltests_get_first_avail_mon(fd);

	/* Clear SOB before we start */
	hltests_clear_sobs(fd, 1);

	upper_cb_device_va = hltests_get_device_va_for_host_ptr(fd,
							upper_cb);

	assert_non_null(upper_cb_device_va);

	/* Allocate cb size plus the size of the unalign offset.
	 * Make the host cb pointer to be unaligned
	 */
	cb = hltests_allocate_host_mem(fd, CB_LEN + offset, NOT_HUGE_MAP);
	assert_non_null(cb);

	cb_device_va = hltests_get_device_va_for_host_ptr(fd, cb);
	assert_non_null(cb_device_va);

	/* Make the CB unaligned */
	cb = (uint8_t *) cb + offset;
	cb_device_va = cb_device_va + offset;

	for (i = 0 ; i < NUM_OF_PKTS ; i++) {
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_TRUE;
		pkt_info.mb = MB_TRUE;
		addr = host_buf_va + (i * sizeof(uint32_t));
		pkt_info.msg_long.address = addr;
		pkt_info.msg_long.value = 0x0ded0000 + i;
		cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);
	}

	/* add packet to signal upper CB once writes done */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.mode = SOB_ADD;
	pkt_info.write_to_sob.sob_id = sob_signal_upper_cb;
	pkt_info.write_to_sob.value = 1;
	cb_size = hltests_add_write_to_sob_pkt(fd, cb, cb_size, &pkt_info);

	/* fill the upper CB */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.cp_dma.src_addr = cb_device_va;
	pkt_info.cp_dma.size = cb_size;
	cb_size = 0;
	cb_size = hltests_add_cp_dma_pkt(fd, upper_cb, cb_size, &pkt_info);

	/* Add monitor to wait for PDMA0 to finish the down DMA job */
	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = hltests_get_ddma_qid(fd, 0, STREAM0);
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = sob_signal_upper_cb;
	mon_and_fence_info.mon_id = mon_lower_cb;
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.sob_val = 1;
	mon_and_fence_info.dec_fence = true;
	mon_and_fence_info.mon_payload = 1;
	cb_size = hltests_add_monitor_and_fence(fd, upper_cb, cb_size,
							&mon_and_fence_info);

	hltests_submit_and_wait_cs(fd, (void *)upper_cb_device_va, cb_size,
				hltests_get_ddma_qid(fd, 0, STREAM0),
				DESTROY_CB_FALSE, HL_WAIT_CS_STATUS_COMPLETED);

	/* Resume the original address of host cb */
	cb = (uint8_t *) cb - offset;
	rc = hltests_free_host_mem(fd, cb);
	assert_int_equal(rc, 0);

	END_TEST;
}

VOID test_common_cb_unalign(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	void *upper_cb, *host_buf;
	uint32_t cmp_buf[NUM_OF_PKTS];
	uint64_t host_buf_va;
	int rc, i, len = sizeof(cmp_buf), fd = tests_state->fd;

	if (!hltests_is_legacy_mode_enabled(fd)) {
		printf("Test is not relevant in ARC mode, skipping\n");
		skip();
	}

	if (!tests_state->mmu) {
		printf("MMU must be enabled for this test, skipping.\n");
		skip();
	}

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.sram_size)
		skip();

	/* Test only asic which supports unaligned cb */
	if (hltests_is_goya(fd) || hltests_is_gaudi(fd)) {
		printf("Test is supported on Greco and above, skipping.\n");
		skip();
	}

	/* Prepare the buf that will be compared to host_buf */
	for (i = 0 ; i < NUM_OF_PKTS ; i++)
		cmp_buf[i] = 0x0ded0000 + i;

	host_buf = hltests_allocate_host_mem(fd, len, NOT_HUGE_MAP);
	assert_non_null(host_buf);

	host_buf_va = hltests_get_device_va_for_host_ptr(fd, host_buf);
	assert_non_null(host_buf_va);

	/* upper CB contains CP_DMA with mon and fence packets */
	upper_cb = hltests_create_cb(fd, 128, INTERNAL, 0);
	assert_non_null(upper_cb);

	/* Test unaligned common CB in HOST memory */
	memset(host_buf, 0, len);
	submit_unalign_host_common_cb(fd, upper_cb, host_buf_va,
						UNALIGN_OFFSET);

	rc = hltests_mem_compare(cmp_buf, host_buf, len);
	assert_int_equal(rc, 0);

	/* Test unaligned CB in SRAM */
	memset(host_buf, 0, len);
	submit_unalign_device_common_cb(fd, upper_cb, host_buf_va,
						UNALIGN_OFFSET, true);

	rc = hltests_mem_compare(cmp_buf, host_buf, len);
	assert_int_equal(rc, 0);

	/* Test unaligned CB in DRAM. Gaudi2 should be able to
	 * execute a CB that stored in unaligned DRAM address
	 */
	if (hltests_is_gaudi2(fd)) {
		memset(host_buf, 0, len);
		submit_unalign_device_common_cb(fd, upper_cb, host_buf_va,
						UNALIGN_OFFSET, false);

		rc = hltests_mem_compare(cmp_buf, host_buf, len);
		assert_int_equal(rc, 0);
	}

	rc = hltests_destroy_cb(fd, upper_cb);
	assert_int_equal(rc, 0);

	rc = hltests_free_host_mem(fd, host_buf);
	assert_int_equal(rc, 0);

	END_TEST;
}

VOID test_cb_kernel_mapped(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int rc, fd = tests_state->fd;
	void *cb;

	/* Mapping a kernel CB is not supported for Goya and Gaudi */
	if (hltests_is_goya(fd) || hltests_is_gaudi(fd)) {
		printf("Test is not relevant for Goya/Gaudi, skipping\n");
		skip();
	}

	/* Mapping a kernel CB is not supported when MMU is disabled */
	if (!tests_state->mmu) {
		printf("Test is skipped when MMU is disabled\n");
		skip();
	}

	cb = hltests_create_cb(fd, 32, CB_TYPE_KERNEL_MAPPED, 0);
	assert_non_null(cb);
	rc = hltests_destroy_cb(fd, cb);
	assert_int_equal(rc, 0);

	cb = hltests_create_cb(fd, SZ_4K, CB_TYPE_KERNEL_MAPPED, 0);
	assert_non_null(cb);
	rc = hltests_destroy_cb(fd, cb);
	assert_int_equal(rc, 0);

	cb = hltests_create_cb(fd, SZ_8K, CB_TYPE_KERNEL_MAPPED, 0);
	assert_non_null(cb);
	rc = hltests_destroy_cb(fd, cb);
	assert_int_equal(rc, 0);

	cb = hltests_create_cb(fd, SZ_64K, CB_TYPE_KERNEL_MAPPED, 0);
	assert_non_null(cb);
	rc = hltests_destroy_cb(fd, cb);
	assert_int_equal(rc, 0);

	if (hltests_is_legacy_mode_enabled(fd))
		cb = hltests_create_cb(fd, HL_MAX_CB_SIZE, CB_TYPE_KERNEL_MAPPED, 0);
	else
		cb = hltests_create_cb(fd, HL_MAX_CB_SIZE - SZ_8K, CB_TYPE_KERNEL_MAPPED, 0);
	assert_non_null(cb);
	rc = hltests_destroy_cb(fd, cb);
	assert_int_equal(rc, 0);

	END_TEST;
}

#ifndef HLTESTS_LIB_MODE

const struct CMUnitTest cb_tests[] = {
	cmocka_unit_test_setup(test_cb_mmap,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cb_unaligned_size,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cb_small_unaligned_odd_size,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cb_unaligned_odd_size,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cb_skip_unmap,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cb_skip_unmap_and_destroy,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cb_unalign,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_common_cb_unalign,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cb_kernel_mapped,
				hltests_ensure_device_operational)
};

static const char *const usage[] = {
	"command_buffer [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = sizeof(cb_tests) / sizeof((cb_tests)[0]);

	hltests_parser(argc, argv, usage, HLTEST_DEVICE_MASK_DONT_CARE, cb_tests,
			num_tests);

	return hltests_run_group_tests("command_buffer", cb_tests, num_tests,
					hltests_setup, hltests_teardown);
}

#endif /* HLTESTS_LIB_MODE */
