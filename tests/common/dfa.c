// SPDX-License-Identifier: MIT

/*
 * Copyright 2022 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_tests.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>

#define NUM_OF_SOBS	100
#define SOB_BASE_VAL	40

VOID test_dfa_device_memory_read_hbm_block(void **state)
{
	struct hltests_state *tests_state = *state;
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;
	int rc, fd = tests_state->fd, read_size = 128;
	uint64_t dram_addr, host_va;
	void *src_ptr, *read_buf;

	if (!hw_ip->dram_enabled) {
		printf("dram is disabled - skip\n");
		skip();
	}

	dram_addr = (uint64_t) hltests_allocate_device_mem(fd, read_size, 0, NOT_CONTIGUOUS);
	assert_int_not_equal(dram_addr, 0);

	src_ptr = hltests_allocate_host_mem(fd, read_size, HUGE_MAP);
	assert_non_null(src_ptr);
	hltests_fill_rand_values(src_ptr, read_size);
	host_va = hltests_get_device_va_for_host_ptr(fd, src_ptr);

	/* fill dram with random values */
	rc = hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, STREAM0), EB_FALSE, MB_TRUE,
					host_va, dram_addr, read_size, DMA_DIR_HOST_TO_DRAM);
	assert_int_equal(rc, 0);

	/* read the dram using the API */
	read_buf = hlthunk_malloc(read_size);
	assert_non_null(read_buf);
	rc = hlthunk_device_memory_read_block_experimental(fd, read_buf, dram_addr, read_size, 0);
	assert_int_equal(rc, 0);

	/* compare with our random values */
	rc = hltests_mem_compare(read_buf, src_ptr, read_size);
	assert_int_equal(rc, 0);

	/* cleanup */
	rc = hltests_free_device_mem(fd, (void *)dram_addr);
	assert_int_equal(rc, 0);
	rc = hltests_free_host_mem(fd, src_ptr);
	assert_int_equal(rc, 0);
	hlthunk_free(read_buf);

	END_TEST;
}

VOID test_dfa_device_memory_read_block(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hltests_pkt_info clear_sob;
	uint64_t sob_base_addr, sob_addr;
	uint16_t sob_id;
	uint32_t val, buff_val[NUM_OF_SOBS], qid;
	void *cb;
	int rc, fd, cb_size = 0, i;

	fd = tests_state->fd;

	cb = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	assert_non_null(cb);

	qid = hltests_get_dma_down_qid(fd, STREAM0);
	sob_id = hltests_get_first_avail_sob(fd);

	memset(&clear_sob, 0, sizeof(clear_sob));
	clear_sob.qid = qid;
	clear_sob.eb = EB_FALSE;
	clear_sob.mb = MB_TRUE;
	clear_sob.write_to_sob.mode = SOB_SET;

	for (i = 0 ; i < NUM_OF_SOBS ; i++) {

		clear_sob.write_to_sob.sob_id = sob_id + i;
		clear_sob.write_to_sob.value = SOB_BASE_VAL + i;
		cb_size = hltests_add_write_to_sob_pkt(fd, cb, cb_size, &clear_sob);
	}

	rc = hltests_submit_and_wait_cs(fd, cb, cb_size, qid,
				DESTROY_CB_FALSE, HL_WAIT_CS_STATUS_COMPLETED);
	assert_int_equal(rc, 0);


	sob_base_addr = hltests_get_sob_base_addr(fd);

	/* read the sob values, one by one */
	for (i = 0 ; i < NUM_OF_SOBS ; i++) {
		sob_addr = sob_base_addr + ((sob_id + i) * 4);
		rc = hlthunk_device_memory_read_block_experimental(fd, &val, sob_addr,
								sizeof(uint32_t), 0);
		assert_int_equal(rc, 0);
		assert_int_equal(val, SOB_BASE_VAL + i);
	}

	/* read the sob values in single call */
	sob_addr = sob_base_addr + (sob_id * 4);
	rc = hlthunk_device_memory_read_block_experimental(fd, buff_val, sob_addr,
								sizeof(uint32_t) * NUM_OF_SOBS, 0);

	assert_int_equal(rc, 0);

	for (i = 0 ; i < NUM_OF_SOBS ; i++)
		assert_int_equal(buff_val[i], SOB_BASE_VAL + i);

	hltests_destroy_cb(fd, cb);

	END_TEST;
}

#ifndef HLTESTS_LIB_MODE

const struct CMUnitTest dfa_tests[] = {
	cmocka_unit_test_setup(test_dfa_device_memory_read_block,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dfa_device_memory_read_hbm_block,
				hltests_ensure_device_operational),
};

static const char *const usage[] = {
	"dfa [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = sizeof(dfa_tests) / sizeof((dfa_tests)[0]);

	hltests_parser(argc, argv, usage, HLTEST_DEVICE_MASK_DONT_CARE, dfa_tests, num_tests);
	hltests_set_capabilities_mask(CAP_ARC_FW_LOAD_SCHED_MASK | CAP_ARC_FW_LOAD_PDMA_MASK);
	return hltests_run_group_tests("dfa", dfa_tests, num_tests,
					hltests_setup, hltests_teardown);
}

#endif /* HLTESTS_LIB_MODE */

