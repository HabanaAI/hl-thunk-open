// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk.h"
#include "hlthunk_tests.h"
#include "goya/goya.h"
#include "goya/asic_reg/goya_regs.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include <limits.h>
#include <cmocka.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

static void test_qman_write_to_protected_register(void **state, bool is_tpc)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	struct hltests_cs_chunk restore_arr[1], execute_arr[2];
	void *engine_cb, *restore_cb, *dma_cb;
	uint64_t cfg_address, engine_cb_sram_addr, engine_cb_device_va, seq;
	uint32_t page_size, engine_qid, engine_cb_size, restore_cb_size,
		dma_cb_size, val;
	int rc, fd = tests_state->fd;

	/* SRAM MAP (base + ):
	 * - 0x3000 : engine's internal CB
	 *
	 * Test Description:
	 * - Engine QMAN tries to write to protected register and then signals
	 *   SOB0.
	 * - DMA QMAN fences on SOB0.
	 * - Setup CB is used to clear SOB0 and to DMA the internal CBs to SRAM.
	 * - The test verifies that the write is not performed.
	 */

	cfg_address = CFG_BASE + mmDMA_QM_4_PQ_BASE_HI;
	page_size = sysconf(_SC_PAGESIZE);

	/* Set engine queue ID and SRAM addresses */
	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (is_tpc) {
		/* Find first available TPC */
		uint8_t tpc_id;
		for (tpc_id = 0;
			(!(hw_ip.tpc_enabled_mask & (0x1 << tpc_id))) &&
			(tpc_id < hltests_get_tpc_cnt(fd, 0));)
			tpc_id++;

		assert_in_range(tpc_id, 0, hltests_get_tpc_cnt(fd, 0) - 1);

		engine_qid = hltests_get_tpc_qid(fd, 0, tpc_id, 0);
	} else {
		engine_qid = hltests_get_mme_qid(fd, 0, 0, 0);
	}

	engine_cb_sram_addr = hw_ip.sram_base_address + 0x3000;

	/* Internal CB for engine QMAN: MSG_LONG + signal SOB0 */
	engine_cb = hltests_create_cb(fd, page_size, false,
					engine_cb_sram_addr);
	assert_ptr_not_equal(engine_cb, NULL);
	engine_cb_device_va = hltests_get_device_va_for_host_ptr(fd, engine_cb);
	engine_cb_size = 0;
	engine_cb_size = hltests_add_msg_long_pkt(fd, engine_cb, engine_cb_size,
					false, false, cfg_address, 0x789a0ded);
	engine_cb_size = hltests_add_write_to_sob_pkt(fd, engine_cb,
					engine_cb_size, false, true, 0, 1, 1);

	/* Setup CB: Clear SOB0 + DMA the internal CB to SRAM */
	restore_cb =  hltests_create_cb(fd, page_size, true, 0);
	assert_ptr_not_equal(restore_cb, NULL);
	restore_cb_size = 0;
	restore_cb_size = hltests_add_set_sob_pkt(fd, restore_cb,
					restore_cb_size, false, false, 0, 0, 0);
	restore_cb_size = hltests_add_dma_pkt(fd, restore_cb, restore_cb_size,
					false, true, engine_cb_device_va,
					engine_cb_sram_addr, engine_cb_size,
					GOYA_DMA_HOST_TO_SRAM);

	/* CB for DMA QMAN: Fence on SOB0 */
	dma_cb = hltests_create_cb(fd, page_size, true, 0);
	assert_ptr_not_equal(dma_cb, NULL);
	dma_cb_size = 0;
	dma_cb_size = hltests_add_monitor_and_fence(fd, dma_cb, dma_cb_size, 0,
					hltests_get_dma_down_qid(fd, 0, 0),
					false, 0, 0, 0);

	/* Submit CS and wait for completion */
	restore_arr[0].cb_ptr = restore_cb;
	restore_arr[0].cb_size = restore_cb_size;
	restore_arr[0].queue_index = hltests_get_dma_down_qid(fd, 0, 0);

	execute_arr[0].cb_ptr = engine_cb;
	execute_arr[0].cb_size = engine_cb_size;
	execute_arr[0].queue_index = engine_qid;

	execute_arr[1].cb_ptr = dma_cb;
	execute_arr[1].cb_size = dma_cb_size;
	execute_arr[1].queue_index = hltests_get_dma_down_qid(fd, 0, 0);

	rc = hltests_submit_cs(fd, restore_arr, 1, execute_arr, 2, true, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_cs(fd, seq, WAIT_FOR_CS_DEFAULT_TIMEOUT);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_BUSY);

	/* Cleanup */
	rc = hltests_destroy_cb(fd, engine_cb);
	assert_int_equal(rc, 0);
	rc = hltests_destroy_cb(fd, restore_cb);
	assert_int_equal(rc, 0);
	rc = hltests_destroy_cb(fd, dma_cb);
	assert_int_equal(rc, 0);

	/* Verify that the protected register wasn't written */
	val = hltests_debugfs_read(fd, cfg_address);
	assert_int_not_equal(val, 0x789a0ded);
}

void test_debugfs_sram_read_write(void **state)
{
	struct hltests_state *tests_state =
					(struct hltests_state *) *state;
	uint32_t val;

	hltests_debugfs_write(tests_state->fd, SRAM_BASE_ADDR + 0x200000,
					0x99775533);
	hltests_debugfs_write(tests_state->fd, SRAM_BASE_ADDR + 0x200000,
					0x12345678);
	val = hltests_debugfs_read(tests_state->fd,
					SRAM_BASE_ADDR + 0x200000);

	assert_int_equal(0x12345678, val);
}

void test_write_to_cfg_space(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hltests_cs_chunk execute_arr[1];
	uint64_t cfg_address = CFG_BASE + mmPSOC_GLOBAL_CONF_SCRATCHPAD_10, seq;
	uint32_t page_size = sysconf(_SC_PAGESIZE), offset = 0, val;
	void *ptr;
	int rc, fd = tests_state->fd;

	hltests_debugfs_write(fd, cfg_address, 0x55555555);
	val = hltests_debugfs_read(fd, cfg_address);
	assert_int_equal(val, 0x55555555);

	ptr = hltests_create_cb(fd, page_size, true, 0);
	assert_ptr_not_equal(ptr, NULL);

	offset = hltests_add_msg_long_pkt(fd, ptr, offset, false, false,
						cfg_address, 0xbaba0ded);

	execute_arr[0].cb_ptr = ptr;
	execute_arr[0].cb_size = offset;
	execute_arr[0].queue_index = hltests_get_dma_down_qid(fd, 0, 0);

	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, 1, false, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_cs(fd, seq, WAIT_FOR_CS_DEFAULT_TIMEOUT);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_BUSY);

	rc = hltests_destroy_cb(fd, ptr);
	assert_int_equal(rc, 0);

	val = hltests_debugfs_read(fd, cfg_address);
	assert_int_not_equal(val, 0xbaba0ded);
}

void test_tpc_qman_write_to_protected_register(void **state)
{
	test_qman_write_to_protected_register(state, true);
}

void test_mme_qman_write_to_protected_register(void **state)
{
	test_qman_write_to_protected_register(state, false);
}

void test_write_to_mmTPC_PLL_CLK_RLX_0_from_qman(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	uint32_t val_orig, val, page_size = sysconf(_SC_PAGESIZE), offset = 0;
	void *ptr;
	int fd = tests_state->fd;

	val_orig = hltests_debugfs_read(fd, CFG_BASE + mmTPC_PLL_CLK_RLX_0);

	hltests_debugfs_write(fd, CFG_BASE + mmTPC_PLL_CLK_RLX_0, 0x300030);
	val = hltests_debugfs_read(fd, CFG_BASE + mmTPC_PLL_CLK_RLX_0);
	assert_int_equal(val, 0x300030);

	ptr = hltests_create_cb(fd, page_size, true, 0);
	assert_ptr_not_equal(ptr, NULL);

	offset = hltests_add_msg_long_pkt(fd, ptr, offset, false, false,
			CFG_BASE + mmTPC_PLL_CLK_RLX_0, 0x400040);

	hltests_submit_and_wait_cs(fd, ptr, offset,
				hltests_get_dma_down_qid(fd, 0, 0), true);

	val = hltests_debugfs_read(fd, CFG_BASE + mmTPC_PLL_CLK_RLX_0);
	assert_int_equal(val, 0x400040);

	hltests_debugfs_write(fd, CFG_BASE + mmTPC_PLL_CLK_RLX_0, val_orig);
}

const struct CMUnitTest goya_root_tests[] = {
	cmocka_unit_test_setup(test_debugfs_sram_read_write,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_write_to_cfg_space,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_tpc_qman_write_to_protected_register,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_mme_qman_write_to_protected_register,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_write_to_mmTPC_PLL_CLK_RLX_0_from_qman,
					hltests_ensure_device_operational)
};

static const char *const usage[] = {
	"goya_root [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	if (access("/sys/kernel/debug", R_OK))
		return 0;

	hltests_parser(argc, argv, usage, HLTHUNK_DEVICE_GOYA, goya_root_tests,
			sizeof(goya_root_tests) / sizeof((goya_root_tests)[0]));

	return cmocka_run_group_tests(goya_root_tests, hltests_root_setup,
					hltests_root_teardown);
}
