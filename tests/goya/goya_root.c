// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_tests.h"
#include "goya/goya.h"
#include "goya/asic_reg/goya_regs.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

VOID test_qman_write_to_protected_register(void **state, bool is_tpc)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	struct hltests_cs_chunk restore_arr[1], execute_arr[2];
	struct hltests_pkt_info pkt_info;
	struct hltests_monitor_and_fence mon_and_fence_info;
	void *engine_cb, *restore_cb, *dma_cb;
	uint64_t cfg_address, engine_cb_sram_addr, engine_cb_device_va, seq;
	uint32_t engine_qid, engine_cb_size, restore_cb_size,
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

	/* Set engine queue ID and SRAM addresses */
	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.sram_size)
		skip();

	if (is_tpc) {
		/* Find first available TPC */
		uint8_t tpc_id, tpc_cnt;

		tpc_cnt = hltests_get_tpc_cnt(fd);
		for (tpc_id = 0;
			(!(hw_ip.tpc_enabled_mask & (0x1 << tpc_id))) &&
			(tpc_id < tpc_cnt);)
			tpc_id++;

		assert_in_range(tpc_id, 0, tpc_cnt - 1);
		engine_qid = hltests_get_tpc_qid(fd, tpc_id, STREAM0);
	} else {
		engine_qid = hltests_get_mme_qid(fd, 0, 0);
	}

	engine_cb_sram_addr = hw_ip.sram_base_address + 0x3000;

	/* Internal CB for engine QMAN: MSG_LONG + signal SOB0 */
	engine_cb = hltests_create_cb(fd, SZ_4K, INTERNAL, engine_cb_sram_addr);
	assert_non_null(engine_cb);
	engine_cb_device_va = hltests_get_device_va_for_host_ptr(fd, engine_cb);
	engine_cb_size = 0;
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.msg_long.address = cfg_address;
	pkt_info.msg_long.value = 0x789a0ded;
	engine_cb_size = hltests_add_msg_long_pkt(fd, engine_cb,
					engine_cb_size,	&pkt_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id = 0;
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_ADD;
	engine_cb_size = hltests_add_write_to_sob_pkt(fd, engine_cb,
					engine_cb_size, &pkt_info);

	/* Setup CB: Clear SOB0 + DMA the internal CB to SRAM */
	hltests_clear_sobs(fd, 1);
	restore_cb =  hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	assert_non_null(restore_cb);
	restore_cb_size = 0;


	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.dma.src_addr = engine_cb_device_va;
	pkt_info.dma.dst_addr = engine_cb_sram_addr;
	pkt_info.dma.size = engine_cb_size;
	pkt_info.dma.dma_dir = DMA_DIR_HOST_TO_SRAM;
	restore_cb_size = hltests_add_dma_pkt(fd, restore_cb, restore_cb_size,
					&pkt_info);

	/* CB for DMA QMAN: Fence on SOB0 */
	dma_cb = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	assert_non_null(dma_cb);
	dma_cb_size = 0;

	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = hltests_get_dma_down_qid(fd, STREAM0);
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = 0;
	mon_and_fence_info.mon_id = 0;
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.sob_val = 1;
	mon_and_fence_info.dec_fence = true;
	mon_and_fence_info.mon_payload = 1;
	dma_cb_size = hltests_add_monitor_and_fence(fd, dma_cb,
					dma_cb_size, &mon_and_fence_info);

	/* Submit CS and wait for completion */
	restore_arr[0].cb_ptr = restore_cb;
	restore_arr[0].cb_size = restore_cb_size;
	restore_arr[0].queue_index = hltests_get_dma_down_qid(fd, STREAM0);

	execute_arr[0].cb_ptr = engine_cb;
	execute_arr[0].cb_size = engine_cb_size;
	execute_arr[0].queue_index = engine_qid;

	execute_arr[1].cb_ptr = dma_cb;
	execute_arr[1].cb_size = dma_cb_size;
	execute_arr[1].queue_index = hltests_get_dma_down_qid(fd, STREAM0);

	rc = hltests_submit_cs(fd, restore_arr, 1, execute_arr, 2, 0, &seq);
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
	val = RREG32(cfg_address);
	assert_int_not_equal(val, 0x789a0ded);

	END_TEST;
}

VOID test_goya_debugfs_sram_read_write(void **state)
{
	struct hltests_state *tests_state =
					(struct hltests_state *) *state;
	uint32_t val;

	WREG32(SRAM_BASE_ADDR + 0x200000, 0x99775533);
	WREG32(SRAM_BASE_ADDR + 0x200000, 0x12345678);
	val = RREG32(SRAM_BASE_ADDR + 0x200000);

	assert_int_equal(0x12345678, val);

	END_TEST;
}

VOID test_write_to_cfg_space(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hltests_cs_chunk execute_arr[1];
	struct hltests_pkt_info pkt_info;
	uint64_t cfg_address = CFG_BASE + mmPSOC_GLOBAL_CONF_SCRATCHPAD_10;
	uint32_t offset = 0, val;
	void *ptr;
	int fd = tests_state->fd;

	WREG32(cfg_address, 0x55555555);
	val = RREG32(cfg_address);
	assert_int_equal(val, 0x55555555);

	ptr = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	assert_non_null(ptr);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.msg_long.address = cfg_address;
	pkt_info.msg_long.value = 0xbaba0ded;
	offset = hltests_add_msg_long_pkt(fd, ptr, offset, &pkt_info);

	execute_arr[0].cb_ptr = ptr;
	execute_arr[0].cb_size = offset;
	execute_arr[0].queue_index = hltests_get_dma_down_qid(fd, STREAM0);
	hltests_submit_and_wait_cs(fd, ptr, offset,
				hltests_get_dma_down_qid(fd, STREAM0),
				DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_TIMEDOUT);

	val = RREG32(cfg_address);
	assert_int_not_equal(val, 0xbaba0ded);

	END_TEST;
}

VOID test_tpc_qman_write_to_protected_register(void **state)
{
	END_TEST_FUNC(test_qman_write_to_protected_register(state, true));
}

VOID test_mme_qman_write_to_protected_register(void **state)
{
	END_TEST_FUNC(test_qman_write_to_protected_register(state, false));
}

VOID test_write_to_mmTPC_PLL_CLK_RLX_0_from_qman(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hltests_pkt_info pkt_info;
	uint32_t val_orig, val, offset = 0;
	void *ptr;
	int fd = tests_state->fd;

	val_orig = RREG32(CFG_BASE + mmTPC_PLL_CLK_RLX_0);

	WREG32(CFG_BASE + mmTPC_PLL_CLK_RLX_0, 0x300030);
	val = RREG32(CFG_BASE + mmTPC_PLL_CLK_RLX_0);
	assert_int_equal(val, 0x300030);

	ptr = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	assert_non_null(ptr);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.msg_long.address = CFG_BASE + mmTPC_PLL_CLK_RLX_0;
	pkt_info.msg_long.value = 0x400040;
	offset = hltests_add_msg_long_pkt(fd, ptr, offset, &pkt_info);

	hltests_submit_and_wait_cs(fd, ptr, offset,
				hltests_get_dma_down_qid(fd, STREAM0),
				DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_COMPLETED);

	val = RREG32(CFG_BASE + mmTPC_PLL_CLK_RLX_0);
	assert_int_equal(val, 0x400040);

	WREG32(CFG_BASE + mmTPC_PLL_CLK_RLX_0, val_orig);

	END_TEST;
}

#ifndef HLTESTS_LIB_MODE

const struct CMUnitTest goya_root_tests[] = {
	cmocka_unit_test_setup(test_goya_debugfs_sram_read_write,
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
	int num_tests = sizeof(goya_root_tests) / sizeof((goya_root_tests)[0]);

	hltests_parser(argc, argv, usage, HLTEST_DEVICE_MASK_GOYA, goya_root_tests,
			num_tests);

	if (access("/sys/kernel/debug", R_OK)) {
		printf("This executable need to be run with sudo\n");
		return 0;
	}

	return hltests_run_group_tests("goya_root", goya_root_tests, num_tests,
				hltests_root_setup, hltests_root_teardown);
}

#endif /* HLTESTS_LIB_MODE */
