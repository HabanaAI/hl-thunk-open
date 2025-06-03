// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_nic_tests.h"
#include "gaudi2/gaudi2.h"
#include "gaudi2/asic_reg/gaudi2_regs.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include <sys/wait.h>
#include <sys/time.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <inttypes.h>

#define RESTART_WAIT_TIMNEOUT_S 40

VOID test_axi_drain_functionality_gaudi2(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;
	struct hlthunk_engines_idle_info idle_info;
	uint64_t unused_addr;
	uint32_t val;
	int i, j, rc, fd = tests_state->fd, axi_event = 0;

	/* Verify AXI drain is enabled as we don't want to crash the system */
	val = READ32(CFG_BASE + mmPCIE_WRAP_LBW_DRAIN_CFG);
	if (!(val & BIT(PCIE_WRAP_LBW_DRAIN_CFG_EN_SHIFT))) {
		printf("AXI_DRAIN is disabled, skipping test\n");
		skip();
	}

	/* Writing to unavailable register causes axi drain.
	 * Verify decoder 1 in dcore0 is not available and use its address for
	 * the test
	 */
	if (hw_ip->decoder_enabled_mask & BIT(1)) {
		printf
		     ("No AXI_DRAIN event generation address, skipping test\n");
		skip();
	}
	unused_addr = mmDCORE0_VDEC1_CTRL_BASE;

	for (j = 0 ; j < 10 ; j++) {
		for (i = 0 ; i < 500 ; i++)
			WRITE32(unused_addr, 0);
		for (i = 0 ; i < 10 ; i++)
			val = READ32(unused_addr);
		/*
		 * Check Drain indication
		 */
		val = READ32(CFG_BASE + mmPCIE_WRAP_AXI_DRAIN_IND);
		if (val & 1 << PCIE_WRAP_AXI_DRAIN_IND_LBW_AXI_DRAIN_IND_SHIFT)
			axi_event = 1;
	}

	if (axi_event)
		printf("Caught an AXI event\n");

	/* Verify driver and hw are operational as an indication of success */
	rc = hlthunk_get_busy_engines_mask(fd, &idle_info);
	assert_int_equal(rc, 0);

	END_TEST;
}

VOID test_sm_map_hw_block_hbw_gaudi2(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	uint32_t objs_blk_sz, glbl_blk_sz, reg_val;
	char *objs_blk, *glbl_blk;
	int fd = tests_state->fd;
	uint32_t *reg_ptr, interrupt;
	uint64_t objs_base, glbl_base, cq_mem_va, *cq_mem;

	if (hltests_is_simulator(fd)) {
		printf("This test cannot run in simulator\n");
		skip();
	}

	objs_base = mmDCORE0_SYNC_MNGR_OBJS_BASE - CFG_BASE;
	glbl_base = mmDCORE0_SYNC_MNGR_GLBL_BASE - CFG_BASE;

	/* Allocate a CQ for our purposes */
	cq_mem = hltests_allocate_host_mem(fd, sizeof(uint64_t), NOT_HUGE_MAP);
	assert_non_null(cq_mem);
	cq_mem_va = hltests_get_device_va_for_host_ptr(fd, cq_mem);
	assert_non_null(cq_mem_va);
	*cq_mem = 0;

	interrupt = hltests_get_first_avail_interrupt(fd);

	/* Map the blocks */
	objs_blk = hltests_map_hw_block(fd, mmDCORE1_SYNC_MNGR_OBJS_BASE, &objs_blk_sz);
	assert_non_null(objs_blk);

	glbl_blk = hltests_map_hw_block(fd, mmDCORE1_SYNC_MNGR_GLBL_BASE, &glbl_blk_sz);
	assert_non_null(glbl_blk);

	/* Test HBW */

	/*
	 * Try to configure our ASID as 0. This should not have any effect.
	 * If it does - we have a security issue.
	 */
	reg_val = 0;
	reg_ptr = (void *)(glbl_blk + (mmDCORE0_SYNC_MNGR_GLBL_ASID_NONE_SEC_PRIV - glbl_base));
	assert_int_equal(hltests_write_lbw_mem(fd, reg_ptr, &reg_val, sizeof(reg_val)), 0);
	reg_ptr = (void *)(glbl_blk + (mmDCORE0_SYNC_MNGR_GLBL_ASID_SEC - glbl_base));
	assert_int_equal(hltests_write_lbw_mem(fd, reg_ptr, &reg_val, sizeof(reg_val)), 0);
	reg_ptr = (void *)(glbl_blk + (mmDCORE0_SYNC_MNGR_GLBL_ASID_PRIV_ONLY - glbl_base));
	assert_int_equal(hltests_write_lbw_mem(fd, reg_ptr, &reg_val, sizeof(reg_val)), 0);

	/* Configure CQ0 */
	reg_val = lower_32_bits(cq_mem_va);
	reg_ptr = (void *)(glbl_blk + (mmDCORE0_SYNC_MNGR_GLBL_CQ_BASE_ADDR_L_0 - glbl_base));
	assert_int_equal(hltests_write_lbw_mem(fd, reg_ptr, &reg_val, sizeof(reg_val)), 0);

	reg_val = upper_32_bits(cq_mem_va);
	reg_ptr = (void *)(glbl_blk + (mmDCORE0_SYNC_MNGR_GLBL_CQ_BASE_ADDR_H_0 - glbl_base));
	assert_int_equal(hltests_write_lbw_mem(fd, reg_ptr, &reg_val, sizeof(reg_val)), 0);

	reg_val = 3;
	reg_ptr = (void *)(glbl_blk + (mmDCORE0_SYNC_MNGR_GLBL_CQ_SIZE_LOG2_0 - glbl_base));
	assert_int_equal(hltests_write_lbw_mem(fd, reg_ptr, &reg_val, sizeof(reg_val)), 0);

	reg_val = lower_32_bits(RESERVED_VA_FOR_VIRTUAL_MSIX_DOORBELL_START);
	reg_ptr = (void *)(glbl_blk + (mmDCORE0_SYNC_MNGR_GLBL_LBW_ADDR_L_0 - glbl_base));
	assert_int_equal(hltests_write_lbw_mem(fd, reg_ptr, &reg_val, sizeof(reg_val)), 0);

	reg_val = upper_32_bits(RESERVED_VA_FOR_VIRTUAL_MSIX_DOORBELL_START);
	reg_ptr = (void *)(glbl_blk + (mmDCORE0_SYNC_MNGR_GLBL_LBW_ADDR_H_0 - glbl_base));
	assert_int_equal(hltests_write_lbw_mem(fd, reg_ptr, &reg_val, sizeof(reg_val)), 0);

	reg_val = interrupt;
	reg_ptr = (void *)(glbl_blk + (mmDCORE0_SYNC_MNGR_GLBL_LBW_DATA_0 - glbl_base));
	assert_int_equal(hltests_write_lbw_mem(fd, reg_ptr, &reg_val, sizeof(reg_val)), 0);

	reg_val = 1;
	reg_ptr = (void *)(glbl_blk + (mmDCORE0_SYNC_MNGR_GLBL_CQ_INC_MODE_0 - glbl_base));
	assert_int_equal(hltests_write_lbw_mem(fd, reg_ptr, &reg_val, sizeof(reg_val)), 0);

	/* Zero SOB0 */
	reg_val = 0;
	reg_ptr = (void *)(objs_blk + (mmDCORE0_SYNC_MNGR_OBJS_SOB_OBJ_0 - objs_base));
	assert_int_equal(hltests_write_lbw_mem(fd, reg_ptr, &reg_val, sizeof(reg_val)), 0);

	/* Configure MON0 address as CQ0 */
	reg_val = 0;
	reg_ptr = (void *)(objs_blk + (mmDCORE0_SYNC_MNGR_OBJS_MON_PAY_ADDRL_0 - objs_base));
	assert_int_equal(hltests_write_lbw_mem(fd, reg_ptr, &reg_val, sizeof(reg_val)), 0);
	reg_ptr = (void *)(objs_blk + (mmDCORE0_SYNC_MNGR_OBJS_MON_PAY_ADDRH_0 - objs_base));
	assert_int_equal(hltests_write_lbw_mem(fd, reg_ptr, &reg_val, sizeof(reg_val)), 0);

	/* Monitor payload */
	reg_val = 0xbaba;
	reg_ptr = (void *)(objs_blk + (mmDCORE0_SYNC_MNGR_OBJS_MON_PAY_DATA_0 - objs_base));
	assert_int_equal(hltests_write_lbw_mem(fd, reg_ptr, &reg_val, sizeof(reg_val)), 0);

	/* Configure MON0 in CQ mode */
	reg_val = 1 << DCORE0_SYNC_MNGR_OBJS_MON_CONFIG_CQ_EN_SHIFT |
		  1 << DCORE0_SYNC_MNGR_OBJS_MON_CONFIG_LBW_EN_SHIFT;
	reg_ptr = (void *)(objs_blk + (mmDCORE0_SYNC_MNGR_OBJS_MON_CONFIG_0 - objs_base));
	assert_int_equal(hltests_write_lbw_mem(fd, reg_ptr, &reg_val, sizeof(reg_val)), 0);

	/* Arm MON0 to wait for SOB0 */
	reg_val = 0 << DCORE0_SYNC_MNGR_OBJS_MON_ARM_SID_SHIFT |
		  0b11111110 << DCORE0_SYNC_MNGR_OBJS_MON_ARM_MASK_SHIFT |
		  1 << DCORE0_SYNC_MNGR_OBJS_MON_ARM_SOP_SHIFT |
		  1 << DCORE0_SYNC_MNGR_OBJS_MON_ARM_SOD_SHIFT;
	reg_ptr = (void *)(objs_blk + (mmDCORE0_SYNC_MNGR_OBJS_MON_ARM_0 - objs_base));
	assert_int_equal(hltests_write_lbw_mem(fd, reg_ptr, &reg_val, sizeof(reg_val)), 0);

	/* Set SOB, to activate the whole chain */
	reg_val = 1;
	reg_ptr = (void *)(objs_blk + (mmDCORE0_SYNC_MNGR_OBJS_SOB_OBJ_0 - objs_base));
	assert_int_equal(hltests_write_lbw_mem(fd, reg_ptr, &reg_val, sizeof(reg_val)), 0);

	/* Wait for CQ to report results */
	assert_int_equal(
		hltests_wait_for_interrupt(fd, cq_mem, 1, interrupt,
					   WAIT_FOR_CS_DEFAULT_TIMEOUT),
		0);

	/*
	 * Validate the result is what we written. If it is - it means ASID 1
	 * was used for this transaction. Despite we tried to outsmart the
	 * system and use ASID 0.
	 * Which means we do not have HBW security issue.
	 */
	assert_int_equal(*cq_mem, 0xbaba);

	/* Cleanup */
	assert_int_equal(hltests_unmap_hw_block(fd, objs_blk, objs_blk_sz), 0);
	assert_int_equal(hltests_unmap_hw_block(fd, glbl_blk, glbl_blk_sz), 0);
	assert_int_equal(hltests_free_host_mem(fd, cq_mem), 0);

	END_TEST;
}

VOID test_sm_map_hw_block_lbw_gaudi2_child(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	uint32_t objs_blk_sz, reg_val;
	char *objs_blk;
	int fd = tests_state->fd;
	uint32_t *reg_ptr;
	uint64_t objs_base;

	objs_base = mmDCORE0_SYNC_MNGR_OBJS_BASE - CFG_BASE;

	/* Map the blocks */
	objs_blk = hltests_map_hw_block(fd, mmDCORE1_SYNC_MNGR_OBJS_BASE, &objs_blk_sz);
	assert_non_null(objs_blk);

	/* Zero SOB0 DCORE1 */
	reg_val = 0;
	reg_ptr = (void *)(objs_blk + (mmDCORE0_SYNC_MNGR_OBJS_SOB_OBJ_0 - objs_base));
	assert_int_equal(hltests_write_lbw_mem(fd, reg_ptr, &reg_val, sizeof(reg_val)), 0);

	/* Configure MON0 address as SOB0 DCORE0 which is secured */
	reg_val = lower_32_bits(mmDCORE0_SYNC_MNGR_OBJS_SOB_OBJ_0 + CFG_BASE);
	reg_ptr = (void *)(objs_blk + (mmDCORE0_SYNC_MNGR_OBJS_MON_PAY_ADDRL_0 - objs_base));
	assert_int_equal(hltests_write_lbw_mem(fd, reg_ptr, &reg_val, sizeof(reg_val)), 0);
	reg_val = upper_32_bits(mmDCORE0_SYNC_MNGR_OBJS_SOB_OBJ_0 + CFG_BASE);
	reg_ptr = (void *)(objs_blk + (mmDCORE0_SYNC_MNGR_OBJS_MON_PAY_ADDRH_0 - objs_base));
	assert_int_equal(hltests_write_lbw_mem(fd, reg_ptr, &reg_val, sizeof(reg_val)), 0);

	/* Monitor payload */
	reg_val = 0x13;
	reg_ptr = (void *)(objs_blk + (mmDCORE0_SYNC_MNGR_OBJS_MON_PAY_DATA_0 - objs_base));
	assert_int_equal(hltests_write_lbw_mem(fd, reg_ptr, &reg_val, sizeof(reg_val)), 0);

	/* Configure MON0 DCORE1 */
	reg_val = 0 << DCORE0_SYNC_MNGR_OBJS_MON_CONFIG_CQ_EN_SHIFT |
		  1 << DCORE0_SYNC_MNGR_OBJS_MON_CONFIG_LBW_EN_SHIFT;
	reg_ptr = (void *)(objs_blk + (mmDCORE0_SYNC_MNGR_OBJS_MON_CONFIG_0 - objs_base));
	assert_int_equal(hltests_write_lbw_mem(fd, reg_ptr, &reg_val, sizeof(reg_val)), 0);

	/* Arm MON0 to wait for SOB0 */
	reg_val = 0 << DCORE0_SYNC_MNGR_OBJS_MON_ARM_SID_SHIFT |
		  0b11111110 << DCORE0_SYNC_MNGR_OBJS_MON_ARM_MASK_SHIFT |
		  1 << DCORE0_SYNC_MNGR_OBJS_MON_ARM_SOP_SHIFT |
		  1 << DCORE0_SYNC_MNGR_OBJS_MON_ARM_SOD_SHIFT;
	reg_ptr = (void *)(objs_blk + (mmDCORE0_SYNC_MNGR_OBJS_MON_ARM_0 - objs_base));
	assert_int_equal(hltests_write_lbw_mem(fd, reg_ptr, &reg_val, sizeof(reg_val)), 0);

	/* Set SOB0 DCORE1, to activate the whole chain */
	reg_val = 1;
	reg_ptr = (void *)(objs_blk + (mmDCORE0_SYNC_MNGR_OBJS_SOB_OBJ_0 - objs_base));
	assert_int_equal(hltests_write_lbw_mem(fd, reg_ptr, &reg_val, sizeof(reg_val)), 0);

	/* Small sleep, allow transaction to happen */
	sleep(10);

	fail_msg("Child process must be dead at this point");

	END_TEST;
}

VOID test_sm_map_hw_block_lbw_gaudi2(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct timeval te_start, te_now;
	int fd = tests_state->fd, rc;
	char pci_bus_id[13];
	uint64_t elapsed = 0;
	pid_t pid;

	if (hltests_is_simulator(fd)) {
		printf("This test cannot run in simulator\n");
		skip();
	}

	/*
	 * During this test, we validate that a user process does NOT have
	 * access to secured LBW registers.
	 * There is one problem - how to check it? If we simply try to access
	 * such register, it will cause a PMMU error, and, as a result,
	 * kill our process. So how can we report success?
	 * Here is the trick:
	 * We create a child process, and transfer our handles ownership to it.
	 * Then we run the test on a child process. The parent process expects
	 * the child to be killed with SIGKILL. In this case, its exit code is
	 * 9 (SIGKILL). Any other code indicates the test failure.
	 * After that, the parent process takes handles ownership back.
	 */

	/* Release the device */
	rc = hlthunk_get_pci_bus_id_from_fd(fd, pci_bus_id, sizeof(pci_bus_id));
	assert_int_equal(rc, 0);
	rc = hltests_teardown_user_engines(tests_state);
	assert_int_equal(rc, 0);
	rc = hltests_close(fd);
	assert_int_equal(rc, 0);

	pid = fork();

	if (pid == 0) {
		/* The child process */
		fd = tests_state->fd = hltests_open(pci_bus_id);
		assert_in_range(fd, 0, INT_MAX);
		rc = hltests_setup_user_engines(tests_state);
		assert_int_equal(rc, 0);
		END_TEST_FUNC(test_sm_map_hw_block_lbw_gaudi2_child(state));
	} else if (pid > 0) {
		/* The parent process */
		if (pid != wait(&rc))
			fail_msg("Waiting for child failed");
		assert_int_equal(rc, 9);
	} else {
		/* Error */
		fail_msg("Fork failed");
	}

	/* Reopen the device - the device is in reset, so first sleep */

	gettimeofday(&te_start, NULL);
	while (elapsed < RESTART_WAIT_TIMNEOUT_S) {
		fd = tests_state->fd = hltests_open(pci_bus_id);
		if (fd > 0 && fd < INT_MAX)
			break;
		sleep(2);
		gettimeofday(&te_now, NULL);
		elapsed = te_now.tv_sec - te_start.tv_sec;
	}

	assert_in_range(fd, 0, INT_MAX);
	rc = hltests_setup_user_engines(tests_state);
	assert_int_equal(rc, 0);

	END_TEST;
}

VOID test_sm_sei_err_gaudi2(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hltests_cs_chunk execute_arr[1];
	struct hltests_pkt_info pkt_info;
	struct hltests_monitor mon_info;
	int fd = tests_state->fd;
	uint32_t cb_size = 0;
	uint16_t mon, sob;
	uint64_t seq;
	void *cb;
	int rc;

	cb = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	assert_non_null(cb);

	sob = hltests_get_first_avail_sob(fd);
	hltests_clear_sobs(fd, 1);
	mon = hltests_get_first_avail_mon(fd) - 7;

	memset(&mon_info, 0, sizeof(mon_info));
	mon_info.qid = hltests_get_dma_down_qid(fd, STREAM0);
	mon_info.sob_id = sob;
	mon_info.mon_id = mon;
	mon_info.sob_val = 1;

	/* Set payload to be more than compared value */
	mon_info.mon_payload = 1;
	mon_info.cq_enable = 0;
	mon_info.mon_address = CFG_BASE + mmPCIE_WRAP_LBW_DRAIN_CFG + 8;
	mon_info.mon_mode = SOB_EQUAL;
	cb_size = hltests_add_monitor(fd, cb, cb_size, &mon_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id = sob;
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_ADD;
	cb_size = hltests_add_write_to_sob_pkt(fd, cb, cb_size, &pkt_info);

	execute_arr[0].cb_ptr = cb;
	execute_arr[0].cb_size = cb_size;
	execute_arr[0].queue_index = hltests_get_dma_down_qid(fd, STREAM0);

	rc = hltests_submit_cs_timeout(fd, NULL, 0, execute_arr, 1, 0,
			30, &seq);
	assert_int_equal(rc, 0);

	END_TEST;
}

#ifndef HLTESTS_LIB_MODE

const struct CMUnitTest gaudi2_root_tests[] = {
	cmocka_unit_test_setup(test_axi_drain_functionality_gaudi2,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_sm_map_hw_block_lbw_gaudi2,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_sm_map_hw_block_hbw_gaudi2,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_sm_sei_err_gaudi2,
				hltests_ensure_device_operational),
};

static const char *const usage[] = {
	"gaudi2_root [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = sizeof(gaudi2_root_tests) /
			sizeof((gaudi2_root_tests)[0]);

	hltests_parser(argc, argv, usage, HLTEST_DEVICE_MASK_GAUDI2_ALL,
			gaudi2_root_tests, num_tests);

	if (!can_open_debugfs(true))
		return 0;

	if (!hltests_get_parser_run_disabled_tests()) {
		printf("gaudi2_root tests should run with --disabled option\n");
		return 0;
	}

	hltests_set_capabilities_mask(CAP_ARC_FW_LOAD_SCHED_MASK |
				CAP_ARC_FW_LOAD_PDMA_MASK);
	return hltests_run_group_tests("gaudi2_root",
				gaudi2_root_tests, num_tests,
				hltests_root_nic_setup, hltests_root_nic_teardown);
}

#endif /* HLTESTS_LIB_MODE */
