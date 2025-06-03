// SPDX-License-Identifier: MIT

/*
 * Copyright 2022 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_tests.h"
#include "gaudi3/gaudi3.h"
#include "gaudi3/asic_reg/gaudi3_regs.h"

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

VOID test_sm_map_hw_block_hbw_gaudi3(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	uint32_t objs_blk_sz, glbl_blk_sz, reg_val;
	char *objs_blk, *glbl_blk;
	int fd = tests_state->fd;
	uint32_t *reg_ptr, interrupt;
	uint64_t glbl_usr_hb_base, glbl_sec_hb_base, glbl_priv_hb_base, cq_mem_va, *cq_mem;

	glbl_usr_hb_base = mmHD0_SYNC_MNGR_GLBL_USR_HBW_USER_BASE - mmHD0_SYNC_MNGR_GLBL_BASE;
	glbl_sec_hb_base = mmHD0_SYNC_MNGR_GLBL_SEC_HBW_USER_BASE - mmHD0_SYNC_MNGR_GLBL_BASE;
	glbl_priv_hb_base = mmHD0_SYNC_MNGR_GLBL_PRIV_HBW_USER_BASE - mmHD0_SYNC_MNGR_GLBL_BASE;

	/* Allocate a CQ for our purposes */
	cq_mem = hltests_allocate_host_mem(fd, sizeof(uint64_t), NOT_HUGE_MAP);
	assert_non_null(cq_mem);
	cq_mem_va = hltests_get_device_va_for_host_ptr(fd, cq_mem);
	assert_non_null(cq_mem_va);
	*cq_mem = 0;

	interrupt = hltests_get_first_avail_interrupt(fd);

	/* Map the blocks */
	objs_blk = hltests_map_hw_block(fd, mmHD1_SYNC_MNGR_OBJS_BASE, &objs_blk_sz);
	assert_non_null(objs_blk);

	glbl_blk = hltests_map_hw_block(fd, mmHD1_SYNC_MNGR_GLBL_BASE, &glbl_blk_sz);
	assert_non_null(glbl_blk);

	/* Test HBW */

	/*
	 * Try to configure our ASID as 0. This should not have any effect.
	 * If it does - we have a security issue.
	 */
	reg_val = 0;
	reg_ptr = (void *)(glbl_blk + (glbl_usr_hb_base + mmSOB_GLBL_USR_HBW_USER_HB_ASID));
	assert_int_equal(hltests_write_lbw_reg(fd, reg_ptr, reg_val), 0);
	reg_ptr = (void *)(glbl_blk + (glbl_usr_hb_base + mmSOB_GLBL_USR_HBW_USER_HB_ASID_OVRD));
	assert_int_equal(hltests_write_lbw_reg(fd, reg_ptr, reg_val), 0);
	reg_ptr = (void *)(glbl_blk + (glbl_sec_hb_base + mmSOB_GLBL_SEC_HBW_USER_HB_ASID));
	assert_int_equal(hltests_write_lbw_reg(fd, reg_ptr, reg_val), 0);
	reg_ptr = (void *)(glbl_blk + (glbl_sec_hb_base + mmSOB_GLBL_SEC_HBW_USER_HB_ASID_OVRD));
	assert_int_equal(hltests_write_lbw_reg(fd, reg_ptr, reg_val), 0);
	reg_ptr = (void *)(glbl_blk + (glbl_priv_hb_base + mmSOB_GLBL_PRIV_HBW_USER_HB_ASID));
	assert_int_equal(hltests_write_lbw_reg(fd, reg_ptr, reg_val), 0);
	reg_ptr = (void *)(glbl_blk + (glbl_priv_hb_base + mmSOB_GLBL_PRIV_HBW_USER_HB_ASID_OVRD));
	assert_int_equal(hltests_write_lbw_reg(fd, reg_ptr, reg_val), 0);

	/* Configure CQ0 */
	reg_val = lower_32_bits(cq_mem_va);
	reg_ptr = (void *)(glbl_blk + mmSOB_GLBL_CQ_BASE_ADDR_L_0);
	assert_int_equal(hltests_write_lbw_reg(fd, reg_ptr, reg_val), 0);

	reg_val = upper_32_bits(cq_mem_va);
	reg_ptr = (void *)(glbl_blk + mmSOB_GLBL_CQ_BASE_ADDR_H_0);
	assert_int_equal(hltests_write_lbw_reg(fd, reg_ptr, reg_val), 0);

	reg_val = 3;
	reg_ptr = (void *)(glbl_blk + mmSOB_GLBL_CQ_SIZE_LOG2_0);
	assert_int_equal(hltests_write_lbw_reg(fd, reg_ptr, reg_val), 0);

	reg_val = lower_32_bits(mmD0_PCIE_MSIX_BASE);
	reg_ptr = (void *)(glbl_blk + mmSOB_GLBL_LBW_ADDR_L_0);
	assert_int_equal(hltests_write_lbw_reg(fd, reg_ptr, reg_val), 0);

	reg_val = upper_32_bits(mmD0_PCIE_MSIX_BASE);
	reg_ptr = (void *)(glbl_blk + mmSOB_GLBL_LBW_ADDR_H_0);
	assert_int_equal(hltests_write_lbw_reg(fd, reg_ptr, reg_val), 0);

	reg_val = interrupt;
	reg_ptr = (void *)(glbl_blk + mmSOB_GLBL_LBW_DATA_0);
	assert_int_equal(hltests_write_lbw_reg(fd, reg_ptr, reg_val), 0);

	reg_val = 1;
	reg_ptr = (void *)(glbl_blk + mmSOB_GLBL_CQ_INC_MODE_0);
	assert_int_equal(hltests_write_lbw_reg(fd, reg_ptr, reg_val), 0);

	/* Zero SOB0 */
	reg_val = 0;
	reg_ptr = (void *)(objs_blk + mmSOB_OBJS_SOB_OBJ_0_0);
	assert_int_equal(hltests_write_lbw_reg(fd, reg_ptr, reg_val), 0);

	/* Configure MON0 address as CQ0 */
	reg_val = 0;
	reg_ptr = (void *)(objs_blk + mmSOB_OBJS_MON_PAY_ADDRL_0_0);
	assert_int_equal(hltests_write_lbw_reg(fd, reg_ptr, reg_val), 0);
	reg_ptr = (void *)(objs_blk + mmSOB_OBJS_MON_PAY_ADDRH_0_0);
	assert_int_equal(hltests_write_lbw_reg(fd, reg_ptr, reg_val), 0);

	/* Monitor payload */
	reg_val = 0xbaba;
	reg_ptr = (void *)(objs_blk + mmSOB_OBJS_MON_PAY_DATA_0_0);
	assert_int_equal(hltests_write_lbw_reg(fd, reg_ptr, reg_val), 0);

	/* Configure MON0 in CQ mode */
	reg_val = 1 << SOB_OBJS_MON_CONFIG_0_CQ_EN_S |
		  1 << SOB_OBJS_MON_CONFIG_0_LBW_EN_S;
	reg_ptr = (void *)(objs_blk + mmSOB_OBJS_MON_CONFIG_0_0);
	assert_int_equal(hltests_write_lbw_reg(fd, reg_ptr, reg_val), 0);

	/* Arm MON0 to wait for SOB0 */
	reg_val = 0 << SOB_OBJS_MON_ARM_0_SID_S |
		  0b11111110 << SOB_OBJS_MON_ARM_0_MASK_S |
		  1 << SOB_OBJS_MON_ARM_0_SOP_S |
		  1 << SOB_OBJS_MON_ARM_0_SOD_S;
	reg_ptr = (void *)(objs_blk + mmSOB_OBJS_MON_ARM_0_0);
	assert_int_equal(hltests_write_lbw_reg(fd, reg_ptr, reg_val), 0);

	/* Set SOB, to activate the whole chain */
	reg_val = 1;
	reg_ptr = (void *)(objs_blk + mmSOB_OBJS_SOB_OBJ_0_0);
	assert_int_equal(hltests_write_lbw_reg(fd, reg_ptr, reg_val), 0);

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

VOID test_sm_map_hw_block_lbw_gaudi3(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	uint32_t objs_blk_sz, reg_val;
	char *objs_blk;
	int fd = tests_state->fd, rc;
	uint32_t *reg_ptr;

	if (hltests_is_simulator(fd)) {
		printf("Test is not supported on simulator, skipping.\n");
		skip();
	}

	/* Map the SYNC_MNGR_OBJS block */
	objs_blk = hltests_map_hw_block(fd, mmHD1_SYNC_MNGR_OBJS_BASE, &objs_blk_sz);
	assert_non_null(objs_blk);

	/* Zero SOB0 HD1 */
	reg_val = 0;
	reg_ptr = (void *)(objs_blk + mmSOB_OBJS_SOB_OBJ_0_0);
	assert_int_equal(hltests_write_lbw_reg(fd, reg_ptr, reg_val), 0);

	/* Configure MON0 address as SOB0 HD0 which is secured */
	reg_val = lower_32_bits(mmHD0_SYNC_MNGR_OBJS_BASE + mmSOB_OBJS_SOB_OBJ_0_0);
	reg_ptr = (void *)(objs_blk + mmSOB_OBJS_MON_PAY_ADDRL_0_0);
	assert_int_equal(hltests_write_lbw_reg(fd, reg_ptr, reg_val), 0);
	reg_val = upper_32_bits(mmHD0_SYNC_MNGR_OBJS_BASE + mmSOB_OBJS_SOB_OBJ_0_0);
	reg_ptr = (void *)(objs_blk + mmSOB_OBJS_MON_PAY_ADDRH_0_0);
	assert_int_equal(hltests_write_lbw_reg(fd, reg_ptr, reg_val), 0);

	/* Monitor payload */
	reg_val = 0x13;
	reg_ptr = (void *)(objs_blk + mmSOB_OBJS_MON_PAY_DATA_0_0);
	assert_int_equal(hltests_write_lbw_reg(fd, reg_ptr, reg_val), 0);

	/* Configure MON0 HD1 */
	reg_val = 0 << SOB_OBJS_MON_CONFIG_0_CQ_EN_S |
		  1 << SOB_OBJS_MON_CONFIG_0_LBW_EN_S;
	reg_ptr = (void *)(objs_blk + mmSOB_OBJS_MON_CONFIG_0_0);
	assert_int_equal(hltests_write_lbw_reg(fd, reg_ptr, reg_val), 0);

	/* Arm MON0 to wait for SOB0 */
	reg_val = 0 << SOB_OBJS_MON_ARM_0_SID_S |
		  0b11111110 << SOB_OBJS_MON_ARM_0_MASK_S |
		  1 << SOB_OBJS_MON_ARM_0_SOP_S |
		  1 << SOB_OBJS_MON_ARM_0_SOD_S;
	reg_ptr = (void *)(objs_blk + mmSOB_OBJS_MON_ARM_0_0);
	assert_int_equal(hltests_write_lbw_reg(fd, reg_ptr, reg_val), 0);

	/* Set SOB0 HD1, to activate the whole chain */
	reg_val = 1;
	reg_ptr = (void *)(objs_blk + mmSOB_OBJS_SOB_OBJ_0_0);
	assert_int_equal(hltests_write_lbw_reg(fd, reg_ptr, reg_val), 0);

	/* Verify that the expected events are received */
	rc = hltests_wait_for_events(tests_state, 0, HL_NOTIFIER_EVENT_USER_ENGINE_ERR, NULL);
	assert_int_equal(rc, 0);

	/* Unmap the SYNC_MNGR_OBJS block */
	rc = hltests_unmap_hw_block(fd, objs_blk, objs_blk_sz);
	assert_int_equal(rc, 0);

	/* Recovery */
	rc = hltests_teardown_and_setup(tests_state);
	assert_int_equal(rc, 0);

	/* Sanity check after the recovery */
	fd = tests_state->fd;
	assert_true(hlthunk_is_device_idle(fd));

	END_TEST;
}

#ifndef HLTESTS_LIB_MODE

const struct CMUnitTest gaudi3_sm_tests[] = {
	cmocka_unit_test_setup(test_sm_map_hw_block_lbw_gaudi3,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_sm_map_hw_block_hbw_gaudi3,
				hltests_ensure_device_operational),
};

static const char *const usage[] = {
	"gaudi3_sm [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = ARRAY_SIZE(gaudi3_sm_tests);

	hltests_parser(argc, argv, usage, HLTEST_DEVICE_MASK_GAUDI3_ALL,
		       gaudi3_sm_tests, num_tests);

	if (!hltests_get_parser_run_disabled_tests())
		return 0;

	return hltests_run_group_tests("gaudi3_sm",
				gaudi3_sm_tests, num_tests,
				hltests_setup, hltests_teardown);
}

#endif /* HLTESTS_LIB_MODE */
