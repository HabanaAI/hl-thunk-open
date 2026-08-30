// SPDX-License-Identifier: MIT

/*
 * Copyright 2022 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_tests.h"
#include "gaudi3/gaudi3.h"
#include "gaudi3/asic_reg/gaudi3_regs.h"

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>

/* PCIE_WRAP_DBI_ACCESS */
#define MSIX_MASK_CTRL_ENABLE_COALESCING \
	(FIELD_PREP(PCIE_WRAP_DBI_ACCESS_MSIX_MASK_CTRL_EN_M, 0x1) | \
			FIELD_PREP(PCIE_WRAP_DBI_ACCESS_MSIX_MASK_CTRL_RESP_M, 0x1))
#define MSIX_MASK_CTRL_DISABLE_COALESCING \
	(FIELD_PREP(PCIE_WRAP_DBI_ACCESS_MSIX_MASK_CTRL_EN_M, 0x0) | \
			FIELD_PREP(PCIE_WRAP_DBI_ACCESS_MSIX_MASK_CTRL_RESP_M, 0x1))

/* A short sleep to let the driver complete the handling of a generated interrupt */
#define DRV_INTERRUPT_HANDLING_SLEEP_USEC	10000	/* 10 msec */

/* Interrupt coalescing window of 2 sec (PCIE CLK clock is 1GHz) */
#define MSIX_LARGE_COALESCING_SEC		2
#define MSIX_LARGE_COALESCING_CNT		(MSIX_LARGE_COALESCING_SEC * 1000000000)
#define PLDM_MSIX_LARGE_COALESCING_CNT		(MSIX_LARGE_COALESCING_CNT / 10000)

/* Twice the length of the coalescing window because the PLDM factor is an approximation */
#define COALESCING_TEST_SLEEP_TIME_SEC		(2 * MSIX_LARGE_COALESCING_SEC)

struct test_coalescing_params {
	struct hltests_cb cq_cb;
	uint64_t cq_device_va;
	uint32_t irq;
	uint32_t num_intr_before;
	uint32_t num_intr_after;
	uint16_t interrupt_id;
	uint16_t cq_id;
};

static VOID test_coalescing_run_shell_command(const char *cmd, char *output, uint32_t output_size)
{
	FILE *fp;
	int rc;

	fp = popen(cmd, "r");
	assert_non_null(fp);

	output = fgets(output, uint_to_int_safe(output_size), fp);
	assert_non_null(output);

	errno = 0;
	rc = pclose(fp);
	assert_return_code(rc, errno);

	END_TEST;
}

static uint32_t test_coalescing_get_irq_from_interrupt_id(int fd, uint16_t interrupt_id)
{
	char pci_bus_id[13], cmd[128] = {0}, output[32] = {0};
	unsigned long start_irq;
	int rc;

	rc = hlthunk_get_pci_bus_id_from_fd(fd, pci_bus_id, sizeof(pci_bus_id));
	assert_int_equal_ret_val(rc, 0, UINT32_MAX);

	rc = snprintf(cmd, sizeof(cmd),
			"ls -v /sys/bus/pci/devices/%s/msi_irqs/ | head -n 1", pci_bus_id);
	assert_in_range_ret_val(rc, 0, INT_MAX, UINT32_MAX);

	test_coalescing_run_shell_command(cmd, output, sizeof(output));

	errno = 0;
	start_irq = strtoul(output, NULL, 10);
	assert_int_equal_ret_val(errno, 0, UINT32_MAX);

	return u32_safe_ret_val(start_irq + interrupt_id, UINT32_MAX);
}

static uint32_t test_coalescing_get_num_of_interrupts(uint32_t irq)
{
	char cmd[128] = {0}, output[32] = {0};
	unsigned long num_of_interrupts;
	int rc;

	rc = snprintf(cmd, sizeof(cmd),
			"cat /sys/kernel/irq/%d/per_cpu_count | sed -e 's/,/+/g' | bc", irq);
	assert_in_range_ret_val(rc, 0, INT_MAX, UINT32_MAX);

	test_coalescing_run_shell_command(cmd, output, sizeof(output));

	errno = 0;
	num_of_interrupts = strtoul(output, NULL, 10);
	assert_int_equal_ret_val(errno, 0, UINT32_MAX);

	return u32_safe_ret_val(num_of_interrupts, UINT32_MAX);
}

static VOID test_coalescing_create_cq_cb(int fd, struct hltests_cb *cq_cb, uint64_t *cq_device_va)
{
	int rc;

	memset(cq_cb, 0, sizeof(*cq_cb));
	cq_cb->cb_size = sizeof(uint64_t);

	rc = hlthunk_request_mapped_command_buffer(fd, cq_cb->cb_size, &cq_cb->cb_handle);
	assert_int_equal(rc, 0);

	cq_cb->ptr = hltests_mmap(fd, cq_cb->cb_size, (off_t)cq_cb->cb_handle);
	assert_ptr_not_equal(cq_cb->ptr, MAP_FAILED);

	rc = hlthunk_get_mapped_cb_device_va_by_handle(fd, cq_cb->cb_handle, cq_device_va);
	assert_int_equal(rc, 0);

	*(uint64_t *) cq_cb->ptr = 0;

	END_TEST;
}

static VOID test_coalescing_release_cq_cb(int fd, struct hltests_cb *cq_cb)
{
	int rc;

	rc = hltests_munmap(fd, cq_cb->ptr, cq_cb->cb_size);
	assert_int_equal(rc, 0);

	rc = hlthunk_destroy_command_buffer(fd, cq_cb->cb_handle);
	assert_int_equal(rc, 0);

	END_TEST;
}

static VOID test_coalescing_configure_cq(int fd, uint16_t cq_id, uint16_t interrupt_id,
					uint64_t cq_device_va, uint8_t *sm_glbl_start_addr)
{
	uint32_t cq_offset = cq_id * sizeof(uint32_t);
	uint64_t msix_db_reg = mmD0_PCIE_MSIX_BASE;
	void *sm_glbl_addr;
	int rc;

	/* HD2_SYNC_MNGR_GLBL.CQ_BASE_ADDR_L */
	sm_glbl_addr = sm_glbl_start_addr + mmSOB_GLBL_CQ_BASE_ADDR_L_0 + cq_offset;
	rc = hltests_write_lbw_reg(fd, sm_glbl_addr, lower_32_bits(cq_device_va));
	assert_int_equal(rc, 0);

	/* HD2_SYNC_MNGR_GLBL.CQ_BASE_ADDR_H */
	sm_glbl_addr = sm_glbl_start_addr + mmSOB_GLBL_CQ_BASE_ADDR_H_0 + cq_offset;
	rc = hltests_write_lbw_reg(fd, sm_glbl_addr, upper_32_bits(cq_device_va));
	assert_int_equal(rc, 0);

	/* HD2_SYNC_MNGR_GLBL.CQ_SIZE_LOG2 */
	sm_glbl_addr = sm_glbl_start_addr + mmSOB_GLBL_CQ_SIZE_LOG2_0 + cq_offset;
	rc = hltests_write_lbw_reg(fd, sm_glbl_addr, CQ_SIZE_LOG_2);
	assert_int_equal(rc, 0);

	/* HD2_SYNC_MNGR_GLBL.LBW_ADDR_L */
	sm_glbl_addr = sm_glbl_start_addr + mmSOB_GLBL_LBW_ADDR_L_0 + cq_offset;
	rc = hltests_write_lbw_reg(fd, sm_glbl_addr, lower_32_bits(msix_db_reg));
	assert_int_equal(rc, 0);

	/* HD2_SYNC_MNGR_GLBL.LBW_ADDR_H */
	sm_glbl_addr = sm_glbl_start_addr + mmSOB_GLBL_LBW_ADDR_H_0 + cq_offset;
	rc = hltests_write_lbw_reg(fd, sm_glbl_addr, upper_32_bits(msix_db_reg));
	assert_int_equal(rc, 0);

	/* HD2_SYNC_MNGR_GLBL.LBW_DATA */
	sm_glbl_addr = sm_glbl_start_addr + mmSOB_GLBL_LBW_DATA_0 + cq_offset;
	rc = hltests_write_lbw_reg(fd, sm_glbl_addr, interrupt_id);
	assert_int_equal(rc, 0);

	/* HD2_SYNC_MNGR_GLBL.CQ_INC_MODE */
	sm_glbl_addr = sm_glbl_start_addr + mmSOB_GLBL_CQ_INC_MODE_0 + cq_offset;
	rc = hltests_write_lbw_reg(fd, sm_glbl_addr, 0x1);
	assert_int_equal(rc, 0);

	END_TEST;
}

static VOID test_coalescing_generate_interrupt(int fd, uint16_t cq_id, uint8_t *sm_objs_start_addr)
{
	uint32_t cq_offset = cq_id * sizeof(uint32_t);
	void *sm_objs_addr;
	int rc;

	/* HD2_SYNC_MNGR_OBJS.CQ_DIRECT */
	sm_objs_addr = sm_objs_start_addr + mmSOB_OBJS_CQ_DIRECT_0 + cq_offset;
	rc = hltests_write_lbw_reg(fd, sm_objs_addr, 1); /* add 1 to the CQ 64-bit counter */
	assert_int_equal(rc, 0);

	END_TEST;
}

static void test_coalescing_save_and_set_regs(struct hltests_state *tests_state, uint32_t mask_ctrl,
						uint32_t glbl_cnt, uint32_t *old_mask_ctrl,
						uint32_t *old_glbl_cnt)
{
	uint64_t mask_ctrl_addr, glbl_cnt_addr;

	mask_ctrl_addr = mmD0_PCIE_WRAP_DBI_ACCESS_BASE + mmPCIE_WRAP_DBI_ACCESS_MSIX_MASK_CTRL;
	glbl_cnt_addr = mmD0_PCIE_WRAP_DBI_ACCESS_BASE + mmPCIE_WRAP_DBI_ACCESS_MSIX_GLBL_CNT;

	if (old_mask_ctrl)
		*old_mask_ctrl = READ32(mask_ctrl_addr);
	if (old_glbl_cnt)
		*old_glbl_cnt = READ32(glbl_cnt_addr);

	WRITE32(mask_ctrl_addr, mask_ctrl);
	WRITE32(glbl_cnt_addr, glbl_cnt);
}

static VOID test_coalescing_common(void **state, uint32_t num_interrupt_ids)
{
	uint32_t sm_glbl_block_size, sm_objs_block_size, orig_mask_ctrl, orig_glbl_cnt, glbl_cnt;
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int rc, fd = tests_state->fd, i, times_to_generate_intr = 10;
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;
	uint64_t sm_glbl_block_addr, sm_objs_block_addr;
	uint16_t j;
	uint8_t *sm_glbl_host_addr, *sm_objs_host_addr;
	struct test_coalescing_params *params;

	/* Test description:
	 * - Disable interrupt coalescing.
	 * - Generate M interrupts N times and verify that each interrupt is triggered N times.
	 * - Enable interrupt coalescing.
	 * - Generate M interrupts N times and verify that each interrupt is triggered twice, one
	 *   within the coalescing window, and another one right after the window, due to the
	 *   pending bit.
	 */

	if (hltests_is_simulator(fd)) {
		printf("Test is not supported on simulator, skipping\n");
		skip();
	}

	if (hw_ip->security_enabled) {
		printf("Cannot access PCIE_WRAP.DBI_ACCESS regs on a secured device, skipping\n");
		skip();
	}

	params = hlthunk_malloc(num_interrupt_ids * sizeof(*params));
	assert_non_null(params);

	sm_glbl_block_addr = mmHD2_SYNC_MNGR_GLBL_BASE;
	sm_glbl_host_addr = hltests_map_hw_block(fd, sm_glbl_block_addr, &sm_glbl_block_size);
	assert_non_null(sm_glbl_host_addr);

	sm_objs_block_addr = mmHD2_SYNC_MNGR_OBJS_BASE;
	sm_objs_host_addr = hltests_map_hw_block(fd, sm_objs_block_addr, &sm_objs_block_size);
	assert_non_null(sm_objs_host_addr);

	for (j = 0 ; j < num_interrupt_ids ; j++) {
		params[j].interrupt_id = hltests_get_first_avail_interrupt(fd) + j;
		params[j].irq =
			test_coalescing_get_irq_from_interrupt_id(fd, params[j].interrupt_id);

		assert_true((params[j].irq < UINT32_MAX) && (params[j].interrupt_id < UINT16_MAX));

		params[j].cq_id = hltests_get_first_avail_cq(fd) + j;
		test_coalescing_create_cq_cb(fd, &params[j].cq_cb, &params[j].cq_device_va);
		test_coalescing_configure_cq(fd, params[j].cq_id, params[j].interrupt_id,
						params[j].cq_device_va, sm_glbl_host_addr);
	}

	/* Disable interrupt coalescing */
	test_coalescing_save_and_set_regs(tests_state, MSIX_MASK_CTRL_DISABLE_COALESCING, 0,
						&orig_mask_ctrl, &orig_glbl_cnt);

	/* Generate M interrupts N times and verify that each interrupt is triggered N times */
	for (j = 0 ; j < num_interrupt_ids ; j++)
		params[j].num_intr_before = test_coalescing_get_num_of_interrupts(params[j].irq);

	for (i = 0 ; i < times_to_generate_intr ; i++) {
		for (j = 0 ; j < num_interrupt_ids ; j++)
			test_coalescing_generate_interrupt(fd, params[j].cq_id, sm_objs_host_addr);

		usleep(DRV_INTERRUPT_HANDLING_SLEEP_USEC);
	}

	sleep(COALESCING_TEST_SLEEP_TIME_SEC);

	for (j = 0 ; j < num_interrupt_ids ; j++) {
		params[j].num_intr_after = test_coalescing_get_num_of_interrupts(params[j].irq);
		assert_int_equal(params[j].num_intr_after - params[j].num_intr_before,
					times_to_generate_intr);
	}

	/* Enable interrupt coalescing */
	glbl_cnt = hltests_is_pldm(fd) ? PLDM_MSIX_LARGE_COALESCING_CNT : MSIX_LARGE_COALESCING_CNT;
	test_coalescing_save_and_set_regs(tests_state, MSIX_MASK_CTRL_ENABLE_COALESCING, glbl_cnt,
						NULL, NULL);

	/* Generate M interrupts N times and verify that each interrupt is triggered twice */
	for (j = 0 ; j < num_interrupt_ids ; j++)
		params[j].num_intr_before = params[j].num_intr_after;

	for (i = 0 ; i < times_to_generate_intr ; i++) {
		for (j = 0 ; j < num_interrupt_ids ; j++)
			test_coalescing_generate_interrupt(fd, params[j].cq_id, sm_objs_host_addr);

		usleep(DRV_INTERRUPT_HANDLING_SLEEP_USEC);
	}

	sleep(COALESCING_TEST_SLEEP_TIME_SEC);

	for (j = 0 ; j < num_interrupt_ids ; j++) {
		params[j].num_intr_after = test_coalescing_get_num_of_interrupts(params[j].irq);
		assert_int_equal(params[j].num_intr_after - params[j].num_intr_before, 2);
	}

	/* Cleanup */
	test_coalescing_save_and_set_regs(tests_state, orig_mask_ctrl, orig_glbl_cnt, NULL, NULL);

	for (j = 0 ; j < num_interrupt_ids ; j++)
		test_coalescing_release_cq_cb(fd, &params[j].cq_cb);

	rc = hltests_unmap_hw_block(fd, sm_objs_host_addr, sm_objs_block_size);
	assert_int_equal(rc, 0);

	rc = hltests_unmap_hw_block(fd, sm_glbl_host_addr, sm_glbl_block_size);
	assert_int_equal(rc, 0);

	hlthunk_free(params);

	END_TEST;
}

VOID test_coalescing_same_interrupt(void **state)
{
	END_TEST_FUNC(test_coalescing_common(state, 1));
}

VOID test_coalescing_different_interrupts(void **state)
{
	END_TEST_FUNC(test_coalescing_common(state, 5));
}

#ifndef HLTESTS_LIB_MODE

const struct CMUnitTest gaudi3_root_tests[] = {
	cmocka_unit_test_setup(test_coalescing_same_interrupt, hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_coalescing_different_interrupts,
				hltests_ensure_device_operational),
};

static const char *const usage[] = {
	"gaudi3_root [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	size_t num_tests = ARRAY_SIZE(gaudi3_root_tests);

	hltests_parser(argc, argv, usage,
		       HLTEST_DEVICE_MASK_GAUDI3_ALL, gaudi3_root_tests, (int)num_tests);

	if (!can_open_debugfs(true))
		return 0;

	if (!hltests_get_parser_run_disabled_tests()) {
		printf("gaudi3_root tests should run with --disabled option\n");
		return 0;
	}

	hltests_set_capabilities_mask(CAP_ARC_FW_LOAD_SCHED_MASK | CAP_ARC_FW_LOAD_PDMA_MASK);

	return hltests_run_group_tests("gaudi3_root", gaudi3_root_tests, num_tests,
					hltests_setup, hltests_teardown);
}

#endif /* HLTESTS_LIB_MODE */
