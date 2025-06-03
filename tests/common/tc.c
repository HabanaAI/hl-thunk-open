// SPDX-License-Identifier: MIT

/*
 * Copyright 2020 HabanaLabs, Ltd.
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

/*
 * VCMD offsets for WREG/RREG
 */

#define VCMD_VC8000D_OFFSET			0x1000
#define VCMD_L2C_OFFSET				0x2000

/*
 * VC8000D/VCMD dummy registers
 */

#define VCMD_DUMMY_REG_0_OFFSET			(64 * 0x4)	/* SWREG64 */

/*
 * VCMD commands
 */

#define VCMD_OPCODE_SHIFT			27
#define VCMD_OPCODE_MASK			0xF8000000

enum vcmd_opcode {
	VCMD_OPCODE_WREG = 0x1,
	VCMD_OPCODE_END = 0x2,
	VCMD_OPCODE_NOP = 0x3,
	VCMD_OPCODE_STALL = 0x9,
	VCMD_OPCODE_RREG = 0x16,
	VCMD_OPCODE_JMP = 0x19,
	VCMD_OPCODE_CLRINT = 0x1A,
	MAX_VCMD_OPCODE = (VCMD_OPCODE_MASK >> VCMD_OPCODE_SHIFT) + 1
};

#define VCMD_CMD_WREG_HDR_START_REG_ADDR_SHIFT	0
#define VCMD_CMD_WREG_HDR_START_REG_ADDR_MASK	0xFFFF
#define VCMD_CMD_WREG_HDR_LENGTH_SHIFT		16
#define VCMD_CMD_WREG_HDR_LENGTH_MASK		0x3FF0000
#define VCMD_CMD_WREG_HDR_FIX_SHIFT		26
#define VCMD_CMD_WREG_HDR_FIX_MASK		0x4000000

#define TC_CB_ALIGNMENT				64
#define TC_CMD_JMP_SZ				16
#define TC_CMD_NOP_SZ				8
#define TC_CMD_READ_REG_SZ			16

#define TC_RST_TRIAL_COUNT			10

struct vcmd_cmd_wreg {
	__le32 header;
	/* Dummy DWORD is required if the LENGTH field is an even number, to
	 * keep the command aligned to 64 bits.
	 */
	__le32 wdata[0];
};

struct vcmd_cmd_nop {
	__le32 header;
	/* Alignment DWORD */
	__le32 pad;
};

#define VCMD_CMD_STALL_HDR_INTR_MASK_SHIFT	0
#define VCMD_CMD_STALL_HDR_INTR_MASK_MASK	0xFFFF
#define VCMD_CMD_STALL_HDR_INTR_MODE_SHIFT	26
#define VCMD_CMD_STALL_HDR_INTR_MODE_MASK	0x4000000

struct vcmd_cmd_stall {
	__le32 header;
	/* Alignment DWORD */
	__le32 pad;
};

#define VCMD_CMD_RREG_HDR_START_REG_ADDR_SHIFT	0
#define VCMD_CMD_RREG_HDR_START_REG_ADDR_MASK	0xFFFF
#define VCMD_CMD_RREG_HDR_LENGTH_SHIFT		16
#define VCMD_CMD_RREG_HDR_LENGTH_MASK		0x3FF0000
#define VCMD_CMD_RREG_HDR_FIX_SHIFT		26
#define VCMD_CMD_RREG_HDR_FIX_MASK		0x4000000

struct vcmd_cmd_rreg {
	__le32 header;
	__le32 reg_val_buf_addr_lo;
	__le32 reg_val_buf_addr_hi;
	/* Alignment DWORD */
	__le32 pad;
};

#define VCMD_CMD_JMP_HDR_NEXT_CB_LEN_SHIFT	0
#define VCMD_CMD_JMP_HDR_NEXT_CB_LEN_MASK	0xFFFF
#define VCMD_CMD_JMP_HDR_INTR_EN_SHIFT		25
#define VCMD_CMD_JMP_HDR_INTR_EN_MASK		0x2000000
#define VCMD_CMD_JMP_HDR_RDY_SHIFT		26
#define VCMD_CMD_JMP_HDR_RDY_MASK		0x4000000

struct vcmd_cmd_jmp {
	__le32 header;
	__le32 next_cb_addr_lo;
	__le32 next_cb_addr_hi;
	__le32 next_cb_id;
};

#define VCMD_CMD_CLRINT_HDR_INTR_REG_ADDR_SHIFT	0
#define VCMD_CMD_CLRINT_HDR_INTR_REG_ADDR_MASK	0xFFFF
#define VCMD_CMD_CLRINT_HDR_OP_TYPE_SHIFT	25
#define VCMD_CMD_CLRINT_HDR_OP_TYPE_MASK	0x6000000

#define WREG_CMD_SIZE(num_regs)	((((2 + (num_regs)) >> 1) << 1) * \
				sizeof(uint32_t))

#define TC_HW_VERSION_ID_OFFSET		0x0	/* SWREG0 */
#define TC_HW_BUILD_DATE_OFFSET		0x4	/* SWREG1 */
#define TC_EXT_INTR_SRC_OFFSET		0x8	/* SWREG2 */
#define TC_EXE_CMDBUF_COUNT_OFFSET	0xc	/* SWREG3 */
#define TC_CMD_EXE_LSB_OFFSET		0x10	/* SWREG4 */
#define TC_CMD_EXE_MSB_OFFSET		0x14	/* SWREG5 */
#define TC_AXI_TOTAL_AR_LEN_OFFSET	0x18	/* SWREG6 */
#define TC_AXI_TOTAL_R_OFFSET		0x1c	/* SWREG7 */
#define TC_AXI_TOTAL_AR_OFFSET		0x20	/* SWREG8 */
#define TC_AXI_TOTAL_R_LAST_OFFSET	0x24	/* SWREG9 */
#define TC_AXI_TOTAL_AW_LEN_OFFSET	0x28	/* SWREG10 */
#define TC_AXI_TOTAL_W_OFFSET		0x2c	/* SWREG11 */
#define TC_AXI_TOTAL_AW_OFSSET		0x30	/* SWREG12 */
#define TC_AXI_TOTAL_W_LAST_OFFSET	0x34	/* SWREG13 */
#define TC_AXI_TOTAL_B_OFFSET		0x38	/* SWREG14 */
#define TC_AXI_STATUS_OFFSET		0x3c	/* SWREG15 */
#define TC_CONTROL_OFFSET		0x40	/* SWREG16 */
#define TC_IRQ_STATUS_OFFSET		0x44	/* SWREG17 */
#define TC_IRQ_CONTROL_OFFSET		0x48	/* SWREG18 */
#define TC_TIMEOUT_CONTROL_OFFSET	0x4c	/* SWREG19 */
#define TC_CMDBUF_EXE_ADDR_LSB_OFFSET	0x50	/* SWREG20 */
#define TC_CMDBUF_EXE_ADDR_MSB_OFFSET	0x54	/* SWREG21 */
#define TC_CMDBUF_EXE_LENGTH_OFFSET	0x58	/* SWREG22 */
#define TC_AXI_CONTROL_OFFSET		0x5c	/* SWREG23 */
#define TC_RDY_CMDBUF_COUNT_OFFSET	0x60	/* SWREG24 */
#define TC_EXT_INTR_GATE_OFFSET		0x64	/* SWREG25 */
#define TC_CMDBUF_EXE_ID_OFFSET		0x68	/* SWREG26 */

#define TC_REGS_NUM			27

#define TC_CONTROL_START_TRIGGER_SHIFT	0
#define TC_CONTROL_START_TRIGGER_MASK	0x1
#define TC_CONTROL_RESET_CORE_SHIFT	2
#define TC_CONTROL_RESET_CORE_MASK	0x4

#define TC_DUMMY_REG_MAGIC_VAL		0xC0DE0
#define TC_RESET_TIMEOUT_USEC		10000

struct transformer_test_param {
	/* process accessible VA to the TC hw block, all register access to
	 * be done suing this address
	 */
	void *base_reg_user_va;
	void *cb;
	/*memory allocated to be used for TC rreg command */
	uint8_t *reg_dump_mem;

	uint64_t target_val;
	uint64_t cb_dev_va;
	uint64_t reg_dump_dev_va;

	uint32_t core_id;
	uint32_t first_cb_sz;
	/* current offset from where new command should be inserted*/
	uint32_t cb_offset;
	/* offset within the reg_dump_mem to used for dumping a target value
	 * to be used by lkd as a criteria for completion
	 */
	uint32_t target_val_offset;
	uint32_t hw_map_sz;
	uint32_t pi;
};

struct vcmd_cmd_wreg_params {
	uint16_t start_reg_addr;
	uint16_t length;
	uint8_t fix;
	uint32_t wdata[0];
};

struct vcmd_cmd_rreg_params {
	uint64_t reg_val_buf_addr;
	uint16_t start_reg_addr;
	uint16_t length;
	uint8_t fix;
};

struct vcmd_cmd_jmp_params {
	uint64_t next_cb_addr;
	uint32_t next_cb_id;
	uint16_t next_cb_len;
	uint8_t intr_en;
	uint8_t rdy;
};

static uint32_t hltests_add_vcmd_wreg_cmd(void *buffer, uint32_t buf_off,
					struct vcmd_cmd_wreg_params *params)
{
	struct vcmd_cmd_wreg *cmd;
	uint32_t header = 0, length, size;
	int i;

	length = params->length;
	if (!length)
		length = 1024; /* 0 means 1024 registers */
	size = WREG_CMD_SIZE(length);
	cmd = hlthunk_malloc(size);
	assert_non_null(cmd);

	header = FIELD_PREP(VCMD_OPCODE_MASK, VCMD_OPCODE_WREG) |
			FIELD_PREP(VCMD_CMD_WREG_HDR_START_REG_ADDR_MASK, params->start_reg_addr) |
			FIELD_PREP(VCMD_CMD_WREG_HDR_LENGTH_MASK, params->length) |
			FIELD_PREP(VCMD_CMD_WREG_HDR_FIX_MASK, params->fix);
	cmd->header = htole32(header);

	for (i = 0 ; i < length ; i++)
		*(cmd->wdata + i) = params->wdata[i];

	buf_off = hltests_add_packet_to_cb(buffer, buf_off, cmd, size);

	hlthunk_free(cmd);

	return buf_off;
}

static uint32_t hltests_add_vcmd_nop_cmd(void *buffer, uint32_t buf_off)
{
	struct vcmd_cmd_nop cmd;
	uint32_t header = 0;

	memset(&cmd, 0, sizeof(cmd));
	header = FIELD_PREP(VCMD_OPCODE_MASK, VCMD_OPCODE_NOP);
	cmd.header = htole32(header);

	return hltests_add_packet_to_cb(buffer, buf_off, &cmd, sizeof(cmd));
}

static uint32_t hltests_add_vcmd_rreg_cmd(void *buffer, uint32_t buf_off,
					struct vcmd_cmd_rreg_params *params)
{
	struct vcmd_cmd_rreg cmd;
	uint32_t header = 0;

	memset(&cmd, 0, sizeof(cmd));
	header = FIELD_PREP(VCMD_OPCODE_MASK, VCMD_OPCODE_RREG) |
			FIELD_PREP(VCMD_CMD_RREG_HDR_START_REG_ADDR_MASK, params->start_reg_addr) |
			FIELD_PREP(VCMD_CMD_RREG_HDR_LENGTH_MASK, params->length) |
			FIELD_PREP(VCMD_CMD_RREG_HDR_FIX_MASK, params->fix);
	cmd.header = htole32(header);
	cmd.reg_val_buf_addr_lo = lower_32_bits(params->reg_val_buf_addr);
	cmd.reg_val_buf_addr_hi = upper_32_bits(params->reg_val_buf_addr);

	return hltests_add_packet_to_cb(buffer, buf_off, &cmd, sizeof(cmd));
}

static uint32_t hltests_add_vcmd_jmp_cmd(void *buffer, uint32_t buf_off,
					struct vcmd_cmd_jmp_params *params)
{
	struct vcmd_cmd_jmp cmd;
	uint32_t header = 0;

	memset(&cmd, 0, sizeof(cmd));
	header = FIELD_PREP(VCMD_OPCODE_MASK, VCMD_OPCODE_JMP) |
			FIELD_PREP(VCMD_CMD_JMP_HDR_NEXT_CB_LEN_MASK, params->next_cb_len) |
			FIELD_PREP(VCMD_CMD_JMP_HDR_INTR_EN_MASK, params->intr_en) |
			FIELD_PREP(VCMD_CMD_JMP_HDR_RDY_MASK, params->rdy);
	cmd.header = htole32(header);
	cmd.next_cb_addr_lo = lower_32_bits(params->next_cb_addr);
	cmd.next_cb_addr_hi = upper_32_bits(params->next_cb_addr);
	cmd.next_cb_id = params->next_cb_id;

	return hltests_add_packet_to_cb(buffer, buf_off, &cmd, sizeof(cmd));
}

static bool test_tc_check_prerequisites(int fd, struct hltests_state *tests_state)
{
	struct hltests_module_params_info module_params;
	int rc;

	/* No CODEC blocks in Goya and Gaudi */
	if (hltests_is_goya(fd) || hltests_is_gaudi(fd)) {
		printf("Test is not relevant for Goya/Gaudi, skipping\n");
		return false;
	}

	rc = hltests_get_module_params_info(fd, &module_params);
	assert_int_equal(rc, 0);

	if (!module_params.decoder_mask) {
		printf("Decoder must be enabled for this test, skipping.\n");
		return false;
	}

	return true;
}

static int hltests_map_transformer_core(int fd, struct transformer_test_param *tc_test_p)
{
	uint64_t base_addr;

	base_addr = hltests_get_tc_base_addr(fd, tc_test_p->core_id);
	assert_int_not_equal(base_addr, 0);

	tc_test_p->base_reg_user_va = hltests_map_hw_block(fd, base_addr, &tc_test_p->hw_map_sz);
	assert_non_null(tc_test_p->base_reg_user_va);

	return 0;
}

static int hltests_unmap_transformer_core(int fd, struct transformer_test_param *tc_test_p)
{
	int rc;

	rc = hltests_unmap_hw_block(fd, tc_test_p->base_reg_user_va, tc_test_p->hw_map_sz);
	assert_int_equal(rc, 0);

	return 0;
}

static int hltests_basic_transformer_setup(int fd, struct transformer_test_param *tc_test_p)
{
	uint8_t *tc_base_reg_va = (uint8_t *)tc_test_p->base_reg_user_va;
	int rc;

	/* Clear reset indication */
	rc = hltests_write_lbw_reg(fd, tc_base_reg_va + TC_IRQ_STATUS_OFFSET, 0x20);
	assert_int_equal(rc, 0);

	/* Enable TC interrupts */
	rc = hltests_write_lbw_reg(fd, tc_base_reg_va + TC_IRQ_CONTROL_OFFSET, 0x7f);
	assert_int_equal(rc, 0);

	/* Enable timeout function */
	rc = hltests_write_lbw_reg(fd, tc_base_reg_va + TC_TIMEOUT_CONTROL_OFFSET,
					500000000 | BIT(31));
	assert_int_equal(rc, 0);

	/* Gate the normal/abnormal interrupts from the decoder core */
	rc = hltests_write_lbw_reg(fd, tc_base_reg_va + TC_EXT_INTR_GATE_OFFSET, 0xffffffff);
	assert_int_equal(rc, 0);

	return 0;
}

static int hltests_alloc_tc_buf(int fd, struct transformer_test_param *tc_test_p)

{
	uint32_t page_size = 0x1000;

	/* allocate TC CBs with 64 bytes alignment */
	tc_test_p->cb = hltests_allocate_host_mem_aligned(fd, page_size, NOT_HUGE_MAP, 64);
	assert_non_null(tc_test_p->cb);

	tc_test_p->reg_dump_mem = hltests_allocate_host_mem(fd, page_size, NOT_HUGE_MAP);
	assert_non_null(tc_test_p->reg_dump_mem);

	tc_test_p->cb_dev_va = hltests_get_device_va_for_host_ptr(fd, tc_test_p->cb);
	assert_non_null(tc_test_p->cb_dev_va);

	tc_test_p->reg_dump_dev_va = hltests_get_device_va_for_host_ptr(fd,
						tc_test_p->reg_dump_mem);
	assert_non_null(tc_test_p->reg_dump_dev_va);

	return 0;
}

static int hltests_destroy_tc_buf(int fd, struct transformer_test_param *tc_test_p)
{
	int rc = 0;

	rc = hltests_free_host_mem(fd, tc_test_p->cb);
	assert_int_equal(rc, 0);

	rc = hltests_free_host_mem(fd, tc_test_p->reg_dump_mem);
	assert_int_equal(rc, 0);

	return 0;
}

static int hltests_reset_tc(int fd, struct transformer_test_param *tc_test_p)
{
	uint8_t *tc_base_reg_va = (uint8_t *)tc_test_p->base_reg_user_va;
	uint32_t status, reset_loop = 0, timeout = TC_RESET_TIMEOUT_USEC;
	int rc;

	if (hltests_is_pldm(fd))
		timeout = (TC_RESET_TIMEOUT_USEC * 100);

	/* RESET CORE*/
	rc = hltests_write_lbw_reg(fd, tc_base_reg_va + TC_CONTROL_OFFSET,
				BIT(TC_CONTROL_RESET_CORE_SHIFT));
	assert_int_equal(rc, 0);

	do {
		usleep(timeout);
		rc = hltests_read_lbw_reg(fd, tc_base_reg_va + TC_CONTROL_OFFSET, &status);
		assert_int_equal(rc, 0);
		if (!(status & TC_CONTROL_RESET_CORE_MASK))
			break;
	} while (++reset_loop < TC_RST_TRIAL_COUNT);

	if (reset_loop == TC_RST_TRIAL_COUNT) {
		printf("Timeout while waiting for TC core reset to complete.\n");
		assert_non_null(0);
	}

	return 0;
}

static int hltests_start_tc(int fd, struct transformer_test_param *tc_test_p)
{
	uint8_t *tc_base_reg_va = (uint8_t *)tc_test_p->base_reg_user_va;
	int rc;

	rc = hltests_write_lbw_reg(fd, tc_base_reg_va + TC_CMDBUF_EXE_ADDR_LSB_OFFSET,
				lower_32_bits(tc_test_p->cb_dev_va));
	assert_int_equal(rc, 0);

	rc = hltests_write_lbw_reg(fd, tc_base_reg_va + TC_CMDBUF_EXE_ADDR_MSB_OFFSET,
				upper_32_bits(tc_test_p->cb_dev_va));
	assert_int_equal(rc, 0);

	rc = hltests_write_lbw_reg(fd, tc_base_reg_va + TC_CMDBUF_EXE_LENGTH_OFFSET,
				(tc_test_p->first_cb_sz / 8));
	assert_int_equal(rc, 0);

	rc = hltests_write_lbw_reg(fd, tc_base_reg_va + TC_CMDBUF_EXE_ID_OFFSET, 0);
	assert_int_equal(rc, 0);

	rc = hltests_write_lbw_reg(fd, tc_base_reg_va + TC_RDY_CMDBUF_COUNT_OFFSET, tc_test_p->pi);
	assert_int_equal(rc, 0);

	rc = hltests_write_lbw_reg(fd, tc_base_reg_va + TC_EXE_CMDBUF_COUNT_OFFSET, 0);
	assert_int_equal(rc, 0);

	/* CORE START*/
	rc = hltests_write_lbw_reg(fd, tc_base_reg_va + TC_CONTROL_OFFSET,
				BIT(TC_CONTROL_START_TRIGGER_SHIFT));
	assert_int_equal(rc, 0);

	return 0;
}

static void hltests_setup_tc_cb(int fd, struct transformer_test_param *tc_test_p)
{
	struct vcmd_cmd_rreg_params rreg_params;
	struct vcmd_cmd_jmp_params jmp_params;
	uint64_t *ptr;
	uint32_t aligned_offset;

	tc_test_p->cb_offset = hltests_add_vcmd_nop_cmd(tc_test_p->cb, tc_test_p->cb_offset);
	tc_test_p->cb_offset = hltests_add_vcmd_nop_cmd(tc_test_p->cb, tc_test_p->cb_offset);
	tc_test_p->cb_offset = hltests_add_vcmd_nop_cmd(tc_test_p->cb, tc_test_p->cb_offset);
	tc_test_p->cb_offset = hltests_add_vcmd_nop_cmd(tc_test_p->cb, tc_test_p->cb_offset);

	/* reset the memory at target_val_offset to 0 */
	tc_test_p->target_val_offset = TC_CMDBUF_EXE_ID_OFFSET;
	ptr = (uint64_t *)(tc_test_p->reg_dump_mem + tc_test_p->target_val_offset);
	*((uint64_t *)ptr) = 0;

	/* increase PI by 1 before jump */
	tc_test_p->pi++;

	memset(&jmp_params, 0, sizeof(jmp_params));
	/* Next CB address is from the same CB allocated with next 64 byte
	 * address within the CB
	 * TODO - confirm with media team if 64 byte alignment is still valid.
	 */
	aligned_offset = ALIGN_UP((tc_test_p->cb_offset + TC_CMD_JMP_SZ), TC_CB_ALIGNMENT);
	jmp_params.next_cb_addr = (tc_test_p->cb_dev_va + aligned_offset);
	jmp_params.next_cb_id = tc_test_p->pi;
	/* next command size = reg command(reg dump) + dummy jump command */
	jmp_params.next_cb_len = (TC_CMD_READ_REG_SZ + TC_CMD_JMP_SZ) / 8;
	jmp_params.intr_en = 0;
	jmp_params.rdy = 1;
	tc_test_p->cb_offset = hltests_add_vcmd_jmp_cmd(tc_test_p->cb,
					tc_test_p->cb_offset, &jmp_params);
	tc_test_p->first_cb_sz = tc_test_p->cb_offset;

	/*set target value as PI value just before the reg dump command */
	tc_test_p->target_val = tc_test_p->pi;

	/* set the CB offset to the new aligned address */
	tc_test_p->cb_offset = aligned_offset;

	memset(&rreg_params, 0, sizeof(rreg_params));
	rreg_params.reg_val_buf_addr = tc_test_p->reg_dump_dev_va;
	rreg_params.start_reg_addr = 0;
	rreg_params.length = TC_REGS_NUM;
	rreg_params.fix = 0;
	tc_test_p->cb_offset = hltests_add_vcmd_rreg_cmd(tc_test_p->cb,
					tc_test_p->cb_offset, &rreg_params);

	tc_test_p->pi++;

	memset(&jmp_params, 0, sizeof(jmp_params));
	jmp_params.next_cb_id = tc_test_p->pi;
	tc_test_p->cb_offset = hltests_add_vcmd_jmp_cmd(tc_test_p->cb,
					tc_test_p->cb_offset, &jmp_params);
}

static int hltests_get_tc_count(int fd, uint32_t *tc_count, uint32_t *tc_mask)
{
	struct hlthunk_hw_ip_info hw_ip;
	uint32_t core_id_mask, enabled_tc_count = 0;
	int rc;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	core_id_mask = hw_ip.decoder_enabled_mask;
	*tc_count = 0;
	for (; core_id_mask > 0;) {
		if (core_id_mask & 0x1)
			enabled_tc_count++;

		core_id_mask = (core_id_mask >> 1);
		rc++;
	}

	*tc_mask = hw_ip.decoder_enabled_mask;
	*tc_count = enabled_tc_count;

	return rc;
}

VOID test_tc_basic_cmd(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct transformer_test_param tc_test;
	uint64_t timeout_usec = WAIT_FOR_CS_DEFAULT_TIMEOUT;
	uint32_t status;
	int rc, fd = tests_state->fd;
	void *ptr;

	if (!test_tc_check_prerequisites(fd, tests_state))
		skip();

	memset(&tc_test, 0, sizeof(tc_test));
	tc_test.core_id = 0;

	hltests_map_transformer_core(fd, &tc_test);
	hltests_basic_transformer_setup(fd, &tc_test);
	hltests_alloc_tc_buf(fd, &tc_test);
	hltests_setup_tc_cb(fd, &tc_test);
	hltests_reset_tc(fd, &tc_test);
	hltests_start_tc(fd, &tc_test);

	ptr = (tc_test.reg_dump_mem + tc_test.target_val_offset);
	rc = hlthunk_wait_for_interrupt(fd, ptr, tc_test.target_val, tc_test.core_id,
						timeout_usec, &status);
	assert_int_equal(status, HL_WAIT_CS_STATUS_COMPLETED);

	hltests_destroy_tc_buf(fd, &tc_test);
	hltests_unmap_transformer_core(fd, &tc_test);

	END_TEST;
}

/* Wait on a higher target value which will never be set.
 * Hence test passes if driver reports busy status
 */
VOID test_tc_cmd_timeout(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct transformer_test_param tc_test;
	uint64_t timeout_usec = WAIT_FOR_CS_DEFAULT_TIMEOUT;
	uint32_t status;
	int rc, fd = tests_state->fd;
	void *ptr;

	if (!test_tc_check_prerequisites(fd, tests_state))
		skip();

	memset(&tc_test, 0, sizeof(tc_test));
	tc_test.core_id = 0;

	hltests_map_transformer_core(fd, &tc_test);
	hltests_basic_transformer_setup(fd, &tc_test);
	hltests_alloc_tc_buf(fd, &tc_test);
	hltests_setup_tc_cb(fd, &tc_test);
	hltests_reset_tc(fd, &tc_test);
	hltests_start_tc(fd, &tc_test);

	ptr = (tc_test.reg_dump_mem + tc_test.target_val_offset);
	rc = hlthunk_wait_for_interrupt(fd, ptr, (tc_test.target_val + 1), tc_test.core_id,
						timeout_usec, &status);
	assert_int_equal(status, HL_WAIT_CS_STATUS_BUSY);

	hltests_destroy_tc_buf(fd, &tc_test);
	hltests_unmap_transformer_core(fd, &tc_test);

	END_TEST;
}

VOID test_tc_multi_core_cmd(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	uint32_t status, core_id, core_id_mask = 0, max_tc, enabled_tc_cnt;
	uint64_t timeout_usec = WAIT_FOR_CS_DEFAULT_TIMEOUT;
	int verbose = hltests_get_verbose_enabled();
	struct transformer_test_param tc_test;
	int rc, fd = tests_state->fd;
	void *ptr;

	if (!test_tc_check_prerequisites(fd, tests_state))
		skip();

	max_tc = hltests_get_tc_count(fd, &enabled_tc_cnt, &core_id_mask);
	if (verbose)
		printf("\nTC Mask:0x%x Count:%u\n", core_id_mask, max_tc);

	for (core_id = 0; core_id < max_tc; core_id++) {
		if (core_id_mask & BIT(core_id)) {
			if (verbose)
				printf("Running simple NOP test on TC:%u\n", core_id);
			memset(&tc_test, 0, sizeof(tc_test));
			tc_test.core_id = core_id;

			hltests_map_transformer_core(fd, &tc_test);
			hltests_basic_transformer_setup(fd, &tc_test);
			hltests_alloc_tc_buf(fd, &tc_test);
			hltests_setup_tc_cb(fd, &tc_test);
			hltests_reset_tc(fd, &tc_test);
			hltests_start_tc(fd, &tc_test);

			ptr = (tc_test.reg_dump_mem + tc_test.target_val_offset);
			rc = hlthunk_wait_for_interrupt(fd, ptr, tc_test.target_val,
								tc_test.core_id, timeout_usec,
								&status);
			assert_int_equal(status, HL_WAIT_CS_STATUS_COMPLETED);

			hltests_destroy_tc_buf(fd, &tc_test);
			hltests_unmap_transformer_core(fd, &tc_test);
		}
	}

	END_TEST;
}

struct tc_thread_params {
	pthread_barrier_t *barrier;
	struct transformer_test_param *tc_test_p;
	int fd;
};

static void *tc_thread_start(void *args)
{
	struct tc_thread_params *params = (struct tc_thread_params *) args;
	struct transformer_test_param *tc_test_p = params->tc_test_p;
	uint64_t timeout_usec = WAIT_FOR_CS_DEFAULT_TIMEOUT;
	int rc, fd = params->fd;
	uint32_t status;
	void *ptr;

	hltests_map_transformer_core(fd, tc_test_p);
	hltests_alloc_tc_buf(fd, tc_test_p);
	hltests_setup_tc_cb(fd, tc_test_p);
	hltests_basic_transformer_setup(fd, tc_test_p);
	hltests_reset_tc(fd, tc_test_p);

	/*
	 * PTHREAD_BARRIER_SERIAL_THREAD is returned to one unspecified thread
	 * and zero is returned to each of the remaining threads.
	 */
	rc = pthread_barrier_wait(params->barrier);
	if (rc && rc != PTHREAD_BARRIER_SERIAL_THREAD)
		return NULL;

	hltests_start_tc(fd, tc_test_p);

	ptr = (tc_test_p->reg_dump_mem + tc_test_p->target_val_offset);
	rc = hlthunk_wait_for_interrupt(fd, ptr, tc_test_p->target_val, tc_test_p->core_id,
						timeout_usec, &status);
	if ((status != HL_WAIT_CS_STATUS_COMPLETED) || (rc != 0))
		return NULL;

	hltests_destroy_tc_buf(fd, tc_test_p);
	hltests_unmap_transformer_core(fd, tc_test_p);

	return args;
}

VOID test_tc_multi_threaded(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	uint32_t core_id_mask = 0, max_tc, enabled_tc_cnt = 0;
	int verbose = hltests_get_verbose_enabled();
	struct transformer_test_param *tc_test_list;
	struct tc_thread_params *thread_params;
	int rc, fd = tests_state->fd, i;
	pthread_barrier_t barrier;
	pthread_t *thread_id;
	void *retval;

	/*
	 * 1 thread running per core
	 * - allocation and setup is done within a thread as its created
	 * - thread then waits on a barrier to synchronize
	 * - post barrier all threads reset, trigger the core and wait for completion
	 */

	if (!test_tc_check_prerequisites(fd, tests_state))
		skip();

	/* Disable the test on simulator because running with the C-model
	 * sometimes leads to a memory access violation (HABANA-64).
	 */
	if (hltests_is_simulator(fd)) {
		printf("Test is not supported on simulator, skipping\n");
		skip();
	}

	max_tc = hltests_get_tc_count(fd, &enabled_tc_cnt, &core_id_mask);
	if (verbose)
		printf("\nTC Mask:0x%x Count:%u\n", core_id_mask, enabled_tc_cnt);

	thread_params = hlthunk_malloc(max_tc * sizeof(*thread_params));
	assert_non_null(thread_params);
	thread_id = hlthunk_malloc(max_tc * sizeof(*thread_id));
	assert_non_null(thread_id);
	tc_test_list = hlthunk_malloc(max_tc * sizeof(*tc_test_list));
	assert_non_null(tc_test_list);

	rc = pthread_barrier_init(&barrier, NULL, enabled_tc_cnt);
	assert_int_equal(rc, 0);

	/* Create and execute threads */
	for (i = 0 ; i < max_tc ; i++) {
		if (core_id_mask & BIT(i)) {
			tc_test_list[i].core_id = i;
			thread_params[i].barrier = &barrier;
			thread_params[i].fd = fd;
			thread_params[i].tc_test_p = &tc_test_list[i];

			rc = pthread_create(&thread_id[i], NULL, tc_thread_start,
						&thread_params[i]);
			assert_int_equal(rc, 0);
		}
	}

	/* Wait for the termination of the threads */
	for (i = 0 ; i < max_tc ; i++) {
		if (thread_params[i].tc_test_p) {
			rc = pthread_join(thread_id[i], &retval);
			assert_int_equal(rc, 0);
			assert_non_null(retval);
		}
	}

	/* Cleanup */
	pthread_barrier_destroy(&barrier);
	hlthunk_free(thread_id);
	hlthunk_free(thread_params);
	hlthunk_free(tc_test_list);

	END_TEST;
}

VOID test_tc_rreg_to_sob(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hltests_monitor_and_fence mon_and_fence_info;
	struct hltests_cs_chunk default_execute_chunk;
	struct transformer_test_param tc_test;
	struct vcmd_cmd_rreg_params rreg_params;
	struct vcmd_cmd_wreg_params *wreg_params;
	uint64_t timeout_usec = WAIT_FOR_CS_DEFAULT_TIMEOUT;
	uint32_t status;
	uint64_t sob_addr, seq = 0;
	void *default_cb, *ptr;
	uint32_t page_size = 0x1000, default_cb_size, wreg_params_size, sob_val = 0x1;
	uint16_t dummy_reg_offset, sob0, mon0;
	int rc, fd = tests_state->fd;

	if (!test_tc_check_prerequisites(fd, tests_state))
		skip();

	/* Test description:
	 * 1. QMAN: fence on SOB0
	 * 2. CODEC: WREG to dummy register
	 * 3. CODEC: RREG the dummy register to SOB0
	 *
	 * The NIC-400 block splits the 16B x 1 cycle into 4B x 4 cycles
	 * transaction, instead of 4B x 1 cycle. As multi cycle transaction in
	 * mesh is not supported, the ECO masks 3 of 4 cycles while only the
	 * last cycle propagates to the mesh.
	 * Due to that, we must use "Length=4" + "Fix=1" for RREG when storing
	 * the dummy register, instead of "Length=1" + "Fix=0".
	 * In addition, even with this W/A, it is possible write to only LBW
	 * address with 0 as the LSB nibble (16B address alignment).
	 */

	dummy_reg_offset = VCMD_DUMMY_REG_0_OFFSET;

	sob0 = hltests_get_first_avail_sob(fd);

	mon0 = hltests_get_first_avail_mon(fd);

	/* Clear SOB0 */
	hltests_clear_sobs(fd, 1);

	/* QMAN: fence on SOB0 */
	default_cb = hltests_create_cb(fd, page_size, EXTERNAL, 0);
	assert_non_null(default_cb);
	default_cb_size = 0;

	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = hltests_get_dma_down_qid(fd, STREAM0);
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = sob0;
	mon_and_fence_info.mon_id = mon0;
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.sob_val = sob_val;
	mon_and_fence_info.dec_fence = true;
	mon_and_fence_info.mon_payload = 1;
	mon_and_fence_info.mon_mode = SOB_EQUAL;
	default_cb_size = hltests_add_monitor_and_fence(fd, default_cb,
					default_cb_size, &mon_and_fence_info);

	memset(&default_execute_chunk, 0, sizeof(default_execute_chunk));
	default_execute_chunk.cb_ptr = default_cb;
	default_execute_chunk.cb_size = default_cb_size;
	default_execute_chunk.queue_index = hltests_get_dma_down_qid(fd, STREAM0);

	memset(&tc_test, 0, sizeof(tc_test));
	tc_test.core_id = 0;
	hltests_map_transformer_core(fd, &tc_test);
	hltests_basic_transformer_setup(fd, &tc_test);
	hltests_alloc_tc_buf(fd, &tc_test);

	sob_addr = hltests_get_sob_base_addr(fd) + sob0 * 0x4;

	wreg_params_size = sizeof(*wreg_params) + sizeof(uint32_t);
	wreg_params = hlthunk_malloc(wreg_params_size);
	assert_non_null(wreg_params);
	wreg_params->start_reg_addr = dummy_reg_offset;
	wreg_params->length = 1;
	wreg_params->fix = 0;
	wreg_params->wdata[0] = sob_val;

	memset(&rreg_params, 0, sizeof(rreg_params));
	rreg_params.reg_val_buf_addr = sob_addr;
	rreg_params.start_reg_addr = dummy_reg_offset;
	rreg_params.length = 1;
	rreg_params.fix = 0;

	tc_test.cb_offset = hltests_add_vcmd_nop_cmd(tc_test.cb, tc_test.cb_offset);
	tc_test.cb_offset = hltests_add_vcmd_wreg_cmd(tc_test.cb, tc_test.cb_offset, wreg_params);
	tc_test.cb_offset = hltests_add_vcmd_rreg_cmd(tc_test.cb, tc_test.cb_offset, &rreg_params);

	hltests_setup_tc_cb(fd, &tc_test);

	/* Submit default CS */
	rc = hltests_submit_cs(fd, NULL, 0, &default_execute_chunk, 1, 0, &seq);
	assert_int_equal(rc, 0);

	hltests_reset_tc(fd, &tc_test);
	hltests_start_tc(fd, &tc_test);

	ptr = (tc_test.reg_dump_mem + tc_test.target_val_offset);
	rc = hlthunk_wait_for_interrupt(fd, ptr, tc_test.target_val, tc_test.core_id,
						timeout_usec, &status);
	assert_int_equal(status, HL_WAIT_CS_STATUS_COMPLETED);

	/* Wait for completion of default CS */
	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	/* Cleanup */
	hlthunk_free(wreg_params);
	hltests_destroy_tc_buf(fd, &tc_test);
	hltests_unmap_transformer_core(fd, &tc_test);
	rc = hltests_destroy_cb(fd, default_cb);
	assert_int_equal(rc, 0);

	END_TEST;
}

#ifndef HLTESTS_LIB_MODE

const struct CMUnitTest tc_tests[] = {
	cmocka_unit_test_setup(test_tc_basic_cmd,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_tc_cmd_timeout,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_tc_multi_core_cmd,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_tc_multi_threaded,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_tc_rreg_to_sob,
				hltests_ensure_device_operational),
};

static const char *const usage[] = {
	"tc [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = ARRAY_SIZE(tc_tests);

	hltests_parser(argc, argv, usage,
			HLTEST_DEVICE_MASK_DONT_CARE &
			~HLTEST_DEVICE_MASK_GOYA &
			~HLTEST_DEVICE_MASK_GAUDI_ALL,
			tc_tests, num_tests);
	hltests_set_capabilities_mask(CAP_ARC_FW_LOAD_SCHED_MASK |
				CAP_ARC_FW_LOAD_PDMA_MASK);
	return hltests_run_group_tests("tc", tc_tests, num_tests,
					hltests_setup, hltests_teardown);
}

#endif /* HLTESTS_LIB_MODE */
