// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "common/hlthunk_tests.h"
#include "gaudi/gaudi.h"
#include "gaudi/asic_reg/gaudi_regs.h"
#include "gaudi/asic_reg/gaudi_blocks.h"
#include "gaudi/gaudi_packets.h"
#include "ini.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>

#define GAUDI_HBM_CFG_BASE		mmHBM0_BASE
#define GAUDI_HBM_CFG_OFFSET		(mmHBM1_BASE - mmHBM0_BASE)
#define GAUDI_HBM_DEVICES		4
#define GAUDI_HBM_CHANNELS		8
#define GAUDI_HBM_CENTER_CHANNEL	9
#define GAUDI_MAX_TEMP_THRESHOLD	85
#define GAUDI_HBM_IEEE1500_WRITE_INST	1
#define GAUDI_HBM_IEEE1500_READ_INST	0

#define FUSE_TIMEOUT_US			100000
#define FUSE_DELAY_US			100
#define FUSE_RETRIES			(FUSE_TIMEOUT_US / FUSE_DELAY_US)

#define RREG32_MASK(reg, mask) ((RREG32(reg) & mask) >> (ffs(mask) - 1))

#define RL_WREG32(reg, val) WREG32(CFG_BASE + reg, val)
#define RL_RREG32(reg) RREG32(CFG_BASE + reg)

enum ieee1500_instruction {
	ieee1500_bypass = 0x00,
	ieee1500_extest_rx = 0x01,
	ieee1500_extest_tx = 0x02,
	ieee1500_intest_rx = 0x03,
	ieee1500_intest_tx = 0x04,
	ieee1500_hbm_reset = 0x05,
	ieee1500_mbist = 0x06,
	ieee1500_soft_repair = 0x07,
	ieee1500_hard_repair = 0x08,
	ieee1500_dword_misr = 0x09,
	ieee1500_aword_misr = 0x0a,
	ieee1500_channel_id = 0x0b,
	ieee1500_misr_mask = 0x0c,
	ieee1500_aword_misr_config = 0x0d,
	ieee1500_device_id = 0x0e,
	ieee1500_temperature = 0x0f,
	ieee1500_mode_register_dump_set = 0x10,
	ieee1500_read_lfsr_compare_sticky = 0x11,
	ieee1500_soft_lane_repair = 0x12,
	ieee1500_hard_lane_repair = 0x13
};

static uint32_t ieee_wdr_len_t[20] = {
	1, /* BYPASS */
	215, /* EXTEST_RX */
	215, /* EXTEST_TX */
	0, /* INTEST_RX */
	0, /* INTEST_TX */
	1, /* HBM_RESET */
	375, /* MBIST */
	21, /* SOFT_REPAIR */
	21, /* HARD_REPAIR */
	320, /* DWORD_MISR */
	30, /* AWORD_MISR */
	1, /* CHANNEL_ID */
	72, /* MISR_MASK */
	8, /* AWORD_MISR_CONFIG */
	82, /* DEVICE_ID */
	8, /* TEMPERATURE */
	128, /* MODE_REGISTER_DUMP_SET */
	175, /* READ_LFSR_COMPARE_STICKY */
	72, /* SOFT_LANE_REPAIR */
	72 /* HARD_LANE_REPAIR */
};

static void ieee1500_inst(struct hltests_state *tests_state, int device,
			uint32_t ch, enum ieee1500_instruction instruction,
			bool write)
{
	uint64_t base = GAUDI_HBM_CFG_BASE + device * GAUDI_HBM_CFG_OFFSET;
	uint32_t wir, op, status;

	/* Write instructions - WDR registers (0x9100 - 0x9188) should be
	 * written prior to calling this function.
	 * Read instructions - WDR registers (0x9800 - 0x9F88) should be read
	 * after calling this function.
	 */

	/* Configure WDR length */
	WREG32(base + 0x9020, ieee_wdr_len_t[instruction] - 1);

	/* Configure WIR
	 * {ch, instruction} - ch may be 0xF to indicate ALL channels
	 */
	wir = (instruction & 0xFF) | ((ch & 0xF) << 8);
	WREG32(base + 0x9024, wir);

	/* Send WIR and write/read WDR */
	op = write ? 0x6 : 0x5;
	WREG32(base + 0x9028, op);

	/* Poll for MLB interrupt */
	do {
		usleep(100);
		status = RREG32(base + 0x9034);
	} while (status != op);

	/* Clear MLB interrupts */
	WREG32(base + 0x9034, 0);
}

static void test_hbm_read_temperature(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int device, temp;
	uint32_t rdata, ignore = 0;
	uint64_t base;
	bool invalid;

	if (tests_state->asic_type != HLTHUNK_DEVICE_GAUDI) {
		printf("Test is skipped because device is not GAUDI\n");
		skip();
	}

	for (device = 0; device < GAUDI_HBM_DEVICES; device++) {
		base = GAUDI_HBM_CFG_BASE + device * GAUDI_HBM_CFG_OFFSET;

		ieee1500_inst(tests_state, device, ignore, ieee1500_temperature,
				GAUDI_HBM_IEEE1500_READ_INST);
		rdata = RREG32(base + GAUDI_HBM_CENTER_CHANNEL * 0x1000 +
									0x800);
		invalid = (rdata >> 7) & 1;
		temp = rdata & 0x7F;

		if (invalid) {
			printf("Temperature read from HBM %d is invalid\n",
				device);
		} else {
			/* Display temperatures - celsius degrees */
			printf("Temperature read from HBM %d: %d deg celsius\n",
				device, temp);
			if (temp > GAUDI_MAX_TEMP_THRESHOLD)
				/* system power down? */
				printf(
					"Temperature read from HBM %d is high!\n",
					device);
		}
	}
}

static void test_hbm_read_interrupts(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int device, ch;
	uint32_t val, val2;
	uint64_t base;

	if (tests_state->asic_type != HLTHUNK_DEVICE_GAUDI) {
		printf("Test is skipped because device is not GAUDI\n");
		skip();
	}

	for (device = 0; device < GAUDI_HBM_DEVICES; device++) {
		base = GAUDI_HBM_CFG_BASE + device * GAUDI_HBM_CFG_OFFSET;
		for (ch = 0; ch < GAUDI_HBM_CHANNELS; ch++) {
			val = RREG32_MASK(base + ch * 0x1000 + 0x06C,
					0x0000FFFF);
			val = (val & 0xFF) | ((val >> 8) & 0xFF);
			if (val) {
				printf(
					"HBM%d pc%d interrupts info: WR_PAR=%d, RD_PAR=%d, CA_PAR=%d, SERR=%d, DERR=%d\n",
					device, ch * 2, val & 0x1,
					(val >> 1) & 0x1, (val >> 2) & 0x1,
					(val >> 3) & 0x1, (val >> 4) & 0x1);

				val2 = RREG32(base + ch * 0x1000 + 0x060);
				printf(
					"HBM%d pc%d ECC info: 1ST_ERR_ADDR=0x%x, 1ST_ERR_TYPE=%d, SEC_CONT_CNT=%d, SEC_CNT=%d, DED_CNT=%d\n",
					device, ch * 2,
					RREG32(base + ch * 0x1000 + 0x064),
					(val2 & 0x200) >> 9,
					(val2 & 0xFC00) >> 10,
					(val2 & 0xFF0000) >> 16,
					(val2 & 0xFF000000) >> 24);
			}

			val = RREG32_MASK(base + ch * 0x1000 + 0x07C,
					0x0000FFFF);
			val = (val & 0xFF) | ((val >> 8) & 0xFF);
			if (val) {
				printf(
					"HBM%d pc%d interrupts info: WR_PAR=%d, RD_PAR=%d, CA_PAR=%d, SERR=%d, DERR=%d\n",
					device, ch * 2 + 1, val & 0x1,
					(val >> 1) & 0x1, (val >> 2) & 0x1,
					(val >> 3) & 0x1, (val >> 4) & 0x1);

				val2 = RREG32(base + ch * 0x1000 + 0x070);
				printf(
					"HBM%d pc%d ECC info: 1ST_ERR_ADDR=0x%x, 1ST_ERR_TYPE=%d, SEC_CONT_CNT=%d, SEC_CNT=%d, DED_CNT=%d\n",
					device, ch * 2 + 1,
					RREG32(base + ch * 0x1000 + 0x074),
					(val2 & 0x200) >> 9,
					(val2 & 0xFC00) >> 10,
					(val2 & 0xFF0000) >> 16,
					(val2 & 0xFF000000) >> 24);
			}

			/* Clear interrupts */
			WREG32(base + (ch * 0x1000) + 0x060, 0x1C8);
			WREG32(base + (ch * 0x1000) + 0x070, 0x1C8);
			WREG32(base + (ch * 0x1000) + 0x06C, 0x1F1F);
			WREG32(base + (ch * 0x1000) + 0x07C, 0x1F1F);
			WREG32(base + (ch * 0x1000) + 0x060, 0x0);
			WREG32(base + (ch * 0x1000) + 0x070, 0x0);
		}

		val = RREG32(base + 0x8F30);
		val2 = RREG32(base + 0x8F34);
		if (val | val2)
			printf(
				"MC SRAM SERR dev=%d: Reg 0x8F30=0x%x, Reg 0x8F34=0x%x\n",
				device, val, val2);
		val = RREG32(base + 0x8F40);
		val2 = RREG32(base + 0x8F44);
		if (val | val2)
			printf(
				"MC SRAM DERR dev=%d: Reg 0x8F40=0x%x, Reg 0x8F44=0x%x\n",
				device, val, val2);
	}
}

static void test_read_every_4KB_registers_block(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	uint64_t addr, end;
	uint32_t val;

	if (tests_state->asic_type != HLTHUNK_DEVICE_GAUDI) {
		printf("Test is skipped because device is not GAUDI\n");
		skip();
	}

	addr = CFG_BASE;
	end = CFG_BASE + 0x2000000;
	while (addr < end) {
		if (!(addr & 0xFFFF))
			printf("Reading 0x%lx\n", addr);
		val = RREG32(addr);
		addr += 0x1000;
	}
}

struct read_through_pci_cfg {
	uint64_t start_address;
	uint64_t end_address;
	uint32_t jump;
	uint32_t print_delta;
};

static int read_through_pci_parsing_handler(void *user, const char *section,
					const char *name, const char *value)
{
	struct read_through_pci_cfg *cfg =
					(struct read_through_pci_cfg *) user;

	if (MATCH("read_through_pci_test", "start_addr"))
		cfg->start_address = strtoul(value, NULL, 0);
	else if (MATCH("read_through_pci_test", "end_addr"))
		cfg->end_address = strtoul(value, NULL, 0);
	else if (MATCH("read_through_pci_test", "jump"))
		cfg->jump = strtoul(value, NULL, 0);
	else if (MATCH("read_through_pci_test", "print_delta"))
		cfg->print_delta = strtoul(value, NULL, 0);
	else
		return 0; /* unknown section/name, error */

	return 1;
}

void test_read_through_pci(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	const char *config_filename = hltests_get_config_filename();
	struct read_through_pci_cfg cfg;
	uint64_t addr, end;
	uint32_t val, prot;

	if (tests_state->asic_type != HLTHUNK_DEVICE_GAUDI) {
		printf("Test is skipped because device is not GAUDI\n");
		skip();
	}

	memset(&cfg, 0, sizeof(struct read_through_pci_cfg));

	if (!config_filename)
		fail_msg("User didn't supply a configuration file name!\n");

	if (ini_parse(config_filename, read_through_pci_parsing_handler,
								&cfg) < 0)
		fail_msg("Can't load %s\n", config_filename);

	printf("Configuration loaded from %s:\n", config_filename);
	printf("start address = 0x%lx, end address = 0x%lx, jump = 0x%x\n",
		cfg.start_address, cfg.end_address, cfg.jump);

	printf("print_delta = 0x%x\n", cfg.print_delta);

	if (!cfg.jump)
		fail_msg("jump can't be 0\n");

	/* make PCI non-secured to make sure we hit RR protection */
	prot = RREG32(mmPCIE_WRAP_LBW_PROT_OVR);
	WREG32(mmPCIE_WRAP_LBW_PROT_OVR, 0);
	val = RREG32(mmPCIE_WRAP_LBW_PROT_OVR);
	sleep(1);

	addr = cfg.start_address;
	end = cfg.end_address;
	while (addr < end) {
		if (!(addr & (cfg.print_delta - 1)))
			printf("Reading 0x%lx\n", addr);
		val = RREG32(addr);
		addr += cfg.jump;
	}

	WREG32(mmPCIE_WRAP_LBW_PROT_OVR, prot);
}

const struct CMUnitTest gaudi_root_debug_tests[] = {
	cmocka_unit_test(test_hbm_read_interrupts),
	cmocka_unit_test(test_hbm_read_temperature),
	cmocka_unit_test(test_read_every_4KB_registers_block),
	cmocka_unit_test(test_read_through_pci)
};

static const char *const usage[] = {
	"gaudi_root_debug [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = sizeof(gaudi_root_debug_tests) /
			sizeof((gaudi_root_debug_tests)[0]);

	hltests_parser(argc, argv, usage, HLTHUNK_DEVICE_GAUDI,
			gaudi_root_debug_tests, num_tests);

	if (access("/sys/kernel/debug", R_OK)) {
		printf("This executable need to be run with sudo\n");
		return 0;
	}

	return hltests_run_group_tests("gaudi_root_debug",
			gaudi_root_debug_tests, num_tests,
			hltests_root_debug_setup, hltests_root_debug_teardown);
}
