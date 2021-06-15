// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_tests.h"
#include "ini.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#define RANGE_PARAMS_NUM	7
#define IS_RANGE_VALID(v) 	(v == 0x7F)
#define BIT(sh)			((1) << (sh))
#define RANGE_START_SHIFT	0
#define RANGE_END_SHIFT		1
#define RANGE_PRINT_SHIFT	2
#define RANGE_VALUE_SHIFT	3
#define RANGE_REG_OFF_SHIFT	4
#define RANGE_DATA64_SHIFT	5
#define RANGE_WR_THEN_RD_SHIFT	6

typedef struct range_param {
	uint64_t range_start_addr;
	uint64_t range_end_addr;
	uint32_t print_addr_freq;
	uint32_t value;
	uint32_t reg_offset;
	uint32_t valid_mask;
	bool	 data64;
	bool	 write_then_read;
}range_param;

struct lbw_scan_cfg {
	range_param *ranges_block;
	uint64_t num_of_ranges;
	uint32_t ranges_block_idx;
	uint32_t range_config_params_count;
	bool ranges_block_allocated;
};

static int test_lbw_scan_parsing_handler(void *user, const char *section,
					const char *name, const char *value)
{
	struct lbw_scan_cfg *cfg = (struct lbw_scan_cfg *) user;
	char *tmp;

	if (MATCH("lbw_scan_test", "ranges_num")) {
		cfg->num_of_ranges = strtoul(value, NULL, 0);

		if (!cfg->ranges_block_allocated) {
			cfg->ranges_block =
			malloc(cfg->num_of_ranges * sizeof(range_param));
			if (!cfg->ranges_block) {
				printf("Faild to allocate memory\n");
				return 0;
			}

			memset(cfg->ranges_block, 0 ,
				cfg->num_of_ranges * sizeof(range_param));
			cfg->ranges_block_allocated = true;
		}
	} else if (MATCH("lbw_scan_test", "range_start")) {
		if (cfg->range_config_params_count &&
			cfg->range_config_params_count != RANGE_PARAMS_NUM) {
			printf("Invalid range block config, fix config file\n");
			return 0;
		} else if (cfg->range_config_params_count){
			/* parsing next range params */
			cfg->range_config_params_count = 0;
			cfg->ranges_block_idx++;
		}

		cfg->ranges_block[cfg->ranges_block_idx].range_start_addr =
				strtoul(value, NULL, 0);
		cfg->ranges_block[cfg->ranges_block_idx].valid_mask |=
					BIT(RANGE_START_SHIFT);
		cfg->range_config_params_count++;
	} else if (MATCH("lbw_scan_test", "range_end")) {
		cfg->ranges_block[cfg->ranges_block_idx].range_end_addr =
						strtoul(value, NULL, 0);
		cfg->ranges_block[cfg->ranges_block_idx].valid_mask |=
					BIT(RANGE_END_SHIFT);
		cfg->range_config_params_count++;
	} else if (MATCH("lbw_scan_test", "data64")) {
		tmp = strdup(value);
		if (!tmp)
			return 0;

		cfg->ranges_block[cfg->ranges_block_idx].data64 =
				strcmp("true", tmp) ? false : true;
		cfg->ranges_block[cfg->ranges_block_idx].valid_mask |=
					BIT(RANGE_DATA64_SHIFT);
		cfg->range_config_params_count++;
		free(tmp);
	} else if (MATCH("lbw_scan_test", "write_then_read")) {
		tmp = strdup(value);
		if (!tmp)
			return 0;

		cfg->ranges_block[cfg->ranges_block_idx].write_then_read =
			strcmp("true", tmp) ? false : true;
		cfg->ranges_block[cfg->ranges_block_idx].valid_mask |=
					BIT(RANGE_WR_THEN_RD_SHIFT);
		cfg->range_config_params_count++;
		free(tmp);
	} else if (MATCH("lbw_scan_test", "value")) {
		cfg->ranges_block[cfg->ranges_block_idx].value =
				strtoul(value, NULL, 0);
		cfg->ranges_block[cfg->ranges_block_idx].valid_mask |=
					BIT(RANGE_VALUE_SHIFT);
		cfg->range_config_params_count++;
	} else if (MATCH("lbw_scan_test", "print_freq")) {
		cfg->ranges_block[cfg->ranges_block_idx].print_addr_freq =
			strtoul(value, NULL, 0);
		cfg->ranges_block[cfg->ranges_block_idx].valid_mask |=
					BIT(RANGE_PRINT_SHIFT);
		cfg->range_config_params_count++;
	} else if (MATCH("lbw_scan_test", "reg_offset")) {
		cfg->ranges_block[cfg->ranges_block_idx].reg_offset =
			strtoul(value, NULL, 0);
		cfg->ranges_block[cfg->ranges_block_idx].valid_mask |=
					BIT(RANGE_REG_OFF_SHIFT);
		cfg->range_config_params_count++;
	} else {
		return 0; /* unknown section/name, error */
	}

	return 1;
}

void test_lbw_scan(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	const char *config_filename = hltests_get_config_filename();
	struct lbw_scan_cfg cfg = {0};
	uint64_t addr, end;
	uint64_t val;
	int i;

	if (!config_filename)
		fail_msg("User didn't supply a configuration file name!\n");

	cfg.num_of_ranges = 0;
	cfg.ranges_block_allocated = false;
	cfg.ranges_block_idx = 0;
	cfg.range_config_params_count = 0;

	if (ini_parse(config_filename, test_lbw_scan_parsing_handler, &cfg))
		fail_msg("Can't load %s\n", config_filename);

	printf("Configuration loaded from %s:\n", config_filename);

	printf("Number of ranges: 0x%lx\n", cfg.num_of_ranges);

	for (i = 0 ; i < cfg.num_of_ranges ; i++) {
		printf("range_%u_start = 0x%lx, range_%u_end = 0x%lx\n"
				"print_addr_freq = 0x%X, "
				"value = 0x%X\ndata64 = %s, "
				"write_then_read = %s, reg_offset = 0x%X\n",
				i, cfg.ranges_block[i].range_start_addr,
				i , cfg.ranges_block[i].range_end_addr,
				cfg.ranges_block[i].print_addr_freq,
				cfg.ranges_block[i].value,
				cfg.ranges_block[i].data64 ? "true" : "false",
				cfg.ranges_block[i].write_then_read ? "true" : "false",
				cfg.ranges_block[i].reg_offset);
	}

	for( i = 0 ; i < cfg.num_of_ranges ; i++) {
		if (!IS_RANGE_VALID(cfg.ranges_block[i].valid_mask)) {
			printf("Range num %u Invalid\n", i);
			continue;
		}
		printf("LBW scan range%u...\n", i);

		addr = cfg.ranges_block[i].range_start_addr;
		end = cfg.ranges_block[i].range_end_addr;

		while (addr < end) {
			if (!(addr & cfg.ranges_block[i].print_addr_freq)) {
				printf("Reading 0x%lx\n", addr);
				fflush(stdout);
			}

			if (cfg.ranges_block[i].write_then_read) {
				if (cfg.ranges_block[i].data64)
					WREG64(addr, cfg.ranges_block[i].value);
				else
					WREG32(addr, cfg.ranges_block[i].value);
			}

			if (cfg.ranges_block[i].data64)
				val = RREG64(addr);
			else
				val = RREG32(addr);

			if (cfg.ranges_block[i].write_then_read)
				assert_int_equal
				(val, cfg.ranges_block[i].value);

			addr += cfg.ranges_block[i].reg_offset;
		}
	}

	if (cfg.ranges_block)
		free(cfg.ranges_block);
}

const struct CMUnitTest debug_tests[] = {
		cmocka_unit_test(test_lbw_scan)
};

static const char *const usage[] = {
	"root_debug [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = sizeof(debug_tests) / sizeof((debug_tests)[0]);

	hltests_parser(argc, argv, usage, HLTHUNK_DEVICE_DONT_CARE, debug_tests,
			num_tests);

	if (access("/sys/kernel/debug", R_OK)) {
		printf("This executable need to be run with sudo\n");
		return 0;
	}

	return hltests_run_group_tests("debug", debug_tests, num_tests,
			hltests_root_debug_setup, hltests_root_debug_teardown);
}
