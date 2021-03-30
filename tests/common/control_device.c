// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_tests.h"
#include "ini.h"

#include "goya/goya_async_events.h"
#include "gaudi/gaudi_async_events.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include <limits.h>
#include <cmocka.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>

void test_print_hw_ip_info(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int rc, fd = tests_state->fd;
	struct hlthunk_hw_ip_info hw_ip;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	printf("\nDevice information:");
	printf("\n-----------------------");
	printf("\nPCI Device id        : 0x%x", hw_ip.device_id);
	printf("\nCard name            : %s", hw_ip.card_name);
	printf("\nDRAM enabled         : %d", hw_ip.dram_enabled);
	printf("\nDRAM base address    : 0x%lx", hw_ip.dram_base_address);
	printf("\nDRAM size            : %lu (0x%lx)", hw_ip.dram_size,
							hw_ip.dram_size);
	printf("\nSRAM base address    : 0x%lx", hw_ip.sram_base_address);
	printf("\nSRAM size            : %u (0x%x)", hw_ip.sram_size,
							hw_ip.sram_size);
	printf("\nFirst user interrupt : %u",
					hw_ip.first_available_interrupt_id);

	printf("\nTPC enabled mask     : 0x%x", hw_ip.tpc_enabled_mask);

	if (hltests_is_gaudi(fd))
		printf("\nModule ID            : %d", hw_ip.module_id);

	printf("\n\n");

}

static void print_engine_name(enum hlthunk_device_name device_id,
					uint32_t engine_id)
{
	if (device_id == HLTHUNK_DEVICE_GOYA) {
		switch (engine_id) {
		case GOYA_ENGINE_ID_DMA_0 ... GOYA_ENGINE_ID_DMA_4:
			printf("  DMA%d\n", engine_id - GOYA_ENGINE_ID_DMA_0);
			break;
		case GOYA_ENGINE_ID_MME_0:
			printf("  MME\n");
			break;
		case GOYA_ENGINE_ID_TPC_0 ... GOYA_ENGINE_ID_TPC_7:
			printf("  TPC%d\n", engine_id - GOYA_ENGINE_ID_TPC_0);
			break;
		default:
			fail_msg("Unexpected engine id %d\n", engine_id);
		}
	} else if (device_id == HLTHUNK_DEVICE_GAUDI) {
		switch (engine_id) {
		case GAUDI_ENGINE_ID_DMA_0 ... GAUDI_ENGINE_ID_DMA_7:
			printf("  DMA%d\n", engine_id - GAUDI_ENGINE_ID_DMA_0);
			break;
		case GAUDI_ENGINE_ID_MME_0 ... GAUDI_ENGINE_ID_MME_3:
			printf("  MME%d\n", engine_id - GAUDI_ENGINE_ID_MME_0);
			break;
		case GAUDI_ENGINE_ID_TPC_0 ... GAUDI_ENGINE_ID_TPC_7:
			printf("  TPC%d\n", engine_id - GAUDI_ENGINE_ID_TPC_0);
			break;
		case GAUDI_ENGINE_ID_NIC_0 ... GAUDI_ENGINE_ID_NIC_9:
			printf("  NIC%d\n", engine_id - GAUDI_ENGINE_ID_NIC_0);
			break;
		default:
			fail_msg("Unexpected engine id %d\n", engine_id);
		}
	} else {
		fail_msg("Unexpected device id %d\n", device_id);
	}
}

void test_print_hw_idle_info(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int rc, fd = tests_state->fd;
	struct hlthunk_engines_idle_info idle_info;
	uint64_t i;
	bool is_idle;

	printf("\n");
	printf("Idle status\n");
	printf("-----------\n");

	is_idle = hlthunk_is_device_idle(fd);
	if (is_idle) {
		printf("Device is idle\n");
		goto out;
	}

	rc = hlthunk_get_busy_engines_mask(fd, &idle_info);
	assert_int_equal(rc, 0);

	printf("Busy engine(s):\n");
	for (i = 0 ; i < sizeof(idle_info.mask) * CHAR_BIT ; i++)
		if (idle_info.mask[i >> 6] & (1ull << (i & 0x3f)))
			print_engine_name(fd, i);
out:
	printf("\n");
}

void test_print_dram_usage_info_no_stop(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int rc, fd = tests_state->fd;
	struct hlthunk_dram_usage_info dram_usage;

	printf("\n");

	while (1) {
		memset(&dram_usage, 0, sizeof(dram_usage));

		rc = hlthunk_get_dram_usage(fd, &dram_usage);
		assert_int_equal(rc, 0);

		printf("dram free memory: %"PRIu64"MB\n",
			dram_usage.dram_free_mem / 1024 / 1024);

		usleep(250 * 1000);
	}
}

void test_print_device_utilization_no_stop(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int rc, fd = tests_state->fd;
	uint32_t rate;

	printf("\n");

	while (1) {
		rc = hlthunk_get_device_utilization(fd, 500, &rate);
		assert_int_equal(rc, 0);

		printf("device utilization: %u%%\n", rate);

		usleep(450 * 1000);
	}
}

void test_print_clk_rate(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int rc, fd = tests_state->fd;
	uint32_t cur_clk, max_clk;

	rc = hlthunk_get_clk_rate(fd, &cur_clk, &max_clk);
	assert_int_equal(rc, 0);

	printf("\n");
	printf("Current clock rate  : %dMHz\n", cur_clk);
	printf("Maximum clock rate  : %dMHz\n\n", max_clk);
}

void test_print_reset_count(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int rc, fd = tests_state->fd;
	struct hlthunk_reset_count_info info;

	rc = hlthunk_get_reset_count_info(fd, &info);
	assert_int_equal(rc, 0);

	printf("\n");
	printf("Hard reset count  : %d\n", info.hard_reset_count);
	printf("Soft reset count  : %d\n\n", info.soft_reset_count);
}

void test_print_time_sync_info(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int rc, fd = tests_state->fd;
	struct hlthunk_time_sync_info info;

	rc = hlthunk_get_time_sync_info(fd, &info);
	assert_int_equal(rc, 0);

	printf("\n");
	printf("Device time  : 0x%"PRIx64"\n", info.device_time);
	printf("Host time    : 0x%"PRIx64"\n\n", info.host_time);

}

void test_print_hlthunk_version(void **state)
{
	char *version;

	version = hlthunk_get_version();
	assert_int_not_equal(version, NULL);

	printf("\nhlthunk version: %s\n\n", version);

	hlthunk_free(version);
}

void test_print_cs_drop_statistics(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int rc, fd = tests_state->fd;
	struct hl_info_cs_counters info;

	rc = hlthunk_get_cs_counters_info(fd, &info);
	assert_int_equal(rc, 0);

	printf("\n");
	printf("out_of_mem_drop_cnt            : %llu\n",
						info.total_out_of_mem_drop_cnt);

	printf("parsing_drop_cnt               : %llu\n",
						info.total_parsing_drop_cnt);

	printf("queue_full_drop_cnt            : %llu\n",
						info.total_queue_full_drop_cnt);

	printf("max CS in-flight drop_cnt      : %llu\n",
					info.total_max_cs_in_flight_drop_cnt);

	printf("device_in_reset_drop_cnt       : %llu\n",
					info.total_device_in_reset_drop_cnt);

	printf("validation_drop_cnt            : %llu\n",
						info.total_validation_drop_cnt);

	printf("ctx_out_of_mem_drop_cnt        : %llu\n",
						info.ctx_out_of_mem_drop_cnt);

	printf("ctx_parsing_drop_cnt           : %llu\n",
						info.ctx_parsing_drop_cnt);

	printf("ctx_queue_full_drop_cnt        : %llu\n",
						info.ctx_queue_full_drop_cnt);

	printf("ctx max CS in-flight drop_cnt  : %llu\n",
					info.ctx_max_cs_in_flight_drop_cnt);

	printf("ctx_device_in_reset_drop_cnt   : %llu\n",
					info.ctx_device_in_reset_drop_cnt);

	printf("ctx_validation_drop_cnt        : %llu\n\n",
						info.ctx_validation_drop_cnt);

	hlthunk_close(fd);
}

void test_print_pci_counters(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int rc, fd = tests_state->fd;
	struct hlthunk_pci_counters_info info;

	rc = hlthunk_get_pci_counters_info(fd, &info);
	assert_int_equal(rc, 0);

	printf("\n");
	printf("rx_throughput   : %lu\n", info.rx_throughput);
	printf("tx_throughput   : %lu\n", info.tx_throughput);
	printf("replay counter  : %u\n\n", info.replay_cnt);
}

void test_print_clk_throttling_reason(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int rc, fd = tests_state->fd;
	struct hlthunk_clk_throttle_info info;

	rc = hlthunk_get_clk_throttle_info(fd, &info);
	assert_int_equal(rc, 0);

	printf("\nclk throttling bitmask: %u\n\n",
			info.clk_throttle_reason_bitmask);
}

void test_print_total_energy_consumption(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int rc, fd = tests_state->fd;
	struct hlthunk_energy_info energy_info = {0};

	rc = hlthunk_get_total_energy_consumption_info(fd, &energy_info);
	assert_int_equal(rc, 0);

	printf("\nTotal energy consumption: %lu(mj)\n\n",
			energy_info.total_energy_consumption);
}

void print_events_counters(void **state, bool aggregate)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int i, rc, fd = tests_state->fd;
	uint32_t hw_events_arr_size;
	uint32_t *hw_events_arr;

	rc = hlthunk_get_device_name_from_fd(fd);
	switch (rc) {
	case HLTHUNK_DEVICE_GOYA:
		hw_events_arr_size = GOYA_ASYNC_EVENT_ID_SIZE;
		break;

	case HLTHUNK_DEVICE_GAUDI:
		hw_events_arr_size = GAUDI_EVENT_SIZE;
		break;

	default:
		printf("Invalid device %d\n", rc);
		fail();
		return;
	}

	hw_events_arr = (uint32_t *) hlthunk_malloc(hw_events_arr_size *
							sizeof(uint32_t));
	assert_int_not_equal(hw_events_arr, 0);

	rc = hlthunk_get_hw_events_arr(fd, aggregate, hw_events_arr_size,
					hw_events_arr);
	assert_int_equal(rc, 0);

	for (i = 0 ; i < hw_events_arr_size ; i++)
		printf("\nhw_events_arr[%d]: %d", i, hw_events_arr[i]);

	printf("\n");

	hlthunk_free((void *) hw_events_arr);
}

void test_print_events_counters(void **state)
{
	print_events_counters(state, false);
}

void test_print_events_counters_aggregate(void **state)
{
	print_events_counters(state, true);
}

void test_print_pci_bdf(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int rc, fd = tests_state->fd;
	char pci_bus_id[16];

	rc = hlthunk_get_pci_bus_id_from_fd(fd, pci_bus_id, 16);
	assert_int_equal(rc, 0);

	printf("PCI BDF: %s\n", pci_bus_id);

}

void test_print_pll_info(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int rc, fd = tests_state->fd;
	struct hlthunk_hw_ip_info hw_ip;
	uint32_t pll_idx, max_pll_idx;
	struct hlthunk_pll_frequency_info freq_info;

	if (hltests_is_simulator(fd)) {
		printf("Test is not required on simulator\n");
		skip();
	}

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);
	printf("\nCPUCP: %s\n", hw_ip.cpucp_version);

	max_pll_idx = hltests_get_max_pll_idx(fd);

	for (pll_idx = 0; pll_idx < max_pll_idx; pll_idx++) {
		rc = hlthunk_get_pll_frequency(fd, pll_idx, &freq_info);
		assert_int_equal(rc, 0);

		printf("\nFrequency for %s[%u]:\n",
			hltests_stringify_pll_idx(fd, pll_idx),
			pll_idx);
		printf("\t%s: %u Mhz\n\t%s: %u Mhz\n\t%s: %u Mhz\n\t%s: %u Mhz\n",
			hltests_stringify_pll_type(fd, pll_idx, 0),
			freq_info.output[0],
			hltests_stringify_pll_type(fd, pll_idx, 1),
			freq_info.output[1],
			hltests_stringify_pll_type(fd, pll_idx, 2),
			freq_info.output[2],
			hltests_stringify_pll_type(fd, pll_idx, 3),
			freq_info.output[3]);
	}
}

const struct CMUnitTest control_tests[] = {
	cmocka_unit_test(test_print_hw_ip_info),
	cmocka_unit_test(test_print_hw_idle_info),
	cmocka_unit_test(test_print_dram_usage_info_no_stop),
	cmocka_unit_test(test_print_device_utilization_no_stop),
	cmocka_unit_test(test_print_clk_rate),
	cmocka_unit_test(test_print_reset_count),
	cmocka_unit_test(test_print_time_sync_info),
	cmocka_unit_test(test_print_hlthunk_version),
	cmocka_unit_test(test_print_cs_drop_statistics),
	cmocka_unit_test(test_print_pci_counters),
	cmocka_unit_test(test_print_clk_throttling_reason),
	cmocka_unit_test(test_print_total_energy_consumption),
	cmocka_unit_test(test_print_events_counters),
	cmocka_unit_test(test_print_events_counters_aggregate),
	cmocka_unit_test(test_print_pci_bdf),
	cmocka_unit_test(test_print_pll_info)
};

static const char *const usage[] = {
	"control_device [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = sizeof(control_tests) / sizeof((control_tests)[0]);

	hltests_parser(argc, argv, usage, HLTHUNK_DEVICE_DONT_CARE,
			control_tests, num_tests);

	if (!hltests_get_parser_run_disabled_tests()) {
		printf("This executable need to be run with -d flag\n");
		return 0;
	}

	return hltests_run_group_tests("control_device", control_tests,
					num_tests,
					hltests_control_dev_setup,
					hltests_control_dev_teardown);
}
