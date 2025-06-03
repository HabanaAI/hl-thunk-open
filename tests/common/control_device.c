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
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>
#include <fcntl.h>

VOID test_print_hw_ip_info(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;
	int fd = tests_state->fd;

	if (!hltests_get_parser_run_disabled_tests())
		skip();

	printf("\nDevice information:");
	printf("\n-----------------------");
	printf("\nPCI Device id             : %#x", hw_ip->device_id);
	printf("\nPCI Revision id           : %#x", hw_ip->revision_id);
	printf("\nCard name                 : %s", hw_ip->card_name);
	printf("\nDRAM enabled              : %d", hw_ip->dram_enabled);
	printf("\nDRAM base address         : %#lx", hw_ip->dram_base_address);
	printf("\nDRAM size                 : %luGB (0x%lx)", hw_ip->dram_size / 1024 / 1024 / 1024,
								hw_ip->dram_size);
	printf("\nReserved DRAM size        : %luMB", hw_ip->reserved_dram_size / 1024 / 1024);

	printf("\nDRAM default page size    : %luMB",
			hw_ip->device_mem_alloc_default_page_size / 1024 / 1024);
	printf("\nSRAM base address         : %#lx", hw_ip->sram_base_address);
	printf("\nSRAM size                 : %uMB (0x%x)", hw_ip->sram_size / 1024 / 1024,
								hw_ip->sram_size);

	printf("\nFirst user interrupt      : %u", hw_ip->first_available_interrupt_id);
	printf("\nNumber of user interrupts : %u", hw_ip->number_of_user_interrupts);
	printf("\nTPC enabled mask          : %#lx", hw_ip->tpc_enabled_mask_ext);
	printf("\nMME enabled mask          : %#x", hw_ip->mme_enabled_mask);
	printf("\nDecoder enabled mask      : %#x", hw_ip->decoder_enabled_mask);
	printf("\nEDMA enabled mask         : %#x", hw_ip->edma_enabled_mask);

	if (hltests_is_gaudi3(fd)) {
		printf("\nPDMA enabled mask         : %#lx\n", hw_ip->pdma_user_owned_ch_mask);
		printf("\nODP supported             : %d", hw_ip->odp_supported);
		printf("\nRotator enabled mask      : %#x", hw_ip->rotator_enabled_mask);
	}

	if (hltests_is_gaudi_family(fd))
		printf("\nSecurity enabled          : %d", hw_ip->security_enabled);

	if (!hltests_is_goya(fd))
		printf("\nModule ID                 : %d", hw_ip->module_id);

	if (hltests_is_gaudi_family(fd))
		printf("\nServer type               : %u", hw_ip->server_type);

	/* NIC ports masks are exposed via IB driver sysfs from Gaudi2 onward. */
	if (hltests_is_gaudi(fd)) {
		printf("\nNIC ports enabled mask    : 0x%lx", hw_ip->nic_ports_mask);
		printf("\nNIC external ports mask   : 0x%lx", hw_ip->nic_ports_external_mask);
	}

	if (hltests_is_gaudi2(fd) || hltests_is_gaudi3(fd)) {
		printf("\nTPC interrupt ID          : %d", hw_ip->tpc_interrupt_id);
		printf("\nEngine Core int addr      : %#lx", hw_ip->engine_core_interrupt_reg_addr);
		printf("\nSched Arcs enabled mask   : %#x", hw_ip->sched_arc_enabled_mask);
	}

	printf("\n\n");

	END_TEST;
}

VOID print_engine_name(int fd, uint32_t engine_id)
{
	if (hltests_is_goya(fd)) {
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
	} else if (hltests_is_gaudi(fd)) {
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
		fail_msg("Unexpected device id %d\n",
				hlthunk_get_device_name_from_fd(fd));
	}

	END_TEST;
}

VOID test_get_hw_idle_info(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	bool is_idle, verbose = !!hltests_get_verbose_enabled();
	struct hlthunk_engines_idle_info idle_info;
	int rc, fd = tests_state->fd;
	uint64_t i;

	if (verbose) {
		printf("\n");
		printf("Idle status\n");
		printf("-----------\n");
	}

	is_idle = hlthunk_is_device_idle(fd);
	if (is_idle && verbose) {
		printf("Device is idle\n");
		goto out;
	}

	rc = hlthunk_get_busy_engines_mask(fd, &idle_info);
	assert_int_equal(rc, 0);

	if (!verbose)
		goto out;

	printf("Busy engine(s):\n");
	for (i = 0 ; i < sizeof(idle_info.mask) * CHAR_BIT ; i++)
		if (idle_info.mask[i >> 6] & (1ull << (i & 0x3f)))
			print_engine_name(fd, i);
out:
	if (verbose)
		printf("\n");

	END_TEST;
}

VOID test_print_dram_usage_info_no_stop(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_dram_usage_info dram_usage;
	int rc, fd = tests_state->fd;

	if (!hltests_get_parser_run_disabled_tests()) {
		printf("Being endless - test is disabled. Execute with '-d' flag\n");
		skip();
	}

	printf("Monitor DRAM usage in an endless loop. CTRL-C to stop\n");

	printf("\n");

	while (1) {
		memset(&dram_usage, 0, sizeof(dram_usage));

		rc = hlthunk_get_dram_usage(fd, &dram_usage);
		assert_int_equal(rc, 0);

		printf("dram free memory: %"PRIu64"MB\n",
			dram_usage.dram_free_mem / 1024 / 1024);

		usleep(250 * 1000);
	}

	END_TEST;
}

VOID test_print_device_utilization_no_stop(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int rc, fd = tests_state->fd;
	uint32_t rate;

	if (hltests_is_gaudi3(fd)) {
		printf("device utilization not supported on this ASIC\n");
		skip();
	}

	if (!hltests_get_parser_run_disabled_tests()) {
		printf("Being endless - test is disabled. Execute with '-d' flag\n");
		skip();
	}

	printf("Monitor device utilization in an endless loop. CTRL-C to stop\n");

	printf("\n");

	while (1) {
		rc = hlthunk_get_device_utilization(fd, 500, &rate);
		assert_int_equal(rc, 0);

		printf("device utilization: %u%%\n", rate);

		usleep(450 * 1000);
	}

	END_TEST;
}

VOID test_get_clk_rate(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int rc, fd = tests_state->fd;
	uint32_t cur_clk, max_clk;

	rc = hlthunk_get_clk_rate(fd, &cur_clk, &max_clk);
	assert_int_equal(rc, 0);

	if (hltests_get_verbose_enabled()) {
		printf("\n");
		printf("Current clock rate  : %dMHz\n", cur_clk);
		printf("Maximum clock rate  : %dMHz\n\n", max_clk);
	}

	END_TEST;
}

VOID test_get_reset_count(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_reset_count_info info;
	int rc, fd = tests_state->fd;

	rc = hlthunk_get_reset_count_info(fd, &info);
	assert_int_equal(rc, 0);

	if (hltests_get_verbose_enabled()) {
		printf("\n");
		printf("Hard reset count  : %d\n", info.hard_reset_count);
		printf("Soft reset count  : %d\n\n", info.soft_reset_count);
	}

	END_TEST;
}

VOID test_get_time_sync_info(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_time_sync_info info;
	int rc, fd = tests_state->fd;

	rc = hlthunk_get_time_sync_info(fd, &info);
	assert_int_equal(rc, 0);

	if (hltests_get_verbose_enabled()) {
		printf("\n");
		printf("Device time  : 0x%"PRIx64"\n", info.device_time);
		printf("Host time    : 0x%"PRIx64"\n\n", info.host_time);
		printf("Host TSC     : 0x%"PRIx64"\n\n", info.tsc_time);
	}

	END_TEST;
}

VOID test_print_hlthunk_version(void **state)
{
	char *version;

	version = hlthunk_get_version();
	assert_int_not_equal(version, NULL);

	printf("\nhlthunk version: %s\n\n", version);

	hlthunk_free(version);

	END_TEST;
}

VOID test_get_cs_drop_statistics(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hl_info_cs_counters info;
	int rc, fd = tests_state->fd;

	rc = hlthunk_get_cs_counters_info(fd, &info);
	assert_int_equal(rc, 0);

	if (hltests_get_verbose_enabled()) {
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
	}

	END_TEST;
}

VOID test_get_pci_counters(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_pci_counters_info info;
	int rc, fd = tests_state->fd;

	rc = hlthunk_get_pci_counters_info(fd, &info);
	assert_int_equal(rc, 0);

	if (hltests_get_verbose_enabled()) {
		printf("\n");
		printf("rx_throughput   : %lu\n", info.rx_throughput);
		printf("tx_throughput   : %lu\n", info.tx_throughput);
		printf("replay counter  : %u\n\n", info.replay_cnt);
	}

	END_TEST;
}

VOID test_get_clk_throttling_reason(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_clk_throttle_info info;
	int rc, fd = tests_state->fd;

	rc = hlthunk_get_clk_throttle_info(fd, &info);
	assert_int_equal(rc, 0);

	if (!hltests_get_verbose_enabled())
		goto out;

	printf("\nCurrent clk throttling bitmask: %u\n\n",
			info.clk_throttle_reason_bitmask);

	if (info.clk_throttle_start_timestamp_us[HL_CLK_THROTTLE_TYPE_POWER])
		printf("\nPower clk throttling Start: %lu us\n\n",
			info.clk_throttle_start_timestamp_us[HL_CLK_THROTTLE_TYPE_POWER]);

	if (info.clk_throttle_duration_ns[HL_CLK_THROTTLE_TYPE_POWER])
		printf("\nPower clk throttling duration: %lu ns\n\n",
			info.clk_throttle_duration_ns[HL_CLK_THROTTLE_TYPE_POWER]);

	if (info.clk_throttle_start_timestamp_us[HL_CLK_THROTTLE_TYPE_THERMAL])
		printf("\nThermal clk throttling Start: %lu us\n\n",
			info.clk_throttle_start_timestamp_us[HL_CLK_THROTTLE_TYPE_THERMAL]);

	if (info.clk_throttle_duration_ns[HL_CLK_THROTTLE_TYPE_THERMAL])
		printf("\nThermal clk throttling duration: %lu ns\n\n",
			info.clk_throttle_duration_ns[HL_CLK_THROTTLE_TYPE_THERMAL]);

out:
	END_TEST;
}

VOID test_get_total_energy_consumption(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_energy_info energy_info = {0};
	int rc, fd = tests_state->fd;

	rc = hlthunk_get_total_energy_consumption_info(fd, &energy_info);
	assert_int_equal(rc, 0);

	if (hltests_get_verbose_enabled())
		printf("\nTotal energy consumption: %lu(mj)\n\n",
			energy_info.total_energy_consumption);

	END_TEST;
}

VOID get_events_counters(void **state, bool aggregate)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int i, rc, fd = tests_state->fd;
	uint32_t hw_events_arr_size = 0;
	uint32_t *hw_events_arr;

	rc = hlthunk_get_device_name_from_fd(fd);
	switch (rc) {
	case HLTHUNK_DEVICE_GOYA:
		hw_events_arr_size = GOYA_ASYNC_EVENT_ID_SIZE;
		break;

	case HLTHUNK_DEVICE_GAUDI:
	case HLTHUNK_DEVICE_GAUDI_HL2000M:
		hw_events_arr_size = GAUDI_EVENT_SIZE;
		break;

	case HLTHUNK_DEVICE_GAUDI2:
	case HLTHUNK_DEVICE_GAUDI2B:
	case HLTHUNK_DEVICE_GAUDI2C:
	case HLTHUNK_DEVICE_GAUDI2D:
		hw_events_arr_size = 1024; /* TODO: replace to real value */
		break;

	case HLTHUNK_DEVICE_GAUDI3:
	case HLTHUNK_DEVICE_GAUDI3D:
		printf("Event counters not supported for gaudi3\n");
		skip();
		break;
	default:
		fail_msg("Invalid device %d\n", rc);
		EXIT_FROM_TEST;
	}

	hw_events_arr = (uint32_t *) hlthunk_malloc(hw_events_arr_size *
							sizeof(uint32_t));
	assert_int_not_equal(hw_events_arr, 0);

	rc = hlthunk_get_hw_events_arr(fd, aggregate, hw_events_arr_size * sizeof(uint32_t),
					hw_events_arr);
	assert_int_equal(rc, 0);

	if (!hltests_get_verbose_enabled())
		goto out;

	for (i = 0 ; i < hw_events_arr_size ; i++)
		printf("\nhw_events_arr[%d]: %d", i, hw_events_arr[i]);

	printf("\n");

out:
	hlthunk_free((void *) hw_events_arr);

	END_TEST;
}

VOID test_get_events_counters(void **state)
{
	END_TEST_FUNC(get_events_counters(state, false));
}

VOID test_get_events_counters_aggregate(void **state)
{
	END_TEST_FUNC(get_events_counters(state, true));
}

VOID test_get_pci_bdf(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int rc, fd = tests_state->fd;
	char pci_bus_id[16];

	rc = hlthunk_get_pci_bus_id_from_fd(fd, pci_bus_id, 16);
	assert_int_equal(rc, 0);

	if (hltests_get_verbose_enabled())
		printf("PCI BDF: %s\n", pci_bus_id);

	END_TEST;
}

VOID test_get_pll_info(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	bool verbose = !!hltests_get_verbose_enabled();
	struct hlthunk_pll_frequency_info freq_info;
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;
	uint32_t pll_idx, max_pll_idx;
	int rc, fd = tests_state->fd;

	if (hltests_is_simulator(fd)) {
		printf("Test is not required on simulator\n");
		skip();
	}

	if (verbose)
		printf("\nCPUCP: %s\n", hw_ip->cpucp_version);

	max_pll_idx = hltests_get_max_pll_idx(fd);

	for (pll_idx = 0; pll_idx < max_pll_idx; pll_idx++) {
		rc = hlthunk_get_pll_frequency(fd, pll_idx, &freq_info);
		if (rc) {
			printf("Failed to get PLL freq for index: %u\n", pll_idx);
			assert_int_equal(rc, 0);
		}

		if (!verbose)
			continue;

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

	END_TEST;
}

VOID test_get_hw_asic_status(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_asic_status hw_asic_status;
	int rc, fd = tests_state->fd;

	rc = hlthunk_get_hw_asic_status(fd, &hw_asic_status);
	assert_int_equal(rc, 0);
	assert_true(hw_asic_status.valid);

	if (!hltests_get_verbose_enabled())
		goto out;

	printf("\nHW ASIC Status:");
	printf("\n----------------------------------");
	printf("\nStatus                           : %d",
		hw_asic_status.status);
	printf("\nThrottle reason bitmask          : 0x%x",
		hw_asic_status.throttle.clk_throttle_reason_bitmask);
	printf("\nPower                            : %ld",
		hw_asic_status.power.power);
	printf("\nOpen counter                     : %ld",
		hw_asic_status.open_stats.open_counter);
	printf("\nLast open period (ms)            : %ld",
		hw_asic_status.open_stats.last_open_period_ms);
	printf("\nCompute CTX active               : %u",
		hw_asic_status.open_stats.is_compute_ctx_active);
	printf("\nCompute CTX in release           : %u",
		hw_asic_status.open_stats.compute_ctx_in_release);
	printf("\nCompute CTX has mapped resources : %u",
		hw_asic_status.open_stats.compute_ctx_has_mapped_resources);
	printf("\nTimestamp (sec)                  : %ld",
		hw_asic_status.timestamp_sec);
	printf("\n\n");

out:
	END_TEST;
}

VOID test_get_nic_ports_mask(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int fd = tests_state->fd, rc;
	uint64_t mask;

	rc = hlthunk_nic_get_enabled_ports_mask(fd, &mask);
	assert_int_equal(rc, 0);

	if (hltests_get_verbose_enabled())
		printf("NIC ports mask: 0x%lx\n", mask);

	END_TEST;
}

VOID test_get_nic_link_state(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_get_habana_link_state_out out = {0};
	struct hlthunk_get_habana_link_state_in in = {0};
	int fd = tests_state->fd, rc;

	if (!hltests_get_parser_run_disabled_tests())
		skip();

	in.port = hltests_get_parser_nic_port();
	rc = hlthunk_get_habana_link_state(fd, &in, &out);
	assert_int_equal(rc, 0);

	if (hltests_get_verbose_enabled())
		printf("NIC port %u is %s\n", in.port, out.up ? "up" : "down");

	END_TEST;
}

VOID test_print_nic_statistics(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_get_habana_link_stat_out out = {0};
	struct hlthunk_get_habana_link_stat_in in = {0};
	int fd = tests_state->fd, rc, i, port;
	uint64_t *val_buf;
	uint8_t *str_buf;

	if (!hltests_get_parser_run_disabled_tests())
		skip();

	port = hltests_get_parser_nic_port();

	str_buf = hlthunk_malloc(HABANA_LINK_STR_LEN * HABANA_LINK_CNT_MAX_NUM);
	assert_non_null(str_buf);
	val_buf = hlthunk_malloc(sizeof(uint64_t) * HABANA_LINK_CNT_MAX_NUM);
	assert_non_null(val_buf);

	in.port = port;
	out.str_buf = str_buf;
	out.val_buf = val_buf;
	rc = hlthunk_get_habana_link_statistics(fd, &in, &out);
	assert_int_equal(rc, 0);

	if (!hltests_get_verbose_enabled())
		goto free_mem;

	for (i = 0 ; i < out.num_of_stat ; i++) {
		printf("%s: ", str_buf + (HABANA_LINK_STR_LEN * i));
		printf("%ld\n", val_buf[i]);
	}

free_mem:
	hlthunk_free(val_buf);
	hlthunk_free(str_buf);

	END_TEST;
}

VOID test_event_record(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_event_record_undefined_opcode undef_opcode;
	struct hlthunk_event_record_open_dev_time open_dev_time;
	struct hlthunk_event_record_cs_timeout cs_timeout;
	struct hlthunk_event_record_razwi_event razwi;
	bool verbose = hltests_get_verbose_enabled();
	int rc, fd = tests_state->fd, i;

	rc = hlthunk_get_event_record(fd, HLTHUNK_OPEN_DEV, &open_dev_time);
	assert_int_equal(rc, 0);

	rc = hlthunk_get_event_record(fd, HLTHUNK_CS_TIMEOUT, &cs_timeout);
	assert_int_equal(rc, 0);

	rc = hlthunk_get_event_record(fd, HLTHUNK_RAZWI_EVENT, &razwi);
	assert_int_equal(rc, 0);

	if (verbose) {
		printf("RAZWI addr = 0x%lX, flags = 0x%X, timestamp = %ld\n",
				razwi.addr, razwi.flags, razwi.timestamp);
		for (i = 0 ; i < razwi.num_of_possible_engines ; i++)
			printf("%u. Engine id %u.\n", i, razwi.engine_id[i]);
	}

	rc = hlthunk_get_event_record(fd, HLTHUNK_UNDEFINED_OPCODE, &undef_opcode);
	assert_int_equal(rc, 0);

	END_TEST;
}

VOID test_get_dev_memalloc_page_orders(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	uint64_t expected_mask, page_order_bitmask = ULLONG_MAX;
	int fd = tests_state->fd, rc;

	/*
	 * as many ASICs that are not supporting multiple page size in device memory
	 * allocation are expected to return 0-ed mask, initializing to all 1-s will
	 * catch errors better
	 */
	page_order_bitmask = ULLONG_MAX;

	rc = hlthunk_get_dev_memalloc_page_orders(fd, &page_order_bitmask);
	assert_int_equal(rc, 0);

	if (hltests_get_verbose_enabled())
		printf("device mem alloc page order mask %#lx\n", page_order_bitmask);

	expected_mask = hltests_is_gaudi3(fd) ? (SZ_32M | SZ_1G) : 0;
	assert_int_equal(page_order_bitmask, expected_mask);

	END_TEST;
}

VOID test_engine_status(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int rc, fd = tests_state->fd, data_size;
	uint32_t buf_size = SZ_16K;
	char *str;

	str = hlthunk_malloc(buf_size);
	assert_non_null(str);

	rc = hlthunk_get_engine_status(fd, str, buf_size, &data_size);
	assert_int_equal(rc, 0);

	if (hltests_get_verbose_enabled()) {
		printf("engine data size is %d\n", data_size);
		fwrite(str, 1, data_size, stdout);
	}

	hlthunk_free(str);

	END_TEST;
}

VOID test_get_mac_addresses(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_mac_addr_info mac_info;
	int i, fd = tests_state->fd;

	if (!hltests_is_gaudi_family(fd)) {
		printf("Test is skipped because the device's type is not a Gaudi\n");
		skip();
	}

	hlthunk_get_mac_addr_info(fd, &mac_info);

	if (!hltests_get_verbose_enabled())
		goto out;

	printf("mask[0] = 0x%lx\n", mac_info.mask[0]);
	printf("mask[1] = 0x%lx\n", mac_info.mask[1]);

	for (i = 0 ; i < HL_INFO_MAC_ADDR_MAX_NUM ; i++) {
		if (!(mac_info.mask[DIV_ROUND_DOWN_ULL(i, 64)] & (1ul << (i % 64))))
			continue;

		printf("port: %d, MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", i,
			mac_info.array[i].addr[0],
			mac_info.array[i].addr[1],
			mac_info.array[i].addr[2],
			mac_info.array[i].addr[3],
			mac_info.array[i].addr[4],
			mac_info.array[i].addr[5]);
	}

out:
	END_TEST;
}

VOID test_get_sec_attest_info(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_sec_attest_info *info;
	int rc, fd = tests_state->fd;

	if (!hltests_get_parser_run_disabled_tests())
		skip();

	if (!hltests_is_gaudi2(fd)) {
		printf("Test not supported for this ASIC\n");
		skip();
	}

	info = hlthunk_malloc(sizeof(struct hlthunk_sec_attest_info));
	assert_non_null(info);

	rc = hlthunk_get_sec_attest_info(fd, 0x1234A5A5, info);
	assert_int_equal(rc, 0);

	hlthunk_free(info);

	END_TEST;
}

VOID test_get_dev_info_signed(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_dev_info_signed *info;
	uint32_t nonce = 0x1234A5A5;

	int rc, fd = tests_state->fd;

	if (!hltests_get_parser_run_disabled_tests())
		skip();

	if (!hltests_is_gaudi2(fd)) {
		printf("Test not supported for this ASIC\n");
		skip();
	}

	info = hlthunk_malloc(sizeof(struct hlthunk_dev_info_signed));
	assert_non_null(info);

	rc = hlthunk_get_dev_info_signed(fd, nonce, info);
	assert_int_equal(rc, 0);

	/* test the roundtrip of nonce (test -> driver -> fw -> driver -> test) */
	assert_int_equal(nonce, info->nonce);

	assert_true(info->dev_info_len < SEC_DEV_INFO_BUF_SZ);

	hlthunk_free(info);

	END_TEST;
}

VOID test_page_fault_info(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	bool verbose = !!hltests_get_verbose_enabled();
	struct hlthunk_page_fault_info pgf_info;
	int i, rc, fd = tests_state->fd;

	memset(&pgf_info, 0, sizeof(pgf_info));

	pgf_info.mappings_buf = hlthunk_malloc(sizeof(struct hlthunk_user_mapping));
	assert_non_null(pgf_info.mappings_buf);

	rc = hlthunk_get_page_fault_info(fd, &pgf_info, 1);
	if (rc) {
		assert_int_not_equal(pgf_info.num_of_mappings, 0xFFFFFFFF);

		if (verbose) {
			printf("Got page fault info failed\n");
			printf("timestamp %ld, addr 0x%lX, eng_id %u, number of mappings %u\n",
					pgf_info.timestamp, pgf_info.addr, pgf_info.engine_id,
					pgf_info.num_of_mappings);
			printf("Trying again with retrieved num_of_mappings\n");
		}

		if (pgf_info.num_of_mappings) {
			hlthunk_free(pgf_info.mappings_buf);
			pgf_info.mappings_buf =
					hlthunk_malloc(pgf_info.num_of_mappings *
							sizeof(struct hlthunk_user_mapping));
			assert_non_null(pgf_info.mappings_buf);

			memset(&pgf_info, 0, sizeof(pgf_info));
			rc = hlthunk_get_page_fault_info(fd, &pgf_info, pgf_info.num_of_mappings);
			assert_int_equal(rc, 0);
		}
	}

	if (!verbose)
		goto free_mem;

	printf("Success: timestamp %ld, addr 0x%lX, eng_id %u, number of mappings %u\n",
			pgf_info.timestamp, pgf_info.addr, pgf_info.engine_id,
			pgf_info.num_of_mappings);

	for (i = 0 ; i < pgf_info.num_of_mappings ; i++)
		printf("addr 0x%lX, size %lu\n",
				pgf_info.mappings_buf[i].dev_va, pgf_info.mappings_buf[i].size);

free_mem:
	hlthunk_free(pgf_info.mappings_buf);

	END_TEST;
}

VOID test_get_device_count(void **state)
{
	enum hlthunk_device_name device_name;
	uint32_t total = 0;
	int count;

	count = hlthunk_get_device_count(HLTHUNK_DEVICE_INVALID);
	assert_in_range(count, INT_MIN, -1);

	count = hlthunk_get_device_count(HLTHUNK_DEVICE_MAX);
	assert_in_range(count, INT_MIN, -1);

	count = hlthunk_get_device_count(HLTHUNK_DEVICE_MAX + 1);
	assert_in_range(count, INT_MIN, -1);

	for (device_name = 0 ; device_name < HLTHUNK_DEVICE_MAX ; device_name++) {
		if (device_name == HLTHUNK_DEVICE_INVALID ||
				device_name == HLTHUNK_DEVICE_DONT_CARE)
			continue;

		count = hlthunk_get_device_count(device_name);
		total += count;

		if (hltests_get_verbose_enabled()) {
			if (device_name == 0)
				printf("\nDevice count\n------------\n");

			if (!strcmp(asic_names[device_name], ""))
				printf("Device %-6u : %u\n", device_name, count);
			else
				printf("%-13s : %u\n", asic_names[device_name], count);
		}
	}

	count = hlthunk_get_device_count(HLTHUNK_DEVICE_DONT_CARE);
	assert_int_equal(count, total);

	if (hltests_get_verbose_enabled())
		printf("---\nTotal         : %u\n", total);

	END_TEST;
}

VOID test_hard_reset(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int rc, device_idx, hard_reset_fd, fd = tests_state->fd;
	char path[PATH_MAX], pci_bus_id[16];
	uint32_t size;

	/* Make sure we have sudo permissions */
	if (!can_open_debugfs(true))
		skip();

	rc = hlthunk_get_pci_bus_id_from_fd(fd, pci_bus_id, sizeof(pci_bus_id));
	assert_int_equal(rc, 0);

	device_idx = hlthunk_get_device_index_from_pci_bus_id(pci_bus_id);
	assert_in_range(device_idx, 0, INT_MAX);

	snprintf(path, PATH_MAX, "/sys/class/accel/accel%d/device/hard_reset", device_idx);

	hard_reset_fd = open(path, O_WRONLY);
	assert_in_range(hard_reset_fd, 0, INT_MAX);

	size = pwrite(hard_reset_fd, "1", 2, 0);
	if (size < 0) {
		printf("failed to write to hard reset sysfs node(%u)\n", size);
		rc = errno;
		goto close_fd;
	}

	/* Wait till hard reset is completed */
	rc = wait_until_device_not_in_reset(fd);
	if (rc)
		printf("Failed to wait for hard reset(%d)\n", rc);

close_fd:
	close(hard_reset_fd);

	assert_int_equal(rc, 0);

	END_TEST;
}

#ifndef HLTESTS_LIB_MODE

const struct CMUnitTest control_tests[] = {
	cmocka_unit_test(test_print_hw_ip_info),
	cmocka_unit_test(test_get_hw_idle_info),
	cmocka_unit_test(test_print_dram_usage_info_no_stop),
	cmocka_unit_test(test_print_device_utilization_no_stop),
	cmocka_unit_test(test_get_clk_rate),
	cmocka_unit_test(test_get_reset_count),
	cmocka_unit_test(test_get_time_sync_info),
	cmocka_unit_test(test_print_hlthunk_version),
	cmocka_unit_test(test_get_cs_drop_statistics),
	cmocka_unit_test(test_get_pci_counters),
	cmocka_unit_test(test_get_clk_throttling_reason),
	cmocka_unit_test(test_get_total_energy_consumption),
	cmocka_unit_test(test_get_events_counters),
	cmocka_unit_test(test_get_events_counters_aggregate),
	cmocka_unit_test(test_get_pci_bdf),
	cmocka_unit_test(test_get_pll_info),
	cmocka_unit_test(test_get_hw_asic_status),
	cmocka_unit_test(test_get_nic_ports_mask),
	cmocka_unit_test(test_get_nic_link_state),
	cmocka_unit_test(test_print_nic_statistics),
	cmocka_unit_test(test_event_record),
	cmocka_unit_test(test_get_dev_memalloc_page_orders),
	cmocka_unit_test(test_engine_status),
	cmocka_unit_test(test_get_mac_addresses),
	cmocka_unit_test(test_get_sec_attest_info),
	cmocka_unit_test(test_get_dev_info_signed),
	cmocka_unit_test(test_page_fault_info),
	cmocka_unit_test(test_get_device_count),
	cmocka_unit_test(test_hard_reset)
};

static const char *const usage[] = {
	"control_device [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = ARRAY_SIZE(control_tests);

	hltests_parser(argc, argv, usage, HLTEST_DEVICE_MASK_DONT_CARE,
			control_tests, num_tests);

	return hltests_run_group_tests("control_device", control_tests,
					num_tests,
					hltests_control_dev_setup,
					hltests_control_dev_teardown);
}

#endif /* HLTESTS_LIB_MODE */
