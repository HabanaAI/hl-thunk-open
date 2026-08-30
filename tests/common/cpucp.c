// SPDX-License-Identifier: MIT

/*
 * Copyright 2022 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_tests.h"

#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <libfdt.h>
#include <inttypes.h>

#define HL_EQ_LENGTH			64U
#define HL_QUEUE_LENGTH			4096

/* Example property names used by hl_smi */
#define PROP_ADDR   "addr"
#define PROP_BANK   "bank"
#define PROP_ECC    "ecc"

/* ECC string example: "DERR" */
static const char *ecc_str = "DERR";

/*
 * The Type of the generic request (and other input arguments) will be fetched from user by reading
 * from "pkt_subidx" field in struct cpucp_packet.
 *
 * HL_PASSTHROUGHT_VERSIONS	- Fetch all firmware versions.
 * HL_ECC_INJECTION		- Inject ecc, for debug and non-security only
 * HL_PASSTHROUGH_PID_CMD	- Send commands to the ARCPID
 * HL_GET_ERR_COUNTERS_CMD	- Command to get error counters
 * HL_GET_P_STATE		- get performance state
 * HL_GET_SUPPORTED_P_STATES	- get supported performance states
 * HL_GET_POWER_LIMITS_CONSTRAINTS - get power limits constraints
 */
enum hl_passthrough_type {
	HL_PASSTHROUGH_VERSIONS,
	HL_ECC_INJECTION,
	HL_PASSTHROUGH_PID_CMD,
	HL_GET_ERR_COUNTERS_CMD,
	HL_GET_P_STATE,
	HL_GET_SUPPORTED_P_STATES,
	HL_GET_POWER_LIMITS_CONSTRAINTS,
	HL_PASSTHROUGH_TYPE_MAX		/* must be last */
};

static inline int
fdt_setprop_string_safe(void *fdt, int nodeoffset, const char *name, const char *str)
{
	size_t len = strlen(str);

	if (len >= INT_MAX)
		return -FDT_ERR_TRUNCATED;

	return fdt_setprop(fdt, nodeoffset, name, str, (int)(len + 1));
}

VOID test_cpucp_msg_stress(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int i, rc, fd = tests_state->fd, num_cpucp_msgs, num_wrap_arounds;
	struct hlthunk_power_info power_info;

	/* By default have 4 wraparounds. */
	num_wrap_arounds = 4;

	if (hltests_is_simulator(fd) || hltests_is_pldm(fd)) {
		printf("Test is not supported on simulator/pldm\n");
		skip();
	}

	num_cpucp_msgs = HL_QUEUE_LENGTH * num_wrap_arounds;
	for (i = 0 ; i < num_cpucp_msgs ; i++) {
		rc = hlthunk_get_power_info(fd, &power_info);
		assert_int_equal(rc, 0);
	}

	END_TEST;
}

VOID test_cpucp_eq_stress(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int i, fd = tests_state->fd, rc, device_idx, max_power_fd;
	char path[PATH_MAX], power_val_str[16], power_val_str_default[16], pci_bus_id[13];
	uint32_t *hw_events = 0, asic_pwr_s_event_id, asic_pwr_e_event_id, hw_arr_size,
			start_pwr_e_eq_num, total_pwr_events_num, num_wrap_arounds,
			start_pwr_s_eq_num, us_sleep_time;
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;
	struct hlthunk_clk_throttle_info clk_throttle_info;
	struct hlthunk_power_info power_info;
	ssize_t size;

	/* By default have 2 wraparounds. */
	num_wrap_arounds = 2;

	if (hltests_is_goya(fd) || hltests_is_gaudi3(fd)) {
		printf("Test is not supported on %s\n", hltests_is_goya(fd) ? "goya" : "gaudi3");
		skip();
	}

	if (hltests_is_simulator(fd) || hltests_is_pldm(fd)) {
		printf("Test is not supported on simulator/pldm\n");
		skip();
	}

	if (hw_ip->security_enabled) {
		printf("Cannot set max power on a secured device, skipping\n");
		skip();
	}

	if (!hltests_get_parser_run_disabled_tests()) {
		printf("%s should run with --disabled option\n", __func__);
		skip();
	}

	rc = hlthunk_get_clk_throttle_info(fd, &clk_throttle_info);
	assert_int_equal(rc, 0);
	if (clk_throttle_info.clk_throttle_reason_bitmask & HL_CLK_THROTTLE_POWER) {
		printf("Test should start without clock throttling\n");
		skip();
	}

	/* Ensure null-terminate char is set on the entire string. */
	memset(power_val_str_default, 0, sizeof(power_val_str_default));

	/* Wait for 'total_pwr_events_num' events of 'POWER_END_E'.
	 * 'POWER_END_E' event comes after a 'POWER_END_S'. Therefore there will be at least
	 * (2*total_pwr_events_num) EQ events.
	 */
	total_pwr_events_num = HL_EQ_LENGTH * num_wrap_arounds;

	us_sleep_time = hltests_is_gaudi(fd) ? 200000 : 600000;

	rc = hlthunk_get_pci_bus_id_from_fd(fd, pci_bus_id, sizeof(pci_bus_id));
	assert_int_equal(rc, 0);

	device_idx = hlthunk_get_device_index_from_pci_bus_id(pci_bus_id);
	assert_in_range(device_idx, 0, INT_MAX);

	snprintf(path, PATH_MAX, "//sys/class/accel/accel%d/device/max_power", device_idx);

	max_power_fd = open(path, O_RDWR);

	/* coverity[negative_returns] */
	assert_in_range(max_power_fd, 0, INT_MAX);

	size = pread(max_power_fd, power_val_str_default, sizeof(power_val_str_default) - 1, 0);
	if (size < 0) {
		printf("Failed to read from max_power_fd [rc %zd]\n", size);
		rc = errno;
		goto close_max_power_fd;
	}

	rc = hlthunk_get_power_info(fd, &power_info);
	if (rc) {
		printf("Failed to get power info\n");
		goto close_max_power_fd;
	}

	hw_arr_size = hw_ip->num_of_events * sizeof(uint32_t);
	hw_events = hlthunk_malloc(hw_arr_size);
	if (!hw_events) {
		printf("Failed to malloc hw events\n");
		goto close_max_power_fd;
	}

	rc = hlthunk_get_hw_events_arr(fd, false, hw_arr_size, hw_events);
	if (rc) {
		printf("Failed to get hw events arr\n");
		goto free_hw_events;
	}

	rc = hltests_get_async_event_id(fd, FIX_POWER_ENV_S, &asic_pwr_s_event_id);
	if (rc) {
		printf("Failed to get asic event id of FIX_POWER_ENV_S\n");
		goto free_hw_events;
	}

	if (asic_pwr_s_event_id >= hw_ip->num_of_events) {
		printf("ERROR: asic event id of FIX_POWER_ENV_S  %u is too big (max %u)\n",
				asic_pwr_s_event_id, hw_ip->num_of_events);
		rc = -E2BIG;
		goto free_hw_events;
	}
	start_pwr_s_eq_num = hw_events[asic_pwr_s_event_id];

	rc = hltests_get_async_event_id(fd, FIX_POWER_ENV_E, &asic_pwr_e_event_id);
	if (rc) {
		printf("Failed to get asic event id of FIX_POWER_ENV_E\n");
		goto free_hw_events;
	}

	if (asic_pwr_e_event_id >= hw_ip->num_of_events) {
		printf("ERROR: asic event id of FIX_POWER_ENV_E %u is too big (max %u)\n",
				asic_pwr_e_event_id, hw_ip->num_of_events);
		rc = -E2BIG;
		goto free_hw_events;
	}
	start_pwr_e_eq_num = hw_events[asic_pwr_e_event_id];

	/* Limit curr power to 80% power in order to trigger clock throttling */
	snprintf(power_val_str, 16, "%ld", power_info.power * 4 / 5);

	for (i = 0 ; i < total_pwr_events_num ; i++) {
		size = pwrite(max_power_fd, power_val_str, strlen(power_val_str) + 1, 0);
		if (size < 0) {
			printf("Failed to write low power to max_power_fd [rc %zd]\n", size);
			rc = errno;
			goto free_hw_events;
		}

		usleep(us_sleep_time);

		size = pwrite(max_power_fd, power_val_str_default,
				strlen(power_val_str_default) + 1, 0);
		if (size < 0) {
			printf("Failed to write default power from max_power_fd [rc %zd]\n", size);
			rc = errno;
			goto free_hw_events;
		}

		usleep(us_sleep_time);
	}

	rc = hlthunk_get_hw_events_arr(fd, false, hw_arr_size, hw_events);
	if (rc) {
		printf("Failed to get hw events arr\n");
		rc = errno;
		goto free_hw_events;
	}

	if (((start_pwr_s_eq_num + total_pwr_events_num) != hw_events[asic_pwr_s_event_id]) ||
		((start_pwr_e_eq_num + total_pwr_events_num) != hw_events[asic_pwr_e_event_id])) {
		printf("Error - expected %d events per event type\n", (total_pwr_events_num));
		printf("        got: %d POWER_ENV_S, %d POWER_ENV_E\n",
				hw_events[asic_pwr_s_event_id] - start_pwr_s_eq_num,
				hw_events[asic_pwr_e_event_id] - start_pwr_e_eq_num);
		rc = -1;
		goto free_hw_events;
	}

free_hw_events:
	hlthunk_free(hw_events);
close_max_power_fd:
	close(max_power_fd);

	assert_int_equal(rc, 0);
	END_TEST;
}

/*
 * Build a single-node FDT and return:
 *   - fdt: allocated buffer
 *   - return: size of final FDT blob
 */
static int64_t test_cpucp_build_single_ecc_fdt(void *fdt, uint32_t addr, uint32_t bank)
{
	int node, ret;

	/* Create empty tree */
	ret = fdt_create_empty_tree(fdt, SZ_1M);
	if (ret)
		return -2;

	/* Add our node at root: /ecc_inj */
	node = fdt_add_subnode(fdt, 0, "ecc_inj");
	if (node < 0)
		return -3;

	/* Add compatible property */
	ret = fdt_setprop_string_safe(fdt, node, "compatible", "hl,sram_inj");
	if (ret)
		goto fail;

	/* Add addr property */
	ret = fdt_setprop_u32(fdt, node, PROP_ADDR, addr);
	if (ret)
		goto fail;

	/* Add bank property */
	ret = fdt_setprop_u32(fdt, node, PROP_BANK, bank);
	if (ret)
		goto fail;

	/* Add ECC string property */
	ret = fdt_setprop_string_safe(fdt, node, PROP_ECC, ecc_str);
	if (ret)
		goto fail;

	/* Finalize / compress FDT */
	ret = fdt_pack(fdt);
	if (ret)
		goto fail;

	return fdt_totalsize(fdt);

fail:
	return -4;
}

VOID test_cpucp_generic_request(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *)*state;
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;
	int rc, fd = tests_state->fd;
	void *buff;
	uint32_t buff_size = SZ_1M;

	if (hltests_is_simulator(fd) || hltests_is_pldm(fd)) {
		printf("Test is not supported on simulator/pldm\n");
		skip();
	}

	if (!hltests_is_gaudi3(fd)) {
		printf("Test is supported on gaudi3 only\n");
		skip();
	}

	buff = hlthunk_malloc(buff_size);
	if (!buff) {
		printf("Failed to allocate memory\n");
		skip();
		__builtin_unreachable();
	}

	memset(buff, 0, buff_size);

	for (uint32_t i = 0 ; i < HL_PASSTHROUGH_TYPE_MAX ; i++) {
		if (i == HL_ECC_INJECTION) {
			if (hw_ip->security_enabled) {
				/* Skip ECC Injection request if fw security enabled */
				printf("FW secured - skipping ecc injection\n");
				continue;
			} else {
				int64_t actual_buff_size;

				actual_buff_size = test_cpucp_build_single_ecc_fdt(buff, 0x1234, 2);
				assert_true(actual_buff_size > 0);
				assert_true(actual_buff_size <= buff_size);

				printf("Built FDT with size = 0x%" PRIx64 " bytes\n",
					actual_buff_size);
			}
		}

		rc = hlthunk_fw_send_generic_request(fd, buff, buff_size, i);
		assert_int_equal(rc, 0);

		memset(buff, 0, buff_size);
	}

	hlthunk_free(buff);
	END_TEST;
}

VOID test_set_memory_consumption(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *)*state;
	int rc, fd = tests_state->fd;
	struct timeval tv;
	void *device_addr;

	if (!hltests_is_gaudi3(fd)) {
		printf("Test is supported on gaudi3 only\n");
		skip();
	}

	device_addr = hltests_allocate_device_mem(fd, SZ_1K, 0, CONTIGUOUS);
	gettimeofday(&tv, NULL);
	rc = hlthunk_set_memory_consumption(fd, SZ_1K, (uint64_t)tv.tv_sec);
	assert_int_equal(rc, 0);
	hltests_free_device_mem(fd, device_addr);

	END_TEST;
}

#ifndef HLTESTS_LIB_MODE

const struct CMUnitTest cpucp_tests[] = {
	cmocka_unit_test_setup(test_cpucp_msg_stress, hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cpucp_eq_stress, hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cpucp_generic_request, hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_set_memory_consumption, hltests_ensure_device_operational)
};

static const char *const usage[] = {
	"cpucp [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	size_t num_tests = sizeof(cpucp_tests) / sizeof((cpucp_tests)[0]);

	hltests_parser(argc, argv, usage, HLTEST_DEVICE_MASK_DONT_CARE,
			cpucp_tests, (int)num_tests);

	if (!can_open_debugfs(true))
		return 0;

	hltests_set_capabilities_mask(0);

	return hltests_run_group_tests("cpucp", cpucp_tests, num_tests,
					hltests_setup, hltests_teardown);
}

#endif /* HLTESTS_LIB_MODE */
