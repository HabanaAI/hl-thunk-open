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

#define HL_EQ_LENGTH			64
#define HL_QUEUE_LENGTH			4096

VOID test_cpucp_msg_stress(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int i, rc, fd = tests_state->fd, num_cpucp_msgs, num_wrap_arounds;
	struct hlthunk_power_info power_info;

	/* By default have 4 wraparounds. */
	num_wrap_arounds = 4;

	if (hltests_is_simulator(fd)) {
		printf("Test is not supported on simulator\n");
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
	int fd = tests_state->fd, rc, device_idx, max_power_fd, us_sleep_time, start_pwr_s_eq_num;
	int start_pwr_e_eq_num, total_pwr_events_num, i, hw_arr_size, num_wrap_arounds;
	char path[PATH_MAX], power_val_str[16], power_val_str_default[16], pci_bus_id[13];
	uint32_t *hw_events = 0, asic_pwr_s_event_id, asic_pwr_e_event_id;
	struct hlthunk_clk_throttle_info clk_throttle_info;
	struct hlthunk_power_info power_info;
	struct hlthunk_hw_ip_info hw_ip;
	ssize_t size;


	/* By default have 2 wraparounds. */
	num_wrap_arounds = 2;

	if (hltests_is_goya(fd)) {
		printf("Test is not supported on goya\n");
		skip();
	}

	if (hltests_is_simulator(fd)) {
		printf("Test is not supported on simulator\n");
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

	us_sleep_time = 200000;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	rc = hlthunk_get_pci_bus_id_from_fd(fd, pci_bus_id, sizeof(pci_bus_id));
	assert_int_equal(rc, 0);

	device_idx = hlthunk_get_device_index_from_pci_bus_id(pci_bus_id);
	assert_in_range(device_idx, 0, INT_MAX);

	snprintf(path, PATH_MAX, "//sys/class/habanalabs/hl%d/max_power", device_idx);

	max_power_fd = open(path, O_RDWR);
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

	hw_arr_size = hw_ip.num_of_events * sizeof(uint32_t);
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
	start_pwr_s_eq_num = hw_events[asic_pwr_s_event_id];

	rc = hltests_get_async_event_id(fd, FIX_POWER_ENV_E, &asic_pwr_e_event_id);
	if (rc) {
		printf("Failed to get asic event id of FIX_POWER_ENV_E\n");
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

#ifndef HLTESTS_LIB_MODE

const struct CMUnitTest cpucp_tests[] = {
		cmocka_unit_test_setup(test_cpucp_msg_stress,
					hltests_ensure_device_operational),
		cmocka_unit_test_setup(test_cpucp_eq_stress,
					hltests_ensure_device_operational),
};

static const char *const usage[] = {
	"cpucp [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = sizeof(cpucp_tests) / sizeof((cpucp_tests)[0]);

	hltests_parser(argc, argv, usage, HLTEST_DEVICE_MASK_DONT_CARE, cpucp_tests, num_tests);

	if (access("/sys/kernel/debug", R_OK)) {
		printf("This executable need to be run with sudo\n");
		return 0;
	}

	return hltests_run_group_tests("cpucp", cpucp_tests, num_tests,
			hltests_root_setup, hltests_root_teardown);
}

#endif /* HLTESTS_LIB_MODE */
