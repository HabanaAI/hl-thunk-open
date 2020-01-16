// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk.h"
#include "hlthunk_tests.h"
#include "hlthunk_err_inject.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <setjmp.h>
#include <unistd.h>
#include <limits.h>
#include <cmocka.h>
#include <stdio.h>
#include <errno.h>


void test_error_injection_endless_command(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_reset_count_info pre, post;
	int rc, fd = tests_state->fd;

	rc = hlthunk_get_reset_count_info(fd, &pre);
	assert_int_equal(rc, 0);

	rc = hlthunk_err_inject_endless_command(fd);
	assert_int_equal(rc, 0);

	rc = hlthunk_get_reset_count_info(fd, &post);
	assert_int_equal(rc, 0);

	/* Command lockup should generate a soft reset only */
	if (!((post.soft_reset_count == pre.soft_reset_count + 1) &&
	      (post.hard_reset_count == pre.hard_reset_count)))
		fail_msg("Driver did not recover from command lockup");
}

void test_error_injection_non_fatal_event(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_reset_count_info pre, post;
	struct hlthunk_hw_ip_info hw_ip;
	uint32_t *pre_hw_events, *post_hw_events;
	int event_num = 0, rc, fd = tests_state->fd;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	rc = hlthunk_get_reset_count_info(fd, &pre);
	assert_int_equal(rc, 0);

	pre_hw_events = hlthunk_malloc(hw_ip.num_of_events);
	assert_non_null(pre_hw_events);

	post_hw_events = hlthunk_malloc(hw_ip.num_of_events);
	assert_non_null(post_hw_events);

	rc = hlthunk_get_hw_events_arr(fd, true,
				       hw_ip.num_of_events, pre_hw_events);
	if (rc)
		goto exit;

	rc = hlthunk_err_inject_non_fatal_event(fd, &event_num);
	if (rc)
		goto exit;

	if (event_num >= hw_ip.num_of_events || event_num < 0)
		goto exit;

	rc = hlthunk_get_hw_events_arr(fd, true,
				       hw_ip.num_of_events, post_hw_events);
	if (rc)
		goto exit;

	rc = hlthunk_get_reset_count_info(fd, &post);
	if (rc)
		goto exit;

	/* Verify soft event was seen and no device reset happened */
	if (post_hw_events[event_num] == pre_hw_events[event_num])
		fail_msg("Driver did not identify a non-fatal event");

	if ((post.soft_reset_count != pre.soft_reset_count) ||
	    (post.hard_reset_count != pre.hard_reset_count))
		fail_msg("Driver performed an unexpected reset");

exit:
	hlthunk_free(pre_hw_events);
	hlthunk_free(post_hw_events);
	assert_int_equal(rc, 0);
	assert_false(event_num >= hw_ip.num_of_events || event_num < 0);
}

void test_error_injection_fatal_event(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_reset_count_info pre, post;
	struct hlthunk_hw_ip_info hw_ip;
	uint32_t *pre_hw_events, *post_hw_events;
	int event_num = 0, rc, fd = tests_state->fd;
	char pci_bus_id[13];

	rc = hlthunk_get_pci_bus_id_from_fd(fd, pci_bus_id, sizeof(pci_bus_id));
	assert_int_equal(rc, 0);

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	rc = hlthunk_get_reset_count_info(fd, &pre);
	assert_int_equal(rc, 0);

	pre_hw_events = hlthunk_malloc(hw_ip.num_of_events);
	assert_non_null(pre_hw_events);

	post_hw_events = hlthunk_malloc(hw_ip.num_of_events);
	assert_non_null(post_hw_events);

	rc = hlthunk_get_hw_events_arr(fd, true,
				       hw_ip.num_of_events, pre_hw_events);
	if (rc)
		goto exit;

	rc = hlthunk_err_inject_fatal_event(fd, &event_num);
	/* fd is not usable anymore */
	tests_state->fd = fd = -1;
	if (rc)
		goto exit;

	if (event_num >= hw_ip.num_of_events || event_num < 0)
		goto exit;

	tests_state->fd = fd = hlthunk_open(HLTHUNK_DEVICE_DONT_CARE,
					    pci_bus_id);
	if (fd < 0) {
		rc = -ENODEV;
		goto exit;
	}

	rc = hlthunk_get_hw_events_arr(fd, true,
				       hw_ip.num_of_events, post_hw_events);
	if (rc)
		goto exit;

	rc = hlthunk_get_reset_count_info(fd, &post);
	if (rc)
		goto exit;

	/* Verify hard event was seen and device reset happened */
	if (post_hw_events[event_num] == pre_hw_events[event_num])
		fail_msg("Driver did not identify a fatal event");

	if (!((post.hard_reset_count == pre.hard_reset_count + 1) &&
	      (post.soft_reset_count == pre.soft_reset_count)))
		fail_msg("Driver did not perform the unexpected reset");

exit:
	hlthunk_free(pre_hw_events);
	hlthunk_free(post_hw_events);
	assert_int_equal(rc, 0);
	assert_false(event_num >= hw_ip.num_of_events || event_num < 0);
	assert_in_range(fd, 0, INT_MAX);
}

void test_error_injection_heartbeat(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_reset_count_info pre, post;
	int rc, fd = tests_state->fd;
	char pci_bus_id[13];

	rc = hlthunk_get_pci_bus_id_from_fd(fd, pci_bus_id, sizeof(pci_bus_id));
	assert_int_equal(rc, 0);

	rc = hlthunk_get_reset_count_info(fd, &pre);
	assert_int_equal(rc, 0);

	rc = hlthunk_err_inject_loss_of_heartbeat(fd);
	/* fd is not usable anymore */
	tests_state->fd = fd = -1;
	assert_int_equal(rc, 0);

	tests_state->fd = fd = hlthunk_open(HLTHUNK_DEVICE_DONT_CARE,
					    pci_bus_id);
	assert_in_range(fd, 0, INT_MAX);

	rc = hlthunk_get_reset_count_info(fd, &post);
	assert_int_equal(rc, 0);

	/* Loss of heartbeat should generate a hard reset */
	if (!((post.hard_reset_count == pre.hard_reset_count + 1) &&
	      (post.soft_reset_count == pre.soft_reset_count)))
		fail_msg("Driver did not recover from loss of heartbeat");
}

void test_error_injection_thermal_event(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	uint32_t *pre_hw_events, *post_hw_events;
	int event_num = 0, rc, fd = tests_state->fd;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	pre_hw_events = hlthunk_malloc(hw_ip.num_of_events);
	assert_non_null(pre_hw_events);

	post_hw_events = hlthunk_malloc(hw_ip.num_of_events);
	assert_non_null(post_hw_events);

	rc = hlthunk_get_hw_events_arr(fd, true,
				       hw_ip.num_of_events, pre_hw_events);
	if (rc)
		goto exit;

	rc = hlthunk_err_inject_thermal_event(fd, &event_num);
	if (rc)
		goto exit;

	if (event_num >= hw_ip.num_of_events || event_num < 0)
		goto exit;

	rc = hlthunk_get_hw_events_arr(fd, true,
				       hw_ip.num_of_events, post_hw_events);
	if (rc)
		goto exit;

	/* Verify thermal event was seen */
	if (post_hw_events[event_num] == pre_hw_events[event_num])
		fail_msg("Driver did not identify a thermal event");

exit:
	hlthunk_free(pre_hw_events);
	hlthunk_free(post_hw_events);
	assert_int_equal(rc, 0);
	assert_false(event_num >= hw_ip.num_of_events || event_num < 0);
}

const struct CMUnitTest ei_tests[] = {
	cmocka_unit_test_setup(test_error_injection_endless_command,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_error_injection_non_fatal_event,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_error_injection_fatal_event,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_error_injection_heartbeat,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_error_injection_thermal_event,
				hltests_ensure_device_operational),
};

static const char *const usage[] = {
	"error_injection [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = sizeof(ei_tests) / sizeof((ei_tests)[0]);

	hltests_parser(argc, argv, usage, HLTHUNK_DEVICE_DONT_CARE, ei_tests,
			num_tests);

	if (access("/sys/kernel/debug", R_OK)) {
		printf("This executable need to be run with sudo\n");
		return 0;
	}

	if (!hltests_get_parser_run_disabled_tests()) {
		printf("This executable need to be run with -d flag\n");
		return 0;
	}

	return hltests_run_group_tests("error_injection", ei_tests, num_tests,
					hltests_setup, hltests_teardown);
}
