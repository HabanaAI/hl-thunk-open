// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_tests.h"
#include "uapi/hlthunk_err_inject.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <setjmp.h>
#include <unistd.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>

static int get_device_temperature(int fd, const char *fname, long *temperature)
{
	const char *base_path = "/sys/bus/pci/devices/";
	const char *hwmon_dir_name = "/hwmon/";
	const char *device_hwmon_dir_prefix = "hwmon";
	char pci_bus_id[13];
	char value[64] = "";
	char *fd_path;
	struct dirent *entry;
	DIR *dir = NULL;
	ssize_t size;
	int rc, temp_fd = -1;

	if (fname == NULL || strlen(fname) > NAME_MAX)  {
		printf("Invalid file name");
		return -EINVAL;
	}

	rc = hlthunk_get_pci_bus_id_from_fd(fd, pci_bus_id, sizeof(pci_bus_id));
	if (rc) {
		printf("No PCI device was found for fd %d\n", fd);
		return -ENODEV;
	}

	fd_path = malloc(PATH_MAX + 1);
	if (fd_path == NULL) {
		printf("Failed to allocate memory\n");
		return -ENOMEM;
	}

	/* Open device hwmon dir
	 *  example: /sys/bus/pci/devices/0000:01:00.0/hwmon/
	 */
	snprintf(fd_path, PATH_MAX, "%s%s%s",
		 base_path, pci_bus_id, hwmon_dir_name);

	dir = opendir(fd_path);
	if (dir == NULL) {
		rc = -errno;
		printf("Failed to open device directory %s\n", fd_path);
		goto exit;
	}

	while ((entry = readdir(dir)) != NULL) {
		if (strstr(entry->d_name, device_hwmon_dir_prefix) != NULL)
			break;
	}
	if (entry == NULL) {
		printf("Failed to find device hwmon directory\n");
		rc = -ENOENT;
		goto exit;
	}

	/*
	 * Create the paths to the requested temperature sensor attribute file
	 *  example: /sys/bus/pci/devices/0000:01:00.0/hwmon/hwmon3/temp1_max
	 */
	snprintf(fd_path, PATH_MAX, "%s%s%s%s/%s", base_path,
		 pci_bus_id, hwmon_dir_name, entry->d_name, fname);

	temp_fd = open(fd_path, O_RDONLY);
	if (temp_fd < 0) {
		rc = -errno;
		printf("failed to open %s, %s\n", fd_path, strerror(errno));
		goto exit;
	}

	/* Read the temperature */
	size = pread(temp_fd, value, sizeof(value), 0);
	if (size < 0) {
		rc = -errno;
		goto exit;
	}

	*temperature = strtol(value, NULL, 10);

exit:
	free(fd_path);

	if (temp_fd != -1)
		close(temp_fd);

	if (dir)
		closedir(dir);

	return rc;
}

static VOID test_error_injection_endless_command(void **state)
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

	END_TEST
}

static VOID test_error_injection_non_fatal_event(void **state)
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

	END_TEST
}

static VOID test_error_injection_fatal_event(void **state)
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

	END_TEST
}

static VOID test_error_injection_heartbeat(void **state)
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

	END_TEST
}

static VOID test_error_injection_thermal_event(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	long temp_pre, temp_post;
	int rc, rc1, fd = tests_state->fd;

	rc = get_device_temperature(fd, "temp7_input", &temp_pre);
	assert_int_equal(rc, 0);

	rc = hlthunk_err_inject_thermal_event(fd);
	assert_int_equal(rc, 0);

	sleep(1);

	rc = get_device_temperature(fd, "temp7_input", &temp_post);
	rc1 = hlthunk_err_eject_thermal_event(fd);

	assert_int_equal(rc, 0);
	/* The test faked an overheat of 100 Deg Celsius */
	assert_true(temp_post > 100000);
	assert_int_equal(rc1, 0);

	sleep(1);

	rc = get_device_temperature(fd, "temp7_input", &temp_pre);
	assert_int_equal(rc, 0);

	assert_true(temp_pre < temp_post);

	END_TEST
}

#ifndef HLTESTS_LIB_MODE

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

#endif /* HLTESTS_LIB_MODE */
