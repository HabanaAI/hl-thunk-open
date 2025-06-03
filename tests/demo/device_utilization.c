// SPDX-License-Identifier: MIT

/*
 * Copyright 2022 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#define _GNU_SOURCE

#include "hlthunk_tests.h"

#include <stdio.h>
#include <curses.h>
#include <unistd.h>

int main(int argc, const char **argv)
{
	struct hlthunk_open_stats_info *open_info;
	struct hlthunk_hw_asic_status hw_status;
	struct hltests_state *tests_state;
	void *state;
	int rc, c;

	hltests_parser(argc, argv, NULL, HLTEST_DEVICE_MASK_DONT_CARE);

	rc = hltests_init();
	if (rc) {
		printw("Failed to initialize hlthunk tests library (%d)\n", rc);
		return rc;
	}

	/* Similar to synDeviceAcquire */
	rc = hltests_control_dev_setup(&state);
	if (rc) {
		printw("Failed to run setup phase of control device (%d)\n", rc);
		goto tests_fini;
	}

	tests_state = (struct hltests_state *) state;

	initscr();
	timeout(0);

	while (1) {
		rc = hlthunk_get_hw_asic_status(tests_state->fd, &hw_status);
		if (rc < 0) {
			printw("Failed to get h/w status (%d)\n", rc);
			goto dev_fini;
		}

		if (!hw_status.valid) {
			printw("h/w status is invalid (%d)\n", rc);
			goto dev_fini;
		}

		open_info = &hw_status.open_stats;

		clear();

		printw("\nPower                            : %ld",
			hw_status.power.power);
		printw("\nOpen counter                     : %ld",
			open_info->open_counter);
		printw("\nLast open period (ms)            : %ld",
			open_info->last_open_period_ms);
		printw("\nCompute CTX active               : %u",
			open_info->is_compute_ctx_active);
		printw("\nCompute CTX in release           : %u",
			open_info->compute_ctx_in_release);
		printw("\nCompute CTX has mapped resources : %u",
			open_info->compute_ctx_has_mapped_resources);
		printw("\nTimestamp (sec)                  : %ld",
			hw_status.timestamp_sec);

		refresh();

		usleep(500000);

		c = getch();
		if (c == 'q')
			break;
	}

	printw("\n\n");

dev_fini:
	refresh();
	hltests_control_dev_teardown(&state);
tests_fini:
	hltests_fini();

	sleep(2);

	endwin();
	return 0;
}
