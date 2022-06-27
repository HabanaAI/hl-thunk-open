// SPDX-License-Identifier: MIT

/*
 * Copyright 2021 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#define _GNU_SOURCE

#include "hlthunk_tests.h"

#include <stdio.h>

int main(int argc, const char **argv)
{
	struct hltests_state *tests_state;
	void *state;
	int rc;

	hltests_parser(argc, argv, NULL, HLTEST_DEVICE_MASK_DONT_CARE);

	rc = hltests_init();
	if (rc) {
		printf("Failed to initialize hlthunk tests library %d\n", rc);
		return rc;
	}

	/* Similar to synAcquireDevice */
	rc = hltests_setup(&state);
	if (rc) {
		printf("Failed to run setup phase of hlthunk tests %d\n", rc);
		hltests_fini();
		return rc;
	}

	tests_state = (struct hltests_state *) state;

	printf("Running test to measure PCI B/W Host -> DRAM\n");

	rc = test_host_dram_perf(&state);

	printf("HOST->DRAM             %7.2lf GB/Sec\n",
		tests_state->perf_outcomes[RESULTS_DMA_PERF_HOST2DRAM]);

	printf("\nRunning test to measure command submission latency\n");

	rc = test_and_measure_wait_after_64_submit_cs_nop(&state);

	hltests_teardown(&state);

	hltests_fini();

	return 0;
}
