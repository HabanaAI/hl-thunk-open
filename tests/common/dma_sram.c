// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_tests.h"
#include "kvec.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>

void test_dma_entire_sram_random(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	int rc;

	if (hltests_is_pldm(tests_state->fd))
		skip();

	rc = hlthunk_get_hw_ip_info(tests_state->fd, &hw_ip);
	assert_int_equal(rc, 0);

	hltests_dma_test(state, false, hw_ip.sram_size);
}

DMA_TEST_INC_SRAM(test_dma_sram_size_1KB, state, 1 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_2KB, state, 2 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_3KB, state, 3 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_4KB, state, 4 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_5KB, state, 5 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_6KB, state, 6 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_7KB, state, 7 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_8KB, state, 8 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_9KB, state, 9 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_10KB, state, 10 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_11KB, state, 11 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_12KB, state, 12 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_13KB, state, 13 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_14KB, state, 14 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_15KB, state, 15 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_16KB, state, 16 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_20KB, state, 20 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_24KB, state, 24 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_28KB, state, 28 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_32KB, state, 32 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_36KB, state, 36 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_40KB, state, 40 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_44KB, state, 44 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_48KB, state, 48 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_52KB, state, 52 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_56KB, state, 56 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_60KB, state, 60 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_64KB, state, 64 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_96KB, state, 96 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_128KB, state, 128 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_160KB, state, 160 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_192KB, state, 192 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_224KB, state, 224 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_256KB, state, 256 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_288KB, state, 288 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_320KB, state, 320 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_352KB, state, 352 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_384KB, state, 384 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_416KB, state, 416 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_448KB, state, 448 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_480KB, state, 480 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_512KB, state, 512 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_640KB, state, 640 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_768KB, state, 768 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_896KB, state, 896 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_1024KB, state, 1024 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_1152KB, state, 1152 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_1280KB, state, 1280 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_1408KB, state, 1408 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_1536KB, state, 1536 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_1664KB, state, 1664 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_1792KB, state, 1792 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_1920KB, state, 1920 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_2MB, state, 2 * 1024 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_3MB, state, 3 * 1024 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_4MB, state, 4 * 1024 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_5MB, state, 5 * 1024 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_6MB, state, 6 * 1024 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_7MB, state, 7 * 1024 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_8MB, state, 8 * 1024 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_9MB, state, 9 * 1024 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_10MB, state, 10 * 1024 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_11MB, state, 11 * 1024 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_12MB, state, 12 * 1024 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_13MB, state, 13 * 1024 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_14MB, state, 14 * 1024 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_15MB, state, 15 * 1024 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_16MB, state, 16 * 1024 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_20MB, state, 20 * 1024 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_24MB, state, 24 * 1024 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_28MB, state, 28 * 1024 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_32MB, state, 32 * 1024 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_36MB, state, 36 * 1024 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_40MB, state, 40 * 1024 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_44MB, state, 44 * 1024 * 1024)
DMA_TEST_INC_SRAM(test_dma_sram_size_48MB, state, 48 * 1024 * 1024)

#ifndef HLTESTS_LIB_MODE

const struct CMUnitTest dma_sram_tests[] = {
	cmocka_unit_test_setup(test_dma_sram_size_1KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_2KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_3KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_4KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_5KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_6KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_7KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_8KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_9KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_10KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_11KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_12KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_13KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_14KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_15KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_16KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_20KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_24KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_28KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_32KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_36KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_40KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_44KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_48KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_52KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_56KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_60KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_entire_sram_random,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_64KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_96KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_128KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_160KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_192KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_224KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_256KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_288KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_320KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_352KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_384KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_416KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_448KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_480KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_512KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_640KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_768KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_896KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_1024KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_1152KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_1280KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_1408KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_1536KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_1664KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_1792KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_1920KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_2MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_3MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_4MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_5MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_6MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_7MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_8MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_9MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_10MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_11MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_12MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_13MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_14MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_15MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_16MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_20MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_24MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_28MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_32MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_36MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_40MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_44MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_48MB,
			hltests_ensure_device_operational),
};

static const char *const usage[] = {
	"dma_sram [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = sizeof(dma_sram_tests) / sizeof((dma_sram_tests)[0]);

	hltests_parser(argc, argv, usage, HLTHUNK_DEVICE_DONT_CARE,
			dma_sram_tests, num_tests);

	return hltests_run_group_tests("dma_sram", dma_sram_tests, num_tests,
					hltests_setup, hltests_teardown);
}

#endif /* HLTESTS_LIB_MODE */
