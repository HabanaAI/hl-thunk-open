// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_tests.h"
#include "kvec.h"
#include "ini.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include <limits.h>
#include <cmocka.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>

struct bench_mappings_custom_cfg {
	uint64_t n_allocs;
	uint64_t alloc_size;
	enum hltests_huge huge;
	uint64_t n_maps;
	uint64_t n_unmaps;
	enum hltests_random random;
	uint32_t n_iter;
};

void test_debug_mode(void **state)
{
	struct hltests_state *tests_state =
			(struct hltests_state *) *state;
	struct hl_debug_args debug;
	int rc, fd = tests_state->fd;

	memset(&debug, 0, sizeof(struct hl_debug_args));
	debug.op = HL_DEBUG_OP_SET_MODE;
	debug.enable = 1;

	rc = hlthunk_debug(fd, &debug);
	assert_int_equal(rc, 0);

	memset(&debug, 0, sizeof(struct hl_debug_args));
	debug.op = HL_DEBUG_OP_SET_MODE;
	debug.enable = 0;

	rc = hlthunk_debug(fd, &debug);
	assert_int_equal(rc, 0);
}

/**
 * This is an internal helper function used by hltest_bench_host_map_one_iter
 * in random mode.
 * @details Given a kvec containing objects of type hltests_memory*, an index,
 * and a search criteria, this function will search kvec, srating at index,
 * until it finds the element that matches the search criteria.
 * @param kv input kvec of hltests_memory*
 * @param i index to start the search from
 * @param mapped search criteria - whether to match mapped elements or unmapped.
 */
static struct hltests_memory *hltest_host_map_kv_fetch(void *kv, int i,
							bool mapped)
{
	kvec_t(struct hltests_memory *) *allocs = kv;
	struct hltests_memory *mem;
	int j;

	mem = kv_A(*allocs, i);
	if (!!mem->device_virt_addr == !!mapped)
		return mem;
	j = (i + 1) % kv_size(*allocs);
	while (j != i) {
		mem = kv_A(*allocs, j);
		if (!!mem->device_virt_addr == !!mapped)
			return mem;
		j = (j + 1) % kv_size(*allocs);
	}
	return NULL;
}

/**
 * This function will perform a host map benchmark with respect to the input
 * arguments.
 * @details The function is a suite for performing multiple possible variants
 * of memory map benchmarking. It has 2 operation modes - random and non random.
 *
 * Random mode is used to test map/unmap performance under fragmentation of
 * the virtual space. For this, it performs maps/unmaps without any order,
 * causing potential holes to appear in the middle of the virtual space:
 * 1. Allocate requested number of memory chunks, of desired size, store all
 *    allocations in kvec.
 * 2. Start the clock.
 * 3. Repeat the following:
 *    3.1. Flip a coin to decide if next operation is map or unmap.
 *    3.2. Pick a random allocation from kvec and perform the operation on it.
 *         Make sure the allocation matches the operation type (for example,
 *         if operation is map, choose only from unmapped allocations).
 *    3.3. Stop when performed exactly @n_maps and @n_unmaps.
 * 4. Stop the clock.
 * 5. Cleanup and report results.
 *
 * Non-random mode is used to test pure operation performance, allowing to
 * measure map performance independand of unmap performance. It will first
 * perform all the maps, one after another, then all the unmaps:
 * 1. Allocate requested number of memory chunks, of desired size, store all
 *    allocations in kvec.
 * 2. If number of unmaps is larger than the number of maps, do some pre-maps,
 *    before starting the clock.
 * 3. Start the clock.
 * 4. Do all map operations.
 * 5. Do all unmap operations.
 * 6. Stop the clock.
 * 7. Cleanup, unmap the leftovers (in case @n_maps > @n_unmaps).
 * 8. Report result.
 *
 * @param n_allocs number of allocations to perform before test
 * @param alloc_size size of each allocation
 * @param huge spefify whether huge pages shall be used for allocations
 * @param n_maps total number of map operations to benchmark
 * @param n_unmaps toatl number of unmap operations to benchmark
 * @param random specify whether map/unmaps shall be done in a random order
 * to test fragmentation issues
 * @return benchmark measured in nanoseconds
 */
static uint64_t
hltest_bench_host_map_one_iter(struct hltests_state *tests_state,
			       uint64_t n_allocs, uint64_t alloc_size,
			       enum hltests_huge huge, uint64_t n_maps,
			       uint64_t n_unmaps, enum hltests_random random)
{
	struct hltest_host_meminfo host_mem_info;
	struct hltests_memory *mem;
	struct timespec t_start, t_end;
	uint64_t n_currently_mapped = 0, host_page_size, pages_required,
		pages_available;
	int i, rc, fd = tests_state->fd;

	kvec_t(struct hltests_memory *) allocs;

	/* Firt, validate we have enough pages to do all the allocations.
	 * This does not 100% guarantee the allocations will work, as there may
	 * be another processes consuming memory, but it prevents tests
	 * designed for large systems to run on low memory systems to begin
	 * with.
	 */
	rc = hltest_get_host_meminfo(&host_mem_info);
	assert_int_equal(rc, 0);
	host_page_size =
		huge ? host_mem_info.hugepage_size : host_mem_info.page_size;
	pages_required =
		n_allocs * ((alloc_size + host_page_size - 1) / host_page_size);
	pages_available = huge ? host_mem_info.hugepage_free :
				(host_mem_info.mem_available / host_page_size);
	if (pages_required > pages_available) {
		print_message("Not enough memory on the host, skipping\n");
		skip();
	}

	/* In case of non random, n_maps and n_unmaps cannot be higher than
	 * the number of allocations. In case of random test, it is possible.
	 */
	if (!random && (n_maps > n_allocs || n_unmaps > n_allocs))
		fail_msg(
			"Invalid input n_maps=%lu, n_unmaps=%lu, n_allocs=%lu");

	/* Start by allocatin host memory, as much as requested. */
	kv_init(allocs);
	for (i = 0; i < n_allocs; ++i) {
		mem = hltests_allocate_host_mem_nomap(alloc_size, huge);
		assert_non_null(mem);
		kv_push(struct hltests_memory *, allocs, mem);
	}

	/* If we have more numaps than maps, do pre run maps. */
	if (n_unmaps > n_maps) {
		/* If testing unmap performance - map before benchmark start */
		for (i = 0; i < n_unmaps - n_maps; ++i) {
			mem = kv_A(allocs, i);
			rc = hltests_map_host_mem(fd, mem);
			assert_int_equal(rc, 0);
		}
		n_currently_mapped = n_unmaps - n_maps;
	}

	/* Benchmark starts HERE */
	clock_gettime(CLOCK_REALTIME, &t_start);

	if (random) {
		/* Running in random mode. */
		while (n_maps || n_unmaps) {
			if (n_maps && n_currently_mapped < n_allocs && (
				!n_currently_mapped ||
				hltests_rand_flip_coin())) {
				/* Next operation is map. */
				mem = hltest_host_map_kv_fetch(
					&allocs,
					hltests_rand_u32() % kv_size(allocs),
					false);
				assert_non_null(mem);

				rc = hltests_map_host_mem(fd, mem);
				assert_int_equal(rc, 0);

				n_maps--;
				n_currently_mapped++;
			} else {
				/* Next operation is unmap. */
				mem = hltest_host_map_kv_fetch(
					&allocs,
					hltests_rand_u32() % kv_size(allocs),
					true);
				assert_non_null(mem);

				rc = hltests_unmap_host_mem(fd, mem);
				assert_int_equal(rc, 0);

				n_unmaps--;
				n_currently_mapped--;
			}
		}
	} else {
		/* Running in non-random mode. */
		/* Do all maps. */
		for (i = n_currently_mapped; i < n_currently_mapped + n_maps;
			++i) {
			mem = kv_A(allocs, i);
			rc = hltests_map_host_mem(fd, mem);
			assert_int_equal(rc, 0);
		}
		/* Do all unmaps. */
		for (i = 0; i < n_unmaps; ++i) {
			mem = kv_A(allocs, i);
			rc = hltests_unmap_host_mem(fd, mem);
			assert_int_equal(rc, 0);
		}
	}

	/* Benchmark ends HERE */
	clock_gettime(CLOCK_REALTIME, &t_end);

	/* Cleanup, in case n_maps > n_unmaps we will have some maps left. */
	for (i = 0; i < n_allocs; ++i) {
		mem = kv_A(allocs, i);
		if (mem->device_virt_addr)
			hltests_unmap_host_mem(fd, mem);
	}

	/* Free the memory. */
	for (i = 0; i < n_allocs; ++i) {
		mem = kv_A(allocs, i);
		if (mem)
			hltests_free_host_mem_nounmap(mem, huge);
	}
	kv_destroy(allocs);

	return (t_end.tv_sec - t_start.tv_sec) * 1000000000 +
		(t_end.tv_nsec - t_start.tv_nsec);
}

/**
 * This function will perform a host map benchmark with respect to the input
 * arguments. It will invoke @hltest_bench_host_map_on_iter for @n_iter times.
 * @param n_allocs number of allocations to perform before test
 * @param alloc_size size of each allocation
 * @param huge spefify whether huge pages shall be used for allocations
 * @param n_maps total number of map operations to benchmark
 * @param n_unmaps toatl number of unmap operations to benchmark
 * @param random specify whether map/unmaps shall be done in a random order
 *               to test fragmentation issues
 * @param n_iter number of times to repeat the test, total time will be returned
 * @return sum of benchmarks measured in nanoseconds
 */
uint64_t hltest_bench_host_map(struct hltests_state *tests_state,
				uint64_t n_allocs, uint64_t alloc_size,
				enum hltests_huge huge,
				uint64_t n_maps, uint64_t n_unmaps,
				enum hltests_random random,
				uint32_t n_iter)
{
	uint32_t i;
	uint64_t total_time_ns = 0;

	for (i = 0; i < n_iter; ++i) {
		total_time_ns += hltest_bench_host_map_one_iter(
			tests_state, n_allocs, alloc_size, huge, n_maps,
			n_unmaps, random);
	}

	return total_time_ns;
}

void test_bench_host_map_nounmap_2MBx4K(void **state)
{
	uint64_t t_ns;

	if (!hltests_get_parser_run_disabled_tests()) {
		print_message("This test need to be run with -d flag\n");
		skip();
	}
	t_ns = hltest_bench_host_map((struct hltests_state *)*state,
				0x1000UL,
				0x200000UL,
				NOT_HUGE,
				0x1000UL,
				0,
				NOT_RANDOM,
				1);
	print_message("%luns\n", t_ns);
}

void test_bench_host_map_nounmap_8GB(void **state)
{
	uint64_t t_ns;

	if (!hltests_get_parser_run_disabled_tests()) {
		print_message("This test need to be run with -d flag\n");
		skip();
	}
	t_ns = hltest_bench_host_map((struct hltests_state *)*state,
				1,
				0x200000000UL,
				NOT_HUGE,
				1,
				0,
				NOT_RANDOM,
				1);
	print_message("%luns\n", t_ns);
}

void test_bench_host_nomap_unmap_2MBx4K(void **state)
{
	uint64_t t_ns;

	if (!hltests_get_parser_run_disabled_tests()) {
		print_message("This test need to be run with -d flag\n");
		skip();
	}
	t_ns = hltest_bench_host_map((struct hltests_state *)*state,
				0x1000UL,
				0x200000UL,
				NOT_HUGE,
				0,
				0x1000UL,
				NOT_RANDOM,
				1);
	print_message("%luns\n", t_ns);
}

void test_bench_host_nomap_unmap_8GB(void **state)
{
	uint64_t t_ns;

	if (!hltests_get_parser_run_disabled_tests()) {
		print_message("This test need to be run with -d flag\n");
		skip();
	}
	t_ns = hltest_bench_host_map((struct hltests_state *)*state,
				1,
				0x200000000UL,
				NOT_HUGE,
				0,
				1,
				NOT_RANDOM,
				1);
	print_message("%luns\n", t_ns);
}

void test_bench_host_map_nounmap_rand_2MBx4K(void **state)
{
	uint64_t t_ns;

	if (!hltests_get_parser_run_disabled_tests()) {
		print_message("This test need to be run with -d flag\n");
		skip();
	}
	t_ns = hltest_bench_host_map((struct hltests_state *)*state,
				0x1000UL,
				0x200000UL,
				NOT_HUGE,
				0x1000UL,
				0x1000UL,
				RANDOM,
				1);
	print_message("%luns\n", t_ns);
}

void test_bench_host_map_nounmap_huge_rand_2MBx4K(void **state)
{
	uint64_t t_ns;

	if (!hltests_get_parser_run_disabled_tests()) {
		print_message("This test need to be run with -d flag\n");
		skip();
	}
	t_ns = hltest_bench_host_map((struct hltests_state *)*state,
				0x1000UL,
				0x200000UL,
				HUGE,
				0x1000UL,
				0x1000UL,
				RANDOM,
				1);
	print_message("%luns\n", t_ns);
}

static int bench_mappings_custom_parsing_handler(void *user,
						const char *section,
						const char *name,
						const char *value)
{
	struct bench_mappings_custom_cfg *cfg =
		(struct bench_mappings_custom_cfg *) user;

	if (MATCH("bench_mappings_custom", "n_allocs"))
		cfg->n_allocs = strtoul(value, NULL, 0);
	else if (MATCH("bench_mappings_custom", "alloc_size"))
		cfg->alloc_size = strtoul(value, NULL, 0);
	else if (MATCH("bench_mappings_custom", "huge"))
		cfg->huge = strcmp("true", value) ? false : true;
	else if (MATCH("bench_mappings_custom", "n_maps"))
		cfg->n_maps = strtoul(value, NULL, 0);
	else if (MATCH("bench_mappings_custom", "n_unmaps"))
		cfg->n_unmaps = strtoul(value, NULL, 0);
	else if (MATCH("bench_mappings_custom", "random"))
		cfg->random = strcmp("true", value) ? false : true;
	else if (MATCH("bench_mappings_custom", "n_iter"))
		cfg->n_iter = strtoul(value, NULL, 0);
	else
		return 0; /* unknown section/name, error */

	return 1;
}

void test_bench_mappings_custom(void **state)
{
	struct bench_mappings_custom_cfg cfg;
	const char *config_filename = hltests_get_config_filename();
	uint64_t t_ns;

	if (!hltests_get_parser_run_disabled_tests()) {
		print_message("This test need to be run with -d flag\n");
		skip();
	}

	if (!config_filename)
		fail_msg("User didn't supply a configuration file name!\n");

	if (ini_parse(config_filename, bench_mappings_custom_parsing_handler,
			&cfg) < 0)
		fail_msg("Can't load %s\n", config_filename);

	printf("Configuration loaded from %s:\n", config_filename);

	printf("n_allocs=%ld\n"
		"alloc_size=0x%lx\n"
		"huge=%d\n"
		"n_maps=%ld\n"
		"n_unmaps=%ld\n"
		"random=%d\n"
		"n_iter=%d\n",
		cfg.n_allocs, cfg.alloc_size, cfg.huge,
		cfg.n_maps, cfg.n_unmaps,
		cfg.random, cfg.n_iter);

	t_ns = hltest_bench_host_map((struct hltests_state *)*state,
					cfg.n_allocs, cfg.alloc_size, cfg.huge,
		cfg.n_maps, cfg.n_unmaps,
		cfg.random, cfg.n_iter);

	print_message("%luns\n", t_ns);
}

const struct CMUnitTest profiling_tests[] = {
	cmocka_unit_test_setup(test_debug_mode,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_bench_host_map_nounmap_2MBx4K,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_bench_host_map_nounmap_8GB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_bench_host_nomap_unmap_2MBx4K,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_bench_host_nomap_unmap_8GB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_bench_host_map_nounmap_rand_2MBx4K,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_bench_host_map_nounmap_huge_rand_2MBx4K,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_bench_mappings_custom,
			hltests_ensure_device_operational),
};

static const char *const usage[] = {
	"profiling [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = sizeof(profiling_tests) / sizeof((profiling_tests)[0]);

	hltests_parser(argc, argv, usage, HLTHUNK_DEVICE_DONT_CARE,
			profiling_tests, num_tests);

	return hltests_run_group_tests("profiling", profiling_tests,
				num_tests, hltests_setup, hltests_teardown);
}
