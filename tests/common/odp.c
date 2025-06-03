// SPDX-License-Identifier: MIT

/*
 * Copyright 2022 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_tests.h"
#include "ini.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#include <sys/utsname.h>


/* When compiling agains old version of glibc - may be undefined */
#ifndef MADV_PAGEOUT
#define MADV_PAGEOUT 21
#endif

/*
 * Note that this value cannot be freely modified, it shall be in sync with
 * the default value of the FAULTQ_SIZE register.
 */
#define GAUDI3_PFQ_SIZE		SZ_8K
#define GAUDI3_PFQ_ENTRY_SIZE	0x10	/* 16B */
#define GAUDI3_PFQ_NUM_ENTRIES	(GAUDI3_PFQ_SIZE / GAUDI3_PFQ_ENTRY_SIZE)

#define TEST_PFQ_FULL_NUM_ENTRIES	((int)(1.5 * GAUDI3_PFQ_NUM_ENTRIES))

enum odp_stress_type {
	ODP_STRESS_PFQ_FULL,
	ODP_STRESS_PFQ_SAME_REGION,
	ODP_STRESS_PFQ_MAX,
};

struct os_version {
	uint32_t kernel_version;
	uint32_t major_revision;
	uint32_t minor_revision;
	uint32_t patch;
};

struct swappable_mem {
	void *ptr;
	uint64_t va;
	uint64_t size;
	int fd;
};

/* compiler doesn't recognize function called in cmoka main as usage */
static __attribute__((unused)) int get_os_version(struct os_version *osver)
{
	struct utsname buf;
	int rc;

	memset(osver, 0, sizeof(*osver));

	rc = uname(&buf);
	if (rc)
		return rc;

	rc = sscanf(buf.release, "%d.%d.%d-%d", &osver->kernel_version,
		&osver->major_revision, &osver->minor_revision, &osver->patch);

	if (rc < 0)
		return rc;

	if (rc < 3) {
		errno = EINVAL;
		return -EINVAL;
	}

	return 0;
}

static __attribute__((unused)) bool os_ver_ge(struct os_version *osver, uint32_t kernel_version,
		uint32_t major_revision, uint32_t minor_revision,
		uint32_t patch)
{
	uint32_t v1[] = { osver->kernel_version, osver->major_revision,
			  osver->minor_revision, osver->patch },
		 v2[] = { kernel_version, major_revision, minor_revision,
			  patch };
	int i;

	for (i = 0; i < ARRAY_SIZE(v1); ++i) {
		if (v1[i] > v2[i])
			return true;
		if (v1[i] < v2[i])
			return false;
	}
	return true;
}

VOID test_odp_page_in_flow_basic(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;
	bool is_ddr = false;

	if (hltests_get_parser_mini_suite())
		skip();

	if (!hw_ip->sram_size) {
		if (hw_ip->dram_enabled) {
			is_ddr = true;
		} else {
			printf("No device memory is available so skipping test\n");
			skip();
		}
	}

	END_TEST_FUNC(hltests_dma_test_flags(state, is_ddr, SZ_4K, 0, HL_MEM_ODP));
}

VOID test_odp_page_in_concurrent(void **state, int ncs)
{
	uint32_t dma_dir_down = DMA_DIR_HOST_TO_SRAM, dma_dir_up = DMA_DIR_SRAM_TO_HOST;
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	uint64_t device_va = 0, device_va_orig = 0, host_va, size = SZ_4K, *seq;
	void **host_src_mem, **host_dst_mem, *dram_ptr = NULL;
	struct hltests_cs_chunk *css;
	struct hltests_pkt_info pkt_info;
	int i, rc, fd = tests_state->fd;
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;

	if (hltests_get_parser_mini_suite())
		skip();

	/* Prepare the memory */
	if (hw_ip->sram_size) {
		device_va_orig = hw_ip->sram_base_address;
	} else if (hw_ip->dram_enabled) {
		dram_ptr = hltests_allocate_device_mem(fd, size * ncs, 0, CONTIGUOUS);
		assert_non_null(dram_ptr);
		device_va_orig = (uint64_t) (uintptr_t) dram_ptr;
		dma_dir_down = DMA_DIR_HOST_TO_DRAM;
		dma_dir_up = DMA_DIR_DRAM_TO_HOST;
	} else {
		printf("No device memory is available so skipping test\n");
		skip();
	}

	css = calloc(ncs, sizeof(*css));
	assert_non_null(css);

	host_dst_mem = calloc(ncs, sizeof(*host_dst_mem));
	assert_non_null(host_dst_mem);

	host_src_mem = calloc(ncs, sizeof(*host_src_mem));
	assert_non_null(host_src_mem);

	seq = calloc(ncs, sizeof(*seq));
	assert_non_null(seq);

	/* Allocate memory */
	for (i = 0; i < ncs; ++i) {
		css[i].cb_ptr = hltests_create_cb(fd, 0x1000, EXTERNAL, 0);
		assert_non_null(css[i].cb_ptr);

		host_src_mem[i] = hltests_allocate_host_mem_aligned_flags(
			fd, size, HUGE_MAP, 0, HL_MEM_ODP);
		assert_non_null(host_src_mem[i]);
		hltests_fill_rand_values(host_src_mem[i], size);

		host_dst_mem[i] = hltests_allocate_host_mem_aligned_flags(
			fd, size, HUGE_MAP, 0, HL_MEM_ODP);
		assert_non_null(host_dst_mem[i]);
		memset(host_dst_mem[i], 0, size);
	}

	/* Schedule all downloads at once */
	device_va = device_va_orig;

	for (i = 0; i < ncs; ++i, device_va += size) {

		host_va = hltests_get_device_va_for_host_ptr(fd, host_src_mem[i]);

		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.qid = hltests_get_dma_down_qid(fd, i % NUM_OF_STREAMS);
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_FALSE;
		pkt_info.dma.src_addr = host_va;
		pkt_info.dma.dst_addr = device_va;
		pkt_info.dma.size = size;
		pkt_info.dma.dma_dir = dma_dir_down;
		css[i].cb_size = hltests_add_dma_pkt(fd, css[i].cb_ptr, 0, &pkt_info);
		css[i].queue_index = pkt_info.qid;

		rc = hltests_submit_cs(fd, NULL, 0, &css[i], 1, 0, &seq[i]);
		assert_int_equal(rc, 0);
	}

	/* Wait for all completions */
	for (i = 0; i < ncs; ++i) {
		rc = hltests_wait_for_cs_until_not_busy(fd, seq[i]);
		assert_int_equal(rc, 0);
	}

	/* Schedule all uploads at once */
	device_va = device_va_orig;

	for (i = 0 ; i < ncs ; ++i, device_va += size) {

		host_va = hltests_get_device_va_for_host_ptr(fd, host_dst_mem[i]);

		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.qid = hltests_get_dma_up_qid(fd, i % NUM_OF_STREAMS);
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_FALSE;
		pkt_info.dma.src_addr = device_va;
		pkt_info.dma.dst_addr = host_va;
		pkt_info.dma.size = size;
		pkt_info.dma.dma_dir = dma_dir_up;
		css[i].cb_size = hltests_add_dma_pkt(fd, css[i].cb_ptr, 0, &pkt_info);
		css[i].queue_index = pkt_info.qid;

		rc = hltests_submit_cs(fd, NULL, 0, &css[i], 1, 0, &seq[i]);
		assert_int_equal(rc, 0);
	}

	/* Wait for all completions */
	device_va = device_va_orig;

	for (i = 0 ; i < ncs ; ++i, device_va += size) {
		rc = hltests_wait_for_cs_until_not_busy(fd, seq[i]);
		assert_int_equal(rc, 0);
	}

	/* Verify data integrity */
	for (i = 0; i < ncs; ++i) {
		rc = hltests_mem_compare(host_src_mem[i], host_dst_mem[i], size);
		assert_int_equal(rc, 0);
	}

	/* Cleanup */
	for (i = 0; i < ncs; ++i) {
		rc = hltests_free_host_mem(fd, host_src_mem[i]);
		assert_int_equal(rc, 0);
		rc = hltests_free_host_mem(fd, host_dst_mem[i]);
		assert_int_equal(rc, 0);
		rc = hltests_destroy_cb(fd, css[i].cb_ptr);
		assert_int_equal(rc, 0);
	}

	if (dram_ptr) {
		rc = hltests_free_device_mem(fd, dram_ptr);
		assert_int_equal(rc, 0);
	}

	free(host_src_mem);
	free(host_dst_mem);
	free(seq);
	free(css);

	END_TEST;
}

VOID test_odp_page_in_concurrent_2(void **state)
{
	END_TEST_FUNC(test_odp_page_in_concurrent(state, 2));
}

VOID test_odp_page_in_concurrent_20(void **state)
{
	END_TEST_FUNC(test_odp_page_in_concurrent(state, 20));
}

static bool odp_swappable_mem_get(struct hltests_state *tests_state, uint64_t size,
					struct swappable_mem *mem)
{
	char filename[] = "/tmp/odp-test-XXXXXX";
	uint64_t host_va;
	int memfile_fd;
	void *mem_ptr;

	memfile_fd = mkstemp(filename);
	if (memfile_fd == -1) {
		printf("mkstemp error %d\n", errno);
		return false;
	}

	unlink(filename);

	if (ftruncate(memfile_fd, size) == -1) {
		printf("ftruncate error %d\n", errno);
		goto close_tmp;
	}

	mem_ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, memfile_fd, 0);
	if (mem_ptr == MAP_FAILED) {
		printf("mmap error %d\n", errno);
		goto close_tmp;
	}

	host_va = hlthunk_host_memory_map_flags(tests_state->fd, mem_ptr, 0, size, HL_MEM_ODP);
	if (host_va == 0)
		goto mem_unmap;

	mem->ptr = mem_ptr;
	mem->va = host_va;
	mem->size = size;
	mem->fd = memfile_fd;

	return true;

mem_unmap:
	munmap(mem_ptr, size);
close_tmp:
	close(memfile_fd);
	return false;
}

static bool odp_swappable_mem_put(struct hltests_state *tests_state, struct swappable_mem *mem)
{
	bool ret = true;

	if (hlthunk_memory_unmap(tests_state->fd, mem->va))
		ret = false;

	if (munmap(mem->ptr, mem->size))
		ret = false;

	if (close(mem->fd))
		ret = false;

	return ret;
}

VOID test_odp_full_cycle_basic(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	uint32_t dma_dir_down = DMA_DIR_HOST_TO_SRAM, dma_dir_up = DMA_DIR_SRAM_TO_HOST,
			double_pfq_size, track_ci_size;
	uint64_t size = SZ_16K, host_src_va, host_dst_va, device_va = 0x0;
	void *src_ptr, *dst_ptr, *dram_ptr = NULL;
	struct swappable_mem src_mem, dst_mem;
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;
	int fd = tests_state->fd, rc;

	double_pfq_size = GAUDI3_PFQ_SIZE * 2;
	track_ci_size = 0;

	/*
	 * The memory is allocated using memory mapped file. This is done on
	 * purpose to force this memory be swappable, so that we would be able
	 * to cause page out using madvise.
	 */
	assert_true(odp_swappable_mem_get(tests_state, size, &src_mem));
	assert_true(odp_swappable_mem_get(tests_state, size, &dst_mem));
	src_ptr = src_mem.ptr;
	host_src_va = src_mem.va;
	hltests_fill_rand_values(src_ptr, size);
	dst_ptr = dst_mem.ptr;
	host_dst_va = dst_mem.va;
	memset(dst_ptr, 0, size);

	/* Prepare the memory */
	if (hw_ip->sram_size) {
		device_va = hw_ip->sram_base_address;
	} else if (hw_ip->dram_enabled) {
		dram_ptr = hltests_allocate_device_mem(fd, size, 0, CONTIGUOUS);
		assert_non_null(dram_ptr);
		device_va = (uint64_t) (uintptr_t) dram_ptr;
		dma_dir_down = DMA_DIR_HOST_TO_DRAM;
		dma_dir_up = DMA_DIR_DRAM_TO_HOST;
	} else {
		printf("No device memory is available so skipping test\n");
		skip();
	}

	while (track_ci_size <= double_pfq_size) {
		/* Step one - dma transfer to cause page in */

		/* DMA: host->device */
		rc = hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, STREAM0),
					EB_FALSE, MB_TRUE, host_src_va, device_va, size,
					dma_dir_down);
		assert_int_equal(rc, 0);
		track_ci_size += GAUDI3_PFQ_ENTRY_SIZE;

		/* DMA: device->host */
		rc = hltests_dma_transfer(fd, hltests_get_dma_up_qid(fd, STREAM0), EB_FALSE,
					MB_TRUE, device_va, host_dst_va, size, dma_dir_up);
		assert_int_equal(rc, 0);
		track_ci_size += GAUDI3_PFQ_ENTRY_SIZE;

		assert_int_equal(hltests_mem_compare(src_ptr, dst_ptr, size), 0);

		/* Step two - cause page out, full and partial */

		memset(dst_ptr, 0, size);
		rc = madvise(src_ptr, size, MADV_PAGEOUT);
		if (rc) {
			printf("page out failed, address %p, err (%d): %s\n",
					src_ptr, errno, strerror(errno));
			fail();
		};
		rc = madvise((void *)((uint64_t)dst_ptr + SZ_4K), SZ_4K, MADV_PAGEOUT);
		if (rc) {
			printf("page out failed, aaddress %p, err (%d): %s\n",
				(void *)((uint64_t)dst_ptr + SZ_4K), errno, strerror(errno));
			fail();
		};
	}

	/* cleanup */
	assert_true(odp_swappable_mem_put(tests_state, &src_mem));
	assert_true(odp_swappable_mem_put(tests_state, &dst_mem));

	if (dram_ptr) {
		rc = hltests_free_device_mem(fd, dram_ptr);
		assert_int_equal(rc, 0);
	}

	END_TEST;
}

bool available_queues_number(struct hltests_state *tests_state, struct hlthunk_hw_ip_info *hw_ip,
				uint32_t *queue_num)
{
	int fd = tests_state->fd;
	const struct hltests_asic_funcs *asic;
	struct hltests_device *hdev;
	uint32_t qnum = 0;

	/* count NIC QIDs */
	hdev = get_hdev_from_fd(fd);
	if (!hdev) {
		printf("failed to get hdev from FD\n");
		return false;
	}

	asic = hdev->asic_funcs;
	if (!asic) {
		printf("ASIC functions are NULL\n");
		return false;
	}

	qnum += __builtin_popcountll(hw_ip->tpc_enabled_mask_ext);
	qnum += __builtin_popcount(hw_ip->mme_enabled_mask);
	qnum += __builtin_popcount(hw_ip->edma_enabled_mask);

	*queue_num = qnum;

	return true;
}

static bool odp_get_valid_qids(struct hltests_state *tests_state, struct hlthunk_hw_ip_info *hw_ip,
				uint32_t *qid_arr)
{
	int fd = tests_state->fd;
	uint8_t tpc_id, tpc_cnt, mme_id, mme_cnt, edma_id, edma_cnt;
	const struct hltests_asic_funcs *asic;
	struct hltests_device *hdev;
	uint32_t qidx = 0;

	/* find NIC available QID */
	hdev = get_hdev_from_fd(fd);
	if (!hdev) {
		printf("failed to get hdev from FD\n");
		return false;
	}

	asic = hdev->asic_funcs;
	if (!asic) {
		printf("ASIC functions are NULL\n");
		return false;
	}

	/* find TPC available QID */
	tpc_cnt = hltests_get_tpc_cnt(fd);
	for (tpc_id = 0 ; tpc_id < tpc_cnt ; tpc_id++) {
		if (hw_ip->tpc_enabled_mask_ext & (0x1ULL << tpc_id))
			qid_arr[qidx++] = hltests_get_tpc_qid(fd, tpc_id, STREAM0);
	}

	/* find MME available QID */
	mme_cnt = hltests_get_mme_cnt(fd, hw_ip->mme_master_slave_mode);
	for (mme_id = 0 ; mme_id < mme_cnt ; mme_id++) {
		if (hw_ip->mme_enabled_mask & (0x1ULL << mme_id))
			qid_arr[qidx++] = hltests_get_mme_qid(fd, mme_id, STREAM0);
	}

	/* find EDMA available QID */
	edma_cnt = hltests_get_ddma_cnt(fd);
	for (edma_id = 0 ; edma_id < edma_cnt ; edma_id++) {
		/* Unlike in NIC/TPC/MME, for DDMA - hltests_get_ddma_qid()'s
		 * implementation already takes its corresponding bitmask-values
		 * into account. i.e., it returns only QIDs that actually exist.
		 */
		qid_arr[qidx++] = hltests_get_ddma_qid(fd, edma_id, STREAM0);
	}

	return true;
}

VOID test_odp_stress_common(void **state, enum odp_stress_type test_type)
{
	uint32_t queue_num = 0, *qid_arr, size, cb_alloc_size, *cb_size_arr;
	struct swappable_mem *host_mem_arr, *mem_entry = NULL;
	struct hltests_monitor_and_fence mon_and_fence_info;
	int q, i, fd, rc, num_mem_entries = 0;
	struct hltests_cs_chunk *execute_arr;
	struct hltests_state *tests_state;
	struct hltests_pkt_info pkt_info;
	struct hlthunk_hw_ip_info *hw_ip;
	uint64_t seq, timeout_sec;
	uint16_t sob0, mon0;
	void **cb_array;

	if (hltests_get_parser_mini_suite())
		skip();

	tests_state = *state;
	fd = tests_state->fd;
	hw_ip = &tests_state->hw_ip;

	/* we want to distribute the CBs across many queues */
	assert_true(available_queues_number(tests_state, hw_ip, &queue_num));
	if (!queue_num) {
		printf("Test requires at least one QMAN, skipping\n");
		skip();
	}

	/* var init */
	switch (test_type) {
	case ODP_STRESS_PFQ_FULL:
		num_mem_entries = TEST_PFQ_FULL_NUM_ENTRIES;
		break;
	case ODP_STRESS_PFQ_SAME_REGION:
		num_mem_entries = 1;
		break;
	default:
		fail();
	}

	size = SZ_16K;
	cb_alloc_size = SZ_1M;

	sob0 = hltests_get_first_avail_sob(fd);
	mon0 = hltests_get_first_avail_mon(fd);

	/* Clear SOB before we start */
	hltests_clear_sobs(fd, 1);

	cb_array = hlthunk_malloc((queue_num + 1) * sizeof(void *));
	assert_non_null(cb_array);

	qid_arr = hlthunk_malloc((queue_num + 1) * sizeof(uint32_t));
	assert_non_null(qid_arr);

	cb_size_arr = hlthunk_malloc((queue_num + 1) * sizeof(uint32_t));
	assert_non_null(cb_size_arr);

	execute_arr = hlthunk_malloc((queue_num + 1) * sizeof(struct hltests_cs_chunk));
	assert_non_null(execute_arr);

	host_mem_arr = hlthunk_malloc(TEST_PFQ_FULL_NUM_ENTRIES * sizeof(struct swappable_mem));
	assert_non_null(host_mem_arr);

	/* allocations associated with the queues (and one last for the signaling CB) */
	for (i = 0; i < queue_num + 1; i++) {
		/* CB per queue */
		cb_array[i] = hltests_create_cb(fd, cb_alloc_size, INTERNAL, 0);
		assert_non_null(cb_array[i]);
	}

	/* num that we know how many valid Qs are there- fill the QIDs */
	assert_true(odp_get_valid_qids(tests_state, hw_ip, qid_arr));
	qid_arr[queue_num] = hltests_get_dma_down_qid(fd, STREAM0);

	/* Add monitor template to wait for PDMA0 to signal all jobs */
	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = sob0;
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.sob_val = 1;
	mon_and_fence_info.dec_fence = true;
	mon_and_fence_info.mon_payload = 1;
	mon_and_fence_info.mon_mode = SOB_EQUAL;

	/* put fence packet so all will be done in parallel */
	for (q = 0; q < queue_num; q++) {
		mon_and_fence_info.queue_id = qid_arr[q];
		mon_and_fence_info.mon_id = mon0 + q;
		cb_size_arr[q] = hltests_add_monitor_and_fence(fd, cb_array[q], cb_size_arr[q],
							&mon_and_fence_info);
	}

	/* add packet to signal all jobs */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = qid_arr[queue_num];
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.mode = SOB_ADD;
	pkt_info.write_to_sob.sob_id = sob0;
	pkt_info.write_to_sob.value = 1;
	cb_size_arr[queue_num] = hltests_add_write_to_sob_pkt(fd, cb_array[queue_num],
								cb_size_arr[queue_num], &pkt_info);


	/* msg long packet template */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.msg_long.value = 0xf0e1d2c3;

	/*
	 * This loops has the following parameters:
	 * 1. TEST_PFQ_FULL_NUM_ENTRIES: an integer greater than GAUDI3_PFQ_NUM_ENTRIES.
	 *                               this is to try and force full PFQ.
	 * 2. number of QIDs
	 *
	 * The test does the following:
	 * - "feed" the QIDs with TEST_PFQ_FULL_NUM_ENTRIES memory entries.
	 *   memory entry is a swappable host memory chunk which is ODP mapped to the
	 *   device. this can be one or more memory entries that are spread or shared
	 *   between the queues.
	 * - each memory entry is "force-swapped-out"
	 * - distribute the memory entry/entries (round robin policy) between the QIDs.
	 *   each QID gets CB to do a msg_long to an address in the memory entry.
	 *
	 * As the all the QIDs are waiting on the same SOB they will start doing
	 * the msg_longs together (in parallel) and so generating multiple PFQ entries
	 * and so test the ODP fixes.
	 */
	for (i = 0; i < TEST_PFQ_FULL_NUM_ENTRIES; i++) {
		/* round robin the packets on Qs, wrap queue index */
		q = i % queue_num;

		/*
		 * This function can cover two problematic cases in which we had bugs
		 * 1. PFQ full: if PFQ is full and we are issuing invalidation there
		 *    will be a HW deadlock. we try to simulate this (and test the fix)
		 *    by giving at one time transactions to different memory regions that
		 *    will, hopefully, fill the PFQ.
		 * 2. PFQ same region: another HW bug that cause a deadlock. caused by many
		 *    page faults to the same memory region (description in comments of SW-93779)
		 */
		if ((test_type == ODP_STRESS_PFQ_FULL) ||
				((test_type == ODP_STRESS_PFQ_SAME_REGION) && (i == 0))) {
			mem_entry = &host_mem_arr[i];

			/* get chunk of swappable memory, set it to 0 and swap it out */
			assert_true(odp_swappable_mem_get(tests_state, size, mem_entry));
			memset(mem_entry->ptr, 0, mem_entry->size);
			rc = madvise(mem_entry->ptr, mem_entry->size, MADV_PAGEOUT);
			if (rc) {
				printf("page out failed, address %p, err (%d): %s\n",
						mem_entry->ptr, errno, strerror(errno));
				fail();
			};
		}

		assert_non_null(mem_entry);

		/* update msg long packet with relevant info */
		pkt_info.msg_long.address = mem_entry->va;
		pkt_info.qid = qid_arr[q];
		cb_size_arr[q] =
			hltests_add_msg_long_pkt(fd, cb_array[q], cb_size_arr[q], &pkt_info);
		assert_true(cb_size_arr[q] < cb_alloc_size);
	}

	/* create the execute array */
	for (i = 0; i < queue_num + 1; i++) {
		execute_arr[i].cb_ptr = cb_array[i];
		execute_arr[i].cb_size = cb_size_arr[i];
		execute_arr[i].queue_index = qid_arr[i];
	}

	/* perform submission and wait for it */
	timeout_sec = 120;
	rc = hltests_submit_cs_timeout(fd, NULL, 0, execute_arr, queue_num + 1, 0, timeout_sec,
						&seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_cs(fd, seq, timeout_sec * 1000 * 1000);
	/* TODO: should be modified with SW-111109 */
	assert_int_equal(rc, 0);

	/* cleanup */
	for (i = 0; i < num_mem_entries; i++)
		assert_true(odp_swappable_mem_put(tests_state, &host_mem_arr[i]));

	for (i = 0; i < queue_num + 1; i++)
		assert_int_equal(hltests_destroy_cb(fd, cb_array[i]), 0);

	hlthunk_free(qid_arr);
	hlthunk_free(cb_size_arr);
	hlthunk_free(execute_arr);
	hlthunk_free(cb_array);
	hlthunk_free(host_mem_arr);

	END_TEST;
}

VOID test_odp_pfq_full(void **state)
{
	END_TEST_FUNC(test_odp_stress_common(state, ODP_STRESS_PFQ_FULL));
}

VOID test_odp_stress_same_region(void **state)
{
	END_TEST_FUNC(test_odp_stress_common(state, ODP_STRESS_PFQ_SAME_REGION));
}

#ifndef HLTESTS_LIB_MODE

const struct CMUnitTest odp_tests[] = {
	cmocka_unit_test_setup(test_odp_page_in_flow_basic,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_odp_full_cycle_basic,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_odp_page_in_concurrent_2,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_odp_page_in_concurrent_20,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_odp_pfq_full,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_odp_stress_same_region,
				hltests_ensure_device_operational),
};

static const char *const usage[] = {
	"odp [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = ARRAY_SIZE(odp_tests);
	struct os_version osver;
	int rc;

	rc = get_os_version(&osver);

	if (rc) {
		printf("failed to get the os version rc=%d\n", rc);
		return rc;
	}
	if (!os_ver_ge(&osver, 5, 5, 0, 0)) {
		printf("ODP tests requires kernel version >= v5.5\n");
		return 0;
	}

	hltests_parser(argc, argv, usage, HLTEST_DEVICE_MASK_GAUDI3_ALL,
		       odp_tests, num_tests);

	hltests_set_capabilities_mask(CAP_ARC_FW_LOAD_SCHED_MASK |
				CAP_ARC_FW_LOAD_MME_MASK |
				CAP_ARC_FW_LOAD_TPC_MASK |
				CAP_ARC_FW_LOAD_NIC_MASK |
				CAP_ARC_FW_LOAD_EDMA_MASK |
				CAP_ARC_FW_LOAD_PDMA_MASK);

	return hltests_run_group_tests("odp", odp_tests, num_tests,
					hltests_setup, hltests_teardown);
}

#endif /* HLTESTS_LIB_MODE */
