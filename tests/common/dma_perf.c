// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk.h"
#include "hlthunk_tests.h"

#include <stddef.h>
#include <limits.h>
#include <cmocka.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>

struct dma_perf_transfer {
	uint64_t src_addr;
	uint64_t dst_addr;
	uint32_t size;
	uint32_t queue_index;
	enum hltests_goya_dma_direction dma_dir;
};

static double hltests_transfer_perf(int fd,
				struct dma_perf_transfer *first_transfer,
				struct dma_perf_transfer *second_transfer)
{
	struct hltests_cs_chunk execute_arr[2];
	struct hltests_pkt_info pkt_info;
	uint64_t num_of_transfers, i;
	struct timespec begin, end;
	double time_diff;
	void *cb1, *cb2;
	int rc, num_of_cb = 1;
	uint64_t seq = 0;
	uint32_t offset_cb1 = 0, offset_cb2 = 0;

	num_of_transfers = hltests_is_simulator(fd) ? 5 :
					(0x400000000ull / first_transfer->size);

	cb1 = hltests_create_cb(fd, getpagesize(), EXTERNAL, 0);
	assert_non_null(cb1);
	cb2 = hltests_create_cb(fd, getpagesize(), EXTERNAL, 0);
	assert_non_null(cb2);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.dma.src_addr = first_transfer->src_addr;
	pkt_info.dma.dst_addr = first_transfer->dst_addr;
	pkt_info.dma.size = first_transfer->size;
	pkt_info.dma.dma_dir = first_transfer->dma_dir;
	offset_cb1 = hltests_add_dma_pkt(fd, cb1, offset_cb1, &pkt_info);

	execute_arr[0].cb_ptr = cb1;
	execute_arr[0].cb_size = offset_cb1;
	execute_arr[0].queue_index = first_transfer->queue_index;

	if (second_transfer) {
		num_of_cb = 2;

		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_FALSE;
		pkt_info.dma.src_addr = second_transfer->src_addr;
		pkt_info.dma.dst_addr = second_transfer->dst_addr;
		pkt_info.dma.size = second_transfer->size;
		pkt_info.dma.dma_dir = second_transfer->dma_dir;
		offset_cb2 = hltests_add_dma_pkt(fd, cb2, offset_cb2,
							&pkt_info);

		execute_arr[1].cb_ptr = cb2;
		execute_arr[1].cb_size = offset_cb2;
		execute_arr[1].queue_index = second_transfer->queue_index;
	}

	clock_gettime(CLOCK_MONOTONIC_RAW, &begin);

	for (i = 0 ; i <= num_of_transfers ; i++) {

		rc = hltests_submit_cs(fd, NULL, 0, execute_arr,
					num_of_cb, FORCE_RESTORE_FALSE, &seq);
		assert_int_equal(rc, 0);
	}

	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	clock_gettime(CLOCK_MONOTONIC_RAW, &end);
	time_diff = (end.tv_nsec - begin.tv_nsec) / 1000000000.0 +
						(end.tv_sec  - begin.tv_sec);

	rc = hltests_destroy_cb(fd, cb1);
	assert_int_equal(rc, 0);
	rc = hltests_destroy_cb(fd, cb2);
	assert_int_equal(rc, 0);

	/* return value in GB/Sec */
	if (second_transfer)
		return ((double)(first_transfer->size + second_transfer->size) *
			num_of_transfers / time_diff) / 1024 / 1024 / 1024;
	else
		return ((double)(first_transfer->size) *
			num_of_transfers / time_diff) / 1024 / 1024 / 1024;
}

void hltest_host_sram_transfer_perf(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct dma_perf_transfer transfer;
	struct hlthunk_hw_ip_info hw_ip;
	double *host_sram_perf_outcome;
	uint64_t host_addr, sram_addr;
	void *src_ptr;
	uint32_t size;
	int rc, fd = tests_state->fd;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	sram_addr = hw_ip.sram_base_address;
	size = 4 * 1024 * 1024;

	src_ptr = hltests_allocate_host_mem(fd, size, HUGE);
	assert_non_null(src_ptr);

	host_addr = hltests_get_device_va_for_host_ptr(fd, src_ptr);

	host_sram_perf_outcome =
		&tests_state->perf_outcomes[DMA_PERF_RESULTS_HOST_TO_SRAM];

	transfer.queue_index = hltests_get_dma_down_qid(fd, DCORE0, STREAM0);
	transfer.src_addr = host_addr;
	transfer.dst_addr = sram_addr;
	transfer.size = size;
	transfer.dma_dir = GOYA_DMA_HOST_TO_SRAM;

	*host_sram_perf_outcome = hltests_transfer_perf(fd, &transfer, NULL);

	hltests_free_host_mem(fd, src_ptr);

	if ((hltests_is_goya(fd)) && (!hltests_is_simulator(fd)) &&
				(*host_sram_perf_outcome < 9.5f)) {
		printf("HOST->SRAM must be at least 9.5 GB/Sec");
		fail();
	}
}

void hltest_sram_host_transfer_perf(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct dma_perf_transfer transfer;
	struct hlthunk_hw_ip_info hw_ip;
	double *sram_host_perf_outcome;
	uint64_t host_addr, sram_addr;
	void *dst_ptr;
	uint32_t size;
	int rc, fd = tests_state->fd;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	sram_addr = hw_ip.sram_base_address;
	size = 4 * 1024 * 1024;

	dst_ptr = hltests_allocate_host_mem(fd, size, HUGE);
	assert_non_null(dst_ptr);

	host_addr = hltests_get_device_va_for_host_ptr(fd, dst_ptr);

	sram_host_perf_outcome =
		&tests_state->perf_outcomes[DMA_PERF_RESULTS_SRAM_TO_HOST];

	transfer.queue_index = hltests_get_dma_up_qid(fd, DCORE0, STREAM0);
	transfer.src_addr = sram_addr;
	transfer.dst_addr = host_addr;
	transfer.size = size;
	transfer.dma_dir = GOYA_DMA_SRAM_TO_HOST;

	*sram_host_perf_outcome = hltests_transfer_perf(fd, &transfer, NULL);

	hltests_free_host_mem(fd, dst_ptr);

	if ((hltests_is_goya(fd)) && (!hltests_is_simulator(fd)) &&
				(*sram_host_perf_outcome < 11.9f)) {
		printf("SRAM->HOST must be at least 11.9 GB/Sec");
		fail();
	}
}

void hltest_host_dram_transfer_perf(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct dma_perf_transfer transfer;
	struct hlthunk_hw_ip_info hw_ip;
	double *host_dram_perf_outcome;
	void *src_ptr, *dram_addr;
	uint64_t host_addr;
	int rc, fd = tests_state->fd;
	uint32_t size = 4 * 1024 * 1024;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	assert_int_equal(hw_ip.dram_enabled, 1);
	assert_in_range(size, 1, hw_ip.dram_size);
	dram_addr = hltests_allocate_device_mem(fd, size, NOT_CONTIGUOUS);
	assert_non_null(dram_addr);

	src_ptr = hltests_allocate_host_mem(fd, size, HUGE);
	assert_non_null(src_ptr);

	host_addr = hltests_get_device_va_for_host_ptr(fd, src_ptr);

	host_dram_perf_outcome =
		&tests_state->perf_outcomes[DMA_PERF_RESULTS_HOST_TO_DRAM];

	transfer.queue_index = hltests_get_dma_down_qid(fd, DCORE0, STREAM0);
	transfer.src_addr = host_addr;
	transfer.dst_addr = (uint64_t) (uintptr_t) dram_addr;
	transfer.size = size;
	transfer.dma_dir = GOYA_DMA_HOST_TO_DRAM;

	*host_dram_perf_outcome = hltests_transfer_perf(fd, &transfer, NULL);

	hltests_free_host_mem(fd, src_ptr);
	hltests_free_device_mem(fd, dram_addr);

	if ((hltests_is_goya(fd)) && (!hltests_is_simulator(fd)) &&
				(*host_dram_perf_outcome < 9.5f)) {
		printf("HOST->DRAM must be at least 9.5 GB/Sec");
		fail();
	}
}

void hltest_dram_host_transfer_perf(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct dma_perf_transfer transfer;
	struct hlthunk_hw_ip_info hw_ip;
	double *dram_host_perf_outcome;
	void *dst_ptr, *dram_addr;
	uint64_t host_addr;
	int rc, fd = tests_state->fd;
	uint32_t size = 32 * 1024 * 1024;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	assert_int_equal(hw_ip.dram_enabled, 1);
	assert_in_range(size, 1, hw_ip.dram_size);
	dram_addr = hltests_allocate_device_mem(fd, size, NOT_CONTIGUOUS);
	assert_non_null(dram_addr);

	dst_ptr = hltests_allocate_host_mem(fd, size, HUGE);
	assert_non_null(dst_ptr);

	host_addr = hltests_get_device_va_for_host_ptr(fd, dst_ptr);

	dram_host_perf_outcome =
		&tests_state->perf_outcomes[DMA_PERF_RESULTS_DRAM_TO_HOST];

	transfer.queue_index = hltests_get_dma_up_qid(fd, DCORE0, STREAM0);
	transfer.src_addr = (uint64_t) (uintptr_t) dram_addr;
	transfer.dst_addr = host_addr;
	transfer.size = size;
	transfer.dma_dir = GOYA_DMA_DRAM_TO_HOST;

	*dram_host_perf_outcome = hltests_transfer_perf(fd, &transfer, NULL);

	hltests_free_host_mem(fd, dst_ptr);
	hltests_free_device_mem(fd, dram_addr);

	if ((hltests_is_goya(fd)) && (!hltests_is_simulator(fd)) &&
				(*dram_host_perf_outcome < 11.5f)) {
		printf("DRAM->HOST must be at least 11.5 GB/Sec");
		fail();
	}
}

static uint32_t setup_lower_cb_in_sram(int fd, uint64_t src_addr,
				uint64_t dst_addr, int num_of_transfers,
				uint32_t size, uint64_t sram_addr)
{
	void *lower_cb;
	uint64_t lower_cb_device_va;
	uint32_t  lower_cb_offset = 0, i;
	struct hltests_pkt_info pkt_info;

	lower_cb = hltests_allocate_host_mem(fd, 0x2000, NOT_HUGE);
	assert_non_null(lower_cb);
	lower_cb_device_va = hltests_get_device_va_for_host_ptr(fd, lower_cb);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.dma.src_addr = src_addr;
	pkt_info.dma.dst_addr = dst_addr;
	pkt_info.dma.size = size;

	for (i = 0 ; i < num_of_transfers ; i++)
		lower_cb_offset = hltests_add_dma_pkt(fd, lower_cb,
						lower_cb_offset, &pkt_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id = 0;
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_ADD;
	lower_cb_offset = hltests_add_write_to_sob_pkt(fd, lower_cb,
						lower_cb_offset, &pkt_info);

	hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, DCORE0, STREAM0),
				EB_FALSE, MB_FALSE, lower_cb_device_va,
				sram_addr, lower_cb_offset, 0);
	hltests_free_host_mem(fd, lower_cb);

	return lower_cb_offset;
}

static double indirect_transfer_perf_test(int fd, uint32_t queue_index,
					uint64_t src_addr, uint64_t dst_addr)
{
	struct hlthunk_hw_ip_info hw_ip;
	struct hltests_pkt_info pkt_info;
	struct hltests_monitor_and_fence mon_and_fence_info;
	void *cp_dma_cb, *cb;
	uint64_t sram_addr, cp_dma_cb_device_va;
	uint32_t size, cp_dma_cb_offset = 0, cb_offset = 0, lower_cb_offset;
	int rc, num_of_transfers, i;

	struct timespec begin, end;
	struct hltests_cs_chunk execute_arr[2];
	uint64_t seq = 0;
	double time_diff;

	memset(&pkt_info, 0, sizeof(pkt_info));

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);
	sram_addr = hw_ip.sram_base_address;
	size = hw_ip.sram_size - 0x3000;

	num_of_transfers = hltests_is_simulator(fd) ? 10 : 300;

	lower_cb_offset = setup_lower_cb_in_sram(fd, src_addr, dst_addr,
					num_of_transfers, size, sram_addr);

	/* Clear SOB before we start */
	hltests_clear_sobs(fd, DCORE0, 1);

	/* Internal CB for CP_DMA */
	cp_dma_cb = hltests_create_cb(fd, 0x20, INTERNAL, sram_addr + 0x2000);
	assert_non_null(cp_dma_cb);
	cp_dma_cb_device_va = hltests_get_device_va_for_host_ptr(fd, cp_dma_cb);

	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.cp_dma.src_addr = sram_addr;
	pkt_info.cp_dma.size = lower_cb_offset;
	cp_dma_cb_offset = hltests_add_cp_dma_pkt(fd, cp_dma_cb,
					cp_dma_cb_offset, &pkt_info);

	hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, DCORE0, STREAM0),
				EB_FALSE, MB_FALSE, cp_dma_cb_device_va,
				sram_addr + 0x2000, cp_dma_cb_offset, 0);

	cb = hltests_create_cb(fd, 0x1000, EXTERNAL, 0);
	assert_non_null(cb);
	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.dcore_id = 0;
	mon_and_fence_info.queue_id = hltests_get_dma_down_qid(fd,
							DCORE0, STREAM0);
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = 0;
	mon_and_fence_info.mon_id = 0;
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.target_val = 1;
	mon_and_fence_info.dec_val = 1;
	cb_offset = hltests_add_monitor_and_fence(fd, cb, 0,
						&mon_and_fence_info);

	execute_arr[0].cb_ptr = cp_dma_cb;
	execute_arr[0].cb_size = cp_dma_cb_offset;
	execute_arr[0].queue_index = queue_index;

	execute_arr[1].cb_ptr = cb;
	execute_arr[1].cb_size = cb_offset;
	execute_arr[1].queue_index = hltests_get_dma_down_qid(fd,
							DCORE0, STREAM0);

	clock_gettime(CLOCK_MONOTONIC_RAW, &begin);

	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, 2,
					FORCE_RESTORE_FALSE, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	clock_gettime(CLOCK_MONOTONIC_RAW, &end);
	time_diff = (end.tv_nsec - begin.tv_nsec) / 1000000000.0 +
						(end.tv_sec  - begin.tv_sec);
	hltests_destroy_cb(fd, cp_dma_cb);
	hltests_destroy_cb(fd, cb);

	/* return value in GB/Sec */
	return ((double)(size) * num_of_transfers / time_diff)
							/ 1024 / 1024 / 1024;
}

void hltest_sram_dram_transfer_perf(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct dma_perf_transfer transfer;
	struct hlthunk_hw_ip_info hw_ip;
	double *sram_dram_perf_outcome;
	void *dram_addr;
	uint64_t sram_addr;
	uint32_t size;
	int rc, fd = tests_state->fd;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	sram_addr = hw_ip.sram_base_address;
	size = hw_ip.sram_size;
	assert_int_equal(hw_ip.dram_enabled, 1);
	assert_in_range(size, 1, hw_ip.dram_size);
	dram_addr = hltests_allocate_device_mem(fd, size, NOT_CONTIGUOUS);
	assert_non_null(dram_addr);

	sram_dram_perf_outcome =
		&tests_state->perf_outcomes[DMA_PERF_RESULTS_SRAM_TO_DRAM];

	if (hltests_is_goya(fd)) {
		transfer.queue_index =
			hltests_get_dma_sram_to_dram_qid(fd, DCORE0, STREAM0);

		transfer.src_addr = sram_addr;
		transfer.dst_addr = (uint64_t) (uintptr_t) dram_addr;
		transfer.size = size;
		transfer.dma_dir = GOYA_DMA_SRAM_TO_DRAM;

		*sram_dram_perf_outcome = hltests_transfer_perf(fd, &transfer,
								NULL);
	} else {
		*sram_dram_perf_outcome =
			indirect_transfer_perf_test(fd,
			hltests_get_dma_sram_to_dram_qid(fd, DCORE0, STREAM0),
			sram_addr + 0x3000, (uint64_t) (uintptr_t) dram_addr);
	}

	hltests_free_device_mem(fd, dram_addr);

	if ((hltests_is_goya(fd)) && (!hltests_is_simulator(fd)) &&
				(*sram_dram_perf_outcome < 34.0f)) {
		printf("SRAM->DRAM must be at least 34 GB/Sec");
		fail();
	}
}

void hltest_dram_sram_transfer_perf(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct dma_perf_transfer transfer;
	struct hlthunk_hw_ip_info hw_ip;
	double *dram_sram_perf_outcome;
	void *dram_addr;
	uint64_t sram_addr;
	uint32_t size;
	int rc, fd = tests_state->fd;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	sram_addr = hw_ip.sram_base_address;
	size = hw_ip.sram_size;

	assert_int_equal(hw_ip.dram_enabled, 1);
	assert_in_range(size, 1, hw_ip.dram_size);
	dram_addr = hltests_allocate_device_mem(fd, size, NOT_CONTIGUOUS);
	assert_non_null(dram_addr);

	dram_sram_perf_outcome =
		&tests_state->perf_outcomes[DMA_PERF_RESULTS_DRAM_TO_SRAM];

	if (hltests_is_goya(fd)) {
		transfer.queue_index =
			hltests_get_dma_dram_to_sram_qid(fd, DCORE0, STREAM0);

		transfer.src_addr = (uint64_t) (uintptr_t) dram_addr;
		transfer.dst_addr = sram_addr;
		transfer.size = size;
		transfer.dma_dir = GOYA_DMA_DRAM_TO_SRAM;

		*dram_sram_perf_outcome = hltests_transfer_perf(fd, &transfer,
								NULL);
	} else {
		*dram_sram_perf_outcome =
			indirect_transfer_perf_test(fd,
			hltests_get_dma_dram_to_sram_qid(fd, DCORE0, STREAM0),
			(uint64_t) (uintptr_t) dram_addr, sram_addr + 0x3000);
	}

	hltests_free_device_mem(fd, dram_addr);

	if ((hltests_is_goya(fd)) && (!hltests_is_simulator(fd)) &&
				(*dram_sram_perf_outcome < 35.0f)) {
		printf("DRAM->SRAM must be at least 35 GB/Sec");
		fail();
	}
}

void hltest_host_sram_bidirectional_transfer_perf(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct dma_perf_transfer host_to_sram_transfer, sram_to_host_transfer;
	struct hlthunk_hw_ip_info hw_ip;
	double *host_sram_perf_outcome;
	uint64_t host_src_addr, host_dst_addr, sram_addr1, sram_addr2;
	void *src_ptr, *dst_ptr;
	uint32_t size;
	int rc, fd = tests_state->fd;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	size = 4 * 1024 * 1024;
	sram_addr1 = hw_ip.sram_base_address;
	sram_addr2 = sram_addr1 + size;

	src_ptr = hltests_allocate_host_mem(fd, size, HUGE);
	assert_non_null(src_ptr);
	host_src_addr = hltests_get_device_va_for_host_ptr(fd, src_ptr);

	dst_ptr = hltests_allocate_host_mem(fd, size, HUGE);
	assert_non_null(dst_ptr);
	host_dst_addr = hltests_get_device_va_for_host_ptr(fd, dst_ptr);

	host_sram_perf_outcome =
		&tests_state->perf_outcomes[DMA_PERF_RESULTS_HOST_SRAM_BIDIR];

	host_to_sram_transfer.queue_index =
			hltests_get_dma_down_qid(fd, DCORE0, STREAM0);
	host_to_sram_transfer.src_addr = host_src_addr;
	host_to_sram_transfer.dst_addr = sram_addr1;
	host_to_sram_transfer.size = size;
	host_to_sram_transfer.dma_dir = GOYA_DMA_HOST_TO_SRAM;

	sram_to_host_transfer.queue_index =
			hltests_get_dma_up_qid(fd, DCORE0, STREAM0);
	sram_to_host_transfer.src_addr = sram_addr2;
	sram_to_host_transfer.dst_addr = host_dst_addr;
	sram_to_host_transfer.size = size;
	sram_to_host_transfer.dma_dir = GOYA_DMA_SRAM_TO_HOST;

	*host_sram_perf_outcome = hltests_transfer_perf(fd,
				&host_to_sram_transfer, &sram_to_host_transfer);

	hltests_free_host_mem(fd, src_ptr);
	hltests_free_host_mem(fd, dst_ptr);
}

void hltest_host_dram_bidirectional_transfer_perf(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct dma_perf_transfer host_to_dram_transfer, dram_to_host_transfer;
	struct hlthunk_hw_ip_info hw_ip;
	double *host_dram_perf_outcome;
	uint64_t host_src_addr, host_dst_addr;
	void *src_ptr, *dst_ptr, *dram_ptr1, *dram_ptr2;
	uint32_t host_to_dram_size = 4 * 1024 * 1024;
	uint32_t dram_to_host_size = 32 * 1024 * 1024;
	int rc, fd = tests_state->fd;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	assert_int_equal(hw_ip.dram_enabled, 1);
	assert_in_range(host_to_dram_size + dram_to_host_size, 1,
			hw_ip.dram_size);
	dram_ptr1 = hltests_allocate_device_mem(fd, host_to_dram_size,
						NOT_CONTIGUOUS);
	assert_non_null(dram_ptr1);
	dram_ptr2 = hltests_allocate_device_mem(fd, dram_to_host_size,
						NOT_CONTIGUOUS);
	assert_non_null(dram_ptr2);

	src_ptr = hltests_allocate_host_mem(fd, host_to_dram_size, HUGE);
	assert_non_null(src_ptr);
	host_src_addr = hltests_get_device_va_for_host_ptr(fd, src_ptr);

	dst_ptr = hltests_allocate_host_mem(fd, dram_to_host_size, HUGE);
	assert_non_null(dst_ptr);
	host_dst_addr = hltests_get_device_va_for_host_ptr(fd, dst_ptr);

	host_dram_perf_outcome =
		&tests_state->perf_outcomes[DMA_PERF_RESULTS_HOST_DRAM_BIDIR];

	host_to_dram_transfer.queue_index =
			hltests_get_dma_down_qid(fd, DCORE0, STREAM0);
	host_to_dram_transfer.src_addr = host_src_addr;
	host_to_dram_transfer.dst_addr = (uint64_t) (uintptr_t) dram_ptr1;
	host_to_dram_transfer.size = host_to_dram_size;
	host_to_dram_transfer.dma_dir = GOYA_DMA_HOST_TO_DRAM;

	dram_to_host_transfer.queue_index =
			hltests_get_dma_up_qid(fd, DCORE0, STREAM0);
	dram_to_host_transfer.src_addr = (uint64_t) (uintptr_t) dram_ptr2;
	dram_to_host_transfer.dst_addr = host_dst_addr;
	dram_to_host_transfer.size = dram_to_host_size;
	dram_to_host_transfer.dma_dir = GOYA_DMA_DRAM_TO_HOST;

	*host_dram_perf_outcome = hltests_transfer_perf(fd,
				&host_to_dram_transfer, &dram_to_host_transfer);

	hltests_free_host_mem(fd, src_ptr);
	hltests_free_host_mem(fd, dst_ptr);

	hltests_free_device_mem(fd, dram_ptr1);
	hltests_free_device_mem(fd, dram_ptr2);
}

static int hltests_perf_teardown(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	double *perf_outcomes = tests_state->perf_outcomes;
	int i;

	if (!tests_state)
		return -EINVAL;

	printf("========\n");
	printf("RESULTS:\n");
	printf("========\n");
	printf("HOST->SRAM %lf GB/Sec\n",
			perf_outcomes[DMA_PERF_RESULTS_HOST_TO_SRAM]);
	printf("SRAM->HOST %lf GB/Sec\n",
			perf_outcomes[DMA_PERF_RESULTS_SRAM_TO_HOST]);
	printf("HOST->DRAM %lf GB/Sec\n",
			perf_outcomes[DMA_PERF_RESULTS_HOST_TO_DRAM]);
	printf("DRAM->HOST %lf GB/Sec\n",
			perf_outcomes[DMA_PERF_RESULTS_DRAM_TO_HOST]);
	printf("SRAM->DRAM %lf GB/Sec\n",
			perf_outcomes[DMA_PERF_RESULTS_SRAM_TO_DRAM]);
	printf("DRAM->SRAM %lf GB/Sec\n",
			perf_outcomes[DMA_PERF_RESULTS_DRAM_TO_SRAM]);
	printf("HOST<->SRAM %lf GB/Sec\n",
			perf_outcomes[DMA_PERF_RESULTS_HOST_SRAM_BIDIR]);
	printf("HOST<->DRAM %lf GB/Sec\n",
			perf_outcomes[DMA_PERF_RESULTS_HOST_DRAM_BIDIR]);

	return hltests_teardown(state);
}

const struct CMUnitTest dma_perf_tests[] = {
	cmocka_unit_test_setup(hltest_host_sram_transfer_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(hltest_sram_host_transfer_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(hltest_host_dram_transfer_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(hltest_dram_host_transfer_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(hltest_sram_dram_transfer_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(hltest_dram_sram_transfer_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(hltest_host_sram_bidirectional_transfer_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(hltest_host_dram_bidirectional_transfer_perf,
				hltests_ensure_device_operational)
};

static const char *const usage[] = {
	"dma_perf [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int rc, num_tests = sizeof(dma_perf_tests) /
				sizeof((dma_perf_tests)[0]);

	hltests_parser(argc, argv, usage, HLTHUNK_DEVICE_DONT_CARE,
			dma_perf_tests, num_tests);

	return hltests_run_group_tests("dma_perf", dma_perf_tests, num_tests,
					hltests_setup, hltests_perf_teardown);
}
