// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk.h"
#include "mersenne-twister.h"
#include "hlthunk_tests.h"

#include <stddef.h>
#include <limits.h>
#include <cmocka.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>

#define MAX_DMA_CH 6
#define LIN_DMA_PKT_SIZE 24
#define MAX_NUM_LIN_DMA_PKTS_IN_EXTERNAL_CB (HL_MAX_CB_SIZE / LIN_DMA_PKT_SIZE)

#define LIN_DMA_SIZE_FOR_HOST 0x1000	/* 4KB per LIN_DMA packet */

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
	struct hltests_cs_chunk *execute_arr;
	struct hltests_pkt_info pkt_info;
	uint64_t num_of_lindma_pkts, num_of_lindma_pkts_per_cb, i, j;
	struct timespec begin, end;
	double time_diff;
	void **cb1, **cb2;
	int rc, num_of_cb = 1;
	uint64_t seq = 0;
	uint32_t num_of_cb_per_transfer, offset_cb1 = 0, offset_cb2 = 0;

	if (hltests_is_simulator(fd))
		num_of_lindma_pkts = 5;
	else
		num_of_lindma_pkts = 0x400000000ull / first_transfer->size;

	num_of_lindma_pkts_per_cb = num_of_lindma_pkts;
	num_of_cb_per_transfer = 1;

	if (num_of_lindma_pkts > MAX_NUM_LIN_DMA_PKTS_IN_EXTERNAL_CB) {
		num_of_lindma_pkts_per_cb = MAX_NUM_LIN_DMA_PKTS_IN_EXTERNAL_CB;

		num_of_cb_per_transfer =
			(num_of_lindma_pkts / num_of_lindma_pkts_per_cb) + 1;

		num_of_lindma_pkts = num_of_cb_per_transfer *
					num_of_lindma_pkts_per_cb;
	}

	if (second_transfer)
		num_of_cb = num_of_cb_per_transfer * 2;
	else
		num_of_cb = num_of_cb_per_transfer;

	assert_in_range(num_of_cb, 1, HL_MAX_JOBS_PER_CS);

	execute_arr = hlthunk_malloc(sizeof(struct hltests_cs_chunk) *
					num_of_cb);
	assert_non_null(execute_arr);

	cb1 = hlthunk_malloc(sizeof(void *) * num_of_cb_per_transfer);
	assert_non_null(cb1);
	cb2 = hlthunk_malloc(sizeof(void *) * num_of_cb_per_transfer);
	assert_non_null(cb2);

	for (i = 0 ; i < num_of_cb_per_transfer ; i++) {
		uint64_t cb_size = num_of_lindma_pkts_per_cb * LIN_DMA_PKT_SIZE;

		cb1[i] = hltests_create_cb(fd, cb_size, EXTERNAL, 0);
		assert_non_null(cb1[i]);

		if (second_transfer) {
			cb2[i] = hltests_create_cb(fd, cb_size, EXTERNAL, 0);
			assert_non_null(cb2[i]);
		}
	}

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.dma.src_addr = first_transfer->src_addr;
	pkt_info.dma.dst_addr = first_transfer->dst_addr;
	pkt_info.dma.size = first_transfer->size;
	pkt_info.dma.dma_dir = first_transfer->dma_dir;

	for (i = 0 ; i < num_of_cb_per_transfer ; i++) {
		for (j = 0 ; j < num_of_lindma_pkts_per_cb ; j++)
			offset_cb1 = hltests_add_dma_pkt(fd, cb1[i], offset_cb1,
							&pkt_info);

		execute_arr[i].cb_ptr = cb1[i];
		execute_arr[i].cb_size = offset_cb1;
		execute_arr[i].queue_index = first_transfer->queue_index;

		offset_cb1 = 0;
	}

	if (second_transfer) {
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_FALSE;
		pkt_info.dma.src_addr = second_transfer->src_addr;
		pkt_info.dma.dst_addr = second_transfer->dst_addr;
		pkt_info.dma.size = second_transfer->size;
		pkt_info.dma.dma_dir = second_transfer->dma_dir;

		for (i = 0 ; i < num_of_cb_per_transfer ; i++) {
			for (j = 0 ; j < num_of_lindma_pkts_per_cb ; j++)
				offset_cb2 = hltests_add_dma_pkt(fd, cb2[i],
							offset_cb2, &pkt_info);

			execute_arr[num_of_cb_per_transfer + i].cb_ptr = cb2[i];
			execute_arr[num_of_cb_per_transfer + i].cb_size =
								offset_cb2;
			execute_arr[num_of_cb_per_transfer + i].queue_index =
						second_transfer->queue_index;

			offset_cb2 = 0;
		}
	}

	clock_gettime(CLOCK_MONOTONIC_RAW, &begin);

	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, num_of_cb, 0, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	clock_gettime(CLOCK_MONOTONIC_RAW, &end);
	time_diff = (end.tv_nsec - begin.tv_nsec) / 1000000000.0 +
						(end.tv_sec  - begin.tv_sec);

	for (i = 0 ; i < num_of_cb_per_transfer ; i++) {
		rc = hltests_destroy_cb(fd, cb1[i]);
		assert_int_equal(rc, 0);

		if (second_transfer) {
			rc = hltests_destroy_cb(fd, cb2[i]);
			assert_int_equal(rc, 0);
		}
	}

	hlthunk_free(cb1);
	hlthunk_free(cb2);
	hlthunk_free(execute_arr);

	/* return value in GB/Sec */
	if (second_transfer)
		return ((double)(first_transfer->size + second_transfer->size) *
			num_of_lindma_pkts / time_diff) / 1000 / 1000 / 1000;
	else
		return ((double)(first_transfer->size) *
			num_of_lindma_pkts / time_diff) / 1000 / 1000 / 1000;
}

void hltest_host_sram_perf(void **state)
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

	size = LIN_DMA_SIZE_FOR_HOST;

	src_ptr = hltests_allocate_host_mem(fd, size, HUGE);
	assert_non_null(src_ptr);

	host_addr = hltests_get_device_va_for_host_ptr(fd, src_ptr);

	host_sram_perf_outcome =
		&tests_state->perf_outcomes[DMA_PERF_HOST2SRAM];

	transfer.queue_index = hltests_get_dma_down_qid(fd, STREAM0);
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

void hltest_sram_host_perf(void **state)
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

	size = LIN_DMA_SIZE_FOR_HOST;

	dst_ptr = hltests_allocate_host_mem(fd, size, HUGE);
	assert_non_null(dst_ptr);

	host_addr = hltests_get_device_va_for_host_ptr(fd, dst_ptr);

	sram_host_perf_outcome =
		&tests_state->perf_outcomes[DMA_PERF_SRAM2HOST];

	transfer.queue_index = hltests_get_dma_up_qid(fd, STREAM0);
	transfer.src_addr = sram_addr;
	transfer.dst_addr = host_addr;
	transfer.size = size;
	transfer.dma_dir = GOYA_DMA_SRAM_TO_HOST;

	*sram_host_perf_outcome = hltests_transfer_perf(fd, &transfer, NULL);

	hltests_free_host_mem(fd, dst_ptr);

	if ((hltests_is_goya(fd)) && (!hltests_is_simulator(fd)) &&
				(*sram_host_perf_outcome < 10.71f)) {
		printf("SRAM->HOST must be at least 10.71 GB/Sec");
		fail();
	}
}

void hltest_host_dram_perf(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct dma_perf_transfer transfer;
	struct hlthunk_hw_ip_info hw_ip;
	double *host_dram_perf_outcome;
	void *src_ptr, *dram_addr;
	uint64_t host_addr;
	int rc, fd = tests_state->fd;
	uint32_t size;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	size = LIN_DMA_SIZE_FOR_HOST;

	assert_in_range(size, 1, hw_ip.dram_size);
	dram_addr = hltests_allocate_device_mem(fd, size, NOT_CONTIGUOUS);
	assert_non_null(dram_addr);

	src_ptr = hltests_allocate_host_mem(fd, size, HUGE);
	assert_non_null(src_ptr);

	host_addr = hltests_get_device_va_for_host_ptr(fd, src_ptr);

	host_dram_perf_outcome =
		&tests_state->perf_outcomes[DMA_PERF_HOST2DRAM];

	transfer.queue_index = hltests_get_dma_down_qid(fd, STREAM0);
	transfer.src_addr = host_addr;
	transfer.dst_addr = (uint64_t) (uintptr_t) dram_addr;
	transfer.size = size;
	transfer.dma_dir = GOYA_DMA_HOST_TO_DRAM;

	*host_dram_perf_outcome = hltests_transfer_perf(fd, &transfer, NULL);

	hltests_free_host_mem(fd, src_ptr);
	hltests_free_device_mem(fd, dram_addr);

	if ((hltests_is_goya(fd)) && (!hltests_is_simulator(fd)) &&
				(*host_dram_perf_outcome < 9.0f)) {
		printf("HOST->DRAM must be at least 9.0 GB/Sec");
		fail();
	}
}

void hltest_dram_host_perf(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct dma_perf_transfer transfer;
	struct hlthunk_hw_ip_info hw_ip;
	double *dram_host_perf_outcome;
	void *dst_ptr, *dram_addr;
	uint64_t host_addr;
	int rc, fd = tests_state->fd;
	uint32_t size;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	size = LIN_DMA_SIZE_FOR_HOST;

	assert_in_range(size, 1, hw_ip.dram_size);
	dram_addr = hltests_allocate_device_mem(fd, size, NOT_CONTIGUOUS);
	assert_non_null(dram_addr);

	dst_ptr = hltests_allocate_host_mem(fd, size, HUGE);
	assert_non_null(dst_ptr);

	host_addr = hltests_get_device_va_for_host_ptr(fd, dst_ptr);

	dram_host_perf_outcome =
		&tests_state->perf_outcomes[DMA_PERF_DRAM2HOST];

	transfer.queue_index = hltests_get_dma_up_qid(fd, STREAM0);
	transfer.src_addr = (uint64_t) (uintptr_t) dram_addr;
	transfer.dst_addr = host_addr;
	transfer.size = size;
	transfer.dma_dir = GOYA_DMA_DRAM_TO_HOST;

	*dram_host_perf_outcome = hltests_transfer_perf(fd, &transfer, NULL);

	hltests_free_host_mem(fd, dst_ptr);
	hltests_free_device_mem(fd, dram_addr);

	if ((hltests_is_goya(fd)) && (!hltests_is_simulator(fd)) &&
				(*dram_host_perf_outcome < 11.2f)) {
		printf("DRAM->HOST must be at least 11.2 GB/Sec");
		fail();
	}
}

static double indirect_perf_test(int fd, uint32_t num_of_dma_ch,
				struct dma_perf_transfer *transfer,
				int num_of_lindma_pkts)
{
	struct hlthunk_hw_ip_info hw_ip;
	struct hltests_pkt_info pkt_info;
	struct hltests_monitor_and_fence mon_and_fence_info;
	void *cp_dma_cb[MAX_DMA_CH], *cb, *lower_cb[MAX_DMA_CH];
	uint64_t cp_dma_cb_device_va[MAX_DMA_CH],
		lower_cb_device_va[MAX_DMA_CH], total_dma_size = 0;
	uint32_t cp_dma_cb_offset = 0, cb_offset = 0, lower_cb_offset = 0;
	uint16_t sob0, mon0;
	int rc, i, ch;

	struct timespec begin, end;
	struct hltests_cs_chunk execute_arr[MAX_DMA_CH + 1];
	uint64_t seq = 0;
	double time_diff;

	for (ch = 0 ; ch < num_of_dma_ch ; ch++) {
		transfer[ch].size = (transfer[ch].size - 0x80) & ~0x7F;
		transfer[ch].src_addr =	(transfer[ch].src_addr + 0x7F) & ~0x7F;
		transfer[ch].dst_addr =	(transfer[ch].dst_addr + 0x7F) & ~0x7F;
		total_dma_size += transfer[ch].size;
	}

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	sob0 = hltests_get_first_avail_sob(fd);
	mon0 = hltests_get_first_avail_mon(fd);

	/* SOB0/MON0 - used to signal from DDMA channels to PDMA that the DMA
	 *             job is done.
	 * SOB1/MON1+2 - used to signal from PDMA to DDMA channels that they
	 *               can start the DMA operation. This is needed so they
	 *               will start together
	 * SOB2/MON3   - used to signal from DDMA channels to PDMA that they
	 *               have started to execute their CB and they are waiting
	 *               on the fence for SOB1
	 */

	/* Clear SOB before we start */
	hltests_clear_sobs(fd, 3);

	/* Setup lower CB for internal DMA engine */
	for (ch = 0 ; ch < num_of_dma_ch ; ch++) {
		lower_cb[ch] = hltests_allocate_host_mem(fd,
				(num_of_lindma_pkts + 10) * LIN_DMA_PKT_SIZE,
				NOT_HUGE);
		assert_non_null(lower_cb[ch]);

		lower_cb_device_va[ch] = hltests_get_device_va_for_host_ptr(fd,
								lower_cb[ch]);

		/* Just configure and ARM the monitor but don't put the fence */
		memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
		mon_and_fence_info.queue_id = transfer[ch].queue_index;
		mon_and_fence_info.cmdq_fence = true;
		mon_and_fence_info.sob_id = sob0 + 1;
		mon_and_fence_info.mon_id = mon0 + 1 + ch;
		mon_and_fence_info.mon_address = 0;
		mon_and_fence_info.sob_val = 1;
		mon_and_fence_info.dec_fence = true;
		mon_and_fence_info.mon_payload = 1;
		mon_and_fence_info.no_fence = true;
		lower_cb_offset = hltests_add_monitor_and_fence(fd,
					lower_cb[ch], 0, &mon_and_fence_info);

		/* add 1 to SOB2 by the DDMA QMAN */
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_TRUE;
		pkt_info.write_to_sob.mode = SOB_ADD;
		pkt_info.write_to_sob.sob_id = sob0 + 2;
		pkt_info.write_to_sob.value = 1;
		lower_cb_offset = hltests_add_write_to_sob_pkt(fd, lower_cb[ch],
						lower_cb_offset, &pkt_info);

		/* Now put the fence of the monitor we configured before */
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_TRUE;
		pkt_info.fence.dec_val = 1;
		pkt_info.fence.gate_val = 1;
		pkt_info.fence.fence_id = 0;
		lower_cb_offset = hltests_add_fence_pkt(fd, lower_cb[ch],
						lower_cb_offset, &pkt_info);

		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_FALSE;
		pkt_info.dma.src_addr = transfer[ch].src_addr;
		pkt_info.dma.dst_addr = transfer[ch].dst_addr;
		pkt_info.dma.size = transfer[ch].size;

		for (i = 0 ; i < num_of_lindma_pkts ; i++)
			lower_cb_offset = hltests_add_dma_pkt(fd, lower_cb[ch],
						lower_cb_offset, &pkt_info);

		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_TRUE;
		pkt_info.mb = MB_TRUE;
		pkt_info.write_to_sob.sob_id = sob0;
		pkt_info.write_to_sob.value = 1;
		pkt_info.write_to_sob.mode = SOB_ADD;
		lower_cb_offset = hltests_add_write_to_sob_pkt(fd, lower_cb[ch],
						lower_cb_offset, &pkt_info);

		/* Setup upper CB for internal DMA engine (cp_dma) */
		cp_dma_cb[ch] = hltests_allocate_host_mem(fd, 0x1000, NOT_HUGE);
		assert_non_null(cp_dma_cb[ch]);
		cp_dma_cb_device_va[ch] =
			hltests_get_device_va_for_host_ptr(fd, cp_dma_cb[ch]);

		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_FALSE;
		pkt_info.cp_dma.src_addr = lower_cb_device_va[ch];
		pkt_info.cp_dma.size = lower_cb_offset;
		cp_dma_cb_offset = hltests_add_cp_dma_pkt(fd, cp_dma_cb[ch],
								0, &pkt_info);

		execute_arr[ch].cb_ptr = (void *) cp_dma_cb_device_va[ch];
		execute_arr[ch].cb_size = cp_dma_cb_offset;
		execute_arr[ch].queue_index = transfer[ch].queue_index;
	}

	/* Setup CB for PDMA */
	cb = hltests_create_cb(fd, 0x1000, EXTERNAL, 0);
	assert_non_null(cb);

	/* Add monitor to wait on all DDMA to announce they are ready */
	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = hltests_get_dma_down_qid(fd, STREAM0);
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = sob0 + 2;
	mon_and_fence_info.mon_id = mon0 + 1 + num_of_dma_ch;
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.sob_val = num_of_dma_ch;
	mon_and_fence_info.dec_fence = true;
	mon_and_fence_info.mon_payload = 1;
	cb_offset = hltests_add_monitor_and_fence(fd, cb, cb_offset,
						&mon_and_fence_info);

	/* Now signal DDMA channels they can start executing */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id = sob0 + 1;
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_SET;
	cb_offset = hltests_add_write_to_sob_pkt(fd, cb, 0, &pkt_info);

	/* Wait for DDMA channels to announce they finished */
	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = hltests_get_dma_down_qid(fd, STREAM0);
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = sob0;
	mon_and_fence_info.mon_id = mon0;
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.sob_val = num_of_dma_ch;
	mon_and_fence_info.dec_fence = true;
	mon_and_fence_info.mon_payload = 1;
	cb_offset = hltests_add_monitor_and_fence(fd, cb, cb_offset,
						&mon_and_fence_info);

	execute_arr[num_of_dma_ch].cb_ptr = cb;
	execute_arr[num_of_dma_ch].cb_size = cb_offset;
	execute_arr[num_of_dma_ch].queue_index =
				hltests_get_dma_down_qid(fd, STREAM0);

	clock_gettime(CLOCK_MONOTONIC_RAW, &begin);

	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, num_of_dma_ch + 1, 0,
				&seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	clock_gettime(CLOCK_MONOTONIC_RAW, &end);
	time_diff = (end.tv_nsec - begin.tv_nsec) / 1000000000.0 +
						(end.tv_sec  - begin.tv_sec);
	hltests_destroy_cb(fd, cb);
	for (ch = 0 ; ch < num_of_dma_ch ; ch++) {
		hltests_free_host_mem(fd, cp_dma_cb[ch]);
		hltests_free_host_mem(fd, lower_cb[ch]);
	}

	/* return value in GB/Sec */
	return (((double)(total_dma_size) * num_of_lindma_pkts) / time_diff) /
							1000 / 1000 / 1000;
}

void hltest_sram_dram_single_ch_perf(void **state)
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

	if (!hw_ip.dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	sram_addr = hw_ip.sram_base_address;
	size = hw_ip.sram_size;

	assert_in_range(size, 1, hw_ip.dram_size);
	dram_addr = hltests_allocate_device_mem(fd, size, NOT_CONTIGUOUS);
	assert_non_null(dram_addr);

	sram_dram_perf_outcome =
		&tests_state->perf_outcomes[DMA_PERF_SRAM2DRAM_SINGLE_CH];

	transfer.queue_index = hltests_get_ddma_qid(fd, 1, STREAM0);

	transfer.src_addr = sram_addr;
	transfer.dst_addr = (uint64_t) (uintptr_t) dram_addr;
	transfer.size = size;
	transfer.dma_dir = GOYA_DMA_SRAM_TO_DRAM;

	if (hltests_is_goya(fd)) {
		*sram_dram_perf_outcome = hltests_transfer_perf(fd, &transfer,
								NULL);
	} else {
		int num_of_lindma_pkts;

		if (hltests_is_simulator(fd))
			num_of_lindma_pkts = 10;
		else
			num_of_lindma_pkts = 30000;

		*sram_dram_perf_outcome = indirect_perf_test(fd, 1, &transfer,
							num_of_lindma_pkts);
	}

	hltests_free_device_mem(fd, dram_addr);

	if ((hltests_is_goya(fd)) && (!hltests_is_simulator(fd)) &&
				(*sram_dram_perf_outcome < 30.6f)) {
		printf("SRAM->DRAM must be at least 30.6 GB/Sec");
		fail();
	}
}

void hltest_dram_sram_single_ch_perf(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct dma_perf_transfer transfer;
	struct hlthunk_hw_ip_info hw_ip;
	double *dram_sram_perf_outcome;
	void *dram_addr;
	uint64_t sram_addr;
	uint32_t size, queue_index;
	int rc, fd = tests_state->fd;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	sram_addr = hw_ip.sram_base_address;
	size = hw_ip.sram_size;

	if (!hw_ip.dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	assert_in_range(size, 1, hw_ip.dram_size);
	dram_addr = hltests_allocate_device_mem(fd, size, NOT_CONTIGUOUS);
	assert_non_null(dram_addr);

	dram_sram_perf_outcome =
		&tests_state->perf_outcomes[DMA_PERF_DRAM2SRAM_SINGLE_CH];

	transfer.queue_index = hltests_get_ddma_qid(fd, 0, STREAM0);

	transfer.src_addr = (uint64_t) (uintptr_t) dram_addr;
	transfer.dst_addr = sram_addr;
	transfer.size = size;
	transfer.dma_dir = GOYA_DMA_DRAM_TO_SRAM;

	if (hltests_is_goya(fd)) {
		*dram_sram_perf_outcome = hltests_transfer_perf(fd, &transfer,
								NULL);
	} else {
		int num_of_lindma_pkts;

		if (hltests_is_simulator(fd))
			num_of_lindma_pkts = 10;
		else
			num_of_lindma_pkts = 30000;

		*dram_sram_perf_outcome = indirect_perf_test(fd, 1, &transfer,
							num_of_lindma_pkts);
	}

	hltests_free_device_mem(fd, dram_addr);

	if ((hltests_is_goya(fd)) && (!hltests_is_simulator(fd)) &&
				(*dram_sram_perf_outcome < 31.5f)) {
		printf("DRAM->SRAM must be at least 31.5 GB/Sec");
		fail();
	}
}

void hltest_dram_dram_single_ch_perf(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct dma_perf_transfer transfer;
	struct hlthunk_hw_ip_info hw_ip;
	double *dram_dram_perf_outcome;
	void *dram_addr;
	uint32_t size;
	int rc, fd = tests_state->fd;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	size = 0x400000;

	if (!hw_ip.dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	assert_in_range(size, 1, hw_ip.dram_size);
	dram_addr = hltests_allocate_device_mem(fd, size * 2, NOT_CONTIGUOUS);
	assert_non_null(dram_addr);

	dram_dram_perf_outcome =
		&tests_state->perf_outcomes[DMA_PERF_DRAM2DRAM_SINGLE_CH];

	transfer.queue_index = hltests_get_ddma_qid(fd, 0, STREAM0);

	transfer.src_addr = (uint64_t) (uintptr_t) dram_addr;
	transfer.dst_addr = ((uint64_t) (uintptr_t) dram_addr) + size;
	transfer.size = size;
	transfer.dma_dir = GOYA_DMA_DRAM_TO_DRAM;

	if (hltests_is_goya(fd)) {
		*dram_dram_perf_outcome = hltests_transfer_perf(fd, &transfer,
								NULL);
	} else {
		int num_of_lindma_pkts;

		if (hltests_is_simulator(fd))
			num_of_lindma_pkts = 10;
		else
			num_of_lindma_pkts = 130000;

		*dram_dram_perf_outcome = indirect_perf_test(fd, 1, &transfer,
							num_of_lindma_pkts);
	}

	hltests_free_device_mem(fd, dram_addr);
}

void hltest_sram_dram_multi_ch_perf(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct dma_perf_transfer transfer[MAX_DMA_CH];
	struct hlthunk_hw_ip_info hw_ip;
	double *sram_dram_perf_outcome;
	uint64_t dram_addr;
	uint64_t sram_addr;
	uint32_t size;
	int num_of_lindma_pkts, rc, ch, fd = tests_state->fd;
	int num_of_ddma_ch = hltests_get_ddma_cnt(fd);
	uint8_t factor = hltests_is_simulator(fd) ? 0xf : 0xff;

	/* This test can't run on Goya */
	if (hlthunk_get_device_name_from_fd(fd) == HLTHUNK_DEVICE_GOYA) {
		printf("Test is skipped for GOYA\n");
		skip();
	}

	if (hltests_is_simulator(fd))
		num_of_lindma_pkts = 10;
	else
		num_of_lindma_pkts = 60000;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	assert_in_range(num_of_ddma_ch, 1, MAX_DMA_CH);

	sram_addr = hw_ip.sram_base_address;
	size = hw_ip.sram_size;

	sram_dram_perf_outcome =
		&tests_state->perf_outcomes[DMA_PERF_SRAM2DRAM_MULTI_CH];

	assert_in_range(size, 1, hw_ip.dram_size);
	dram_addr = (uint64_t) (uintptr_t)
			hltests_allocate_device_mem(fd, hw_ip.dram_size,
						NOT_CONTIGUOUS);
	assert_non_null(dram_addr);

	for (ch = 0 ; ch < num_of_ddma_ch ; ch++) {
		struct dma_perf_transfer *t = &transfer[ch];

		t->queue_index = hltests_get_ddma_qid(fd, ch, STREAM0);
		t->src_addr = sram_addr + ch * (size / num_of_ddma_ch);
		t->dst_addr =
			dram_addr + ch * (hltests_rand_u32() & factor) * size;
		t->size = size / num_of_ddma_ch;

		assert_in_range(t->dst_addr, dram_addr,
				dram_addr + hw_ip.dram_size);
		assert_in_range(t->dst_addr + t->size,
				dram_addr, dram_addr + hw_ip.dram_size);
	}

	*sram_dram_perf_outcome = indirect_perf_test(fd, num_of_ddma_ch,
						transfer, num_of_lindma_pkts);

	hltests_free_device_mem(fd, (void *) dram_addr);
}

void hltest_dram_sram_multi_ch_perf(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct dma_perf_transfer transfer[MAX_DMA_CH];
	struct hlthunk_hw_ip_info hw_ip;
	double *dram_sram_perf_outcome;
	uint64_t dram_addr;
	uint64_t sram_addr;
	uint32_t size;
	int num_of_lindma_pkts, rc, ch, fd = tests_state->fd;
	int num_of_ddma_ch = hltests_get_ddma_cnt(fd);
	uint8_t factor = hltests_is_simulator(fd) ? 0xf : 0xff;

	/* This test can't run on Goya */
	if (hlthunk_get_device_name_from_fd(fd) == HLTHUNK_DEVICE_GOYA) {
		printf("Test is skipped for GOYA\n");
		skip();
	}

	if (hltests_is_simulator(fd))
		num_of_lindma_pkts = 10;
	else
		num_of_lindma_pkts = 60000;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	assert_in_range(num_of_ddma_ch, 1, MAX_DMA_CH);

	sram_addr = hw_ip.sram_base_address;
	size = hw_ip.sram_size;

	dram_sram_perf_outcome =
		&tests_state->perf_outcomes[DMA_PERF_DRAM2SRAM_MULTI_CH];

	assert_in_range(size, 1, hw_ip.dram_size);
	dram_addr = (uint64_t) (uintptr_t)
			hltests_allocate_device_mem(fd, hw_ip.dram_size,
						NOT_CONTIGUOUS);
	assert_non_null(dram_addr);

	for (ch = 0 ; ch < num_of_ddma_ch ; ch++) {
		struct dma_perf_transfer *t = &transfer[ch];

		t->queue_index = hltests_get_ddma_qid(fd, ch, STREAM0);
		t->src_addr =
			dram_addr + ch * (hltests_rand_u32() & factor) * size;
		t->dst_addr = sram_addr + ch * (size / num_of_ddma_ch);
		t->size = size / num_of_ddma_ch;

		assert_in_range(t->src_addr, dram_addr,
				dram_addr + hw_ip.dram_size);
		assert_in_range(t->src_addr + t->size,
				dram_addr, dram_addr + hw_ip.dram_size);
	}

	*dram_sram_perf_outcome = indirect_perf_test(fd, num_of_ddma_ch,
						transfer, num_of_lindma_pkts);

	hltests_free_device_mem(fd, (void *) dram_addr);
}

void hltest_dram_dram_multi_ch_perf(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct dma_perf_transfer transfer[MAX_DMA_CH];
	struct hlthunk_hw_ip_info hw_ip;
	double *dram_dram_perf_outcome;
	uint64_t dram_addr;
	uint32_t size;
	int num_of_lindma_pkts, rc, ch, fd = tests_state->fd;
	int num_of_ddma_ch = hltests_get_ddma_cnt(fd);

	/* This test can't run on Goya */
	if (hlthunk_get_device_name_from_fd(fd) == HLTHUNK_DEVICE_GOYA) {
		printf("Test is skipped for GOYA\n");
		skip();
	}

	/* This test can't run on Simulator */
	if (hltests_is_simulator(fd)) {
		printf("Test is skipped for Simulator\n");
		skip();
	}

	num_of_lindma_pkts = 40000;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	assert_in_range(num_of_ddma_ch, 1, MAX_DMA_CH);

	size = hw_ip.sram_size;

	dram_dram_perf_outcome =
		&tests_state->perf_outcomes[DMA_PERF_DRAM2DRAM_MULTI_CH];

	assert_in_range(size, 1, hw_ip.dram_size);
	dram_addr = (uint64_t) (uintptr_t)
			hltests_allocate_device_mem(fd, hw_ip.dram_size,
						NOT_CONTIGUOUS);
	assert_non_null(dram_addr);

	for (ch = 0 ; ch < num_of_ddma_ch ; ch++) {
		struct dma_perf_transfer *t = &transfer[ch];

		t->queue_index = hltests_get_ddma_qid(fd, ch, STREAM0);
		t->src_addr =
			dram_addr + ch * (hltests_rand_u32() & 0xff) * size;
		t->dst_addr =
			dram_addr + ch * (hltests_rand_u32() & 0xff) * size;
		t->size = size / num_of_ddma_ch;

		assert_in_range(t->src_addr, dram_addr,
				dram_addr + hw_ip.dram_size);
		assert_in_range(t->src_addr + t->size,
				dram_addr, dram_addr + hw_ip.dram_size);
		assert_in_range(t->dst_addr, dram_addr,
				dram_addr + hw_ip.dram_size);
		assert_in_range(t->dst_addr + t->size,
				dram_addr, dram_addr + hw_ip.dram_size);
	}

	*dram_dram_perf_outcome = indirect_perf_test(fd, num_of_ddma_ch,
						transfer, num_of_lindma_pkts);

	hltests_free_device_mem(fd, (void *) dram_addr);
}

void hltest_sram_dram_bidirectional_full_multi_ch_perf(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct dma_perf_transfer transfer[MAX_DMA_CH];
	struct hlthunk_hw_ip_info hw_ip;
	double *sram_dram_perf_outcome;
	uint64_t dram_addr;
	uint64_t sram_addr;
	uint32_t size;
	int num_of_lindma_pkts, rc, ch, fd = tests_state->fd;
	int num_of_ddma_ch = hltests_get_ddma_cnt(fd);
	uint8_t factor = hltests_is_simulator(fd) ? 0xf : 0xff;

	/* This test can't run on Goya */
	if (hlthunk_get_device_name_from_fd(fd) == HLTHUNK_DEVICE_GOYA) {
		printf("Test is skipped for GOYA\n");
		skip();
	}

	if (hltests_is_simulator(fd))
		num_of_lindma_pkts = 10;
	else
		num_of_lindma_pkts = 60000;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	assert_in_range(num_of_ddma_ch, 1, MAX_DMA_CH);

	sram_addr = hw_ip.sram_base_address;
	size = hw_ip.sram_size;

	sram_dram_perf_outcome =
		&tests_state->perf_outcomes[DMA_PERF_SRAM_DRAM_BIDIR_FULL_CH];

	assert_in_range(size, 1, hw_ip.dram_size);
	dram_addr = (uint64_t) (uintptr_t)
			hltests_allocate_device_mem(fd, hw_ip.dram_size,
						NOT_CONTIGUOUS);
	assert_non_null(dram_addr);

	for (ch = 0 ; ch < num_of_ddma_ch ; ch++) {
		struct dma_perf_transfer *t = &transfer[ch];

		t->queue_index = hltests_get_ddma_qid(fd, ch, STREAM0);
		t->size = size / num_of_ddma_ch;

		if ((ch == 1) || (ch == 2) || (ch == 5)) {
			t->src_addr = sram_addr + ch * (size / num_of_ddma_ch);
			t->dst_addr =
				dram_addr + ch *
					(hltests_rand_u32() & factor) * size;

			assert_in_range(t->dst_addr, dram_addr,
					dram_addr + hw_ip.dram_size);
			assert_in_range(t->dst_addr + t->size,
					dram_addr, dram_addr + hw_ip.dram_size);
		} else {
			t->dst_addr = sram_addr + ch * (size / num_of_ddma_ch);
			t->src_addr =
				dram_addr + ch *
					(hltests_rand_u32() & factor) * size;

			assert_in_range(t->src_addr, dram_addr,
					dram_addr + hw_ip.dram_size);
			assert_in_range(t->src_addr + t->size,
					dram_addr, dram_addr + hw_ip.dram_size);
		}
	}

	*sram_dram_perf_outcome = indirect_perf_test(fd, num_of_ddma_ch,
						transfer, num_of_lindma_pkts);

	hltests_free_device_mem(fd, (void *) dram_addr);
}

void hltest_dram_sram_5ch_perf(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct dma_perf_transfer transfer[MAX_DMA_CH];
	struct hlthunk_hw_ip_info hw_ip;
	double *dram_sram_perf_outcome;
	uint64_t dram_addr;
	uint64_t sram_addr;
	uint32_t size;
	int num_of_lindma_pkts, rc, ch, fd = tests_state->fd;
	int num_of_ddma_ch = 5;
	uint32_t queue_index[5] = {0, 1, 2, 3, 4};
	uint8_t factor = hltests_is_simulator(fd) ? 0xf : 0xff;

	/* This test runs on Gaudi */
	if (hlthunk_get_device_name_from_fd(fd) != HLTHUNK_DEVICE_GAUDI) {
		printf("Test is only for GAUDI\n");
		skip();
	}

	if (hltests_is_simulator(fd))
		num_of_lindma_pkts = 10;
	else
		num_of_lindma_pkts = 60000;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	sram_addr = hw_ip.sram_base_address;
	size = hw_ip.sram_size;

	dram_sram_perf_outcome =
		&tests_state->perf_outcomes[DMA_PERF_DRAM2SRAM_5_CH];

	assert_in_range(size, 1, hw_ip.dram_size);
	dram_addr = (uint64_t) (uintptr_t)
			hltests_allocate_device_mem(fd, hw_ip.dram_size,
						NOT_CONTIGUOUS);
	assert_non_null(dram_addr);

	for (ch = 0 ; ch < num_of_ddma_ch ; ch++) {
		struct dma_perf_transfer *t = &transfer[ch];

		t->queue_index = hltests_get_ddma_qid(fd, queue_index[ch],
							STREAM0);
		t->src_addr =
			dram_addr + ch * (hltests_rand_u32() & factor) * size;
		t->dst_addr = sram_addr + ch * (size / num_of_ddma_ch);
		t->size = size / num_of_ddma_ch;

		assert_in_range(t->src_addr, dram_addr,
				dram_addr + hw_ip.dram_size);
		assert_in_range(t->src_addr + t->size,
				dram_addr, dram_addr + hw_ip.dram_size);
	}

	*dram_sram_perf_outcome = indirect_perf_test(fd, num_of_ddma_ch,
						transfer, num_of_lindma_pkts);

	hltests_free_device_mem(fd, (void *) dram_addr);
}

void hltest_host_sram_bidirectional_perf(void **state)
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

	size = LIN_DMA_SIZE_FOR_HOST;

	sram_addr1 = hw_ip.sram_base_address;
	sram_addr2 = sram_addr1 + size;

	src_ptr = hltests_allocate_host_mem(fd, size, HUGE);
	assert_non_null(src_ptr);
	host_src_addr = hltests_get_device_va_for_host_ptr(fd, src_ptr);

	dst_ptr = hltests_allocate_host_mem(fd, size, HUGE);
	assert_non_null(dst_ptr);
	host_dst_addr = hltests_get_device_va_for_host_ptr(fd, dst_ptr);

	host_sram_perf_outcome =
		&tests_state->perf_outcomes[DMA_PERF_HOST_SRAM_BIDIR];

	host_to_sram_transfer.queue_index =
			hltests_get_dma_down_qid(fd, STREAM0);
	host_to_sram_transfer.src_addr = host_src_addr;
	host_to_sram_transfer.dst_addr = sram_addr1;
	host_to_sram_transfer.size = size;
	host_to_sram_transfer.dma_dir = GOYA_DMA_HOST_TO_SRAM;

	sram_to_host_transfer.queue_index =
			hltests_get_dma_up_qid(fd, STREAM0);
	sram_to_host_transfer.src_addr = sram_addr2;
	sram_to_host_transfer.dst_addr = host_dst_addr;
	sram_to_host_transfer.size = size;
	sram_to_host_transfer.dma_dir = GOYA_DMA_SRAM_TO_HOST;

	*host_sram_perf_outcome = hltests_transfer_perf(fd,
				&host_to_sram_transfer, &sram_to_host_transfer);

	hltests_free_host_mem(fd, src_ptr);
	hltests_free_host_mem(fd, dst_ptr);

	if ((hltests_is_goya(fd)) && (!hltests_is_simulator(fd)) &&
				(*host_sram_perf_outcome < 16.65f)) {
		printf("HOST<->SRAM must be at least 16.65 GB/Sec");
		fail();
	}
}

void hltest_host_dram_bidirectional_perf(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct dma_perf_transfer host_to_dram_transfer, dram_to_host_transfer;
	struct hlthunk_hw_ip_info hw_ip;
	double *host_dram_perf_outcome;
	uint64_t host_src_addr, host_dst_addr;
	void *src_ptr, *dst_ptr, *dram_ptr1, *dram_ptr2;
	uint32_t host_to_dram_size, dram_to_host_size;
	int rc, fd = tests_state->fd;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	host_to_dram_size = dram_to_host_size = LIN_DMA_SIZE_FOR_HOST;

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
		&tests_state->perf_outcomes[DMA_PERF_HOST_DRAM_BIDIR];

	host_to_dram_transfer.queue_index =
			hltests_get_dma_down_qid(fd, STREAM0);
	host_to_dram_transfer.src_addr = host_src_addr;
	host_to_dram_transfer.dst_addr = (uint64_t) (uintptr_t) dram_ptr1;
	host_to_dram_transfer.size = host_to_dram_size;
	host_to_dram_transfer.dma_dir = GOYA_DMA_HOST_TO_DRAM;

	dram_to_host_transfer.queue_index =
			hltests_get_dma_up_qid(fd, STREAM0);
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

	if ((hltests_is_goya(fd)) && (!hltests_is_simulator(fd)) &&
				(*host_dram_perf_outcome < 16.2f)) {
		printf("HOST<->DRAM must be at least 16.2 GB/Sec");
		fail();
	}
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
	printf("HOST->SRAM             %7.2lf GB/Sec\n",
			perf_outcomes[DMA_PERF_HOST2SRAM]);
	printf("SRAM->HOST             %7.2lf GB/Sec\n",
			perf_outcomes[DMA_PERF_SRAM2HOST]);
	printf("HOST->DRAM             %7.2lf GB/Sec\n",
			perf_outcomes[DMA_PERF_HOST2DRAM]);
	printf("DRAM->HOST             %7.2lf GB/Sec\n",
			perf_outcomes[DMA_PERF_DRAM2HOST]);
	printf("HOST<->SRAM            %7.2lf GB/Sec\n",
			perf_outcomes[DMA_PERF_HOST_SRAM_BIDIR]);
	printf("HOST<->DRAM            %7.2lf GB/Sec\n",
			perf_outcomes[DMA_PERF_HOST_DRAM_BIDIR]);

	printf("SRAM->DRAM   Single DMA %7.2lf GB/Sec\n",
			perf_outcomes[DMA_PERF_SRAM2DRAM_SINGLE_CH]);
	printf("DRAM->SRAM   Single DMA %7.2lf GB/Sec\n",
			perf_outcomes[DMA_PERF_DRAM2SRAM_SINGLE_CH]);
	printf("DRAM->DRAM   Single DMA %7.2lf GB/Sec\n",
			perf_outcomes[DMA_PERF_DRAM2DRAM_SINGLE_CH]);

	printf("SRAM->DRAM   Multi  DMA %7.2lf GB/Sec\n",
			perf_outcomes[DMA_PERF_SRAM2DRAM_MULTI_CH]);
	printf("DRAM->SRAM   Multi  DMA %7.2lf GB/Sec\n",
			perf_outcomes[DMA_PERF_DRAM2SRAM_MULTI_CH]);
	printf("DRAM->DRAM   Multi  DMA %7.2lf GB/Sec\n",
			perf_outcomes[DMA_PERF_DRAM2DRAM_MULTI_CH]);
	printf("SRAM<->DRAM  Multi  DMA %7.2lf GB/Sec\n",
			perf_outcomes[DMA_PERF_SRAM_DRAM_BIDIR_FULL_CH]);

	printf("DRAM->SRAM   5-ch   DMA %7.2lf GB/Sec\n",
			perf_outcomes[DMA_PERF_DRAM2SRAM_5_CH]);

	return hltests_teardown(state);
}

const struct CMUnitTest dma_perf_tests[] = {
	cmocka_unit_test_setup(hltest_host_sram_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(hltest_sram_host_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(hltest_host_dram_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(hltest_dram_host_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(hltest_host_sram_bidirectional_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(hltest_host_dram_bidirectional_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(hltest_sram_dram_single_ch_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(hltest_dram_sram_single_ch_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(hltest_dram_dram_single_ch_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(hltest_sram_dram_multi_ch_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(hltest_dram_sram_multi_ch_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(hltest_dram_dram_multi_ch_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(
			hltest_sram_dram_bidirectional_full_multi_ch_perf,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(hltest_dram_sram_5ch_perf,
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
