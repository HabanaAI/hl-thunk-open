// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_tests.h"
#include "ini.h"

#include <stddef.h>
#include <limits.h>
#include <cmocka.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>

#define MAX_DMA_CH 8
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

uint32_t calc_factor(uint32_t num_ch, uint32_t dram_size, uint32_t dma_size)
{
	if (num_ch > 1)
		return dram_size / ((num_ch - 1) * dma_size);
	else
		return dram_size / dma_size;
}

static double execute_host_bidirectional_transfer(int fd,
				struct dma_perf_transfer *host_to_device,
				struct dma_perf_transfer *device_to_host)
{
	struct hltests_cs_chunk *execute_arr;
	struct hltests_pkt_info pkt_info;
	struct timespec begin, end;
	void **h2d_cb, **d2h_cb;
	int rc, h2d_num_of_cb = 1, d2h_num_of_cb = 1;
	uint64_t h2d_lindma_pkts, h2d_lindma_pkts_per_cb, i, j,
		d2h_lindma_pkts, d2h_lindma_pkts_per_cb, seq = 0;
	uint32_t h2d_cb_offset = 0, d2h_cb_offset = 0;

	if (hltests_is_pldm(fd)) {
		h2d_lindma_pkts = 1;
		d2h_lindma_pkts = 1;
	} else if (hltests_is_simulator(fd)) {
		h2d_lindma_pkts = 5;
		d2h_lindma_pkts = 5;
	} else {
		h2d_lindma_pkts = 0x43F9B1000ull / host_to_device->size;
		d2h_lindma_pkts = 0x4A817C000ull / device_to_host->size;
	}

	h2d_lindma_pkts_per_cb = h2d_lindma_pkts;
	h2d_num_of_cb = 1;

	if (h2d_lindma_pkts > MAX_NUM_LIN_DMA_PKTS_IN_EXTERNAL_CB) {
		h2d_lindma_pkts_per_cb = MAX_NUM_LIN_DMA_PKTS_IN_EXTERNAL_CB;

		h2d_num_of_cb =
			(h2d_lindma_pkts / h2d_lindma_pkts_per_cb) + 1;

		h2d_lindma_pkts = h2d_num_of_cb *
					h2d_lindma_pkts_per_cb;
	}

	assert_in_range(h2d_num_of_cb, 1, HL_MAX_JOBS_PER_CS / 2);

	d2h_lindma_pkts_per_cb = d2h_lindma_pkts;
	d2h_num_of_cb = 1;

	if (d2h_lindma_pkts > MAX_NUM_LIN_DMA_PKTS_IN_EXTERNAL_CB) {
		d2h_lindma_pkts_per_cb = MAX_NUM_LIN_DMA_PKTS_IN_EXTERNAL_CB;

		d2h_num_of_cb =
			(d2h_lindma_pkts / d2h_lindma_pkts_per_cb) + 1;

		d2h_lindma_pkts = d2h_num_of_cb *
					d2h_lindma_pkts_per_cb;
	}


	assert_in_range(d2h_num_of_cb, 1, HL_MAX_JOBS_PER_CS / 2);

	execute_arr = hlthunk_malloc(sizeof(struct hltests_cs_chunk) *
					(h2d_num_of_cb + d2h_num_of_cb));
	assert_non_null(execute_arr);

	h2d_cb = hlthunk_malloc(sizeof(void *) * h2d_num_of_cb);
	assert_non_null(h2d_cb);
	d2h_cb = hlthunk_malloc(sizeof(void *) * d2h_num_of_cb);
	assert_non_null(d2h_cb);

	for (i = 0 ; i < h2d_num_of_cb ; i++) {
		uint64_t cb_size = h2d_lindma_pkts_per_cb * LIN_DMA_PKT_SIZE;

		h2d_cb[i] = hltests_create_cb(fd, cb_size, EXTERNAL, 0);
		assert_non_null(h2d_cb[i]);
	}

	for (i = 0 ; i < d2h_num_of_cb ; i++) {
		uint64_t cb_size = d2h_lindma_pkts_per_cb * LIN_DMA_PKT_SIZE;

		d2h_cb[i] = hltests_create_cb(fd, cb_size, EXTERNAL, 0);
		assert_non_null(d2h_cb[i]);
	}

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.dma.src_addr = host_to_device->src_addr;
	pkt_info.dma.dst_addr = host_to_device->dst_addr;
	pkt_info.dma.size = host_to_device->size;
	pkt_info.dma.dma_dir = host_to_device->dma_dir;

	for (i = 0 ; i < h2d_num_of_cb ; i++) {
		for (j = 0 ; j < h2d_lindma_pkts_per_cb ; j++)
			h2d_cb_offset = hltests_add_dma_pkt(fd, h2d_cb[i],
						h2d_cb_offset, &pkt_info);

		execute_arr[i].cb_ptr = h2d_cb[i];
		execute_arr[i].cb_size = h2d_cb_offset;
		execute_arr[i].queue_index = host_to_device->queue_index;

		h2d_cb_offset = 0;
	}

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.dma.src_addr = device_to_host->src_addr;
	pkt_info.dma.dst_addr = device_to_host->dst_addr;
	pkt_info.dma.size = device_to_host->size;
	pkt_info.dma.dma_dir = device_to_host->dma_dir;

	for (i = 0 ; i < d2h_num_of_cb ; i++) {
		for (j = 0 ; j < d2h_lindma_pkts_per_cb ; j++)
			d2h_cb_offset = hltests_add_dma_pkt(fd, d2h_cb[i],
						d2h_cb_offset, &pkt_info);

		execute_arr[h2d_num_of_cb + i].cb_ptr = d2h_cb[i];
		execute_arr[h2d_num_of_cb + i].cb_size =
							d2h_cb_offset;
		execute_arr[h2d_num_of_cb + i].queue_index =
					device_to_host->queue_index;

		d2h_cb_offset = 0;
	}

	clock_gettime(CLOCK_MONOTONIC_RAW, &begin);

	rc = hltests_submit_cs(fd, NULL, 0, execute_arr,
				h2d_num_of_cb + d2h_num_of_cb, 0, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	clock_gettime(CLOCK_MONOTONIC_RAW, &end);

	for (i = 0 ; i < h2d_num_of_cb ; i++) {
		rc = hltests_destroy_cb(fd, h2d_cb[i]);
		assert_int_equal(rc, 0);
	}

	for (i = 0 ; i < d2h_num_of_cb ; i++) {
		rc = hltests_destroy_cb(fd, d2h_cb[i]);
		assert_int_equal(rc, 0);
	}

	hlthunk_free(h2d_cb);
	hlthunk_free(d2h_cb);
	hlthunk_free(execute_arr);

	/* return value in GB/Sec */
	return get_bw_gigabyte_per_sec(host_to_device->size * h2d_lindma_pkts +
			device_to_host->size * d2h_lindma_pkts, &begin, &end);
}

static double execute_host_transfer(int fd,
				struct dma_perf_transfer *transfer)
{
	struct hltests_cs_chunk *execute_arr;
	struct hltests_pkt_info pkt_info;
	uint64_t num_of_lindma_pkts, num_of_lindma_pkts_per_cb, i, j;
	struct timespec begin, end;
	void **cb1;
	int rc, num_of_cb = 1;
	uint64_t seq = 0;
	uint32_t num_of_cb_per_transfer, offset_cb1 = 0;

	if (hltests_is_pldm(fd))
		num_of_lindma_pkts = 1;
	else if (hltests_is_simulator(fd))
		num_of_lindma_pkts = 5;
	else
		num_of_lindma_pkts = 0x400000000ull / transfer->size;

	num_of_lindma_pkts_per_cb = num_of_lindma_pkts;
	num_of_cb_per_transfer = 1;

	if (num_of_lindma_pkts > MAX_NUM_LIN_DMA_PKTS_IN_EXTERNAL_CB) {
		num_of_lindma_pkts_per_cb = MAX_NUM_LIN_DMA_PKTS_IN_EXTERNAL_CB;

		num_of_cb_per_transfer =
			(num_of_lindma_pkts / num_of_lindma_pkts_per_cb) + 1;

		num_of_lindma_pkts = num_of_cb_per_transfer *
					num_of_lindma_pkts_per_cb;
	}

	num_of_cb = num_of_cb_per_transfer;
	assert_in_range(num_of_cb, 1, HL_MAX_JOBS_PER_CS);

	execute_arr = hlthunk_malloc(sizeof(struct hltests_cs_chunk) *
					num_of_cb);
	assert_non_null(execute_arr);

	cb1 = hlthunk_malloc(sizeof(void *) * num_of_cb_per_transfer);
	assert_non_null(cb1);

	for (i = 0 ; i < num_of_cb_per_transfer ; i++) {
		uint64_t cb_size = num_of_lindma_pkts_per_cb * LIN_DMA_PKT_SIZE;

		cb1[i] = hltests_create_cb(fd, cb_size, EXTERNAL, 0);
		assert_non_null(cb1[i]);
	}

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.dma.src_addr = transfer->src_addr;
	pkt_info.dma.dst_addr = transfer->dst_addr;
	pkt_info.dma.size = transfer->size;
	pkt_info.dma.dma_dir = transfer->dma_dir;

	for (i = 0 ; i < num_of_cb_per_transfer ; i++) {
		for (j = 0 ; j < num_of_lindma_pkts_per_cb ; j++)
			offset_cb1 = hltests_add_dma_pkt(fd, cb1[i], offset_cb1,
							&pkt_info);

		execute_arr[i].cb_ptr = cb1[i];
		execute_arr[i].cb_size = offset_cb1;
		execute_arr[i].queue_index = transfer->queue_index;

		offset_cb1 = 0;
	}

	clock_gettime(CLOCK_MONOTONIC_RAW, &begin);

	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, num_of_cb, 0, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	clock_gettime(CLOCK_MONOTONIC_RAW, &end);

	for (i = 0 ; i < num_of_cb_per_transfer ; i++) {
		rc = hltests_destroy_cb(fd, cb1[i]);
		assert_int_equal(rc, 0);
	}

	hlthunk_free(cb1);
	hlthunk_free(execute_arr);

	/* return value in GB/Sec */
	return get_bw_gigabyte_per_sec(transfer->size * num_of_lindma_pkts,
								&begin, &end);
}

struct dma_perf_cfg {
	uint32_t dma_size;
};

static int dma_perf_parser(void *user, const char *section, const char *name,
				const char *value)
{
	struct dma_perf_cfg *dma_cfg = (struct dma_perf_cfg *) user;

	if (MATCH("dma_perf", "host_dma_size"))
		dma_cfg->dma_size = strtoul(value, NULL, 0);
	else
		return 0; /* unknown section/name, error */

	return 1;
}

void test_host_sram_perf(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	const char *config_filename = hltests_get_config_filename();
	struct dma_perf_transfer transfer;
	struct hlthunk_hw_ip_info hw_ip;
	double *host_sram_perf_outcome;
	struct dma_perf_cfg cfg;
	uint64_t host_addr, sram_addr;
	void *src_ptr;
	int rc, fd = tests_state->fd;

	cfg.dma_size = LIN_DMA_SIZE_FOR_HOST;

	if (config_filename) {
		if (ini_parse(config_filename, dma_perf_parser, &cfg) < 0)
			fail_msg("Can't load %s\n", config_filename);

		printf("Configuration loaded from %s:\n", config_filename);
		printf("dma_size = 0x%x\n", cfg.dma_size);
	}

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);
	assert_in_range(cfg.dma_size, 1, hw_ip.sram_size);

	sram_addr = hw_ip.sram_base_address;

	src_ptr = hltests_allocate_host_mem(fd, cfg.dma_size, HUGE);
	assert_non_null(src_ptr);

	host_addr = hltests_get_device_va_for_host_ptr(fd, src_ptr);

	host_sram_perf_outcome =
		&tests_state->perf_outcomes[DMA_PERF_HOST2SRAM];

	transfer.queue_index = hltests_get_dma_down_qid(fd, STREAM0);
	transfer.src_addr = host_addr;
	transfer.dst_addr = sram_addr;
	transfer.size = cfg.dma_size;
	transfer.dma_dir = GOYA_DMA_HOST_TO_SRAM;

	*host_sram_perf_outcome = execute_host_transfer(fd, &transfer);

	hltests_free_host_mem(fd, src_ptr);
}

void test_sram_host_perf(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	const char *config_filename = hltests_get_config_filename();
	struct dma_perf_cfg cfg;
	struct dma_perf_transfer transfer;
	struct hlthunk_hw_ip_info hw_ip;
	double *sram_host_perf_outcome;
	uint64_t host_addr, sram_addr;
	void *dst_ptr;
	int rc, fd = tests_state->fd;

	cfg.dma_size = LIN_DMA_SIZE_FOR_HOST;

	if (config_filename) {
		if (ini_parse(config_filename, dma_perf_parser, &cfg) < 0)
			fail_msg("Can't load %s\n", config_filename);

		printf("Configuration loaded from %s:\n", config_filename);
		printf("dma_size = 0x%x\n", cfg.dma_size);
	}

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);
	assert_in_range(cfg.dma_size, 1, hw_ip.sram_size);

	sram_addr = hw_ip.sram_base_address;

	dst_ptr = hltests_allocate_host_mem(fd, cfg.dma_size, HUGE);
	assert_non_null(dst_ptr);

	host_addr = hltests_get_device_va_for_host_ptr(fd, dst_ptr);

	sram_host_perf_outcome =
		&tests_state->perf_outcomes[DMA_PERF_SRAM2HOST];

	transfer.queue_index = hltests_get_dma_up_qid(fd, STREAM0);
	transfer.src_addr = sram_addr;
	transfer.dst_addr = host_addr;
	transfer.size = cfg.dma_size;
	transfer.dma_dir = GOYA_DMA_SRAM_TO_HOST;

	*sram_host_perf_outcome = execute_host_transfer(fd, &transfer);

	hltests_free_host_mem(fd, dst_ptr);
}

void test_host_dram_perf(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	const char *config_filename = hltests_get_config_filename();
	struct dma_perf_cfg cfg;
	struct dma_perf_transfer transfer;
	struct hlthunk_hw_ip_info hw_ip;
	double *host_dram_perf_outcome;
	void *src_ptr, *dram_addr;
	uint64_t host_addr;
	int rc, fd = tests_state->fd;

	cfg.dma_size = LIN_DMA_SIZE_FOR_HOST;

	if (config_filename) {
		if (ini_parse(config_filename, dma_perf_parser, &cfg) < 0)
			fail_msg("Can't load %s\n", config_filename);

		printf("Configuration loaded from %s:\n", config_filename);
		printf("dma_size = 0x%x\n", cfg.dma_size);
	}

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	assert_in_range(cfg.dma_size, 1, hw_ip.dram_size);
	dram_addr = hltests_allocate_device_mem(fd, cfg.dma_size,
						NOT_CONTIGUOUS);
	assert_non_null(dram_addr);

	src_ptr = hltests_allocate_host_mem(fd, cfg.dma_size, HUGE);
	assert_non_null(src_ptr);

	host_addr = hltests_get_device_va_for_host_ptr(fd, src_ptr);

	host_dram_perf_outcome =
		&tests_state->perf_outcomes[DMA_PERF_HOST2DRAM];

	transfer.queue_index = hltests_get_dma_down_qid(fd, STREAM0);
	transfer.src_addr = host_addr;
	transfer.dst_addr = (uint64_t) (uintptr_t) dram_addr;
	transfer.size = cfg.dma_size;
	transfer.dma_dir = GOYA_DMA_HOST_TO_DRAM;

	*host_dram_perf_outcome = execute_host_transfer(fd, &transfer);

	hltests_free_host_mem(fd, src_ptr);
	hltests_free_device_mem(fd, dram_addr);
}

void test_dram_host_perf(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	const char *config_filename = hltests_get_config_filename();
	struct dma_perf_cfg cfg;
	struct dma_perf_transfer transfer;
	struct hlthunk_hw_ip_info hw_ip;
	double *dram_host_perf_outcome;
	void *dst_ptr, *dram_addr;
	uint64_t host_addr;
	int rc, fd = tests_state->fd;

	cfg.dma_size = LIN_DMA_SIZE_FOR_HOST;

	if (config_filename) {
		if (ini_parse(config_filename, dma_perf_parser, &cfg) < 0)
			fail_msg("Can't load %s\n", config_filename);

		printf("Configuration loaded from %s:\n", config_filename);
		printf("dma_size = 0x%x\n", cfg.dma_size);
	}

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	assert_in_range(cfg.dma_size, 1, hw_ip.dram_size);
	dram_addr = hltests_allocate_device_mem(fd, cfg.dma_size,
						NOT_CONTIGUOUS);
	assert_non_null(dram_addr);

	dst_ptr = hltests_allocate_host_mem(fd, cfg.dma_size, HUGE);
	assert_non_null(dst_ptr);

	host_addr = hltests_get_device_va_for_host_ptr(fd, dst_ptr);

	dram_host_perf_outcome =
		&tests_state->perf_outcomes[DMA_PERF_DRAM2HOST];

	transfer.queue_index = hltests_get_dma_up_qid(fd, STREAM0);
	transfer.src_addr = (uint64_t) (uintptr_t) dram_addr;
	transfer.dst_addr = host_addr;
	transfer.size = cfg.dma_size;
	transfer.dma_dir = GOYA_DMA_DRAM_TO_HOST;

	*dram_host_perf_outcome = execute_host_transfer(fd, &transfer);

	hltests_free_host_mem(fd, dst_ptr);
	hltests_free_device_mem(fd, dram_addr);
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
	hltests_destroy_cb(fd, cb);
	for (ch = 0 ; ch < num_of_dma_ch ; ch++) {
		hltests_free_host_mem(fd, cp_dma_cb[ch]);
		hltests_free_host_mem(fd, lower_cb[ch]);
	}

	/* return value in GB/Sec */
	return get_bw_gigabyte_per_sec(total_dma_size * num_of_lindma_pkts,
								&begin, &end);
}

void test_sram_dram_single_ch_perf(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct dma_perf_transfer transfer;
	struct hlthunk_hw_ip_info hw_ip;
	double *sram_dram_perf_outcome;
	void *dram_addr;
	uint64_t sram_addr;
	uint32_t size;
	int rc, fd = tests_state->fd;

	/* This test can't run if mmu disabled */
	if (!tests_state->mmu) {
		printf("Test is skipped. MMU must be enabled\n");
		skip();
	}

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	sram_addr = hw_ip.sram_base_address;

	if (hltests_is_pldm(fd))
		size = 0x1000;
	else
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
		*sram_dram_perf_outcome = execute_host_transfer(fd, &transfer);
	} else {
		int num_of_lindma_pkts;

		if (hltests_is_pldm(fd))
			num_of_lindma_pkts = 1;
		else if (hltests_is_simulator(fd))
			num_of_lindma_pkts = 10;
		else
			num_of_lindma_pkts = 30000;

		*sram_dram_perf_outcome = indirect_perf_test(fd, 1, &transfer,
							num_of_lindma_pkts);
	}

	hltests_free_device_mem(fd, dram_addr);
}

void test_dram_sram_single_ch_perf(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct dma_perf_transfer transfer;
	struct hlthunk_hw_ip_info hw_ip;
	double *dram_sram_perf_outcome;
	void *dram_addr;
	uint64_t sram_addr;
	uint32_t size;
	int rc, fd = tests_state->fd;

	/* This test can't run if mmu disabled */
	if (!tests_state->mmu) {
		printf("Test is skipped. MMU must be enabled\n");
		skip();
	}

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	sram_addr = hw_ip.sram_base_address;

	if (hltests_is_pldm(fd))
		size = 0x1000;
	else
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
		*dram_sram_perf_outcome = execute_host_transfer(fd, &transfer);
	} else {
		int num_of_lindma_pkts;

		if (hltests_is_pldm(fd))
			num_of_lindma_pkts = 1;
		else if (hltests_is_simulator(fd))
			num_of_lindma_pkts = 10;
		else
			num_of_lindma_pkts = 30000;

		*dram_sram_perf_outcome = indirect_perf_test(fd, 1, &transfer,
							num_of_lindma_pkts);
	}

	hltests_free_device_mem(fd, dram_addr);
}

void test_dram_dram_single_ch_perf(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct dma_perf_transfer transfer;
	struct hlthunk_hw_ip_info hw_ip;
	double *dram_dram_perf_outcome;
	void *dram_addr;
	uint32_t size;
	int rc, fd = tests_state->fd;

	/* This test can't run if mmu disabled */
	if (!tests_state->mmu) {
		printf("Test is skipped. MMU must be enabled\n");
		skip();
	}

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (hltests_is_pldm(fd))
		size = 0x1000;
	else
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
		*dram_dram_perf_outcome = execute_host_transfer(fd, &transfer);
	} else {
		int num_of_lindma_pkts;

		if (hltests_is_pldm(fd))
			num_of_lindma_pkts = 1;
		else if (hltests_is_simulator(fd))
			num_of_lindma_pkts = 10;
		else
			num_of_lindma_pkts = 130000;

		*dram_dram_perf_outcome = indirect_perf_test(fd, 1, &transfer,
							num_of_lindma_pkts);
	}

	hltests_free_device_mem(fd, dram_addr);
}

void test_sram_dram_multi_ch_perf(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct dma_perf_transfer transfer[MAX_DMA_CH];
	struct hlthunk_hw_ip_info hw_ip;
	double *sram_dram_perf_outcome;
	uint64_t dram_addr, sram_addr, tested_dram_size;
	uint32_t total_dma_size, factor;
	int num_of_lindma_pkts, rc, ch, fd = tests_state->fd, num_of_ddma_ch;

	/* This test can't run on Goya */
	if (hltests_is_goya(fd)) {
		printf("Test is skipped for GOYA\n");
		skip();
	}

	/* This test can't run if mmu disabled */
	if (!tests_state->mmu) {
		printf("Test is skipped. MMU must be enabled\n");
		skip();
	}

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	sram_addr = hw_ip.sram_base_address;
	tested_dram_size = hw_ip.dram_size;
	total_dma_size = hw_ip.sram_size;
	num_of_ddma_ch = hltests_get_ddma_cnt(fd);
	num_of_lindma_pkts = 60000;

	if (hltests_is_pldm(fd)) {
		total_dma_size = 0x1000;
		num_of_ddma_ch = 1;
		num_of_lindma_pkts = 1;
	} else if (hltests_is_simulator(fd)) {
		num_of_lindma_pkts = 10;
	}

	factor = calc_factor(num_of_ddma_ch, tested_dram_size, total_dma_size);

	assert_in_range(total_dma_size, 1, tested_dram_size);
	assert_in_range(num_of_ddma_ch, 1, MAX_DMA_CH);

	sram_dram_perf_outcome =
		&tests_state->perf_outcomes[DMA_PERF_SRAM2DRAM_MULTI_CH];

	dram_addr = (uint64_t) (uintptr_t)
			hltests_allocate_device_mem(fd, tested_dram_size,
						NOT_CONTIGUOUS);
	assert_non_null(dram_addr);

	for (ch = 0 ; ch < num_of_ddma_ch ; ch++) {
		struct dma_perf_transfer *t = &transfer[ch];

		t->queue_index = hltests_get_ddma_qid(fd, ch, STREAM0);
		t->src_addr = sram_addr +
				ch * (total_dma_size / num_of_ddma_ch);
		t->dst_addr = dram_addr +
				ch * (hltests_rand_u32() % factor) *
				total_dma_size;
		t->size = total_dma_size / num_of_ddma_ch;

		assert_in_range(t->dst_addr, dram_addr,
				dram_addr + tested_dram_size);
		assert_in_range(t->dst_addr + t->size,
				dram_addr, dram_addr + tested_dram_size);
	}

	*sram_dram_perf_outcome = indirect_perf_test(fd, num_of_ddma_ch,
						transfer, num_of_lindma_pkts);

	hltests_free_device_mem(fd, (void *) dram_addr);
}

void test_dram_sram_multi_ch_perf(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct dma_perf_transfer transfer[MAX_DMA_CH];
	struct hlthunk_hw_ip_info hw_ip;
	double *dram_sram_perf_outcome;
	uint64_t dram_addr, sram_addr, tested_dram_size;
	uint32_t total_dma_size, factor;
	int num_of_lindma_pkts, rc, ch, fd = tests_state->fd, num_of_ddma_ch;

	/* This test can't run on Goya */
	if (hltests_is_goya(fd)) {
		printf("Test is skipped for GOYA\n");
		skip();
	}

	/* This test can't run if mmu disabled */
	if (!tests_state->mmu) {
		printf("Test is skipped. MMU must be enabled\n");
		skip();
	}

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	sram_addr = hw_ip.sram_base_address;
	tested_dram_size = hw_ip.dram_size;
	total_dma_size = hw_ip.sram_size;
	num_of_ddma_ch = hltests_get_ddma_cnt(fd);
	num_of_lindma_pkts = 60000;

	if (hltests_is_pldm(fd)) {
		total_dma_size = 0x1000;
		num_of_lindma_pkts = 1;
	} else if (hltests_is_simulator(fd)) {
		num_of_lindma_pkts = 10;
	}

	factor = calc_factor(num_of_ddma_ch, tested_dram_size, total_dma_size);

	assert_in_range(total_dma_size, 1, tested_dram_size);
	assert_in_range(num_of_ddma_ch, 1, MAX_DMA_CH);

	dram_sram_perf_outcome =
		&tests_state->perf_outcomes[DMA_PERF_DRAM2SRAM_MULTI_CH];

	dram_addr = (uint64_t) (uintptr_t)
			hltests_allocate_device_mem(fd, tested_dram_size,
						NOT_CONTIGUOUS);
	assert_non_null(dram_addr);

	for (ch = 0 ; ch < num_of_ddma_ch ; ch++) {
		struct dma_perf_transfer *t = &transfer[ch];

		t->queue_index = hltests_get_ddma_qid(fd, ch, STREAM0);
		t->src_addr = dram_addr +
				ch * (hltests_rand_u32() % factor) *
				total_dma_size;
		t->dst_addr = sram_addr +
				ch * (total_dma_size / num_of_ddma_ch);
		t->size = total_dma_size / num_of_ddma_ch;

		assert_in_range(t->src_addr, dram_addr,
				dram_addr + tested_dram_size);
		assert_in_range(t->src_addr + t->size,
				dram_addr, dram_addr + tested_dram_size);
	}

	*dram_sram_perf_outcome = indirect_perf_test(fd, num_of_ddma_ch,
						transfer, num_of_lindma_pkts);

	hltests_free_device_mem(fd, (void *) dram_addr);
}

void test_dram_dram_multi_ch_perf(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct dma_perf_transfer transfer[MAX_DMA_CH];
	struct hlthunk_hw_ip_info hw_ip;
	double *dram_dram_perf_outcome;
	uint64_t dram_addr, tested_dram_size;
	uint32_t total_dma_size, factor;
	int num_of_lindma_pkts, rc, ch, fd = tests_state->fd, num_of_ddma_ch;

	/* This test can't run on Goya */
	if (hltests_is_goya(fd)) {
		printf("Test is skipped for GOYA\n");
		skip();
	}

	/* This test can't run if mmu disabled */
	if (!tests_state->mmu) {
		printf("Test is skipped. MMU must be enabled\n");
		skip();
	}

	/* This test can't run on Simulator */
	if (hltests_is_simulator(fd)) {
		printf("Test is skipped for Simulator\n");
		skip();
	}

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	total_dma_size = hw_ip.sram_size;
	tested_dram_size = hw_ip.dram_size;
	num_of_lindma_pkts = 40000;
	num_of_ddma_ch = hltests_get_ddma_cnt(fd);

	if (hltests_is_pldm(fd)) {
		total_dma_size = 0x1000;
		num_of_lindma_pkts = 1;
	}

	factor = calc_factor(num_of_ddma_ch, tested_dram_size, total_dma_size);

	assert_in_range(total_dma_size, 1, tested_dram_size);
	assert_in_range(num_of_ddma_ch, 1, MAX_DMA_CH);

	dram_dram_perf_outcome =
		&tests_state->perf_outcomes[DMA_PERF_DRAM2DRAM_MULTI_CH];

	dram_addr = (uint64_t) (uintptr_t)
			hltests_allocate_device_mem(fd, tested_dram_size,
						NOT_CONTIGUOUS);
	assert_non_null(dram_addr);

	for (ch = 0 ; ch < num_of_ddma_ch ; ch++) {
		struct dma_perf_transfer *t = &transfer[ch];

		t->queue_index = hltests_get_ddma_qid(fd, ch, STREAM0);
		t->src_addr = dram_addr +
				ch * (hltests_rand_u32() % factor) *
				total_dma_size;
		t->dst_addr = dram_addr +
				ch * (hltests_rand_u32() % factor) *
				total_dma_size;
		t->size = total_dma_size / num_of_ddma_ch;

		assert_in_range(t->src_addr, dram_addr,
				dram_addr + tested_dram_size);
		assert_in_range(t->src_addr + t->size,
				dram_addr, dram_addr + tested_dram_size);
		assert_in_range(t->dst_addr, dram_addr,
				dram_addr + tested_dram_size);
		assert_in_range(t->dst_addr + t->size,
				dram_addr, dram_addr + tested_dram_size);
	}

	*dram_dram_perf_outcome = indirect_perf_test(fd, num_of_ddma_ch,
						transfer, num_of_lindma_pkts);

	hltests_free_device_mem(fd, (void *) dram_addr);
}

void test_sram_dram_bidirectional_full_multi_ch_perf(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct dma_perf_transfer transfer[MAX_DMA_CH];
	struct hlthunk_hw_ip_info hw_ip;
	double *sram_dram_perf_outcome;
	uint64_t dram_addr, sram_addr, tested_dram_size;
	uint32_t total_dma_size, factor;
	int num_of_lindma_pkts, rc, ch, fd = tests_state->fd, num_of_ddma_ch;

	if (hltests_is_pldm(fd))
		skip();

	/* This test can't run on Goya */
	if (hltests_is_goya(fd)) {
		printf("Test is skipped for GOYA\n");
		skip();
	}

	/* This test can't run if mmu disabled */
	if (!tests_state->mmu) {
		printf("Test is skipped. MMU must be enabled\n");
		skip();
	}

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	sram_addr = hw_ip.sram_base_address;
	tested_dram_size = hw_ip.dram_size;
	total_dma_size = hw_ip.sram_size;
	num_of_ddma_ch = hltests_get_ddma_cnt(fd);
	num_of_lindma_pkts = 60000;

	if (hltests_is_simulator(fd))
		num_of_lindma_pkts = 10;

	factor = calc_factor(num_of_ddma_ch, tested_dram_size, total_dma_size);

	assert_in_range(total_dma_size, 1, tested_dram_size);
	assert_in_range(num_of_ddma_ch, 1, MAX_DMA_CH);

	sram_dram_perf_outcome =
		&tests_state->perf_outcomes[DMA_PERF_SRAM_DRAM_BIDIR_FULL_CH];

	dram_addr = (uint64_t) (uintptr_t)
			hltests_allocate_device_mem(fd, tested_dram_size,
						NOT_CONTIGUOUS);
	assert_non_null(dram_addr);

	for (ch = 0 ; ch < num_of_ddma_ch ; ch++) {
		struct dma_perf_transfer *t = &transfer[ch];

		t->queue_index = hltests_get_ddma_qid(fd, ch, STREAM0);
		t->size = total_dma_size / num_of_ddma_ch;

		if ((ch == 1) || (ch == 2) || (ch == 5)) {
			t->src_addr = sram_addr +
					ch * (total_dma_size / num_of_ddma_ch);
			t->dst_addr = dram_addr +
					ch * (hltests_rand_u32() % factor) *
					total_dma_size;

			assert_in_range(t->dst_addr, dram_addr,
					dram_addr + tested_dram_size);
			assert_in_range(t->dst_addr + t->size,
					dram_addr,
					dram_addr + tested_dram_size);
		} else {
			t->dst_addr = sram_addr +
					ch * (total_dma_size / num_of_ddma_ch);
			t->src_addr = dram_addr +
					ch * (hltests_rand_u32() % factor) *
					total_dma_size;

			assert_in_range(t->src_addr, dram_addr,
					dram_addr + tested_dram_size);
			assert_in_range(t->src_addr + t->size,
					dram_addr,
					dram_addr + tested_dram_size);
		}
	}

	*sram_dram_perf_outcome = indirect_perf_test(fd, num_of_ddma_ch,
						transfer, num_of_lindma_pkts);

	hltests_free_device_mem(fd, (void *) dram_addr);
}

void test_dram_sram_5ch_perf(void **state)
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

	/* This test can't run if mmu disabled */
	if (!tests_state->mmu) {
		printf("Test is skipped. MMU must be enabled\n");
		skip();
	}

	if (hltests_is_pldm(fd))
		num_of_lindma_pkts = 1;
	else if (hltests_is_simulator(fd))
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

	if (hltests_is_pldm(fd))
		size = 0x1000;
	else
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

void test_host_sram_bidirectional_perf(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct dma_perf_transfer host_to_sram_transfer, sram_to_host_transfer;
	const char *config_filename = hltests_get_config_filename();
	struct dma_perf_cfg cfg;
	struct hlthunk_hw_ip_info hw_ip;
	double *host_sram_perf_outcome;
	uint64_t host_src_addr, host_dst_addr, sram_addr1, sram_addr2;
	void *src_ptr, *dst_ptr;
	int rc, fd = tests_state->fd;

	cfg.dma_size = LIN_DMA_SIZE_FOR_HOST;

	if (config_filename) {
		if (ini_parse(config_filename, dma_perf_parser, &cfg) < 0)
			fail_msg("Can't load %s\n", config_filename);

		printf("Configuration loaded from %s:\n", config_filename);
		printf("dma_size = 0x%x\n", cfg.dma_size);
	}

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);
	assert_in_range(cfg.dma_size, 1, hw_ip.sram_size / 2);

	sram_addr1 = hw_ip.sram_base_address;
	sram_addr2 = sram_addr1 + cfg.dma_size;

	src_ptr = hltests_allocate_host_mem(fd, cfg.dma_size, HUGE);
	assert_non_null(src_ptr);
	host_src_addr = hltests_get_device_va_for_host_ptr(fd, src_ptr);

	dst_ptr = hltests_allocate_host_mem(fd, cfg.dma_size, HUGE);
	assert_non_null(dst_ptr);
	host_dst_addr = hltests_get_device_va_for_host_ptr(fd, dst_ptr);

	host_sram_perf_outcome =
		&tests_state->perf_outcomes[DMA_PERF_HOST_SRAM_BIDIR];

	host_to_sram_transfer.queue_index =
			hltests_get_dma_down_qid(fd, STREAM0);
	host_to_sram_transfer.src_addr = host_src_addr;
	host_to_sram_transfer.dst_addr = sram_addr1;
	host_to_sram_transfer.size = cfg.dma_size;
	host_to_sram_transfer.dma_dir = GOYA_DMA_HOST_TO_SRAM;

	sram_to_host_transfer.queue_index =
			hltests_get_dma_up_qid(fd, STREAM0);
	sram_to_host_transfer.src_addr = sram_addr2;
	sram_to_host_transfer.dst_addr = host_dst_addr;
	sram_to_host_transfer.size = cfg.dma_size;
	sram_to_host_transfer.dma_dir = GOYA_DMA_SRAM_TO_HOST;

	*host_sram_perf_outcome = execute_host_bidirectional_transfer(fd,
				&host_to_sram_transfer, &sram_to_host_transfer);

	hltests_free_host_mem(fd, src_ptr);
	hltests_free_host_mem(fd, dst_ptr);
}

void test_host_dram_bidirectional_perf(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct dma_perf_transfer host_to_dram_transfer, dram_to_host_transfer;
	const char *config_filename = hltests_get_config_filename();
	struct dma_perf_cfg cfg;
	struct hlthunk_hw_ip_info hw_ip;
	double *host_dram_perf_outcome;
	uint64_t host_src_addr, host_dst_addr;
	void *src_ptr, *dst_ptr, *dram_ptr1, *dram_ptr2;
	int rc, fd = tests_state->fd;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	cfg.dma_size = LIN_DMA_SIZE_FOR_HOST;

	if (config_filename) {
		if (ini_parse(config_filename, dma_perf_parser, &cfg) < 0)
			fail_msg("Can't load %s\n", config_filename);

		printf("Configuration loaded from %s:\n", config_filename);
		printf("dma_size = 0x%x\n", cfg.dma_size);
	}

	assert_in_range(cfg.dma_size + cfg.dma_size, 1,
			hw_ip.dram_size);
	dram_ptr1 = hltests_allocate_device_mem(fd, cfg.dma_size,
						NOT_CONTIGUOUS);
	assert_non_null(dram_ptr1);
	dram_ptr2 = hltests_allocate_device_mem(fd, cfg.dma_size,
						NOT_CONTIGUOUS);
	assert_non_null(dram_ptr2);

	src_ptr = hltests_allocate_host_mem(fd, cfg.dma_size, HUGE);
	assert_non_null(src_ptr);
	host_src_addr = hltests_get_device_va_for_host_ptr(fd, src_ptr);

	dst_ptr = hltests_allocate_host_mem(fd, cfg.dma_size, HUGE);
	assert_non_null(dst_ptr);
	host_dst_addr = hltests_get_device_va_for_host_ptr(fd, dst_ptr);

	host_dram_perf_outcome =
		&tests_state->perf_outcomes[DMA_PERF_HOST_DRAM_BIDIR];

	host_to_dram_transfer.queue_index =
			hltests_get_dma_down_qid(fd, STREAM0);
	host_to_dram_transfer.src_addr = host_src_addr;
	host_to_dram_transfer.dst_addr = (uint64_t) (uintptr_t) dram_ptr1;
	host_to_dram_transfer.size = cfg.dma_size;
	host_to_dram_transfer.dma_dir = GOYA_DMA_HOST_TO_DRAM;

	dram_to_host_transfer.queue_index =
			hltests_get_dma_up_qid(fd, STREAM0);
	dram_to_host_transfer.src_addr = (uint64_t) (uintptr_t) dram_ptr2;
	dram_to_host_transfer.dst_addr = host_dst_addr;
	dram_to_host_transfer.size = cfg.dma_size;
	dram_to_host_transfer.dma_dir = GOYA_DMA_DRAM_TO_HOST;

	*host_dram_perf_outcome = execute_host_bidirectional_transfer(fd,
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
	cmocka_unit_test_setup(test_host_sram_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_sram_host_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_host_dram_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dram_host_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_host_sram_bidirectional_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_host_dram_bidirectional_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_sram_dram_single_ch_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dram_sram_single_ch_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dram_dram_single_ch_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_sram_dram_multi_ch_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dram_sram_multi_ch_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dram_dram_multi_ch_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(
			test_sram_dram_bidirectional_full_multi_ch_perf,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dram_sram_5ch_perf,
			hltests_ensure_device_operational)
};

static const char *const usage[] = {
	"dma_perf [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = sizeof(dma_perf_tests) /
				sizeof((dma_perf_tests)[0]);

	hltests_parser(argc, argv, usage, HLTHUNK_DEVICE_DONT_CARE,
			dma_perf_tests, num_tests);

	return hltests_run_group_tests("dma_perf", dma_perf_tests, num_tests,
					hltests_setup, hltests_perf_teardown);
}
