// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_tests.h"
#include "gaudi2/gaudi2.h"

#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

#define GAUDI2_MAX_DMA_CH 8
#define LIN_DMA_PKT_SIZE 24

enum gaudi2_dma_direction {
	DRAM_TO_SRAM,
	DRAM_TO_DRAM,
	SRAM_TO_SRAM
};

struct gaudi2_edma_transfer_data {
	uint64_t addr0;
	uint64_t addr1;
	uint32_t size;
};

struct gaudi2_dma_internal {
	void **cp_dma_cb_arr;
	void **lower_cb_arr;
	uint64_t *cp_dma_cb_va_arr;
	uint64_t *lower_cb_va_arr;
	uint64_t dram_addr;
};

struct gaudi2_dma_external {
	void *cb_pdma0;
	void *cb_pdma1;
	uint64_t host_src_addr;
	uint64_t host_dst_addr;
	uint32_t transfer_size;
	int down_pdma_exec_entry;
	int up_pdma_exec_entry;
};

struct gaudi2_dma_data {
	struct hltests_cs_chunk *execute_arr;
	struct hlthunk_hw_ip_info *hw_ip;
	struct gaudi2_dma_internal *internal_data;
	struct gaudi2_dma_external *external_data;
	void *external_dma_device_addr;
	uint64_t internal_dma_dram_size;
	int dma_channels;
	uint16_t sob_trigger_edma;
	uint16_t sob_trigger_up_pdma;
	uint16_t sob_notify_edma_complete;
	uint16_t monitor_down_pdma;
	uint16_t monitor_edma_complete;
	uint16_t mon_edma_ch_base;
};

static VOID get_edma_dram2sram_transfer_data(int fd, int ch, uint64_t dram_addr,
		uint64_t internal_dma_dram_size, uint64_t dram_ch_size,
		uint64_t sram_addr, uint32_t sram_size, uint32_t sram_ch_size,
		struct gaudi2_edma_transfer_data *data)
{
	uint32_t rand_off;

	data->size = sram_ch_size;
	rand_off = hltests_rand_u32() % (dram_ch_size - data->size);
	if (hltests_get_verbose_enabled())
		printf("DRAM rand offset: %x\n", rand_off);

	/* sram address
	 * The sram is divided to num_of_edma_ch channels. each EDMA will
	 * operate (copy from/to) on a different channel - edma0 on the first
	 * channel, edma1 on the second channel, etc...
	 */
	data->addr0 = sram_addr + ch * sram_ch_size;
	data->addr0 = ALIGN_UP(data->addr0, 128);

	/* dram address
	 * dram is divided to channels the same way as for sram. Also, as dram
	 * channels are larger than sram channels, we pick a random area of size
	 * sram_ch_size in the dram channel.
	 */
	data->addr1 = dram_addr + ch * dram_ch_size + rand_off;
	data->addr1 = ALIGN_UP(data->addr1, 128);

	assert_in_range(data->addr0, sram_addr + ch * sram_ch_size,
				sram_addr + ch * sram_ch_size + sram_ch_size);
	assert_in_range(data->addr1, dram_addr + ch * dram_ch_size,
				dram_addr + ch * dram_ch_size + dram_ch_size);

	/* Write on device memory first to avoid ECC error on pldm */
	if (hltests_is_pldm(fd))
		hltests_zero_device_memory(fd, data->addr1, data->size, 0);

	END_TEST;
}

static VOID get_edma_dram2dram_transfer_data(int fd, int ch, uint64_t dram_addr,
				uint64_t internal_dma_dram_size, uint64_t dram_ch_size,
				struct gaudi2_edma_transfer_data *data)
{
	int verbose = hltests_get_verbose_enabled();
	bool is_pldm = hltests_is_pldm(fd);
	uint64_t src_addr;
	uint32_t rand_off;

	/* divide the number of dram channels by 2 as each edma now operates on
	 * two areas
	 */
	dram_ch_size /= 2;

	/* in pldm EDMAs will transfer 6MB each */
	data->size = is_pldm ? SZ_1M * 6 : dram_ch_size;

	/* each edma will copy data from the first half of a dram channel
	 * (prior to the division by 2) to the second half, or vice versa.
	 * we also take a random region in each divided channel of size
	 * data->size.
	 */
	data->addr0 = dram_addr + (2 * ch) * dram_ch_size;
	if (dram_ch_size - data->size != 0) {
		rand_off = hltests_rand_u32() % (dram_ch_size - data->size);
		if (verbose)
			printf("DRAM address 0 rand offset: %x\n", rand_off);
		data->addr0 += rand_off;
	}
	data->addr0 = ALIGN_UP(data->addr0, 128);

	data->addr1 = dram_addr + (2 * ch + 1) * dram_ch_size;
	if (dram_ch_size - data->size != 0) {
		rand_off = hltests_rand_u32() % (dram_ch_size - data->size);
		if (verbose)
			printf("DRAM address 1 rand offset: %x\n", rand_off);
		data->addr1 += rand_off;
	}
	data->addr1 = ALIGN_UP(data->addr1, 128);

	assert_in_range(data->addr0, dram_addr + (2 * ch) * dram_ch_size,
			dram_addr + (2 * ch) * dram_ch_size + dram_ch_size);
	assert_in_range(data->addr1, dram_addr + (2 * ch + 1) * dram_ch_size,
			dram_addr + (2 * ch + 1) * dram_ch_size + dram_ch_size);

	src_addr = (ch & 1) ? data->addr0 : data->addr1;

	/* Write on device memory first to avoid ECC error on pldm */
	if (is_pldm)
		hltests_zero_device_memory(fd, src_addr, data->size, 0);

	END_TEST;
}

static VOID get_edma_sram2sram_transfer_data(int ch, uint64_t sram_addr,
		uint32_t sram_size, uint32_t sram_ch_size,
		struct gaudi2_edma_transfer_data *data)
{
	/* divide the number of sram channels by 2 as each edma now operates
	 * on two areas
	 */
	sram_ch_size /= 2;

	data->size = sram_ch_size;

	/* each edma will copy data from the first half of an sram channel
	 * (prior to the division by 2) to the second half, or vice versa.
	 * note that this test operates on all available sram
	 */
	data->addr0 = sram_addr + (2 * ch) * sram_ch_size;
	data->addr0 = ALIGN_UP(data->addr0, 128);

	data->addr1 = sram_addr + (2 * ch + 1) * sram_ch_size;
	data->addr1 = ALIGN_UP(data->addr1, 128);

	assert_in_range(data->addr0, sram_addr + (2 * ch) * sram_ch_size,
			sram_addr + (2 * ch) * sram_ch_size + sram_ch_size);
	assert_in_range(data->addr1, sram_addr + (2 * ch + 1) * sram_ch_size,
			sram_addr + (2 * ch + 1) * sram_ch_size + sram_ch_size);
	END_TEST;
}

static VOID set_edma_jobs(struct hltests_state *tests_state,
				struct gaudi2_dma_data *dma_common,
				enum gaudi2_dma_direction direction)
{
	int i, num_of_lindma_pkts, ch, fd, num_of_edma_ch;
	uint32_t queue_index, sram_ch_size, sram_size;
	uint32_t lower_cb_offset = 0, cp_dma_cb_offset = 0;
	uint64_t sram_addr, dram_ch_size, dram_addr;
	uint64_t internal_dma_dram_size;
	uint64_t int_src_addr, int_dst_addr, *lower_cb_device_va;
	uint64_t *cp_dma_cb_device_va;
	void **lower_cb, **cp_dma_cb;
	struct hlthunk_hw_ip_info *hw_ip;
	struct hltests_pkt_info pkt_info;
	struct hltests_cs_chunk *execute_arr;
	struct hltests_monitor_and_fence mon_and_fence_info;
	struct gaudi2_dma_internal *internal_data;
	struct gaudi2_edma_transfer_data transfer_data;
	bool is_simulator, is_pldm;

	internal_data = dma_common->internal_data;

	fd = tests_state->fd;
	is_simulator = hltests_is_simulator(fd);
	is_pldm = hltests_is_pldm(fd);

	hw_ip = dma_common->hw_ip;
	num_of_edma_ch = dma_common->dma_channels;
	execute_arr = dma_common->execute_arr;

	/*
	 * this controls how many times each edma will copy data
	 * as DRAM2DRAM fails with high amount of lindma packet- set
	 * it for now at lower number
	 */
	if (is_simulator || is_pldm)
		num_of_lindma_pkts = 50;
	else
		num_of_lindma_pkts = (direction == DRAM_TO_DRAM) ? 500 : 60000;

	sram_addr = hw_ip->sram_base_address;
	sram_size = hw_ip->sram_size;
	assert_in_range(sram_size, 1, hw_ip->dram_size);

	/* split DRAM between internal and external transfers regions */
	dram_addr = internal_data->dram_addr;
	internal_dma_dram_size = dma_common->internal_dma_dram_size;

	/* getting CB arrays */
	cp_dma_cb = internal_data->cp_dma_cb_arr;
	lower_cb = internal_data->lower_cb_arr;
	cp_dma_cb_device_va = internal_data->cp_dma_cb_va_arr;
	lower_cb_device_va = internal_data->lower_cb_va_arr;

	/* Each edma will operate on a different "channel" (be it sram channel
	 * or dram channel).
	 */
	sram_ch_size = ALIGN_DOWN(sram_size / num_of_edma_ch, 128);
	dram_ch_size = ALIGN_DOWN(internal_dma_dram_size / num_of_edma_ch, 128);

	for (ch = 0 ; ch < num_of_edma_ch ; ch++) {
		queue_index = hltests_get_ddma_qid(fd, ch, STREAM0);

		if (direction == DRAM_TO_SRAM)
			CALL_HELPER_FUNC(
				get_edma_dram2sram_transfer_data(fd, ch, dram_addr,
					internal_dma_dram_size, dram_ch_size,
					sram_addr, sram_size, sram_ch_size,
					&transfer_data));
		else if (direction == DRAM_TO_DRAM)
			CALL_HELPER_FUNC(
				get_edma_dram2dram_transfer_data(fd, ch,
					dram_addr, internal_dma_dram_size,
					dram_ch_size, &transfer_data));
		else
			CALL_HELPER_FUNC(
				get_edma_sram2sram_transfer_data(ch, sram_addr,
					sram_size, sram_ch_size,
					&transfer_data));

		if (ch & 1) {
			int_src_addr = transfer_data.addr0;
			int_dst_addr = transfer_data.addr1;
		} else {
			int_src_addr = transfer_data.addr1;
			int_dst_addr = transfer_data.addr0;
		}
		if (hltests_is_legacy_mode_enabled(fd)) {
			lower_cb[ch] = hltests_allocate_host_mem(fd,
					(num_of_lindma_pkts + 10) * LIN_DMA_PKT_SIZE,
					NOT_HUGE_MAP);
			assert_non_null(lower_cb[ch]);

			lower_cb_device_va[ch] = hltests_get_device_va_for_host_ptr(fd,
									lower_cb[ch]);
		} else {
			lower_cb[ch] = hltests_create_cb(fd,
					((num_of_lindma_pkts + 10) * LIN_DMA_PKT_SIZE) * 2,
					EXTERNAL, 0);
		}

		/* wait for sync from PDMA0 to start internal DMAs */
		memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
		mon_and_fence_info.queue_id = queue_index;
		mon_and_fence_info.cmdq_fence = true;
		mon_and_fence_info.sob_id = dma_common->sob_trigger_edma;
		mon_and_fence_info.mon_id = dma_common->mon_edma_ch_base + ch;
		mon_and_fence_info.mon_address = 0;
		mon_and_fence_info.sob_val = 1;
		mon_and_fence_info.dec_fence = true;
		mon_and_fence_info.mon_payload = 1;
		lower_cb_offset = hltests_add_monitor_and_fence(fd,
					lower_cb[ch], 0, &mon_and_fence_info);

		/* prepare SRAM<->DRAM DMA packet */
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_FALSE;
		pkt_info.dma.src_addr = int_src_addr;
		pkt_info.dma.dst_addr = int_dst_addr;
		pkt_info.dma.size = transfer_data.size;

		/* concatenate number of DMA packets */
		for (i = 0 ; i < num_of_lindma_pkts ; i++)
			lower_cb_offset = hltests_add_dma_pkt(fd, lower_cb[ch],
						lower_cb_offset, &pkt_info);

		/* signal PDMA1 that EDMA job completed */
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_TRUE;
		pkt_info.mb = MB_TRUE;
		pkt_info.write_to_sob.sob_id =
					dma_common->sob_notify_edma_complete;
		pkt_info.write_to_sob.value = 1;
		pkt_info.write_to_sob.mode = SOB_ADD;
		lower_cb_offset = hltests_add_write_to_sob_pkt(fd, lower_cb[ch],
						lower_cb_offset, &pkt_info);

		if (hltests_is_legacy_mode_enabled(fd)) {
			/* Setup upper CB for internal DMA engine (cp_dma) */
			cp_dma_cb[ch] = hltests_allocate_host_mem(fd, 0x1000, NOT_HUGE_MAP);
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
			execute_arr[ch].queue_index = queue_index;
		} else {
			execute_arr[ch].cb_ptr = lower_cb[ch];
			execute_arr[ch].cb_size = lower_cb_offset;
			execute_arr[ch].queue_index = queue_index;
		}
	}

	END_TEST;
}

static void set_down_pdma(struct hltests_state *tests_state,
		struct gaudi2_dma_data *dma_common)
{
	struct hltests_cs_chunk *execute_arr;
	int fd, num_of_edma_ch, exec_entry;
	struct hltests_pkt_info pkt_info;
	uint32_t cb_offset = 0;
	uint64_t host_src_addr;
	void *cb;

	fd = tests_state->fd;
	num_of_edma_ch = dma_common->dma_channels;
	execute_arr = dma_common->execute_arr;

	cb = dma_common->external_data->cb_pdma0;
	host_src_addr = dma_common->external_data->host_src_addr;
	exec_entry = dma_common->external_data->down_pdma_exec_entry;

	/* signal EDMA channels they can start executing */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id = dma_common->sob_trigger_edma;
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_SET;
	cb_offset = hltests_add_write_to_sob_pkt(fd, cb, 0, &pkt_info);

	/* while EDMAs are executing internal jobs, start the down DMA job */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.dma.src_addr = host_src_addr;
	pkt_info.dma.dst_addr = (uint64_t) (uintptr_t)
					dma_common->external_dma_device_addr;
	pkt_info.dma.size = dma_common->external_data->transfer_size;
	cb_offset = hltests_add_dma_pkt(fd, cb, cb_offset, &pkt_info);

	/* signal to PDMA1 it can start working */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.mode = SOB_ADD;
	pkt_info.write_to_sob.sob_id = dma_common->sob_trigger_up_pdma;
	pkt_info.write_to_sob.value = 1;
	cb_offset = hltests_add_write_to_sob_pkt(fd, cb, cb_offset, &pkt_info);

	execute_arr[exec_entry].cb_ptr = cb;
	execute_arr[exec_entry].cb_size = cb_offset;
	execute_arr[exec_entry].queue_index =
				hltests_get_dma_down_qid(fd, STREAM0);
}

static void set_up_pdma(struct hltests_state *tests_state,
		struct gaudi2_dma_data *dma_common)
{
	struct hltests_monitor_and_fence mon_and_fence_info;
	struct hltests_cs_chunk *execute_arr;
	int fd, num_of_edma_ch, exec_entry;
	struct hltests_pkt_info pkt_info;
	uint64_t  host_dst_addr;
	uint32_t cb_offset = 0;
	void *cb;

	fd = tests_state->fd;
	num_of_edma_ch = dma_common->dma_channels;
	execute_arr = dma_common->execute_arr;

	cb = dma_common->external_data->cb_pdma1;
	host_dst_addr = dma_common->external_data->host_dst_addr;
	exec_entry = dma_common->external_data->up_pdma_exec_entry;

	/* Add monitor to wait for PDMA0 to finish the down DMA job */
	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = hltests_get_dma_up_qid(fd, STREAM0);
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = dma_common->sob_trigger_up_pdma;
	mon_and_fence_info.mon_id = dma_common->monitor_down_pdma;
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.sob_val = 1;
	mon_and_fence_info.dec_fence = true;
	mon_and_fence_info.mon_payload = 1;
	cb_offset = hltests_add_monitor_and_fence(fd, cb, cb_offset,
						&mon_and_fence_info);

	/* while EDMAs are executing internal jobs, start the up DMA job */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.dma.src_addr = (uint64_t) (uintptr_t)
					dma_common->external_dma_device_addr;
	pkt_info.dma.dst_addr = host_dst_addr;
	pkt_info.dma.size = dma_common->external_data->transfer_size;
	cb_offset = hltests_add_dma_pkt(fd, cb, cb_offset, &pkt_info);

	/* Wait for EDMA channels and PDMA1 to announce they finished */
	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = hltests_get_dma_up_qid(fd, STREAM0);
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = dma_common->sob_notify_edma_complete;
	mon_and_fence_info.mon_id = dma_common->monitor_edma_complete;
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.sob_val = num_of_edma_ch;
	mon_and_fence_info.dec_fence = true;
	mon_and_fence_info.mon_payload = 1;
	cb_offset = hltests_add_monitor_and_fence(fd, cb, cb_offset,
						&mon_and_fence_info);

	execute_arr[exec_entry].cb_ptr = cb;
	execute_arr[exec_entry].cb_size = cb_offset;
	execute_arr[exec_entry].queue_index =
			hltests_get_dma_up_qid(fd, STREAM0);
}

static VOID dma_all2all(void **state, enum gaudi2_dma_direction direction)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	struct hltests_cs_chunk *execute_arr;
	uint64_t external_dma_dram_size, internal_dma_dram_size, seq = 0;
	uint32_t transfer_size;
	uint16_t sob0, mon0;
	void *host_src_ptr, *host_dst_ptr;
	int rc, ch, fd = tests_state->fd;
	int num_of_edma_ch = hltests_get_ddma_cnt(fd);
	struct gaudi2_dma_internal internal_data;
	struct gaudi2_dma_external external_data;
	struct gaudi2_dma_data dma_common = {
		.internal_data = &internal_data,
		.external_data = &external_data,
	};

	transfer_size = hltests_is_pldm(fd) || hltests_is_simulator(fd) ? SZ_1M : SZ_32M;

	if (hltests_is_pldm(fd) &&
			transfer_size > PLDM_MAX_DMA_SIZE_FOR_TESTING)
		skip();

	/* This test can't run if mmu disabled */
	if (!tests_state->mmu) {
		printf("Test is skipped. MMU must be enabled\n");
		skip();
	}

	assert_in_range(num_of_edma_ch, 1, GAUDI2_MAX_DMA_CH);

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.sram_size)
		skip();

	if (!hw_ip.dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	if (hltests_is_simulator(fd) && hw_ip.dram_size < (SZ_128M)) {
		printf(
			"SIM's DRAM (%lu[B]) is smaller than min requirments (%u[B]) so skipping test\n",
			hw_ip.dram_size, SZ_128M);
		skip();
	}

	/* split DRAM between internal and external transfers regions */
	external_dma_dram_size = hw_ip.dram_size >> 1;
	internal_dma_dram_size = hw_ip.dram_size - external_dma_dram_size;

	if (hltests_is_simulator(fd) || hltests_is_pldm(fd)) {
		/*
		 * In simulator this test is very performance intensive, and
		 * will fail on timeout if there is a lot of RAM.
		 */
		external_dma_dram_size = external_dma_dram_size < SZ_1G ?
						external_dma_dram_size :
						SZ_1G;
		internal_dma_dram_size = internal_dma_dram_size < SZ_1G ?
						internal_dma_dram_size :
						SZ_1G;
	}

	/* we are allocating one exec entry per EDMA + 2: UP and DOWN PDMAs */
	execute_arr = hlthunk_malloc((num_of_edma_ch + 2) *
					sizeof(struct hltests_cs_chunk));
	assert_non_null(execute_arr);

	sob0 = hltests_get_first_avail_sob(fd);
	mon0 = hltests_get_first_avail_mon(fd);

	/* Clear SOB before we start */
	hltests_clear_sobs(fd, 3);

	/* allocations for the internal jobs */
	internal_data.dram_addr = (uint64_t) (uintptr_t)
			hltests_allocate_device_mem(fd, internal_dma_dram_size, 0, NOT_CONTIGUOUS);
	assert_non_null(internal_data.dram_addr);

	/* allocating CB arrays */
	internal_data.cp_dma_cb_arr =
			hlthunk_malloc(num_of_edma_ch * sizeof(void *));
	assert_non_null(internal_data.cp_dma_cb_arr);

	internal_data.lower_cb_arr =
			hlthunk_malloc(num_of_edma_ch * sizeof(void *));
	assert_non_null(internal_data.lower_cb_arr);

	internal_data.cp_dma_cb_va_arr =
			hlthunk_malloc(num_of_edma_ch * sizeof(uint64_t));
	assert_non_null(internal_data.cp_dma_cb_va_arr);

	internal_data.lower_cb_va_arr =
			hlthunk_malloc(num_of_edma_ch * sizeof(uint64_t));
	assert_non_null(internal_data.lower_cb_va_arr);

	dma_common.dma_channels = num_of_edma_ch;
	dma_common.execute_arr = execute_arr;
	dma_common.hw_ip = &hw_ip;
	dma_common.sob_trigger_edma = sob0;
	dma_common.sob_trigger_up_pdma = sob0 + 1;
	dma_common.sob_notify_edma_complete = sob0 + 2;
	dma_common.monitor_down_pdma = mon0;
	dma_common.monitor_edma_complete = mon0 + 1;
	dma_common.mon_edma_ch_base = mon0 + 2;
	dma_common.internal_dma_dram_size = internal_dma_dram_size;

	/* prepare internal (DRAM<->SRAM / DRAM<->DRAM) jobs */
	CALL_HELPER_FUNC(set_edma_jobs(tests_state, &dma_common, direction));

	external_data.transfer_size = transfer_size;
	external_data.down_pdma_exec_entry = num_of_edma_ch;
	external_data.up_pdma_exec_entry = num_of_edma_ch + 1;

	/* allocate device memory for external transfers */
	dma_common.external_dma_device_addr =
			hltests_allocate_device_mem(fd,
				external_data.transfer_size, 0, NOT_CONTIGUOUS);
	assert_non_null(dma_common.external_dma_device_addr);

	/* Setup CB for down PDMA0 which will control the internal jobs and do
	 * the host to device DMA job
	 */
	external_data.cb_pdma0 = hltests_create_cb(fd, 0x1000, EXTERNAL, 0);
	assert_non_null(external_data.cb_pdma0);

	host_src_ptr = hltests_allocate_host_mem(fd,
					external_data.transfer_size, true);
	assert_non_null(host_src_ptr);
	hltests_fill_rand_values(host_src_ptr, external_data.transfer_size);
	external_data.host_src_addr =
			hltests_get_device_va_for_host_ptr(fd, host_src_ptr);

	set_down_pdma(tests_state, &dma_common);

	/* Setup CB for PDMA1, device to host DMA job */
	external_data.cb_pdma1 = hltests_create_cb(fd, 0x1000, EXTERNAL, 0);
	assert_non_null(external_data.cb_pdma1);

	host_dst_ptr = hltests_allocate_host_mem(fd,
					external_data.transfer_size, true);
	assert_non_null(host_dst_ptr);
	memset(host_dst_ptr, 0, external_data.transfer_size);
	external_data.host_dst_addr =
			hltests_get_device_va_for_host_ptr(fd, host_dst_ptr);

	set_up_pdma(tests_state, &dma_common);

	/* number of CS entries is number of EDMAs + 2 (UP/DOWN PDMA) */
	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, num_of_edma_ch + 2, 0,
				&seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	/* Compare host memories */
	rc = hltests_mem_compare(host_src_ptr, host_dst_ptr,
					external_data.transfer_size);
	assert_int_equal(rc, 0);

	hltests_destroy_cb(fd, external_data.cb_pdma0);
	hltests_destroy_cb(fd, external_data.cb_pdma1);
	for (ch = 0 ; ch < num_of_edma_ch ; ch++) {
		hltests_free_host_mem(fd, internal_data.cp_dma_cb_arr[ch]);
		hltests_free_host_mem(fd, internal_data.lower_cb_arr[ch]);
	}

	hlthunk_free(internal_data.cp_dma_cb_arr);
	hlthunk_free(internal_data.lower_cb_arr);
	hlthunk_free(internal_data.cp_dma_cb_va_arr);
	hlthunk_free(internal_data.lower_cb_va_arr);
	hlthunk_free(execute_arr);
	hltests_free_device_mem(fd, (void *) internal_data.dram_addr);

	rc = hltests_free_device_mem(fd, dma_common.external_dma_device_addr);
	assert_int_equal(rc, 0);
	rc = hltests_free_host_mem(fd, host_src_ptr);
	assert_int_equal(rc, 0);
	rc = hltests_free_host_mem(fd, host_dst_ptr);
	assert_int_equal(rc, 0);

	END_TEST;
}

VOID test_dma_all2all_dram2sram(void **state)
{
	END_TEST_FUNC(dma_all2all(state, DRAM_TO_SRAM));
}

VOID test_dma_all2all_dram2dram(void **state)
{
	END_TEST_FUNC(dma_all2all(state, DRAM_TO_DRAM));
}

VOID test_dma_all2all_sram2sram(void **state)
{
	END_TEST_FUNC(dma_all2all(state, SRAM_TO_SRAM));
}

#ifndef HLTESTS_LIB_MODE

const struct CMUnitTest gaudi2_dma_tests[] = {
	cmocka_unit_test_setup(test_dma_all2all_dram2sram,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_all2all_dram2dram,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_all2all_sram2sram,
				hltests_ensure_device_operational)
};

static const char *const usage[] = {
	"gaudi2_dma [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = sizeof(gaudi2_dma_tests) / sizeof((gaudi2_dma_tests)[0]);

	hltests_parser(argc, argv, usage, HLTEST_DEVICE_MASK_GAUDI2,
			gaudi2_dma_tests, num_tests);

	return hltests_run_group_tests("gaudi2_dma", gaudi2_dma_tests, num_tests,
					hltests_setup, hltests_teardown);
}

#endif /* HLTESTS_LIB_MODE */
