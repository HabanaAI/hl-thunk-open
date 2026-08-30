// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_tests.h"

#include <stdio.h>
#include <unistd.h>

#define MAX_DMA_CH 8
#define LIN_DMA_PKT_SIZE 24

enum all2all_dma_engine {
	ALL2ALL_EDMA,
	ALL2ALL_MME_DMA,
};

enum all2all_dma_type {
	DRAM_SRAM,
	DRAM_DRAM,
	SRAM_SRAM
};

/**
 * struct all2all_dma_transfer - holds info of one dma transfer
 * @addr0: first dma address (either to/from, can be decided on runtime)
 * @addr1: second dma address (either to/from, can be decided on runtime)
 * @size: size of dma
 */

struct all2all_dma_transfer {
	uint64_t addr0;
	uint64_t addr1;
	uint32_t size;
};

/**
 * struct all2all_dma_internal - holds info of an internal dma operations (either edma or mme dma)
 * @all2all_dma_engine: the type of engine (mme or edma)
 * @cp_dma_cb_arr: (only for legacy code) the array of cb mem to dma to lower cp
 * @lower_cb_arr: the array of command buffers of the dma internal operations
 * @dram_addr: the dram address to use for all internal dma operations
 * @dma_dram_size: the dram size of the allocated dram_addr
 * @dma_ch_size_alignment: the alignment of the dma size per dma channel.
 * @num_of_dma_ch: number of channels
 * @mon_triggered_internal_base: each channel has a monitor waiting on 'sob_trigger_internal'
 *    so that they all start together. This is the base index for those monitors.
 * @execute_arr: the execute array of the command cs to be filled
 */
struct all2all_dma_internal {
	enum all2all_dma_engine engine;
	void **cp_dma_cb_arr;
	void **lower_cb_arr;
	uint64_t dram_addr;
	uint64_t dma_dram_size;
	uint32_t dma_ch_size_alignment;
	int num_of_dma_ch;
	uint16_t mon_triggered_internal_base;
	struct hltests_cs_chunk *execute_arr;
};

/**
 * struct down_up_pdma_dma - hold info for both down and up 'external' dma (pdma).
 *		we do down pdma host(src)->dram, then up pdam dram->host(dst) and then compare
 *		host(src) and host(dst).
 * @cb_pdma0: the cb for down pdma
 * @cb_pdma1: the cb for up pdma
 * @host_src_addr: the host src address (for down dma)
 * @host_dst_addr: the host dst address (for up dma)
 * @transfer_size: the size of the dma operations
 * @dma_device_addr: the dram address for the dma operations (same for up and down)
 * @sob_notify_down_pdma_complete: sob to notify that pdma down is completed and pdma up can start
 * @mon_down_pdma_complete: mon to sync up dma to start after down dma finishes
 * @down_pdma_exec: the pointer into the place in the execution array of the down dma command buffer
 * @up_pdma_exec: the pointer into the place in the execution array of the up dma command buffer
 */
struct down_up_pdma_dma {
	void *cb_pdma0;
	void *cb_pdma1;
	uint64_t host_src_addr;
	uint64_t host_dst_addr;
	uint32_t transfer_size;
	void *dma_device_addr;
	uint16_t sob_notify_down_pdma_complete;
	uint16_t mon_down_pdma_complete;
	struct hltests_cs_chunk *down_pdma_exec;
	struct hltests_cs_chunk *up_pdma_exec;
};

struct all2all_dma {
	int num_of_internal_dma; /* for guadi2 it's #(edma), for gaudi3 it's #(edma) + #(mme-dma) */
	uint16_t sob_trigger_internal;
	uint16_t sob_notify_internal_complete;
	uint16_t monitor_internal_complete;
};

static VOID get_dram2sram_transfer_data(int fd, unsigned int ch, uint64_t dram_addr,
		uint64_t dram_ch_size, uint64_t sram_addr, uint32_t sram_size,
		uint32_t sram_ch_size, struct all2all_dma_transfer *data)
{
	uint64_t rand_off;

	data->size = sram_ch_size;
	assert_true(dram_ch_size > data->size);
	rand_off = hltests_rand_u32() % (dram_ch_size - data->size);
	if (hltests_get_verbose_enabled())
		printf("DRAM rand offset: %lx\n", rand_off);

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
		hltests_zero_dram_memory(fd, data->addr1, data->size);

	END_TEST;
}

static VOID get_dram2dram_transfer_data(int fd, unsigned int ch, uint64_t dram_addr,
				uint64_t dram_ch_size, struct all2all_dma_transfer *data)
{
	int verbose = hltests_get_verbose_enabled();
	bool is_pldm = hltests_is_pldm(fd);
	uint64_t src_addr;
	uint32_t rand_off, pldm_size_diff = 0;

	/* divide the number of dram channels by 2 as each dma now operates on
	 * two areas
	 */
	dram_ch_size /= 2;
	assert_true(dram_ch_size <= UINT32_MAX);
	data->size = (uint32_t)dram_ch_size;

	/* in pldm reduce transfer to 6MB each */
	if (is_pldm && dram_ch_size > SZ_1M * 6) {
		data->size = SZ_1M * 6;
		pldm_size_diff = (uint32_t)dram_ch_size - data->size;
	}

	/* each dma will copy data from the first half of a dram channel
	 * (prior to the division by 2) to the second half, or vice versa.
	 */
	data->addr0 = dram_addr + (2 * ch) * dram_ch_size;

	/* in case of pldm, we also add a random offset as possible */
	if (is_pldm && pldm_size_diff != 0) {
		rand_off = hltests_rand_u32() % pldm_size_diff;
		if (verbose)
			printf("DRAM address 0 rand offset: 0x%x\n", rand_off);
		data->addr0 += rand_off;
	}
	data->addr0 = ALIGN_UP(data->addr0, 128);

	data->addr1 = dram_addr + (2 * ch + 1) * dram_ch_size;
	if (is_pldm && pldm_size_diff != 0) {
		rand_off = hltests_rand_u32() % pldm_size_diff;
		if (verbose)
			printf("DRAM address 1 rand offset: 0x%x\n", rand_off);
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
		hltests_zero_dram_memory(fd, src_addr, data->size);

	END_TEST;
}

static VOID get_sram2sram_transfer_data(unsigned int ch, uint64_t sram_addr,
		uint32_t sram_size, uint32_t sram_ch_size,
		struct all2all_dma_transfer *data)
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

static VOID free_internal_data(int fd, struct all2all_dma_internal *internal_data,
			int num_of_dma_ch)
{
	int ch, rc;

	for (ch = 0 ; ch < num_of_dma_ch ; ch++) {
		if (hltests_is_legacy_mode_enabled(fd)) {
			rc = hltests_free_host_mem(fd, internal_data->cp_dma_cb_arr[ch]);
			assert_int_equal(rc, 0);
			rc = hltests_free_host_mem(fd, internal_data->lower_cb_arr[ch]);
		} else {
			rc = hltests_destroy_cb(fd, internal_data->lower_cb_arr[ch]);
		}
		assert_int_equal(rc, 0);
	}

	hlthunk_free(internal_data->cp_dma_cb_arr);
	hlthunk_free(internal_data->lower_cb_arr);
	rc = hltests_free_device_mem(fd, (void *) internal_data->dram_addr);
	assert_int_equal(rc, 0);
	END_TEST;
}

/*
 * This function is called to set internal dma, (either MME DMA or EDMA) and does:
 * - allocate cb and memory
 * - fill cb with:
 * 1. wait for sync sob for all internal dma
 * 2. the dma commands
 * 3. increcemnt a sob to indicate engine is done
 * 4. fills execute_arr with the command buffers.
 */
static VOID set_internal_dma_jobs(struct hltests_state *tests_state,
				struct all2all_dma *dma_common,
				struct all2all_dma_internal *internal_data,
				enum all2all_dma_type dma_type)
{
	uint32_t lower_cb_offset = 0, cp_dma_cb_offset = 0, queue_index = 0,
			sram_ch_size, sram_size, dma_ch_size_alignment;
	uint64_t sram_addr, dram_ch_size, dram_addr, int_src_addr, int_dst_addr,
			internal_dma_dram_size;
	enum all2all_dma_engine engine_type = internal_data->engine;
	struct hltests_monitor_and_fence mon_and_fence_info;
	struct all2all_dma_transfer transfer_data = {0};
	uint16_t num_of_dma_ch, ch;
	int i, num_of_lindma_pkts, fd;
	struct hltests_cs_chunk *execute_arr;
	struct hlthunk_hw_ip_info *hw_ip;
	struct hltests_pkt_info pkt_info;
	void **lower_cb, **cp_dma_cb;
	bool is_simulator, is_pldm;
	uint8_t mme_id = UINT8_MAX; /* mme_id is incremented to the next enabled mme idx */

	fd = tests_state->fd;
	is_simulator = hltests_is_simulator(fd);
	is_pldm = hltests_is_pldm(fd);

	hw_ip = &tests_state->hw_ip;
	assert_in_range(internal_data->num_of_dma_ch, 1, UINT16_MAX);
	num_of_dma_ch = (uint16_t)internal_data->num_of_dma_ch;
	execute_arr = internal_data->execute_arr;

	internal_data->dram_addr = (uint64_t) (uintptr_t)
			hltests_allocate_device_mem(fd, internal_data->dma_dram_size, 0,
							NOT_CONTIGUOUS);
	assert_non_null(internal_data->dram_addr);

	internal_data->cp_dma_cb_arr = hlthunk_malloc(num_of_dma_ch * sizeof(void *));
	assert_non_null(internal_data->cp_dma_cb_arr);

	internal_data->lower_cb_arr = hlthunk_malloc(num_of_dma_ch * sizeof(void *));
	assert_non_null(internal_data->lower_cb_arr);

	/*
	 * this controls how many times each dma will copy data
	 * as DRAM2DRAM fails with high amount of lindma packet- set
	 * it for now at lower number
	 */
	if (is_simulator || is_pldm)
		num_of_lindma_pkts = 5;
	else
		num_of_lindma_pkts = (dma_type == DRAM_DRAM) ? 500 : 60000;

	dram_addr = internal_data->dram_addr;
	internal_dma_dram_size = internal_data->dma_dram_size;

	cp_dma_cb = internal_data->cp_dma_cb_arr;
	lower_cb = internal_data->lower_cb_arr;

	/*
	 * The 'dram_ch_size' is divided further by 2 in some of the transfer_data() functions.
	 * Compensate it by multiplying the alignment value by 2.
	 */
	dma_ch_size_alignment = internal_data->dma_ch_size_alignment * 2;

	dram_ch_size = ALIGN_DOWN(internal_dma_dram_size / num_of_dma_ch, dma_ch_size_alignment);

	for (ch = 0 ; ch < num_of_dma_ch ; ch++) {
		switch (engine_type) {
		case ALL2ALL_EDMA:
			queue_index = hltests_get_ddma_qid(fd, (int)ch, STREAM0);
			break;
		case ALL2ALL_MME_DMA:
			/* iterate to the next valid mme_id */
			do {
				mme_id++;
			} while (!(hw_ip->mme_enabled_mask & BIT_ULL(mme_id)));

			queue_index = hltests_get_mme_qid(fd, mme_id, 0);
			break;
		default:
			fail();
			break;
		}

		switch (dma_type) {
		case DRAM_SRAM:
		case SRAM_SRAM:
			sram_addr = hw_ip->sram_base_address;
			sram_size = hw_ip->sram_size;
			assert_in_range(sram_size, 1, hw_ip->dram_size);
			sram_ch_size = ALIGN_DOWN(sram_size / num_of_dma_ch, 128);

			if (DRAM_SRAM)
				CALL_HELPER_FUNC(get_dram2sram_transfer_data(fd, ch, dram_addr,
						dram_ch_size, sram_addr, sram_size, sram_ch_size,
						&transfer_data));
			else
				CALL_HELPER_FUNC(get_sram2sram_transfer_data(ch, sram_addr,
							sram_size, sram_ch_size, &transfer_data));
			break;
		case DRAM_DRAM:
			CALL_HELPER_FUNC(
				get_dram2dram_transfer_data(fd, ch, dram_addr,
							dram_ch_size, &transfer_data));
			break;
		default:
			fail();
		}

		if (ch & 1) {
			int_src_addr = transfer_data.addr0;
			int_dst_addr = transfer_data.addr1;
		} else {
			int_src_addr = transfer_data.addr1;
			int_dst_addr = transfer_data.addr0;
		}

		if (hltests_is_legacy_mode_enabled(fd)) {
			lower_cb[ch] = hltests_allocate_host_mem(fd,
					(uint64_t)(num_of_lindma_pkts + 10) * LIN_DMA_PKT_SIZE,
					NOT_HUGE_MAP);

		} else if (internal_data->engine == ALL2ALL_EDMA) {
			lower_cb[ch] =
				hltests_create_cb(fd, (uint32_t)((num_of_lindma_pkts + 10) *
								  LIN_DMA_PKT_SIZE) * 2,
						  EXTERNAL, 0);
		} else /* MME DMA */ {
			uint32_t alloc_size = hltests_get_mme_dma_cb_size(fd, num_of_lindma_pkts,
								transfer_data.size);

			lower_cb[ch] = hltests_create_cb(fd, alloc_size, EXTERNAL, 0);
		}

		assert_non_null(lower_cb[ch]);

		/* wait for sync from PDMA0 to start internal DMAs */
		memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
		mon_and_fence_info.queue_id = u8_safe(queue_index);
		mon_and_fence_info.cmdq_fence = true;
		mon_and_fence_info.sob_id = dma_common->sob_trigger_internal;
		mon_and_fence_info.mon_id = internal_data->mon_triggered_internal_base + ch;
		mon_and_fence_info.mon_address = 0;
		mon_and_fence_info.sob_val = 1;
		mon_and_fence_info.dec_fence = true;
		mon_and_fence_info.mon_payload = 1;
		mon_and_fence_info.mon_mode = SOB_EQUAL;
		lower_cb_offset = hltests_add_monitor_and_fence(fd,
					lower_cb[ch], 0, &mon_and_fence_info);

		switch (internal_data->engine) {
		case ALL2ALL_EDMA:
			/* prepare DMA packet */
			memset(&pkt_info, 0, sizeof(pkt_info));
			pkt_info.qid = queue_index;
			pkt_info.eb = EB_FALSE;
			pkt_info.mb = MB_FALSE;
			pkt_info.dma.src_addr = int_src_addr;
			pkt_info.dma.dst_addr = int_dst_addr;
			pkt_info.dma.size = transfer_data.size;

			/* concatenate number of DMA packets */
			for (i = 0 ; i < num_of_lindma_pkts ; i++)
				lower_cb_offset = hltests_add_dma_pkt(fd, lower_cb[ch],
							lower_cb_offset, &pkt_info);
			break;
		case ALL2ALL_MME_DMA:
			for (i = 0 ; i < num_of_lindma_pkts ; i++)
				lower_cb_offset = hltests_prepare_mme_dma_req(fd, lower_cb[ch],
									lower_cb_offset,
									int_src_addr, int_dst_addr,
									mme_id, transfer_data.size);
			break;
		default:
			fail();
			break;
		}

		/* signal PDMA1 that DMA job completed */
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.qid = queue_index;
		pkt_info.eb = EB_TRUE;
		pkt_info.mb = MB_TRUE;
		pkt_info.write_to_sob.sob_id =
					dma_common->sob_notify_internal_complete;
		pkt_info.write_to_sob.value = 1;
		pkt_info.write_to_sob.mode = SOB_ADD;
		lower_cb_offset = hltests_add_write_to_sob_pkt(fd, lower_cb[ch],
						lower_cb_offset, &pkt_info);

		if (hltests_is_legacy_mode_enabled(fd)) {
			/* Setup upper CB for internal DMA engine (cp_dma) */
			cp_dma_cb[ch] = hltests_allocate_host_mem(fd, 0x1000, NOT_HUGE_MAP);
			assert_non_null(cp_dma_cb[ch]);

			memset(&pkt_info, 0, sizeof(pkt_info));
			pkt_info.eb = EB_FALSE;
			pkt_info.mb = MB_FALSE;
			pkt_info.cp_dma.src_addr = hltests_get_device_va_for_host_ptr(fd,
									lower_cb[ch]);
			pkt_info.cp_dma.size = lower_cb_offset;
			cp_dma_cb_offset = hltests_add_cp_dma_pkt(fd, cp_dma_cb[ch],
									0, &pkt_info);

			execute_arr[ch].cb_ptr = (void *) hltests_get_device_va_for_host_ptr(fd,
							cp_dma_cb[ch]);
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
		struct down_up_pdma_dma *external_data,
		struct all2all_dma *dma_common)
{
	struct hltests_pkt_info pkt_info;
	uint32_t down_qid, cb_offset = 0;
	uint64_t host_src_addr;
	void *cb;
	int fd;

	fd = tests_state->fd;
	down_qid = hltests_get_dma_down_qid(fd, STREAM0);

	cb = external_data->cb_pdma0;
	host_src_addr = external_data->host_src_addr;

	/* signal EDMA channels they can start executing */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = down_qid;
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id = dma_common->sob_trigger_internal;
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_SET;
	cb_offset = hltests_add_write_to_sob_pkt(fd, cb, 0, &pkt_info);

	/* while EDMAs are executing internal jobs, start the down DMA job */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = down_qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.dma.src_addr = host_src_addr;
	pkt_info.dma.dst_addr = (uint64_t) (uintptr_t) external_data->dma_device_addr;
	pkt_info.dma.size = external_data->transfer_size;
	cb_offset = hltests_add_dma_pkt(fd, cb, cb_offset, &pkt_info);

	/* signal to PDMA1 it can start working */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = down_qid;
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.mode = SOB_ADD;
	pkt_info.write_to_sob.sob_id = external_data->sob_notify_down_pdma_complete;
	pkt_info.write_to_sob.value = 1;
	cb_offset = hltests_add_write_to_sob_pkt(fd, cb, cb_offset, &pkt_info);

	external_data->down_pdma_exec->cb_ptr = cb;
	external_data->down_pdma_exec->cb_size = cb_offset;
	external_data->down_pdma_exec->queue_index = down_qid;
}

static void set_up_pdma(struct hltests_state *tests_state,
		struct down_up_pdma_dma *external_data,
		struct all2all_dma *dma_common)
{
	struct hltests_monitor_and_fence mon_and_fence_info;
	struct hltests_pkt_info pkt_info;
	uint32_t up_qid, cb_offset = 0;
	int fd;
	uint64_t  host_dst_addr, num_of_internal_ch;
	void *cb;

	fd = tests_state->fd;
	assert_true_ret(dma_common->num_of_internal_dma > 0);
	num_of_internal_ch = (uint64_t)dma_common->num_of_internal_dma;
	up_qid = hltests_get_dma_up_qid(fd, STREAM0);

	cb = external_data->cb_pdma1;
	host_dst_addr = external_data->host_dst_addr;

	/* Add monitor to wait for PDMA0 to finish the down DMA job */
	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = u8_safe_ret(up_qid);
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = external_data->sob_notify_down_pdma_complete;
	mon_and_fence_info.mon_id = external_data->mon_down_pdma_complete;
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.sob_val = 1;
	mon_and_fence_info.dec_fence = true;
	mon_and_fence_info.mon_payload = 1;
	mon_and_fence_info.mon_mode = SOB_EQUAL;
	cb_offset = hltests_add_monitor_and_fence(fd, cb, cb_offset,
						&mon_and_fence_info);

	/* while EDMAs are executing internal jobs, start the up DMA job */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = up_qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.dma.src_addr = (uint64_t) (uintptr_t) external_data->dma_device_addr;
	pkt_info.dma.dst_addr = host_dst_addr;
	pkt_info.dma.size = external_data->transfer_size;
	cb_offset = hltests_add_dma_pkt(fd, cb, cb_offset, &pkt_info);

	/* Wait for EDMA channels and PDMA1 to announce they finished */
	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = u8_safe_ret(up_qid);
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = dma_common->sob_notify_internal_complete;
	mon_and_fence_info.mon_id = dma_common->monitor_internal_complete;
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.sob_val = num_of_internal_ch;
	mon_and_fence_info.dec_fence = true;
	mon_and_fence_info.mon_payload = 1;
	mon_and_fence_info.mon_mode = SOB_EQUAL;
	cb_offset = hltests_add_monitor_and_fence(fd, cb, cb_offset,
						&mon_and_fence_info);

	external_data->up_pdma_exec->cb_ptr = cb;
	external_data->up_pdma_exec->cb_size = cb_offset;
	external_data->up_pdma_exec->queue_index = up_qid;
}

static VOID dma_all2all(struct hltests_state *tests_state, enum all2all_dma_type dma_type)
{
	struct all2all_dma_internal edma_data = {0}, mme_dma_data = {0};
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;
	struct hltests_cs_chunk *execute_arr, *execute_arr_ptr;
	uint32_t num_of_internal_dma = 0;
	int rc, fd = tests_state->fd;
	uint64_t dma_size_per_engine_grp, seq = 0,
		num_of_engine_group_types = 1; /* pdma always exist so this is at least 1 */
	uint16_t sob0, mon0, mon_triggered_internal_base, num_of_mme_ch = 0;
	struct down_up_pdma_dma external_data;
	struct all2all_dma dma_common = { 0 };
	void *host_src_ptr, *host_dst_ptr;
	int i;
	bool mme_exist, edma_exist;
	uint32_t transfer_size;
	uint8_t num_of_edma_ch;

	if (hltests_get_parser_mini_suite())
		skip();

	transfer_size = hltests_is_pldm(fd) || hltests_is_simulator(fd) ? SZ_1M : SZ_32M;

	if (hltests_is_pldm(fd) && transfer_size > PLDM_MAX_DMA_SIZE_FOR_TESTING)
		skip();

	if (!hw_ip->dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	if (hltests_is_simulator(fd) && hw_ip->dram_size < (SZ_128M)) {
		printf("SIM's DRAM (%lu[B]) is smaller than min requirments (%u[B]) - skip\n",
			hw_ip->dram_size, SZ_128M);
		skip();
	}

	if (hltests_is_gaudi2(fd)) {
		printf("EDMA is blocked from accessing the PCIe in Gaudi2\n");
		skip();
	}

	mme_exist = hltests_is_mme_dma_enabled(fd);

	/* TODO - remove skip for GAUDI3D once SW-219441 is resolved */
	if (hltests_is_gaudi3d(fd))
		mme_exist = false;

	if (mme_exist) {
		uint32_t max_mme_cnt = hltests_get_mme_cnt(fd, hw_ip->mme_master_slave_mode);

		for (i = 0 ; i < max_mme_cnt ; i++)
			if (hw_ip->mme_enabled_mask & BIT_ULL(i))
				num_of_mme_ch++;
		num_of_internal_dma += num_of_mme_ch;
		num_of_engine_group_types++;
	}

	num_of_edma_ch = hltests_get_ddma_cnt(fd);
	edma_exist = num_of_edma_ch;
	if (!edma_exist && !mme_exist) {
		printf("no edma and no mme - skip\n");
		skip();
	}

	if (edma_exist) {
		assert_in_range(num_of_edma_ch, 1, MAX_DMA_CH);
		num_of_internal_dma += num_of_edma_ch;
		num_of_engine_group_types++;
	}

	/* split DRAM equally between all engine groups */
	dma_size_per_engine_grp = ALIGN_DOWN(hw_ip->dram_size / num_of_engine_group_types, 8);

	 /* In sim/pldm this is performance intensive, and will timeout if dma size is too big */
	if (hltests_is_simulator(fd) || hltests_is_pldm(fd))
		dma_size_per_engine_grp = MIN(dma_size_per_engine_grp, 32ULL * SZ_1M);

	/* we are allocating one exec entry per DMA + 2: UP and DOWN PDMAs */
	execute_arr = hlthunk_malloc((num_of_internal_dma + 2) * sizeof(struct hltests_cs_chunk));
	assert_non_null(execute_arr);
	execute_arr_ptr = execute_arr;

	sob0 = hltests_get_first_avail_sob(fd);
	mon0 = hltests_get_first_avail_mon(fd);

	/* Clear SOB before we start */
	hltests_clear_sobs(fd, 3);

	assert_true(num_of_internal_dma <= INT_MAX);
	dma_common.num_of_internal_dma = (int)num_of_internal_dma;
	dma_common.sob_notify_internal_complete = sob0 + 0;
	dma_common.monitor_internal_complete = mon0 + 0;

	dma_common.sob_trigger_internal = sob0 + 2;
	mon_triggered_internal_base = mon0 + 2;
	if (edma_exist) {
		edma_data.mon_triggered_internal_base = mon_triggered_internal_base;
		mon_triggered_internal_base += num_of_edma_ch;
		edma_data.dma_dram_size = dma_size_per_engine_grp;
		edma_data.dma_ch_size_alignment = 128;
		edma_data.num_of_dma_ch  = num_of_edma_ch;
		edma_data.engine = ALL2ALL_EDMA;
		edma_data.execute_arr = execute_arr_ptr;
		execute_arr_ptr += num_of_edma_ch;
		/* prepare internal (DRAM<->SRAM / DRAM<->DRAM) jobs */
		CALL_HELPER_FUNC(set_internal_dma_jobs(tests_state, &dma_common, &edma_data,
							dma_type));
	}

	if (mme_exist) {
		mme_dma_data.mon_triggered_internal_base = mon_triggered_internal_base;
		mon_triggered_internal_base += num_of_mme_ch;
		mme_dma_data.dma_dram_size = dma_size_per_engine_grp;
		mme_dma_data.dma_ch_size_alignment = MME_DMA_SIZE;
		mme_dma_data.num_of_dma_ch = num_of_mme_ch;
		mme_dma_data.engine = ALL2ALL_MME_DMA;
		mme_dma_data.execute_arr = execute_arr_ptr;
		execute_arr_ptr += num_of_mme_ch;
		/* prepare internal (DRAM<->DRAM MME DMA) jobs */
		CALL_HELPER_FUNC(set_internal_dma_jobs(tests_state, &dma_common, &mme_dma_data,
							dma_type));
	}

	external_data.sob_notify_down_pdma_complete = sob0 + 1;
	external_data.mon_down_pdma_complete = mon0 + 1;

	external_data.transfer_size = transfer_size;
	external_data.down_pdma_exec = execute_arr_ptr++;
	external_data.up_pdma_exec = execute_arr_ptr++;

	/* allocate device memory for external transfers */
	external_data.dma_device_addr = hltests_allocate_device_mem(fd,
				external_data.transfer_size, 0, NOT_CONTIGUOUS);
	assert_non_null(external_data.dma_device_addr);

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

	set_down_pdma(tests_state, &external_data, &dma_common);

	/* Setup CB for PDMA1, device to host DMA job */
	external_data.cb_pdma1 = hltests_create_cb(fd, 0x1000, EXTERNAL, 0);
	assert_non_null(external_data.cb_pdma1);

	host_dst_ptr = hltests_allocate_host_mem(fd,
					external_data.transfer_size, true);
	assert_non_null(host_dst_ptr);
	memset(host_dst_ptr, 0, external_data.transfer_size);
	external_data.host_dst_addr =
			hltests_get_device_va_for_host_ptr(fd, host_dst_ptr);

	set_up_pdma(tests_state, &external_data, &dma_common);

	/* number of CS entries is number of EDMAs + 2 (UP/DOWN PDMA) */
	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, num_of_internal_dma + 2, 0, &seq);
	assert_int_equal(rc, 0);
	if (hltests_is_pldm(fd) || hltests_is_simulator(fd))
		rc = hltests_wait_for_cs(fd, seq, 10 * TIME_1_MIN_IN_USEC);
	else
		rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	/* Compare host memories */
	rc = hltests_mem_compare(host_src_ptr, host_dst_ptr,
					external_data.transfer_size);
	assert_int_equal(rc, 0);

	rc = hltests_destroy_cb(fd, external_data.cb_pdma0);
	assert_int_equal(rc, 0);
	rc = hltests_destroy_cb(fd, external_data.cb_pdma1);
	assert_int_equal(rc, 0);

	if (edma_exist)
		free_internal_data(fd, &edma_data, num_of_edma_ch);
	if (mme_exist)
		free_internal_data(fd, &mme_dma_data, num_of_mme_ch);
	hlthunk_free(execute_arr);

	rc = hltests_free_device_mem(fd, external_data.dma_device_addr);
	assert_int_equal(rc, 0);
	rc = hltests_free_host_mem(fd, host_src_ptr);
	assert_int_equal(rc, 0);
	rc = hltests_free_host_mem(fd, host_dst_ptr);
	assert_int_equal(rc, 0);

	END_TEST;
}

VOID test_dma_all2all_dram2sram(void **state)
{
	struct hltests_state *tests_state = *state;
	int fd = tests_state->fd;

	if (hltests_is_gaudi3(fd)) {
		printf("skip sram<->dram tests for gaudi3\n");
		skip();
	}

	if (!tests_state->hw_ip.sram_size)
		skip();

	END_TEST_FUNC(dma_all2all(tests_state, DRAM_SRAM));
}

VOID test_dma_all2all_dram2dram(void **state)
{
	struct hltests_state *tests_state = *state;

	END_TEST_FUNC(dma_all2all(tests_state, DRAM_DRAM));
}

VOID test_dma_all2all_sram2sram(void **state)
{
	struct hltests_state *tests_state = *state;

	if (!tests_state->hw_ip.sram_size)
		skip();

	END_TEST_FUNC(dma_all2all(tests_state, SRAM_SRAM));
}

#ifndef HLTESTS_LIB_MODE

const struct CMUnitTest all2all_dma_tests[] = {
	cmocka_unit_test_setup(test_dma_all2all_dram2sram,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_all2all_dram2dram,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_all2all_sram2sram,
				hltests_ensure_device_operational)
};

static const char *const usage[] = {
	"dma_all2all [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	size_t num_tests = ARRAY_SIZE(all2all_dma_tests);

	hltests_parser(argc, argv, usage,
			HLTEST_DEVICE_MASK_GAUDI2_ALL | HLTEST_DEVICE_MASK_GAUDI3_ALL,
			all2all_dma_tests, (int)num_tests);

	hltests_set_capabilities_mask(CAP_ARC_FW_LOAD_SCHED_MASK |
				CAP_ARC_FW_LOAD_PDMA_MASK |
				CAP_ARC_FW_LOAD_EDMA_MASK |
				CAP_ARC_FW_LOAD_MME_MASK |
				CAP_MME_DMA_MASK);

	return hltests_run_group_tests("dma_all2all", all2all_dma_tests, num_tests,
					hltests_setup, hltests_teardown);
}

#endif /* HLTESTS_LIB_MODE */
