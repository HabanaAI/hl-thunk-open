// SPDX-License-Identifier: MIT

/*
 * Copyright 2022 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_tests.h"
#include "engines-arc/common/include/arc_sched_packets.h"
#include "engines-arc/common/include/arc_host_packets.h"

#include <stdio.h>
#include <errno.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <linux/mman.h>
#include <time.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <byteswap.h>
#include <immintrin.h>

struct fw_load_hbm_offset {
	uint32_t offset;
};

void *hltests_arc_get_log_buf_ci_addr(uint32_t cpu_id,
				struct hltests_arc_db *arc_db)
{
	struct arc_fw_info *fw_info = &arc_db->fw_info[cpu_id];
	uint32_t log_buf_ci_offset;

	log_buf_ci_offset = offsetof(struct common_arc_reg_t, log_buf_ci);
	return fw_info->dccm_host_addr + log_buf_ci_offset;
}

void *hltests_arc_get_asic_model_addr(uint32_t cpu_id,
				struct hltests_arc_db *arc_db)
{
	struct arc_fw_info *fw_info = &arc_db->fw_info[cpu_id];
	uint32_t asic_model_offset;

	asic_model_offset = offsetof(struct common_arc_reg_t, asic_model);
	return fw_info->dccm_host_addr + asic_model_offset;
}

void *hltests_arc_get_canary_addr(uint32_t cpu_id,
				struct hltests_arc_db *arc_db)
{
	struct arc_fw_info *fw_info = &arc_db->fw_info[cpu_id];
	uint32_t canary_offset;

	canary_offset = offsetof(struct common_arc_reg_t, canary);
	return fw_info->dccm_host_addr + canary_offset;
}

#define MIN_HBM_SIZE SZ_64K

static void _hltests_arc_unmap_lbw_blocks(struct hltests_device *hdev,
				uint32_t cpu_id, struct hltests_arc_db *arc_db)
{
	struct arc_fw_info *fw_info = &arc_db->fw_info[cpu_id];
	int fd = hdev->fd;

	if (cpu_id < hdev->asic_funcs->arc_get_num_schedulers())
		hltests_unmap_hw_block(fd, fw_info->acp_host_addr,
					fw_info->acp_size);

	hltests_unmap_hw_block(fd, fw_info->dccm_host_addr,
				fw_info->dccm_size);
}

static void hltests_arc_unmap_lbw_blocks(struct hltests_device *hdev,
					struct hltests_arc_db *arc_db)
{
	uint32_t arcs_num;
	int i;

	arcs_num = hdev->asic_funcs->arc_get_max_cpuid();

	for (i = 0 ; i < arcs_num ; i++)
		if (arc_db->fw_info[i].enabled)
			_hltests_arc_unmap_lbw_blocks(hdev, i, arc_db);
}

int hltests_arc_add_arc_config(int fd, struct hltests_arc_db *arc_db, void *cfg,
		size_t config_sz, void *cb, uint32_t cb_size, uint32_t cpu_id, uint64_t base,
		uint64_t config_addr_offset, uint64_t config_size_offset, uint64_t arc_pci_reg,
		uint32_t qid)
{
	uint8_t *host_mem;
	uint64_t host_device_va, log_device_va;
	struct hltests_pkt_info pkt_info;
	struct common_config_t *common_cfg = cfg; /* upcast to the common cfg */

	host_mem = (uint8_t *) arc_db->host_mem + arc_db->host_mem_reserved_size;
	host_device_va = arc_db->host_device_va + arc_db->host_mem_reserved_size;
	arc_db->host_mem_reserved_size += config_sz;

	if (hltests_get_parser_enable_arc_log()) {
		common_cfg->log_enabled = true;
		log_device_va = arc_db->host_device_va + arc_db->host_mem_reserved_size;
		arc_db->arc_log_bufs[cpu_id].ptr = (char *) arc_db->host_mem +
						arc_db->host_mem_reserved_size;
		arc_db->host_mem_reserved_size += ARC_LOG_BUF_SIZE;

		common_cfg->log_arc_va = ARC_BUILD_ADDR(arc_pci_reg, log_device_va);
		common_cfg->log_size = ARC_LOG_BUF_SIZE;
	} else {
		common_cfg->log_enabled = false;
	}

	common_cfg->version = ARC_FW_INIT_CONFIG_VER;
	memcpy(host_mem, cfg, config_sz);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.msg_long.address = base + config_addr_offset;
	pkt_info.msg_long.value = ARC_BUILD_ADDR(arc_pci_reg, host_device_va);
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.msg_long.address = base + config_size_offset;
	pkt_info.msg_long.value = config_sz;
	return hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);
}

static void hltests_arc_memory_free(struct hltests_device *hdev, struct hltests_arc_db *arc_db)
{
	int fd = hdev->fd;

	hlthunk_memory_unmap(fd, arc_db->dram_device_va);
	if (!hdev->sim_dram_on_host)
		hlthunk_device_memory_free(fd, arc_db->device_mem_handle);
	else
		hlthunk_free(arc_db->dram_on_host_mem);
	hlthunk_memory_unmap(fd, arc_db->host_device_va);
	hlthunk_free(arc_db->host_mem);
	if (hltests_get_parser_enable_arc_log())
		hlthunk_free(arc_db->arc_log_bufs);
}

static uint32_t hltests_sim_load_arc_fw(struct hltests_device *hdev,
					struct hltests_arc_db *arc_db, uint32_t *host_ptr,
					uint64_t host_va, uint32_t hbm_offset, bool sched_arc)
{
	char arc_path[ARC_BIN_PATH_MAX_LENGTH];
	int i, first_cpuid, last_cpuid, rc, fd = hdev->fd;
	uint32_t size;

	/* Load arc FW */
	if (sched_arc) {
		snprintf(arc_path, ARC_BIN_PATH_MAX_LENGTH - 1,
				"%s/arc/libscheduler_bfm.so", hltests_get_build_path());

		hdev->asic_funcs->arc_get_sched_cpuid_range(&first_cpuid, &last_cpuid);
	} else {
		snprintf(arc_path, ARC_BIN_PATH_MAX_LENGTH - 1,
				"%s/arc/libengine_bfm.so", hltests_get_build_path());

		hdev->asic_funcs->arc_get_engine_cpuid_range(&first_cpuid, &last_cpuid);
	}

	/* First 4 bytes contain string length */
	*(uint32_t *)host_ptr = strlen(arc_path);
	memcpy((uint32_t *)host_ptr + 1, arc_path, strlen(arc_path));
	size = strlen(arc_path) + sizeof(uint32_t);

	/* Copy length + string to HBM */
	for (i = first_cpuid ; i <= last_cpuid ; i++) {
		if (!arc_db->fw_info[i].enabled)
			continue;

		if (hltests_is_gaudi2(fd)) {
			hltests_dma_transfer_legacy(fd,
						hltests_get_dma_down_qid(fd, STREAM0),
							EB_FALSE, MB_FALSE, host_va,
							arc_db->dram_device_va + hbm_offset,
							size, DMA_DIR_HOST_TO_DRAM);
		} else {
			rc = hltests_dma_transfer(fd,
					hltests_get_dma_down_qid(fd, STREAM0),
						EB_FALSE, MB_FALSE, host_va,
						arc_db->dram_device_va + hbm_offset,
						size, DMA_DIR_HOST_TO_DRAM);
			assert_int_equal(rc, 0);
		}

		arc_db->fw_info[i].hbm_offset = hbm_offset;
		hbm_offset += MAX(size, MIN_HBM_SIZE);
	}

	return hbm_offset;
}

static int hltests_sim_load_fw_to_device(struct hltests_device *hdev,
						struct hltests_arc_db *arc_db)
{
	uint32_t hbm_offset = 0;
	uint64_t host_va;
	int fd = hdev->fd;
	void *host_ptr;

	/* Will hold the binary path + length */
	host_ptr = hltests_allocate_host_mem(fd, ARC_BIN_PATH_MAX_LENGTH + 4, NOT_HUGE_MAP);
	if (!host_ptr)
		return -ENOMEM;

	host_va = hltests_get_device_va_for_host_ptr(fd, host_ptr);

	hbm_offset = hltests_sim_load_arc_fw(hdev, arc_db, host_ptr, host_va,
								hbm_offset, true);
	hbm_offset = hltests_sim_load_arc_fw(hdev, arc_db, host_ptr, host_va,
								hbm_offset, false);

	arc_db->device_mem_reserved_size += hbm_offset;

	hltests_free_host_mem(fd, host_ptr);

	return 0;
}

int hltests_asic_iterate_arcs(struct iterate_arcs_ctx *ctx, enum arc_type_mask arc_type_mask)
{
	struct hltests_arc_db *arc_db = ctx->arc_db;
	uint32_t i, first, last;
	enum arc_type arc_type;

	ctx->rc = 0;

	for (arc_type = ARC_TYPE_SCHED; arc_type < ARC_TYPE_NUM; arc_type++) {
		if (!(BIT(arc_type) & arc_type_mask))
			continue;

		if (arc_type == ARC_TYPE_SCHED) {
			first = ctx->load_param->sched_arc_first_idx;
			last = ctx->load_param->sched_arc_last_idx;
		} else {
			first = ctx->load_param->eng_arc_first_idx;
			last = ctx->load_param->eng_arc_last_idx;
		}

		for (i = first ; i <= last ; i++) {
			if (!arc_db->fw_info[i].enabled)
				continue;

			ctx->fn(ctx, i);
			if (ctx->rc)
				return ctx->rc;
		}
	}

	return 0;
}

static void hltests_asic_load_set_arc_hbm_off(struct iterate_arcs_ctx *ctx, uint32_t cpu_id)
{
	struct fw_load_hbm_offset *hbm_off = ctx->data;

	ctx->arc_db->fw_info[cpu_id].hbm_offset = hbm_off->offset;
	hbm_off->offset += ctx->load_param->arc_image_hbm_size;
}

static int hltest_read_arc_fw_img_to_buffer(char *arc_path, void *img_buf, uint64_t img_size)
{
	size_t ret;
	FILE *fp;

	fp = fopen(arc_path, "rb");
	if (!fp) {
		printf("Failed to open ARC binary file %s\n", arc_path);
		return -ENOENT;
	}

	ret = fread(img_buf, sizeof(uint8_t), img_size, fp);
	fclose(fp);
	if (ret != img_size) {
		printf("Failed to read from ARC binary file %s (ret=%zu)\n", arc_path, ret);
		return -EIO;
	}

	return 0;
}

static int hltests_asic_load_fw_to_device(struct hltests_device *hdev,
						struct iterate_arcs_ctx *ctx,
						const char *buildpath)
{
	struct arc_asic_fw_load_params *load_param;
	struct arc_load_data arc_load_data;
	char arc_path[ARC_BIN_PATH_MAX_LENGTH];
	uint64_t sched_host_va, eng_host_va;
	void *sched_host_ptr, *eng_host_ptr;
	struct fw_load_hbm_offset hbm_off;
	struct hltests_arc_db *arc_db;
	int rc = 0, fd = hdev->fd;

	memset(&arc_load_data, 0, sizeof(struct arc_load_data));
	arc_db = ctx->arc_db;
	load_param = ctx->load_param;

	sched_host_ptr = hltests_allocate_host_mem(fd,
				load_param->sched_arc_image_size, NOT_HUGE_MAP);
	if (!sched_host_ptr)
		return -ENOMEM;

	eng_host_ptr = hltests_allocate_host_mem(fd,
				load_param->eng_arc_image_size, NOT_HUGE_MAP);
	if (!eng_host_ptr) {
		rc = -ENOMEM;
		goto free_sched_ptr;
	}

	sched_host_va = hltests_get_device_va_for_host_ptr(fd, sched_host_ptr);
	eng_host_va = hltests_get_device_va_for_host_ptr(fd, eng_host_ptr);

	/* update HBM offset per ARC */
	hbm_off.offset = 0;
	ctx->data = &hbm_off;
	ctx->fn = hltests_asic_load_set_arc_hbm_off;
	rc = hltests_asic_iterate_arcs(ctx, ARC_TYPE_ALL_MASK);
	if (rc)
		return rc;

	/* Load scheduler arc FW */
	snprintf(arc_path, ARC_BIN_PATH_MAX_LENGTH - 1, "%s/arc/scheduler.bin", buildpath);
	rc = hltest_read_arc_fw_img_to_buffer(arc_path, sched_host_ptr,
						load_param->sched_arc_image_size);
	if (rc)
		goto free_eng_ptr;

	snprintf(arc_path, ARC_BIN_PATH_MAX_LENGTH - 1, "%s/arc/engine.bin", buildpath);
	rc = hltest_read_arc_fw_img_to_buffer(arc_path, eng_host_ptr,
						load_param->eng_arc_image_size);
	if (rc)
		goto free_eng_ptr;

	arc_load_data.fd = fd;
	arc_load_data.sched_img_data.img_host_ptr = sched_host_ptr;
	arc_load_data.sched_img_data.img_host_va = sched_host_va;
	arc_load_data.eng_img_data.img_host_ptr = eng_host_ptr;
	arc_load_data.eng_img_data.img_host_va = eng_host_va;

	/* clear non relevant entries in the context struct */
	ctx->data = &arc_load_data;
	ctx->fn = NULL;

	rc = hdev->asic_funcs->asic_load_fw_to_arcs(ctx);
	if (rc)
		goto free_eng_ptr;

	arc_db->device_mem_reserved_size += hbm_off.offset;

free_eng_ptr:
	hltests_free_host_mem(fd, eng_host_ptr);

free_sched_ptr:
	hltests_free_host_mem(fd, sched_host_ptr);
	return rc;
}

static int hltests_load_fw_to_device(struct hltests_device *hdev, struct iterate_arcs_ctx *ctx)
{
	struct hltests_arc_db *arc_db = ctx->arc_db;
	int rc, fd = hdev->fd;

	if (hltests_is_simulator(fd))
		rc = hltests_sim_load_fw_to_device(hdev, arc_db);
	else
		rc = hltests_asic_load_fw_to_device(hdev, ctx, hltests_get_build_path());

	return rc;
}

static int hltests_allocate_arc_memory(struct hltests_device *hdev,
				struct hltests_arc_db *arc_db)
{
	struct hlthunk_hw_ip_info hw_ip;
	unsigned long long arc_va_start;
	int rc, fd = hdev->fd;
	uint64_t device_va;
	uint32_t arcs_num;

	arcs_num = hdev->asic_funcs->arc_get_max_cpuid();

	arc_db->device_mem_size = SZ_256M;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	if (rc)
		return -EINVAL;

	if (hltests_get_parser_enable_arc_log()) {
		arc_db->arc_log_bufs =
			hlthunk_malloc(arcs_num * sizeof(struct arc_log_buf));

		if (!arc_db->arc_log_bufs)
			return -ENOMEM;
	}

	arc_db->host_mem = aligned_alloc(SZ_4K, SZ_256M);
	if (!arc_db->host_mem) {
		rc = -ENOMEM;
		goto free_log_bufs;
	}

	arc_va_start = hdev->asic_funcs->arc_get_va_range_host_start();

	arc_db->host_device_va =
		hlthunk_host_memory_map(fd, arc_db->host_mem, arc_va_start, SZ_256M);

	if (!arc_db->host_device_va) {
		rc = -ENOMEM;
		goto free_host_mem;
	}

	if (arc_db->host_device_va !=
			arc_va_start) {
		printf("HOST addr %#lx differs from requested %#llx\n",
				arc_db->host_device_va,
				arc_va_start);
		rc = -ENOMEM;
		goto unmap_host_mem;
	}

	if (hdev->sim_dram_on_host) {
		arc_db->dram_on_host_mem = aligned_alloc(SZ_4K, SZ_256M);
		if (!arc_db->dram_on_host_mem) {
			rc = -ENOMEM;
			goto unmap_host_mem;
		}
		/*
		 * Although host_device_va used only 256MB of host memory, because of Coral sim
		 * bug (SW-65053), need to use va with all zeroes in lower 32 bits of address,
		 * hence the offset of 4GB.
		 */
		arc_db->dram_device_va =
			hlthunk_host_memory_map(fd, arc_db->dram_on_host_mem,
					arc_va_start + SZ_4G, SZ_256M);

		if ((arc_va_start + SZ_4G) != arc_db->dram_device_va) {
			printf("DRAM addr %#lx differs from requested %#llx\n",
					arc_db->dram_device_va, arc_va_start + SZ_4G);
			rc = -ENOMEM;
			goto free_host_mem;
		}
	} else {
		arc_db->device_mem_handle =
			hlthunk_device_memory_alloc(fd, SZ_256M, 0, NOT_CONTIGUOUS, false);
		if (!arc_db->device_mem_handle) {
			rc = -ENOMEM;
			goto unmap_host_mem;
		}

		device_va = hdev->asic_funcs->arc_get_va_range_dram_start();

		if ((device_va & ARC_HINT_48BIT_MASK) % hw_ip.device_mem_alloc_default_page_size)
			device_va += 0x100000000000;

		arc_db->dram_device_va = hlthunk_device_memory_map(fd,
				arc_db->device_mem_handle, device_va);

		if (device_va != arc_db->dram_device_va) {
			printf("DRAM addr %#lx differs from requested %#lx\n",
					arc_db->dram_device_va, device_va);
			rc = -ENOMEM;
			goto free_dram_mem;
		}
	}

	arc_db->host_mem_reserved_size = 0;

	return 0;

free_dram_mem:
	if (!hdev->sim_dram_on_host)
		hlthunk_device_memory_free(fd, arc_db->device_mem_handle);
	else
		hlthunk_free(arc_db->dram_on_host_mem);
unmap_host_mem:
	hlthunk_memory_unmap(fd, arc_db->host_device_va);
free_host_mem:
	hlthunk_free(arc_db->host_mem);
free_log_bufs:
	if (hltests_get_parser_enable_arc_log())
		hlthunk_free(arc_db->arc_log_bufs);
	return rc;
}

static int hltests_arc_map_lbw_blocks(struct hltests_device *hdev,
				struct hltests_arc_db *arc_db)
{
	int rc, i, map_lbw_blocks_cnt = 0, fd = hdev->fd;
	uint32_t arcs_num;

	arcs_num = hdev->asic_funcs->arc_get_max_cpuid();

	for (i = 0 ; i < arcs_num; i++, map_lbw_blocks_cnt++) {
		if (!arc_db->fw_info[i].enabled)
			continue;

		rc = hdev->asic_funcs->arc_map_lbw_blocks(fd, i, arc_db);
		if (rc) {
			printf("Failed to map LBW blocks for ARC %d\n", i);
			goto err_unmap_lbw_blocks;
		}
	}

	return 0;

err_unmap_lbw_blocks:
	for (i = 0 ; i < map_lbw_blocks_cnt ; i++)
		if (arc_db->fw_info[i].enabled)
			_hltests_arc_unmap_lbw_blocks(hdev, i, arc_db);
	return rc;
}

static int hltests_arc_set_regions(struct hltests_device *hdev, struct hltests_arc_db *arc_db)
{
	uint32_t arcs_num;
	int rc, i, fd = hdev->fd;

	arcs_num = hdev->asic_funcs->arc_get_max_cpuid();

	for (i = 0 ; i < arcs_num; i++) {
		if (!arc_db->fw_info[i].enabled)
			continue;

		rc = hdev->asic_funcs->arc_set_regions(fd, i, arc_db);
		if (rc) {
			printf("Failed to set regions for ARC %d\n", i);
			return rc;
		}
	}

	return 0;
}

static int hltests_arc_set_asic_model(struct hltests_device *hdev, struct hltests_arc_db *arc_db)
{
	uint32_t arcs_num;
	int rc, i, fd = hdev->fd;

	arcs_num = hdev->asic_funcs->arc_get_max_cpuid();

	for (i = 0 ; i < arcs_num; i++) {
		if (!arc_db->fw_info[i].enabled)
			continue;

		rc = hdev->asic_funcs->arc_set_asic_model(fd, i, arc_db);
		if (rc) {
			printf("Failed to set asic model for ARC %d\n", i);
			return rc;
		}
	}

	return 0;
}

static int hltests_arc_set_config(struct hltests_device *hdev, struct hltests_arc_db *arc_db,
					uint16_t run_arc_done_sob)
{
	uint32_t arcs_num;
	int rc, i, fd = hdev->fd;

	arcs_num = hdev->asic_funcs->arc_get_max_cpuid();

	for (i = 0 ; i < arcs_num; i++) {
		if (!arc_db->fw_info[i].enabled)
			continue;

		rc = hdev->asic_funcs->arc_set_config(fd, i, arc_db, run_arc_done_sob);
		if (rc) {
			printf("Failed to set config for ARC %d\n", i);
			return rc;
		}
	}

	return 0;
}

static int hltests_arc_run(struct hltests_device *hdev, struct hltests_arc_db *arc_db,
				uint16_t run_arc_done_sob)
{
	uint32_t cpu_idx, arcs_num, i, *cpu_ids;
	int rc, fd = hdev->fd;

	arcs_num = hdev->asic_funcs->arc_get_max_cpuid();

	cpu_ids = hlthunk_malloc(arc_db->arc_count * sizeof(uint32_t));
	if (!cpu_ids)
		return -ENOMEM;

	cpu_idx = 0;
	for (i = 0 ; i < arcs_num; i++) {
		if (!arc_db->fw_info[i].enabled)
			continue;

		if (cpu_idx == arc_db->arc_count) {
			printf("ARC IDs allocation too small\n");
			rc = -EINVAL;
			goto free_cpu_ids;
		}

		cpu_ids[cpu_idx++] = i;
	}

	rc = hlthunk_engines_command(fd, cpu_ids, arc_db->arc_count, HL_ENGINE_CORE_RUN);
	if (rc) {
		printf("failed to run engines cores (%d)\n", rc);
		goto free_cpu_ids;
	}

	rc = hdev->asic_funcs->wait_arc_run_done(fd, arc_db, run_arc_done_sob);

free_cpu_ids:
	hlthunk_free(cpu_ids);

	return rc;
}

static int hltests_arc_activate(struct hltests_device *hdev,
				struct hltests_arc_db *arc_db)
{
	uint32_t arcs_num;
	int rc, i, fd = hdev->fd;

	arcs_num = hdev->asic_funcs->arc_get_max_cpuid();

	for (i = 0 ; i < arcs_num; i++) {
		if (!arc_db->fw_info[i].enabled)
			continue;

		rc = hdev->asic_funcs->arc_activate(fd, i, arc_db);
		if (rc) {
			printf("Failed to run ARC %d\n", i);
			return rc;
		}
	}

	return 0;
}

/*TODO: make it more elegant */
uint32_t hltests_arc_get_submitter_id(int fd, uint32_t scheduler_id)
{
	uint32_t pdma_ch_cnt = hltests_get_pdma_ch_cnt(fd);

	return (pdma_ch_cnt + scheduler_id);
}

static int hltests_scheduler_submit_buf(int fd, uint32_t queue_id, void *buf, uint32_t len)
{
	/* Both in h6 and h9, we are using first sched arc with cpu id 0 */
	struct hl_debug_params_scheduler arc_args = {
		.cpu_id = 0,
		.queue_id = queue_id,
		.buffer = (uint64_t) (uintptr_t) buf,
		.size = len
	};
	struct hl_debug_args debug = {
		.input_ptr = (uint64_t) (uintptr_t) &arc_args,
		.input_size = sizeof(arc_args),
		.op = HL_DEBUG_OP_SCHED_SUBMIT_BUF,
	};

	return hlthunk_debug(fd, &debug);
}

static int hltests_arc_get_cpu_id_eng_group(int fd, uint32_t queue_idx,
					uint32_t *cpu_id, uint32_t *eng_group)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	return asic->arc_get_cpu_id_eng_group(fd, queue_idx, cpu_id, eng_group);
}

static uint32_t hltests_arc_put_dispatch_static_on_ccb(int fd,
						       struct hltests_sched_arc_cmd_params *params)
{
	int rc;
	struct sched_arc_cmd_dispatch_static_ecb_t cmd = {
		.opcode = SCHED_ARC_CMD_DISPATCH_STATIC_ECB,
		.engine_group_type = params->dispatch_static_ecb_list.engine_group_type,
		.size = params->dispatch_static_ecb_list.size,
		.engine_cpu_id = params->dispatch_static_ecb_list.engine_cpu_id,
		.addr = params->dispatch_static_ecb_list.addr,
	};

	rc = hltests_scheduler_submit_buf(fd, 0, &cmd, sizeof(cmd));

	return 0;
}

int hltests_sched_arc_send_cb(int fd, struct hltests_cs_chunk *hltests_chunk)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct hltests_sched_arc_cmd_params params;
	uint32_t engine_cpu_id, engine_group_id;
	struct hl_cs_chunk submit_chunk;
	int rc;

	rc = hltests_arc_get_cpu_id_eng_group(fd, hltests_chunk->queue_index,
			&engine_cpu_id, &engine_group_id);
	if (rc)
		return rc;

	if (!hdev->arc_db.fw_info[engine_cpu_id].enabled) {
		printf("Cannot submit cb to CPU %d (not enabled)\n", engine_cpu_id);
		return -EINVAL;
	}

	memset(&submit_chunk, 0, sizeof(submit_chunk));
	hltests_fill_cs_chunk(hdev, &submit_chunk, hltests_chunk->cb_ptr,
			hltests_chunk->cb_size, hltests_chunk->queue_index);

	/* Add a dispatch cmd on CCB */
	memset(&params, 0, sizeof(params));
	params.dispatch_static_ecb_list.addr = submit_chunk.cb_handle;
	params.dispatch_static_ecb_list.engine_group_type = engine_group_id;
	params.dispatch_static_ecb_list.size = submit_chunk.cb_size;
	params.dispatch_static_ecb_list.engine_cpu_id = engine_cpu_id;

	hltests_arc_put_dispatch_static_on_ccb(fd, &params);

	return 0;
}

int hltests_sched_arc_submit_cs(int fd, struct hltests_cs_chunk *arr,
					uint32_t arr_size, uint32_t sched_id,
					uint64_t *seq)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct hltests_arc_db *arc_db = &hdev->arc_db;

	return hltests_submit_job(fd, arr, arr_size, seq,
						&arc_db->fw_info[0].submission_lock,
						hltests_sched_arc_send_cb);
}

uint32_t hltests_add_sched_arc_nop_cmd(int fd, void *buffer, uint32_t buf_off,
					struct hltests_sched_arc_cmd_params *params)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	return asic->add_sched_arc_nop_cmd(buffer, buf_off, params);
}

uint32_t hltests_add_sched_arc_dispatch_static_ecb_list(int fd, void *buffer, uint32_t buf_off,
					struct hltests_sched_arc_cmd_params *params)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	return asic->add_sched_arc_dispatch_static_ecb_list(buffer, buf_off, params);
}

static void *hltests_dump_arc_log(void *args)
{
	struct hltests_device *hdev = args;
	struct hltests_arc_db *arc_db = &hdev->arc_db;
	int i, rc, arcs_num = hdev->asic_funcs->arc_get_max_cpuid();
	void *log_buf_ci_addr;
	char *log_buf_ptr;
	bool got_logs = false;

	while (true) {
		/* sleep only if last iteration didn't produced any logs */
		if (!got_logs)
			usleep(1000); /* sleep for 1 milisec */
		got_logs = false;
		pthread_testcancel();

		for (i = 0 ; i < arcs_num; i++) {
			uint32_t ci = arc_db->arc_log_bufs[i].ci;

			if (!arc_db->fw_info[i].enabled)
				continue;

			log_buf_ptr = arc_db->arc_log_bufs[i].ptr;
			if (log_buf_ptr[ci]) {
				printf("\n[%d] ", i);
				got_logs = true;
				do {
					char c = log_buf_ptr[ci];

					putchar(c);
					log_buf_ptr[ci] = 0;
					ci = ARC_LOG_BUF_NEXT_CI(ci);
					if (c == '\n' && log_buf_ptr[ci])
						printf("[%d] ", i);
				} while (log_buf_ptr[ci]);
				arc_db->arc_log_bufs[i].ci = ci;
				log_buf_ci_addr = hltests_arc_get_log_buf_ci_addr(i, arc_db);
				rc = hltests_write_lbw_reg(hdev->fd, log_buf_ci_addr, ci);
				if (rc) {
					printf("Failed writing log buf ci to arc %d\n", i);
					return NULL;
				}
			}
		}
	}

	return NULL;
}

static void hltests_arc_join_log_dump(struct hltests_arc_db *arc_db)
{
	int rc;

	rc = pthread_cancel(arc_db->logs_thread);
	if (!rc) {
		rc = pthread_join(arc_db->logs_thread, NULL);
		if (rc)
			printf("failed to join logging thread\n");
	} else {
		printf("failed to cancel logging thread\n");
	}
}

int hltests_arc_init(int fd, struct hltests_arc_db *arc_db)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct arc_asic_fw_load_params load_param = {0};
	struct iterate_arcs_ctx ctx = {0};
	uint16_t run_arc_done_sob;
	int rc;

	run_arc_done_sob = hltests_get_first_avail_sob(fd);
	hdev->asic_funcs->set_arc_asic_fw_load_params(&load_param);

	/* update common ARC context properties */
	ctx.arc_db = arc_db;
	ctx.load_param = &load_param;

	rc = hdev->asic_funcs->arc_set_enabled_cores(fd, arc_db);
	if (rc) {
		printf("Failed to set enabled arc cores\n");
		return rc;
	}

	if (!arc_db->arc_count)
		return 0;

	rc = hltests_allocate_arc_memory(hdev, arc_db);
	if (rc) {
		printf("Failed to allocate arc memory\n");
		return rc;
	}

	rc = hltests_arc_map_lbw_blocks(hdev, arc_db);
	if (rc) {
		printf("Failed to map lbw hw blocks\n");
		goto err_free_arc_memory;
	}

	rc = hltests_load_fw_to_device(hdev, &ctx);
	if (rc) {
		printf("Failed to load arc FW to device\n");
		goto err_unmap_lbw_blocks;
	}

	rc = hltests_arc_set_asic_model(hdev, arc_db);
	if (rc) {
		printf("Failed to set arc asic model\n");
		goto err_unmap_lbw_blocks;
	}

	rc = hltests_arc_set_regions(hdev, arc_db);
	if (rc) {
		printf("Failed to set arc regions\n");
		goto err_unmap_lbw_blocks;
	}

	rc = hltests_arc_set_config(hdev, arc_db, run_arc_done_sob);
	if (rc) {
		printf("Failed to set arc config\n");
		goto err_unmap_lbw_blocks;
	}

	if (hltests_get_parser_enable_arc_log()) {
		rc = pthread_create(&arc_db->logs_thread, NULL,
				hltests_dump_arc_log, hdev);
		if (rc) {
			printf("Failed to create arc loggings thread\n");
			goto err_unmap_lbw_blocks;
		}
	}

	rc = hltests_arc_run(hdev, arc_db, run_arc_done_sob);
	if (rc) {
		printf("Failed to run arc\n");
		goto err_cancel_log_thread;
	}

	/* Streams configuration must be done after ARC cores taken out of reset,
	 * because they reset the ACP registers as part of their pre_init phase.
	 */
	rc = hdev->asic_funcs->arc_configure_scheduler_streams(fd, arc_db);
	if (rc) {
		printf("Failed to configure the ARC scheduler streams\n");
		goto err_cancel_log_thread;
	}

	rc = hltests_arc_activate(hdev, arc_db);
	if (rc) {
		printf("Failed to activate arc\n");
		goto err_cancel_log_thread;
	}

	return 0;

err_cancel_log_thread:
	if (hltests_get_parser_enable_arc_log())
		hltests_arc_join_log_dump(arc_db);
err_unmap_lbw_blocks:
	hltests_arc_unmap_lbw_blocks(hdev, arc_db);
err_free_arc_memory:
	hltests_arc_memory_free(hdev, arc_db);

	return rc;
}

void hltests_arc_fini(int fd, struct hltests_arc_db *arc_db)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);

	if (!arc_db->arc_count)
		return;

	if (hltests_get_parser_enable_arc_log())
		hltests_arc_join_log_dump(arc_db);

	hltests_free_host_mem(fd, arc_db->cq_host_mem);

	hltests_arc_unmap_lbw_blocks(hdev, arc_db);

	hltests_arc_memory_free(hdev, arc_db);
}
