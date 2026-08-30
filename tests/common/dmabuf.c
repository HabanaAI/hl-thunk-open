// SPDX-License-Identifier: MIT

/*
 * Copyright 2021 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_tests.h"
#include "ini.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>

#ifndef __maybe_unused
#define __maybe_unused  __attribute__((unused))
#endif

static uint64_t hl_reg_dmabuf(int fd, uint64_t length, uint32_t dmabuf_fd)
{
	union hl_mem_args ioctl_args;
	int rc;

	memset(&ioctl_args, 0, sizeof(ioctl_args));
	ioctl_args.in.reg_dmabuf_fd.fd = dmabuf_fd;
	ioctl_args.in.reg_dmabuf_fd.length = length;
	ioctl_args.in.op = HL_MEM_OP_REG_DMABUF_FD;

	rc = ioctl(fd, DRM_IOCTL_HL_MEMORY, &ioctl_args);
	if (rc)
		return 0;

	return ioctl_args.out.device_virt_addr;
}

static int hl_unmap_dmabuf(int fd, uint64_t device_virt_addr)
{
	union hl_mem_args ioctl_args;

	memset(&ioctl_args, 0, sizeof(ioctl_args));
	ioctl_args.in.unmap.device_virt_addr = device_virt_addr;
	ioctl_args.in.op = HL_MEM_OP_UNMAP;

	return ioctl(fd, DRM_IOCTL_HL_MEMORY, &ioctl_args);
}

struct dmabuf_state {
	/* read from .ini file */
	char *pciaddr_exp;
	char *pciaddr_imp;
	uint64_t dmabuf_size;
	uint64_t host_buf_size;
	uint32_t dma_perf_size;

	/* initialized in setup */
	struct hltests_state *tests_state_exp;
	struct hltests_state *tests_state_imp;
	uint64_t dmabuf_exp_va;
	uint64_t dmabuf_imp_va;
	int dmabuf_fd;
};

static int dmabuf_export(struct dmabuf_state *state)
{
	int fd_export = state->tests_state_exp->fd;
	int fd_import = state->tests_state_imp->fd;

	printf("%s - exporter\n", state->pciaddr_exp);
	printf("%s - importer\n", state->pciaddr_imp);


	if (state->host_buf_size > state->dmabuf_size) {
		printf("device allocation must be >= host allocation\n");
		return -1;
	}

	state->dmabuf_exp_va = (uint64_t)(uintptr_t)hltests_allocate_device_mem(fd_export,
						state->dmabuf_size, 0, NOT_CONTIGUOUS);
	if (!state->dmabuf_exp_va) {
		printf("unable to allocate dmabuf_exp_va\n");
		return -1;
	}

	/* Export DMA-BUF and register MR */

	state->dmabuf_fd = hltests_device_memory_export_dmabuf_fd(fd_export,
								(void *)state->dmabuf_exp_va,
								state->dmabuf_size, 0);
	if (state->dmabuf_fd < 0) {
		printf("Failed to export dmabuf %d\n", state->dmabuf_fd);
		return -1;
	}

	printf("Exported dmabuf from %s for HBM address 0x%lx, size %lu\n",
		state->pciaddr_exp, state->dmabuf_exp_va, state->dmabuf_size);

#ifdef MMAP_DEBUG
	{
		void *dmabuf_ptr = mmap(NULL, state->dmabuf_size, PROT_READ | PROT_WRITE,
					MAP_SHARED, state->dmabuf_fd, 0);
		if (dmabuf_ptr == MAP_FAILED) {
			printf("Failed to mmap dmabuf\n");
			return -1;
		}

		munmap(dmabuf_ptr, state->dmabuf_size);
	}
#endif

	assert_true(state->dmabuf_fd >= 0);

	state->dmabuf_imp_va = hl_reg_dmabuf(fd_import,
					     state->dmabuf_size, (uint32_t)state->dmabuf_fd);
	if (!state->dmabuf_imp_va) {
		printf("Failed to register dmabuf\n");
		return -1;
	}

	printf("Registered dmabuf on %s with device VA for dmabuf = 0x%lx\n",
		state->pciaddr_imp, state->dmabuf_imp_va);

	return 0;
}

static int dmabuf_parsing_handler(void *user, const char *section,
	const char *name, const char *value)
{
	struct dmabuf_state *state = (struct dmabuf_state *)user;

	if (MATCH("dmabuf", "exporter"))
		state->pciaddr_exp = strdup(value);
	else if (MATCH("dmabuf", "importer"))
		state->pciaddr_imp = strdup(value);
	else if (MATCH("dmabuf", "dmabuf_size"))
		state->dmabuf_size = strtoul(value, NULL, 0);
	else if (MATCH("dmabuf", "host_buf_size"))
		state->host_buf_size = strtoul(value, NULL, 0);
	else if (MATCH("dmabuf", "dma_perf_size"))
		str_to_u32_safe_ret_on_err(state->dma_perf_size, value, 0, 0);
	else
		return 0; /* unknown section/name, error */

	return 1;
}

static __maybe_unused int dmabuf_setup(void **s)
{
	const char *config_filename = hltests_get_config_filename();
	static struct dmabuf_state g_state;
	struct dmabuf_state *state = &g_state;
	int rc;

	memset(state, 0, sizeof(*state));
	state->dmabuf_fd  = -1;
	*s = state;

	if (!config_filename) {
		printf("User didn't supply a configuration file name!\n");
		return -1;
	}

	if (ini_parse(config_filename, dmabuf_parsing_handler, state) < 0) {
		printf("Can't load %s\n", config_filename);
		return -1;
	}

	hltests_override_parser_pciaddr(state->pciaddr_exp);
	rc = hltests_setup((void **) &state->tests_state_exp);
	if (rc) {
		printf("Failed to run setup phase of hlthunk tests for device %s\n",
			state->pciaddr_exp);
		return rc;
	}

	hltests_override_parser_pciaddr(state->pciaddr_imp);
	rc = hltests_setup((void **) &state->tests_state_imp);
	if (rc) {
		printf("Failed to run setup phase of hlthunk tests for device %s\n",
			state->pciaddr_imp);
		return rc;
	}

	rc = dmabuf_export(state);
	if (rc)
		return rc;

	return 0;
}

static __maybe_unused int dmabuf_teardown(void **s)
{
	struct dmabuf_state *state = (struct dmabuf_state *)(*s);
	int rc;

	if (state->dmabuf_imp_va) {
		rc = hl_unmap_dmabuf(state->tests_state_imp->fd, state->dmabuf_imp_va);
		if (rc)
			printf("Failed to unmap dmabuf %d\n", rc);
		state->dmabuf_imp_va = 0;
	}

	close(state->dmabuf_fd);
	state->dmabuf_fd = -1;

	if (state->dmabuf_exp_va) {
		hltests_free_device_mem(state->tests_state_exp->fd, (void *)state->dmabuf_exp_va);
		state->dmabuf_exp_va = 0;
	}

	free(state->pciaddr_exp);
	state->pciaddr_exp = NULL;
	free(state->pciaddr_imp);
	state->pciaddr_imp = NULL;

	if (state->tests_state_imp) {
		hltests_teardown((void **) &state->tests_state_imp);
		state->tests_state_imp = NULL;
	}

	if (state->tests_state_exp) {
		hltests_teardown((void **) &state->tests_state_exp);
		state->tests_state_exp = NULL;
	}

	return 0;
}

static __maybe_unused int dmabuf_ensure_device_operational(void **state)
{
	struct dmabuf_state *dmabuf_state = (struct dmabuf_state *)(*state);
	int rc;

	rc = hltests_ensure_device_operational((void **)&dmabuf_state->tests_state_exp);
	if (rc)
		return rc;

	rc = hltests_ensure_device_operational((void **)&dmabuf_state->tests_state_imp);
	if (rc)
		return rc;

	return 0;
}

/*
 * Classic test flow:
 * 1. Allocate source buffer on exporter host mem (fill with random).
 * 2. Allocate destination buffer on importer host mem (fill with zeroes).
 * 3. DMA transfer from source buffer to dmabuf on exporter.
 * 4. DMA transfer from dmabuf on importer to destination buffer.
 * 5. Compare source and destination buffers.
 */
VOID test_dmabuf_classic(void **s)
{
	struct dmabuf_state *state = (struct dmabuf_state *)(*s);
	int fd_export = state->tests_state_exp->fd;
	int fd_import = state->tests_state_imp->fd;
	void *src = NULL, *dst = NULL;
	uint64_t src_va, dst_va;
	double bw_gbps;
	int rc;

	src = hltests_allocate_host_mem(fd_export, state->host_buf_size, NOT_HUGE_MAP);
	if (!src) {
		rc = -ENOMEM;
		goto cleanup;
	}
	src_va = hltests_get_device_va_for_host_ptr(fd_export, src);
	hltests_fill_rand_values(src, state->host_buf_size);

	dst = hltests_allocate_host_mem(fd_import, state->host_buf_size, NOT_HUGE_MAP);
	if (!dst) {
		rc = -ENOMEM;
		goto cleanup;
	}
	dst_va = hltests_get_device_va_for_host_ptr(fd_import, dst);
	memset(dst, 0, state->host_buf_size);

	rc = hltests_dma_transfer_large(fd_export,
				    hltests_get_dma_down_qid(fd_export, STREAM0),
				    EB_FALSE,
				    MB_TRUE,
				    src_va,
				    state->dmabuf_exp_va,
				    state->host_buf_size,
				    0,
				    &bw_gbps);
	if (rc) {
		printf("Failed to do dma xfer1\n");
		goto cleanup;
	}

	printf("DMA host to device %s at address 0x%lx, size %lu, BW %7.2lf GB/Sec\n",
		state->pciaddr_exp, state->dmabuf_exp_va, state->host_buf_size, bw_gbps);

	rc = hltests_dma_transfer_large(fd_import,
				    hltests_get_dma_up_qid(fd_import, STREAM0),
				    EB_FALSE,
				    MB_TRUE,
				    state->dmabuf_imp_va,
				    dst_va,
				    state->host_buf_size,
				    0,
				    &bw_gbps);
	if (rc) {
		printf("Failed to do dma xfer2\n");
		goto cleanup;
	}

	printf("Copied data to host by P2P read from device %s to device %s, BW %7.2lf GB/Sec\n",
		state->pciaddr_exp, state->pciaddr_imp, bw_gbps);

	/* Compare host memories */
	rc = hltests_mem_compare(src, dst, state->host_buf_size);
	if (rc) {
		printf("Failed memory comparison\n");
		goto cleanup;
	}

	printf("Memory Compare was successful :)\n");

cleanup:
	if (dst)
		hltests_free_host_mem(fd_import, dst);
	if (src)
		hltests_free_host_mem(fd_export, src);

	assert_int_equal(rc, 0);
	END_TEST;
}

/*
 * Similar to test_dmabuf_classic, but the source buffer is on the importer.
 *
 * 1. Allocate source buffer on importer host mem (fill with random).
 * 2. Allocate destination buffer on importer host mem (fill with zeroes).
 * 3. DMA transfer from source buffer to dmabuf on importer.
 * 4. DMA transfer from dmabuf on importer to destination buffer.
 * 5. Compare source and destination buffers.
 */
VOID test_dmabuf_classic_importer(void **s)
{
	struct dmabuf_state *state = (struct dmabuf_state *)(*s);
	int fd_import = state->tests_state_imp->fd;
	void *src = NULL, *dst = NULL;
	uint64_t src_va, dst_va;
	double bw_gbps;
	int rc;

	src = hltests_allocate_host_mem(fd_import, state->host_buf_size, NOT_HUGE_MAP);
	if (!src) {
		rc = -ENOMEM;
		goto cleanup;
	}
	src_va = hltests_get_device_va_for_host_ptr(fd_import, src);
	hltests_fill_rand_values(src, state->host_buf_size);

	dst = hltests_allocate_host_mem(fd_import, state->host_buf_size, NOT_HUGE_MAP);
	if (!dst) {
		rc = -ENOMEM;
		goto cleanup;
	}
	dst_va = hltests_get_device_va_for_host_ptr(fd_import, dst);
	memset(dst, 0, state->host_buf_size);

	rc = hltests_dma_transfer_large(fd_import,
				    hltests_get_dma_down_qid(fd_import, STREAM0),
				    EB_FALSE,
				    MB_TRUE,
				    src_va,
				    state->dmabuf_imp_va,
				    state->host_buf_size,
				    0,
				    &bw_gbps);
	if (rc) {
		printf("Failed to do dma xfer1\n");
		goto cleanup;
	}

	printf("DMA host to device %s at address 0x%lx, size %lu, BW %7.2lf GB/Sec\n",
		state->pciaddr_imp, state->dmabuf_imp_va, state->host_buf_size, bw_gbps);

	rc = hltests_dma_transfer_large(fd_import,
				    hltests_get_dma_up_qid(fd_import, STREAM0),
				    EB_FALSE,
				    MB_TRUE,
				    state->dmabuf_imp_va,
				    dst_va,
				    state->host_buf_size,
				    0,
				    &bw_gbps);
	if (rc) {
		printf("Failed to do dma xfer2\n");
		goto cleanup;
	}

	printf("Copied data to host by P2P read from device %s to device %s, BW %7.2lf GB/Sec\n",
		state->pciaddr_exp, state->pciaddr_imp, bw_gbps);

	/* Compare host memories */
	rc = hltests_mem_compare(src, dst, state->host_buf_size);
	if (rc) {
		printf("Failed memory comparison\n");
		goto cleanup;
	}

	printf("Memory Compare was successful :)\n");

cleanup:
	if (dst)
		hltests_free_host_mem(fd_import, dst);
	if (src)
		hltests_free_host_mem(fd_import, src);

	assert_int_equal(rc, 0);
	END_TEST;
}

enum p2p_direction {
	P2P_DIR_FROM_DMABUF   = 0b01,
	P2P_DIR_TO_DMABUF     = 0b10,
	P2P_DIR_BIDIRECT      = 0b11,
};

const char p2p_direction_str[] = {
	[P2P_DIR_FROM_DMABUF] = '>',
	[P2P_DIR_TO_DMABUF]   = '<',
	[P2P_DIR_BIDIRECT]    = '*',
};

enum p2p_buf_origin {
	P2P_BUF_HOST,
	P2P_BUF_DRAM,
};

const char *p2p_buf_origin_str[] = {
	[P2P_BUF_HOST]        = "host",
	[P2P_BUF_DRAM]        = "dram",
};

static int dmabuf_perf(struct dmabuf_state *state, enum p2p_buf_origin origin,
		       enum p2p_direction dir)
{
	int fd = state->tests_state_imp->fd;
	uint64_t dmabuf_va = state->dmabuf_imp_va;
	uint32_t size = state->dma_perf_size;
	struct dma_perf_transfer t_to, t_from;
	void *host_ptr = NULL, *host_ptr1 = NULL;
	void *dram_ptr = NULL, *dram_ptr1 = NULL;
	uint64_t host_va, host_va1, dram_va, dram_va1;

	double bw_gbps;
	int rc;

	/* Allocate DRAM buffers */
	dram_ptr = hltests_allocate_device_mem(fd, size, 0, NOT_CONTIGUOUS);
	if (!dram_ptr) {
		rc = -ENOMEM;
		goto cleanup;
	}
	dram_va = (uint64_t)(uintptr_t)dram_ptr;

	dram_ptr1 = hltests_allocate_device_mem(fd, size, 0, NOT_CONTIGUOUS);
	if (!dram_ptr1) {
		rc = -ENOMEM;
		goto cleanup;
	}
	dram_va1 = (uint64_t)(uintptr_t)dram_ptr1;

	/* Allocate Host buffers */
	host_ptr = hltests_allocate_host_mem(fd, size, NOT_HUGE_MAP);
	if (!host_ptr) {
		rc = -ENOMEM;
		goto cleanup;
	}
	host_va = hltests_get_device_va_for_host_ptr(fd, host_ptr);

	host_ptr1 = hltests_allocate_host_mem(fd, size, NOT_HUGE_MAP);
	if (!host_ptr1) {
		rc = -ENOMEM;
		goto cleanup;
	}
	host_va1 = hltests_get_device_va_for_host_ptr(fd, host_ptr1);

	t_to.size = size;
	t_from.size = size;

	if (origin == P2P_BUF_HOST && dir & P2P_DIR_TO_DMABUF) {
		t_to.src_addr = host_va;
		t_to.dst_addr = dmabuf_va;
		t_to.queue_index = hltests_get_dma_down_qid(fd, STREAM0);
		t_to.dma_dir = DMA_DIR_HOST_TO_DRAM;
	}

	if (origin == P2P_BUF_HOST && dir & P2P_DIR_FROM_DMABUF) {
		t_from.src_addr = dmabuf_va + size;
		t_from.dst_addr = host_va1;
		t_from.queue_index = hltests_get_dma_up_qid(fd, STREAM0);
		t_from.dma_dir = DMA_DIR_DRAM_TO_HOST;
	}

	if (origin == P2P_BUF_DRAM && dir & P2P_DIR_TO_DMABUF) {
		t_to.src_addr = dram_va;
		t_to.dst_addr = dmabuf_va;
		t_to.queue_index = hltests_get_dma_down_qid(fd, STREAM0);
		t_to.dma_dir = DMA_DIR_DRAM_TO_DRAM;
	}

	if (origin == P2P_BUF_DRAM && dir & P2P_DIR_FROM_DMABUF) {
		t_from.src_addr = dmabuf_va + size;
		t_from.dst_addr = dram_va1;
		t_from.queue_index = hltests_get_dma_up_qid(fd, STREAM0);
		t_from.dma_dir = DMA_DIR_DRAM_TO_DRAM;
	}

	switch (dir) {
	case P2P_DIR_BIDIRECT:
		bw_gbps = hltests_dma_transfer_perf_bidirectional(fd, &t_to, &t_from);
		break;
	case P2P_DIR_FROM_DMABUF:
		bw_gbps = hltests_dma_transfer_perf(fd, &t_from);
		break;
	case P2P_DIR_TO_DMABUF:
		bw_gbps = hltests_dma_transfer_perf(fd, &t_to);
		break;
	default:
		break;
	}

	printf("P2P perf DMA %c%s BW %7.2lf GB/Sec\n", p2p_direction_str[dir],
	       p2p_buf_origin_str[origin], bw_gbps);

cleanup:
	if (dram_ptr)
		hltests_free_device_mem(fd, dram_ptr);
	if (dram_ptr1)
		hltests_free_device_mem(fd, dram_ptr1);
	if (host_ptr)
		hltests_free_host_mem(fd, host_ptr);
	if (host_ptr1)
		hltests_free_host_mem(fd, host_ptr1);

	return rc;
}

VOID test_dmabuf_perf_host_from_dmabuf(void **s)
{
	struct dmabuf_state *state = (struct dmabuf_state *)(*s);
	int rc;

	rc = dmabuf_perf(state,	P2P_BUF_HOST, P2P_DIR_FROM_DMABUF);
	assert_int_equal(rc, 0);
	END_TEST;
}

VOID test_dmabuf_perf_host_to_dmabuf(void **s)
{
	struct dmabuf_state *state = (struct dmabuf_state *)(*s);
	int rc;

	rc = dmabuf_perf(state,	P2P_BUF_HOST, P2P_DIR_TO_DMABUF);
	assert_int_equal(rc, 0);
	END_TEST;
}

VOID test_dmabuf_perf_host_dmabuf_bidir(void **s)
{
	struct dmabuf_state *state = (struct dmabuf_state *)(*s);
	int rc;

	rc = dmabuf_perf(state,	P2P_BUF_HOST, P2P_DIR_BIDIRECT);
	assert_int_equal(rc, 0);
	END_TEST;
}

VOID test_dmabuf_perf_dram_from_dmabuf(void **s)
{
	struct dmabuf_state *state = (struct dmabuf_state *)(*s);
	int rc;

	rc = dmabuf_perf(state,	P2P_BUF_DRAM, P2P_DIR_FROM_DMABUF);
	assert_int_equal(rc, 0);
	END_TEST;
}

VOID test_dmabuf_perf_dram_to_dmabuf(void **s)
{
	struct dmabuf_state *state = (struct dmabuf_state *)(*s);
	int rc;

	rc = dmabuf_perf(state,	P2P_BUF_DRAM, P2P_DIR_TO_DMABUF);
	assert_int_equal(rc, 0);
	END_TEST;
}

VOID test_dmabuf_perf_dram_dmabuf_bidir(void **s)
{
	struct dmabuf_state *state = (struct dmabuf_state *)(*s);
	int rc;

	rc = dmabuf_perf(state,	P2P_BUF_DRAM, P2P_DIR_BIDIRECT);
	assert_int_equal(rc, 0);
	END_TEST;
}

#ifndef HLTESTS_LIB_MODE

const struct CMUnitTest dmabuf_tests[] = {
	cmocka_unit_test_setup(test_dmabuf_classic, dmabuf_ensure_device_operational),
	cmocka_unit_test_setup(test_dmabuf_classic_importer, dmabuf_ensure_device_operational),
	cmocka_unit_test_setup(test_dmabuf_perf_host_from_dmabuf,
			       dmabuf_ensure_device_operational),
	cmocka_unit_test_setup(test_dmabuf_perf_host_to_dmabuf,
			       dmabuf_ensure_device_operational),
	cmocka_unit_test_setup(test_dmabuf_perf_host_dmabuf_bidir,
			       dmabuf_ensure_device_operational),
	cmocka_unit_test_setup(test_dmabuf_perf_dram_from_dmabuf,
			       dmabuf_ensure_device_operational),
	cmocka_unit_test_setup(test_dmabuf_perf_dram_to_dmabuf,
			       dmabuf_ensure_device_operational),
	cmocka_unit_test_setup(test_dmabuf_perf_dram_dmabuf_bidir,
			       dmabuf_ensure_device_operational),
};

int main(int argc, const char **argv)
{
	size_t num_tests = sizeof(dmabuf_tests) / sizeof((dmabuf_tests)[0]);

	hltests_parser(argc, argv, NULL, HLTEST_DEVICE_MASK_DONT_CARE,
			dmabuf_tests, (int)num_tests);

	if (!hltests_get_parser_run_disabled_tests()) {
		printf("dmabuf tests should run with --disabled option\n");
		return 0;
	}

	hltests_set_capabilities_mask(CAP_ARC_FW_LOAD_SCHED_MASK | CAP_ARC_FW_LOAD_PDMA_MASK);

	return hltests_run_group_tests("dmabuf", dmabuf_tests, num_tests,
					dmabuf_setup, dmabuf_teardown);
}

#endif /* HLTESTS_LIB_MODE */
