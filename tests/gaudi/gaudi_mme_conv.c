// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "uapi/hlthunk.h"
#include "common/hlthunk_tests.h"
#include "gaudi/gaudi.h"
#include "gaudi/asic_reg/gaudi_regs.h"
#include <stdarg.h>
#include <cmocka.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

static void mme_conv_config_prepare(int fd, bool master0,
		void *mme_config_cb, uint16_t sob,
		uint64_t inputs_addr, uint64_t weights_addr,
		uint64_t device_out_mem, uint32_t *out_offset)
{
	struct hltests_pkt_info pkt_info;
	uint32_t mme_config_cb_offset = 0;

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.wreg32.reg_addr = (uint16_t)
			(master0 ? mmMME0_CTRL_ARCH_BASE_ADDR_HIGH_S & 0xfff :
			mmMME2_CTRL_ARCH_BASE_ADDR_HIGH_S & 0xfff);
	pkt_info.wreg32.value = (uint32_t)(inputs_addr >> 32);
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
			(master0 ? mmMME0_CTRL_ARCH_BASE_ADDR_HIGH_L & 0xfff :
			mmMME2_CTRL_ARCH_BASE_ADDR_HIGH_L & 0xfff);
	pkt_info.wreg32.value = (uint32_t)(weights_addr >> 32);
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
			(master0 ? mmMME0_CTRL_ARCH_BASE_ADDR_HIGH_O & 0xfff :
			mmMME2_CTRL_ARCH_BASE_ADDR_HIGH_O & 0xfff);
	pkt_info.wreg32.value = (uint32_t)(device_out_mem >> 32);
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
			(master0 ? mmMME0_CTRL_ARCH_BASE_ADDR_LOW_S & 0xfff :
			mmMME2_CTRL_ARCH_BASE_ADDR_LOW_S & 0xfff);
	pkt_info.wreg32.value = (uint32_t)inputs_addr;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
			(master0 ? mmMME0_CTRL_ARCH_BASE_ADDR_LOW_L & 0xfff :
			mmMME2_CTRL_ARCH_BASE_ADDR_LOW_L & 0xfff);
	pkt_info.wreg32.value = (uint32_t)weights_addr;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
			(master0 ? mmMME0_CTRL_ARCH_BASE_ADDR_LOW_O & 0xfff :
			mmMME2_CTRL_ARCH_BASE_ADDR_LOW_O & 0xfff);
	pkt_info.wreg32.value = (uint32_t)device_out_mem;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_HEADER_LOW & 0xfff :
			mmMME2_CTRL_ARCH_HEADER_LOW & 0xfff);
	pkt_info.wreg32.value = 0x7f0b07a9;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_HEADER_HIGH & 0xfff
			: mmMME2_CTRL_ARCH_HEADER_HIGH & 0xfff);
	pkt_info.wreg32.value = (master0 ? 0xc0000010 : 0xc0200210);
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_CONV_KERNEL_SIZE_MINUS_1 & 0xfff :
			mmMME2_CTRL_ARCH_CONV_KERNEL_SIZE_MINUS_1 & 0xfff);
	pkt_info.wreg32.value = 0x202;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_CONV_ASSOCIATED_DIMS_LOW & 0xfff :
			mmMME2_CTRL_ARCH_CONV_ASSOCIATED_DIMS_LOW & 0xfff);
	pkt_info.wreg32.value = 0x9a0051;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_CONV_ASSOCIATED_DIMS_HIGH & 0xfff :
			mmMME2_CTRL_ARCH_CONV_ASSOCIATED_DIMS_HIGH & 0xfff);
	pkt_info.wreg32.value = 0x500e3;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_NUM_ITERATIONS_MINUS_1 & 0xfff :
			mmMME2_CTRL_ARCH_NUM_ITERATIONS_MINUS_1 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_OUTER_LOOP & 0xfff :
			mmMME2_CTRL_ARCH_OUTER_LOOP & 0xfff);
	pkt_info.wreg32.value = 0x16d;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_S_VALID_ELEMENTS_0 & 0xfff :
			mmMME2_CTRL_ARCH_TENSOR_S_VALID_ELEMENTS_0 & 0xfff);
	pkt_info.wreg32.value = 0x9;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_S_VALID_ELEMENTS_1 & 0xfff :
			mmMME2_CTRL_ARCH_TENSOR_S_VALID_ELEMENTS_1 & 0xfff);
	pkt_info.wreg32.value = 0x12;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_S_VALID_ELEMENTS_2 & 0xfff :
			mmMME2_CTRL_ARCH_TENSOR_S_VALID_ELEMENTS_2 & 0xfff);
	pkt_info.wreg32.value = 0x6c;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_S_VALID_ELEMENTS_3 & 0xfff :
			mmMME2_CTRL_ARCH_TENSOR_S_VALID_ELEMENTS_3 & 0xfff);
	pkt_info.wreg32.value = 0x6c;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_S_VALID_ELEMENTS_4 & 0xfff :
			mmMME2_CTRL_ARCH_TENSOR_S_VALID_ELEMENTS_4 & 0xfff);
	pkt_info.wreg32.value = 0x6c;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_S_LOOP_STRIDE_0 & 0xfff :
			mmMME2_CTRL_ARCH_TENSOR_S_LOOP_STRIDE_0 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_S_LOOP_STRIDE_1 & 0xfff :
			mmMME2_CTRL_ARCH_TENSOR_S_LOOP_STRIDE_1 & 0xfff);
	pkt_info.wreg32.value = 0x3;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_S_LOOP_STRIDE_2 & 0xfff :
			mmMME2_CTRL_ARCH_TENSOR_S_LOOP_STRIDE_2 & 0xfff);
	pkt_info.wreg32.value = 0x12;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_S_LOOP_STRIDE_3 & 0xfff :
			mmMME2_CTRL_ARCH_TENSOR_S_LOOP_STRIDE_3 & 0xfff);
	pkt_info.wreg32.value = 0x6c;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_S_LOOP_STRIDE_4 & 0xfff :
			mmMME2_CTRL_ARCH_TENSOR_S_LOOP_STRIDE_4 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_S_ROI_SIZE_0 & 0xfff :
			mmMME2_CTRL_ARCH_TENSOR_S_ROI_SIZE_0 & 0xfff);
	pkt_info.wreg32.value = 0x9;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_S_ROI_SIZE_1 & 0xfff :
			mmMME2_CTRL_ARCH_TENSOR_S_ROI_SIZE_1 & 0xfff);
	pkt_info.wreg32.value = 0xc;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_S_ROI_SIZE_2 & 0xfff :
			mmMME2_CTRL_ARCH_TENSOR_S_ROI_SIZE_2 & 0xfff);
	pkt_info.wreg32.value = 0x48;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_S_ROI_SIZE_3 & 0xfff :
			mmMME2_CTRL_ARCH_TENSOR_S_ROI_SIZE_3 & 0xfff);
	pkt_info.wreg32.value = 0x6c;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_S_SPATIAL_STRIDES_0 & 0xfff :
			mmMME2_CTRL_ARCH_TENSOR_S_SPATIAL_STRIDES_0 & 0xfff);
	pkt_info.wreg32.value = 0x3;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_S_SPATIAL_STRIDES_1 & 0xfff :
			mmMME2_CTRL_ARCH_TENSOR_S_SPATIAL_STRIDES_1 & 0xfff);
	pkt_info.wreg32.value = 0x12;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_S_SPATIAL_STRIDES_2 & 0xfff :
			mmMME2_CTRL_ARCH_TENSOR_S_SPATIAL_STRIDES_2 & 0xfff);
	pkt_info.wreg32.value = 0x6c;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_S_SPATIAL_STRIDES_3 & 0xfff :
			mmMME2_CTRL_ARCH_TENSOR_S_SPATIAL_STRIDES_3 & 0xfff);
	pkt_info.wreg32.value = 0x6c;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_S_SPATIAL_SIZE_MINUS_1 & 0xfff :
			mmMME2_CTRL_ARCH_TENSOR_S_SPATIAL_SIZE_MINUS_1 & 0xfff);
	pkt_info.wreg32.value = 0xf;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_S_ROI_BASE_OFFSET_0 & 0xfff :
		 mmMME2_CTRL_ARCH_AGU_S_ROI_BASE_OFFSET_0 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_S_ROI_BASE_OFFSET_1 & 0xfff :
			mmMME2_CTRL_ARCH_AGU_S_ROI_BASE_OFFSET_1 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_S_ROI_BASE_OFFSET_2 & 0xfff :
			mmMME2_CTRL_ARCH_AGU_S_ROI_BASE_OFFSET_2 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_S_ROI_BASE_OFFSET_3 & 0xfff :
			mmMME2_CTRL_ARCH_AGU_S_ROI_BASE_OFFSET_3 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_S_ROI_BASE_OFFSET_4 & 0xfff :
			mmMME2_CTRL_ARCH_AGU_S_ROI_BASE_OFFSET_4 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_S_START_OFFSET_0 & 0xfff :
			mmMME2_CTRL_ARCH_AGU_S_START_OFFSET_0 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_S_START_OFFSET_1 & 0xfff :
			mmMME2_CTRL_ARCH_AGU_S_START_OFFSET_1 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_S_START_OFFSET_2 & 0xfff :
			mmMME2_CTRL_ARCH_AGU_S_START_OFFSET_2 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_S_START_OFFSET_3 & 0xfff :
			mmMME2_CTRL_ARCH_AGU_S_START_OFFSET_3 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_S_START_OFFSET_3 & 0xfff :
			mmMME2_CTRL_ARCH_AGU_S_START_OFFSET_3 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_L_VALID_ELEMENTS_0 & 0xfff :
			mmMME2_CTRL_ARCH_TENSOR_L_VALID_ELEMENTS_0 & 0xfff);
	pkt_info.wreg32.value = 0x1;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_L_VALID_ELEMENTS_1 & 0xfff :
			mmMME2_CTRL_ARCH_TENSOR_L_VALID_ELEMENTS_1 & 0xfff);
	pkt_info.wreg32.value = 0x3;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_L_VALID_ELEMENTS_2 & 0xfff :
			mmMME2_CTRL_ARCH_TENSOR_L_VALID_ELEMENTS_2 & 0xfff);
	pkt_info.wreg32.value = 0x9;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ?  mmMME0_CTRL_ARCH_TENSOR_L_VALID_ELEMENTS_3 & 0xfff :
			mmMME2_CTRL_ARCH_TENSOR_L_VALID_ELEMENTS_3 & 0xfff);
	pkt_info.wreg32.value = 0x1b;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_L_VALID_ELEMENTS_4 & 0xfff :
			mmMME2_CTRL_ARCH_TENSOR_L_VALID_ELEMENTS_4 & 0xfff);
	pkt_info.wreg32.value = 0x1b;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_L_LOOP_STRIDE_0 & 0xfff :
			mmMME2_CTRL_ARCH_TENSOR_L_LOOP_STRIDE_0 & 0xfff);
	pkt_info.wreg32.value = 0x80;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_L_LOOP_STRIDE_1 & 0xfff :
			mmMME2_CTRL_ARCH_TENSOR_L_LOOP_STRIDE_1 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_L_LOOP_STRIDE_2 & 0xfff :
			mmMME2_CTRL_ARCH_TENSOR_L_LOOP_STRIDE_2 & 0xfff);
	pkt_info.wreg32.value = 0x3;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_L_LOOP_STRIDE_3 & 0xfff :
			mmMME2_CTRL_ARCH_TENSOR_L_LOOP_STRIDE_3 & 0xfff);
	pkt_info.wreg32.value = 0x9;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_L_LOOP_STRIDE_4 & 0xfff :
			mmMME2_CTRL_ARCH_TENSOR_L_LOOP_STRIDE_4 & 0xfff);
	pkt_info.wreg32.value = 0x1b;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_L_ROI_SIZE_0 & 0xfff :
			mmMME2_CTRL_ARCH_TENSOR_L_ROI_SIZE_0 & 0xfff);
	pkt_info.wreg32.value = 0x1;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_L_ROI_SIZE_1 & 0xfff :
			mmMME2_CTRL_ARCH_TENSOR_L_ROI_SIZE_1 & 0xfff);
	pkt_info.wreg32.value = 0x3;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_L_ROI_SIZE_2 & 0xfff :
			mmMME2_CTRL_ARCH_TENSOR_L_ROI_SIZE_2 & 0xfff);
	pkt_info.wreg32.value = 0x3;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_L_ROI_SIZE_3 & 0xfff :
			mmMME2_CTRL_ARCH_TENSOR_L_ROI_SIZE_3 & 0xfff);
	pkt_info.wreg32.value = 0x9;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_L_SPATIAL_STRIDES_0 & 0xfff :
			mmMME2_CTRL_ARCH_TENSOR_L_SPATIAL_STRIDES_0 & 0xfff);
	pkt_info.wreg32.value = 0x1;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_L_SPATIAL_STRIDES_1 & 0xfff :
			mmMME2_CTRL_ARCH_TENSOR_L_SPATIAL_STRIDES_1 & 0xfff);
	pkt_info.wreg32.value = 0x3;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_L_SPATIAL_STRIDES_2 & 0xfff :
			mmMME2_CTRL_ARCH_TENSOR_L_SPATIAL_STRIDES_2 & 0xfff);
	pkt_info.wreg32.value = 0x9;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_L_SPATIAL_STRIDES_3 & 0xfff :
			mmMME2_CTRL_ARCH_TENSOR_L_SPATIAL_STRIDES_3 & 0xfff);
	pkt_info.wreg32.value = 0x1b;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_L_SPATIAL_SIZE_MINUS_1 & 0xfff :
			mmMME2_CTRL_ARCH_TENSOR_L_SPATIAL_SIZE_MINUS_1 & 0xfff);
	pkt_info.wreg32.value = 0x2;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_L_LOCAL_ROI_BASE_OFFSET_0 & 0xfff :
			mmMME2_CTRL_ARCH_AGU_L_LOCAL_ROI_BASE_OFFSET_0 & 0xfff);
	pkt_info.wreg32.value = master0 ? 0x40 : 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_L_LOCAL_ROI_BASE_OFFSET_1 & 0xfff :
			mmMME2_CTRL_ARCH_AGU_L_LOCAL_ROI_BASE_OFFSET_1 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_L_LOCAL_ROI_BASE_OFFSET_2 & 0xfff :
			mmMME2_CTRL_ARCH_AGU_L_LOCAL_ROI_BASE_OFFSET_2 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_L_LOCAL_ROI_BASE_OFFSET_3 & 0xfff :
			mmMME2_CTRL_ARCH_AGU_L_LOCAL_ROI_BASE_OFFSET_3 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_L_LOCAL_ROI_BASE_OFFSET_4 & 0xfff :
			mmMME2_CTRL_ARCH_AGU_L_LOCAL_ROI_BASE_OFFSET_4 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_L_LOCAL_START_OFFSET_0 & 0xfff :
			mmMME2_CTRL_ARCH_AGU_L_LOCAL_START_OFFSET_0 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_L_LOCAL_START_OFFSET_1 & 0xfff :
			mmMME2_CTRL_ARCH_AGU_L_LOCAL_START_OFFSET_1 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_L_LOCAL_START_OFFSET_2 & 0xfff :
			mmMME2_CTRL_ARCH_AGU_L_LOCAL_START_OFFSET_2 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_L_LOCAL_START_OFFSET_3 & 0xfff :
			mmMME2_CTRL_ARCH_AGU_L_LOCAL_START_OFFSET_3 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_L_REMOTE_ROI_BASE_OFFSET_0 & 0xfff :
		mmMME2_CTRL_ARCH_AGU_L_REMOTE_ROI_BASE_OFFSET_0 & 0xfff);
	pkt_info.wreg32.value = master0 ? 0x60 : 0x20;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_L_REMOTE_ROI_BASE_OFFSET_1 & 0xfff :
		mmMME2_CTRL_ARCH_AGU_L_REMOTE_ROI_BASE_OFFSET_1 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_L_REMOTE_ROI_BASE_OFFSET_2 & 0xfff :
		mmMME2_CTRL_ARCH_AGU_L_REMOTE_ROI_BASE_OFFSET_2 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_L_REMOTE_ROI_BASE_OFFSET_3 & 0xfff :
		mmMME2_CTRL_ARCH_AGU_L_REMOTE_ROI_BASE_OFFSET_3 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_L_REMOTE_ROI_BASE_OFFSET_4 & 0xfff :
		mmMME2_CTRL_ARCH_AGU_L_REMOTE_ROI_BASE_OFFSET_4 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_L_REMOTE_START_OFFSET_0 & 0xfff :
		mmMME2_CTRL_ARCH_AGU_L_REMOTE_START_OFFSET_0 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_L_REMOTE_START_OFFSET_1 & 0xfff :
		mmMME2_CTRL_ARCH_AGU_L_REMOTE_START_OFFSET_1 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_L_REMOTE_START_OFFSET_2 & 0xfff :
		mmMME2_CTRL_ARCH_AGU_L_REMOTE_START_OFFSET_2 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_L_REMOTE_START_OFFSET_3 & 0xfff :
		mmMME2_CTRL_ARCH_AGU_L_REMOTE_START_OFFSET_3 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_O_VALID_ELEMENTS_0 & 0xfff :
			mmMME2_CTRL_ARCH_TENSOR_O_VALID_ELEMENTS_0 & 0xfff);
	pkt_info.wreg32.value = 0x1;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_O_VALID_ELEMENTS_1 & 0xfff :
		mmMME2_CTRL_ARCH_TENSOR_O_VALID_ELEMENTS_1 & 0xfff);
	pkt_info.wreg32.value = 0x4;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_O_VALID_ELEMENTS_2 & 0xfff :
		mmMME2_CTRL_ARCH_TENSOR_O_VALID_ELEMENTS_2 & 0xfff);
	pkt_info.wreg32.value = 0x10;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_O_VALID_ELEMENTS_3 & 0xfff :
		mmMME2_CTRL_ARCH_TENSOR_O_VALID_ELEMENTS_3 & 0xfff);
	pkt_info.wreg32.value = 0x10;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_O_VALID_ELEMENTS_4 & 0xfff :
		mmMME2_CTRL_ARCH_TENSOR_O_VALID_ELEMENTS_4 & 0xfff);
	pkt_info.wreg32.value = 0x10;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_O_LOOP_STRIDE_0 & 0xfff :
		mmMME2_CTRL_ARCH_TENSOR_O_LOOP_STRIDE_0 & 0xfff);
	pkt_info.wreg32.value = 0x80;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_O_LOOP_STRIDE_1 & 0xfff :
		mmMME2_CTRL_ARCH_TENSOR_O_LOOP_STRIDE_1 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_O_LOOP_STRIDE_2 & 0xfff :
		mmMME2_CTRL_ARCH_TENSOR_O_LOOP_STRIDE_2 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_O_LOOP_STRIDE_3 & 0xfff :
		mmMME2_CTRL_ARCH_TENSOR_O_LOOP_STRIDE_3 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_O_LOOP_STRIDE_4 & 0xfff :
		mmMME2_CTRL_ARCH_TENSOR_O_LOOP_STRIDE_4 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_O_ROI_SIZE_0 & 0xfff :
		mmMME2_CTRL_ARCH_TENSOR_O_ROI_SIZE_0 & 0xfff);
	pkt_info.wreg32.value = 0x1;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_O_ROI_SIZE_1 & 0xfff :
		mmMME2_CTRL_ARCH_TENSOR_O_ROI_SIZE_1 & 0xfff);
	pkt_info.wreg32.value = 0x4;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_O_ROI_SIZE_2 & 0xfff :
		mmMME2_CTRL_ARCH_TENSOR_O_ROI_SIZE_2 & 0xfff);
	pkt_info.wreg32.value = 0x10;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_O_ROI_SIZE_3 & 0xfff :
		mmMME2_CTRL_ARCH_TENSOR_O_ROI_SIZE_3 & 0xfff);
	pkt_info.wreg32.value = 0x10;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_O_SPATIAL_STRIDES_0 & 0xfff :
		mmMME2_CTRL_ARCH_TENSOR_O_SPATIAL_STRIDES_0 & 0xfff);
	pkt_info.wreg32.value = 0x1;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_O_SPATIAL_STRIDES_1 & 0xfff :
		mmMME2_CTRL_ARCH_TENSOR_O_SPATIAL_STRIDES_1 & 0xfff);
	pkt_info.wreg32.value = 0x4;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_O_SPATIAL_STRIDES_2 & 0xfff :
		mmMME2_CTRL_ARCH_TENSOR_O_SPATIAL_STRIDES_2 & 0xfff);
	pkt_info.wreg32.value = 0x10;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_O_SPATIAL_STRIDES_3 & 0xfff :
		mmMME2_CTRL_ARCH_TENSOR_O_SPATIAL_STRIDES_3 & 0xfff);
	pkt_info.wreg32.value = 0x10;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_TENSOR_O_SPATIAL_SIZE_MINUS_1 & 0xfff :
		mmMME2_CTRL_ARCH_TENSOR_O_SPATIAL_SIZE_MINUS_1 & 0xfff);
	pkt_info.wreg32.value = 0xf;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_O_LOCAL_ROI_BASE_OFFSET_0 & 0xfff :
		mmMME2_CTRL_ARCH_AGU_O_LOCAL_ROI_BASE_OFFSET_0 & 0xfff);
	pkt_info.wreg32.value = master0 ? 0x40 : 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_O_LOCAL_ROI_BASE_OFFSET_1 & 0xfff :
		mmMME2_CTRL_ARCH_AGU_O_LOCAL_ROI_BASE_OFFSET_1 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_O_LOCAL_ROI_BASE_OFFSET_2 & 0xfff :
		mmMME2_CTRL_ARCH_AGU_O_LOCAL_ROI_BASE_OFFSET_2 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_O_LOCAL_ROI_BASE_OFFSET_3 & 0xfff :
		mmMME2_CTRL_ARCH_AGU_O_LOCAL_ROI_BASE_OFFSET_3 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_O_LOCAL_ROI_BASE_OFFSET_4 & 0xfff :
		mmMME2_CTRL_ARCH_AGU_O_LOCAL_ROI_BASE_OFFSET_4 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_O_LOCAL_START_OFFSET_0 & 0xfff :
		mmMME2_CTRL_ARCH_AGU_O_LOCAL_START_OFFSET_0 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_O_LOCAL_START_OFFSET_1 & 0xfff :
		mmMME2_CTRL_ARCH_AGU_O_LOCAL_START_OFFSET_1 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_O_LOCAL_START_OFFSET_2 & 0xfff :
		mmMME2_CTRL_ARCH_AGU_O_LOCAL_START_OFFSET_2 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_O_LOCAL_START_OFFSET_3 & 0xfff :
		mmMME2_CTRL_ARCH_AGU_O_LOCAL_START_OFFSET_3 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_O_REMOTE_ROI_BASE_OFFSET_0 & 0xfff :
		mmMME2_CTRL_ARCH_AGU_O_REMOTE_ROI_BASE_OFFSET_0 & 0xfff);
	pkt_info.wreg32.value = master0 ? 0x60 : 0x20;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_O_REMOTE_ROI_BASE_OFFSET_1 :
			mmMME2_CTRL_ARCH_AGU_O_REMOTE_ROI_BASE_OFFSET_1);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_O_REMOTE_ROI_BASE_OFFSET_2 & 0xfff :
		mmMME2_CTRL_ARCH_AGU_O_REMOTE_ROI_BASE_OFFSET_2 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_O_REMOTE_ROI_BASE_OFFSET_3 & 0xfff :
		mmMME2_CTRL_ARCH_AGU_O_REMOTE_ROI_BASE_OFFSET_3 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_O_REMOTE_ROI_BASE_OFFSET_4 & 0xfff :
		mmMME2_CTRL_ARCH_AGU_O_REMOTE_ROI_BASE_OFFSET_4 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_O_REMOTE_START_OFFSET_0 & 0xfff :
		mmMME2_CTRL_ARCH_AGU_O_REMOTE_START_OFFSET_0 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_O_REMOTE_START_OFFSET_1 & 0xfff :
			mmMME2_CTRL_ARCH_AGU_O_REMOTE_START_OFFSET_1 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_O_REMOTE_START_OFFSET_2 & 0xfff :
		mmMME2_CTRL_ARCH_AGU_O_REMOTE_START_OFFSET_2 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_AGU_O_REMOTE_START_OFFSET_3 & 0xfff :
		mmMME2_CTRL_ARCH_AGU_O_REMOTE_START_OFFSET_3 & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_DESC_SB_REPEAT & 0xfff :
		mmMME2_CTRL_ARCH_DESC_SB_REPEAT & 0xfff);
	pkt_info.wreg32.value = 0xc000c100;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_DESC_RATE_LIMITER & 0xfff :
		mmMME2_CTRL_ARCH_DESC_RATE_LIMITER & 0xfff);
	pkt_info.wreg32.value = 0x20404;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_DESC_SYNC_OBJECT_ADDR_LOW_LOCAL & 0xfff :
		mmMME2_CTRL_ARCH_DESC_SYNC_OBJECT_ADDR_LOW_LOCAL & 0xfff);
	pkt_info.wreg32.value = master0 ? 0xfc4f20a8 : 0xfc4f20a0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_DESC_SYNC_OBJECT_ADDR_LOW_REMOTE :
			mmMME2_CTRL_ARCH_DESC_SYNC_OBJECT_ADDR_LOW_REMOTE);
	pkt_info.wreg32.value = master0 ? 0xfc4f20ac : 0xfc4f20a4;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_DESC_SYNC_OBJECT_ADDR_HIGH & 0xfff :
		mmMME2_CTRL_ARCH_DESC_SYNC_OBJECT_ADDR_HIGH & 0xfff);
	pkt_info.wreg32.value = 0x7f;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_DESC_SYNC_OBJECT_DATA & 0xfff :
		mmMME2_CTRL_ARCH_DESC_SYNC_OBJECT_DATA & 0xfff);
	pkt_info.wreg32.value = 0x80000001;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_DESC_AXI_USER_DATA & 0xfff :
		mmMME2_CTRL_ARCH_DESC_AXI_USER_DATA & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_DESC_PERF_EVT_S & 0xfff :
		mmMME2_CTRL_ARCH_DESC_PERF_EVT_S & 0xfff);
	pkt_info.wreg32.value = 0x3f30000;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_DESC_PERF_EVT_L_LOCAL & 0xfff :
		mmMME2_CTRL_ARCH_DESC_PERF_EVT_L_LOCAL & 0xfff);
	pkt_info.wreg32.value = 0x3f30000;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_DESC_PERF_EVT_L_REMOTE & 0xfff :
		mmMME2_CTRL_ARCH_DESC_PERF_EVT_L_REMOTE & 0xfff);
	pkt_info.wreg32.value = 0x3f30000;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_DESC_PERF_EVT_O_LOCAL & 0xfff :
		mmMME2_CTRL_ARCH_DESC_PERF_EVT_O_LOCAL & 0xfff);
	pkt_info.wreg32.value = 0x3f30000;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_DESC_PERF_EVT_O_REMOTE & 0xfff :
		mmMME2_CTRL_ARCH_DESC_PERF_EVT_O_REMOTE & 0xfff);
	pkt_info.wreg32.value = 0x3f30000;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_DESC_PADDING_VALUE_S & 0xfff :
		mmMME2_CTRL_ARCH_DESC_PADDING_VALUE_S & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_DESC_PADDING_VALUE_L & 0xfff :
		mmMME2_CTRL_ARCH_DESC_PADDING_VALUE_L & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_DESC_META_DATA_AGU_S & 0xfff :
		mmMME2_CTRL_ARCH_DESC_META_DATA_AGU_S & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_DESC_META_DATA_AGU_L_LOCAL & 0xfff :
		mmMME2_CTRL_ARCH_DESC_META_DATA_AGU_L_LOCAL & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_DESC_META_DATA_AGU_L_REMOTE & 0xfff :
		mmMME2_CTRL_ARCH_DESC_META_DATA_AGU_L_REMOTE & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_DESC_META_DATA_AGU_O_LOCAL & 0xfff :
		mmMME2_CTRL_ARCH_DESC_META_DATA_AGU_O_LOCAL & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_DESC_META_DATA_AGU_O_REMOTE & 0xfff :
		mmMME2_CTRL_ARCH_DESC_META_DATA_AGU_O_REMOTE & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_DESC_PCU_RL_SATURATION & 0xfff :
		mmMME2_CTRL_ARCH_DESC_PCU_RL_SATURATION & 0xfff);
	pkt_info.wreg32.value = 0x10000;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_ARCH_DESC_DUMMY & 0xfff :
		mmMME2_CTRL_ARCH_DESC_DUMMY & 0xfff);
	pkt_info.wreg32.value = 0x0;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	/* Execute the conv on MME */
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.wreg32.reg_addr = (uint16_t)
	(master0 ? mmMME0_CTRL_CMD & 0xfff : mmMME2_CTRL_CMD & 0xfff);
	pkt_info.wreg32.value = 0x1;
	mme_config_cb_offset = hltests_add_wreg32_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);

	/* Signal SOB */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id = sob;
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_ADD;
	*out_offset = hltests_add_write_to_sob_pkt(fd, mme_config_cb,
			mme_config_cb_offset, &pkt_info);
}

static void mme_cb_prepare(int fd, void *mme_cb,
		uint64_t mme_config_cb_sram, uint32_t mme_config_cb_offset,
		uint32_t *out_offset)
{
	struct hltests_pkt_info pkt_info;
	struct hltests_monitor_and_fence mon_and_fence_info;
	uint32_t mme_cb_offset = 0;

	/* Add CP_DMA packet */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.cp_dma.src_addr = mme_config_cb_sram;
	pkt_info.cp_dma.size = mme_config_cb_offset;
	*out_offset = hltests_add_cp_dma_pkt(fd, mme_cb,
			mme_cb_offset, &pkt_info);
}

static void dma_cb_prepare(int fd, void *dma_cb,
		uint64_t host_dst_device_va,
		uint16_t sob, uint16_t mon, uint64_t device_output_addr,
		uint32_t output_size, uint32_t *out_offset)
{
	struct hltests_pkt_info pkt_info;
	struct hltests_monitor_and_fence mon_and_fence_info;
	uint32_t dma_cb_offset = 0;

	/* Fence on SOB */
	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = GAUDI_QUEUE_ID_DMA_0_0;
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = sob;
	mon_and_fence_info.mon_id = mon;
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.sob_val = 2;
	mon_and_fence_info.dec_fence = true;
	mon_and_fence_info.mon_payload = 1;
	dma_cb_offset = hltests_add_monitor_and_fence(fd,
				dma_cb, dma_cb_offset,
				&mon_and_fence_info);

	/* Add some delay */
	dma_cb_offset = hltests_add_nop_pkt(fd, dma_cb, dma_cb_offset,
							EB_TRUE, MB_TRUE);
	dma_cb_offset = hltests_add_nop_pkt(fd, dma_cb, dma_cb_offset,
							EB_TRUE, MB_TRUE);
	dma_cb_offset = hltests_add_nop_pkt(fd, dma_cb, dma_cb_offset,
							EB_TRUE, MB_TRUE);
	dma_cb_offset = hltests_add_nop_pkt(fd, dma_cb, dma_cb_offset,
							EB_TRUE, MB_TRUE);
	dma_cb_offset = hltests_add_nop_pkt(fd, dma_cb, dma_cb_offset,
							EB_TRUE, MB_TRUE);
	dma_cb_offset = hltests_add_nop_pkt(fd, dma_cb, dma_cb_offset,
							EB_TRUE, MB_TRUE);
	/* DMA output to host */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.dma.src_addr = device_output_addr;
	pkt_info.dma.dst_addr = host_dst_device_va;
	pkt_info.dma.size = output_size;
	*out_offset = hltests_add_dma_pkt(fd,
				dma_cb,
				dma_cb_offset,
				&pkt_info);
}

void test_mme_basic_conv(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	uint64_t sram_base;
	struct hlthunk_hw_ip_info hw_ip;
	int rc, i;
	int fd = tests_state->fd;
	struct hltests_cs_chunk execute_arr[3];
	uint64_t seq = 0;
	void *host_src_inputs, *host_src_weights, *host_dst;
	uint64_t mme_master0_cb_sram, mme_master2_cb_sram, inputs_sram_addr,
		weights_sram_addr, mme_master0_config_cb_sram,
		mme_master2_config_cb_sram, output_sram;
	uint64_t host_src_inputs_device_va, host_src_weights_device_va,
		host_dst_device_va, mme_master0_config_cb_device_va,
		mme_master2_config_cb_device_va,
		mme_master0_cb_device_va, mme_master2_cb_device_va;
	void *mme_master0_cb, *mme_master2_cb, *dma_cb;
	void *mme_master0_config_cb, *mme_master2_config_cb;
	uint32_t in_size, wght_size, output_size;
	uint32_t page_size;
	uint32_t mme_master0_cb_offset = 0;
	uint32_t mme_master2_cb_offset = 0;
	uint32_t mme_master0_config_cb_offset = 0;
	uint32_t mme_master2_config_cb_offset = 0;
	uint32_t dma_cb_offset = 0;
	uint16_t sob, mon;

	float ifm_buffer[] = {
		1, 1, 2, 2, 3, 3,
		1, 1, 2, 2, 3, 3,
		4, 3, 1, 3, 2, 1,
		2, 6, 2, 7, 1, 3,
		1, 5, 2, 3, 3, 1,
		4, 6, 5, 9, 6, 9,

		2, 2, 3, 3, 1, 1,
		1, 1, 2, 2, 3, 3,
		5, 1, 5, 2, 2, 5,
		2, 4, 3, 1, 6, 4,
		3, 1, 2, 3, 1, 7,
		3, 6, 4, 1, 6, 4,

		3, 3, 1, 1, 2, 2,
		1, 1, 2, 2, 3, 3,
		1, 1, 4, 1, 3, 1,
		1, 2, 5, 2, 5, 2,
		3, 5, 1, 4, 5, 1,
		6, 4, 8, 8, 5, 0
	};

	float weights_buffer[] = {
		1, 2, 3,
		3, 3, 2,
		2, 5, 8,

		2, 3, 1,
		4, 1, 6,
		5, 9, 8,

		3, 1, 2,
		5, 3, 1,
		7, 1, 2
	};

	float  expected_out_buffer[] = {
		235,
		206,
		291,
		377,
		224,
		230,
		299,
		389,
		184,
		232,
		298,
		287,
		209,
		277,
		301,
		340
	};

	in_size = sizeof(ifm_buffer);
	wght_size = sizeof(weights_buffer);
	output_size = sizeof(expected_out_buffer);

	uint32_t *ifm_buffer_ui = (uint32_t *) malloc(in_size);
	uint32_t *weights_buffer_ui = (uint32_t *) malloc(wght_size);
	uint32_t *expected_out_buffer_ui = (uint32_t *) malloc(output_size);

	/* SRAM MAP:
	 * - 0x80 - DMA 0.0 - conv  inputs->SRAM
	 * - 0x200 - DMA 0.0 - conv  weights->SRAM
	 * - 0x300 - DMA 0.0 - mme master0 cb->SRAM
	 * - 0x400 - DMA 0.0 - mme master2 cb->SRAM
	 * - 0x600 - DMA 0.0 - mme master0 config cb->SRAM
	 * - 0x11B8 - DMA 0.0 - mme master2 config cb->SRAM
	 * - 0x1D70 - DMA 0.0 - output on SRAM->host DRAM
	 *
	 * Test Description:
	 * DMA inputs, weights, MME configs and CB with the CP DMA command
	 * to device SRAM, run MME conv then copy output to host.
	 * 1. DMA inputs, weights, MME CB and MME config CB to SRAM
	 * 2. Start CS with 3 CBs: DMA CB, MME master0 CB,
	 *    MME master2 CB, Details:
	 * 2.1 DMA CB:
	 *	- Fence SOB
	 *	- little delay with nop packets
	 *	- DMA output from SRAM to Host
	 * 2.2 MME CB:
	 *	- CP_DMA to MME config CB
	 * 2.3 MME config CB:
	 *	- MME config registers
	 *	- Signal SOB
	 */

	/* convert from float representative to uint32 */
	for (i = 0 ; i < ARRAY_SIZE(ifm_buffer) ; i++)
		ifm_buffer_ui[i] = *(uint32_t *) &ifm_buffer[i];

	for (i = 0 ; i < ARRAY_SIZE(weights_buffer) ; i++)
		weights_buffer_ui[i] = *(uint32_t *) &weights_buffer[i];

	for (i = 0 ; i < ARRAY_SIZE(expected_out_buffer) ; i++)
		expected_out_buffer_ui[i] =
					*(uint32_t *) &expected_out_buffer[i];

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	sram_base = hw_ip.sram_base_address;

	page_size = sysconf(_SC_PAGESIZE);
	assert_in_range(page_size, PAGE_SIZE_4KB, PAGE_SIZE_64KB);

	/* Setup SRAM addresses */
	inputs_sram_addr = sram_base;
	weights_sram_addr = sram_base  + 0x200;
	mme_master0_cb_sram = sram_base + 0x300;
	mme_master2_cb_sram = sram_base + 0x400;
	mme_master0_config_cb_sram = sram_base + 0x600;
	mme_master2_config_cb_sram = sram_base + 0x11B8;
	output_sram = sram_base + 0x1D70;

	/* Alloc host mem for conv inputs */
	host_src_inputs = hltests_allocate_host_mem(fd, in_size, NOT_HUGE);
	assert_non_null(host_src_inputs);
	host_src_inputs_device_va =
			hltests_get_device_va_for_host_ptr(fd, host_src_inputs);
	memcpy(host_src_inputs, ifm_buffer_ui, in_size);

	/* Alloc host mem for conv weights */
	host_src_weights = hltests_allocate_host_mem(fd, wght_size, NOT_HUGE);
	assert_non_null(host_src_weights);
	host_src_weights_device_va =
		hltests_get_device_va_for_host_ptr(fd, host_src_weights);
	memcpy(host_src_weights, weights_buffer_ui, wght_size);

	/* Alloc host mem for output */
	host_dst = hltests_allocate_host_mem(fd, output_size, NOT_HUGE);
	assert_non_null(host_dst);
	memset(host_dst, 0, output_size);
	host_dst_device_va = hltests_get_device_va_for_host_ptr(fd, host_dst);

	sob = hltests_get_first_avail_sob(fd);
	mon = hltests_get_first_avail_mon(fd);

	/* clear SOB */
	hltests_clear_sobs(fd, 1);

	/* Allocate Command buffers */
	/* 1. MME master0/master2 configs CB: */
	mme_master0_config_cb =
			hltests_allocate_host_mem(fd, page_size, NOT_HUGE);
	assert_non_null(mme_master0_config_cb);
	mme_master0_config_cb_device_va = hltests_get_device_va_for_host_ptr(fd,
				mme_master0_config_cb);

	mme_master2_config_cb =
			hltests_allocate_host_mem(fd, page_size, NOT_HUGE);
	assert_non_null(mme_master2_config_cb);
	mme_master2_config_cb_device_va = hltests_get_device_va_for_host_ptr(fd,
				mme_master2_config_cb);

	/* Configure MME master 0 */
	mme_conv_config_prepare(fd, true, mme_master0_config_cb, sob,
			inputs_sram_addr,
			weights_sram_addr,
			output_sram,
			&mme_master0_config_cb_offset);

	/* Configure MME master 2 */
	mme_conv_config_prepare(fd, false, mme_master2_config_cb, sob,
			inputs_sram_addr,
			weights_sram_addr,
			output_sram,
			&mme_master2_config_cb_offset);

	/* 2. MME CB with CP_DMA: */
	mme_master0_cb = hltests_create_cb(fd, page_size, INTERNAL,
			mme_master0_cb_sram);
	assert_non_null(mme_master0_cb);
	mme_master0_cb_device_va = hltests_get_device_va_for_host_ptr(fd,
					mme_master0_cb);

	mme_master2_cb = hltests_create_cb(fd, page_size, INTERNAL,
			mme_master2_cb_sram);
	assert_non_null(mme_master2_cb);
	mme_master2_cb_device_va = hltests_get_device_va_for_host_ptr(fd,
					mme_master2_cb);

	mme_cb_prepare(fd, mme_master0_cb, mme_master0_config_cb_sram,
			mme_master0_config_cb_offset,
			&mme_master0_cb_offset);

	mme_cb_prepare(fd, mme_master2_cb, mme_master2_config_cb_sram,
			mme_master2_config_cb_offset,
			&mme_master2_cb_offset);

	/* 3. DMA CB: */
	dma_cb = hltests_create_cb(fd, page_size, EXTERNAL, 0);
	assert_non_null(dma_cb);
	dma_cb_prepare(fd, dma_cb, host_dst_device_va, sob, mon,
			output_sram, output_size, &dma_cb_offset);

	/* Move MME masters CB and configs CB to SRAM before start conv */
	hltests_dma_transfer(fd,
			hltests_get_dma_down_qid(fd, STREAM0),
			EB_FALSE, MB_TRUE, mme_master0_config_cb_device_va,
			mme_master0_config_cb_sram,
			mme_master0_config_cb_offset,
			GOYA_DMA_HOST_TO_SRAM);

	hltests_dma_transfer(fd,
			hltests_get_dma_down_qid(fd, STREAM0),
			EB_FALSE, MB_TRUE, mme_master2_config_cb_device_va,
			mme_master2_config_cb_sram,
			mme_master2_config_cb_offset,
			GOYA_DMA_HOST_TO_SRAM);

	hltests_dma_transfer(fd,
			hltests_get_dma_down_qid(fd, STREAM0),
			EB_FALSE, MB_TRUE, mme_master0_cb_device_va,
			mme_master0_cb_sram, mme_master0_cb_offset,
			GOYA_DMA_HOST_TO_SRAM);

	hltests_dma_transfer(fd,
			hltests_get_dma_down_qid(fd, STREAM0),
			EB_FALSE, MB_TRUE, mme_master2_cb_device_va,
			mme_master2_cb_sram, mme_master2_cb_offset,
			GOYA_DMA_HOST_TO_SRAM);

	/* Move inputs and weights to SRAM */
	hltests_dma_transfer(fd,
			hltests_get_dma_down_qid(fd, STREAM1),
			EB_FALSE, MB_TRUE, host_src_inputs_device_va,
			inputs_sram_addr, in_size,
			GOYA_DMA_HOST_TO_SRAM);

	hltests_dma_transfer(fd,
			hltests_get_dma_down_qid(fd, STREAM0),
			EB_FALSE, MB_TRUE, host_src_weights_device_va,
			weights_sram_addr, wght_size,
			GOYA_DMA_HOST_TO_SRAM);

	/* Submit CS and wait */
	execute_arr[0].cb_ptr = dma_cb;
	execute_arr[0].cb_size = dma_cb_offset;
	execute_arr[0].queue_index = GAUDI_QUEUE_ID_DMA_0_0;

	execute_arr[1].cb_ptr = mme_master0_cb;
	execute_arr[1].cb_size = mme_master0_cb_offset;
	execute_arr[1].queue_index = GAUDI_QUEUE_ID_MME_0_0;

	execute_arr[2].cb_ptr = mme_master2_cb;
	execute_arr[2].cb_size = mme_master2_cb_offset;
	execute_arr[2].queue_index = GAUDI_QUEUE_ID_MME_1_0;

	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, 3, 0, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, 0);

	/* Compare output with expected one */
	rc = hltests_mem_compare(expected_out_buffer_ui, host_dst, output_size);
	assert_int_equal(rc, 0);

	/* cleanup */
	free(ifm_buffer_ui);
	free(weights_buffer_ui);
	free(expected_out_buffer_ui);

	rc = hltests_destroy_cb(fd, dma_cb);
	assert_int_equal(rc, 0);

	rc = hltests_destroy_cb(fd, mme_master0_cb);
	assert_int_equal(rc, 0);

	rc = hltests_destroy_cb(fd, mme_master2_cb);
	assert_int_equal(rc, 0);

	rc = hltests_free_host_mem(fd, mme_master0_config_cb);
	assert_int_equal(rc, 0);

	rc = hltests_free_host_mem(fd, mme_master2_config_cb);
	assert_int_equal(rc, 0);

	rc = hltests_free_host_mem(fd, host_src_inputs);
	assert_int_equal(rc, 0);

	rc = hltests_free_host_mem(fd, host_src_weights);
	assert_int_equal(rc, 0);

	rc = hltests_free_host_mem(fd, host_dst);
	assert_int_equal(rc, 0);
}

const struct CMUnitTest gaudi_mme_tests[] = {
	cmocka_unit_test_setup(test_mme_basic_conv,
				hltests_ensure_device_operational)
};

static const char *const usage[] = {
	"gaudi_mme [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = sizeof(gaudi_mme_tests) / sizeof((gaudi_mme_tests)[0]);

	hltests_parser(argc, argv, usage, HLTHUNK_DEVICE_GAUDI, gaudi_mme_tests,
			num_tests);

	return hltests_run_group_tests("gaudi_mme", gaudi_mme_tests, num_tests,
					hltests_setup, hltests_teardown);
}
