/* SPDX-License-Identifier: MIT */

/*
 * Copyright 2021 HabanaLabs, Ltd.
 * All Rights Reserved.
 */
#ifndef _REDUCTION_TEST_H_
#define _REDUCTION_TEST_H_

#define SIGN_MASK_FP16 0x8000
#define SIGN_MASK_FP32 0x80000000

#define RND_TO_NE   0
#define RND_TO_0    1
#define RND_TO_PINF 2
#define RND_TO_NINF 3
#define RND_SR      4
#define RND_HALF_AZ 6

#define DEFAULT_NAN_BFP16 0x7FFF
#define DEFAULT_NAN_FP32  0x7FFFFFFF

#pragma pack(push, 1)
struct bfloat16 {
	union {
		struct {
			unsigned sign : 1;
			signed exp : 8;
			signed mantissa : 7;
		};
		uint16_t _raw;
	};
};

#pragma pack(pop)

VOID fill_buffer_bfloat16(struct bfloat16 *buf, uint64_t size);
void calc_reduction_int8(enum hltests_nic_reduction_operation oper, int8_t *src_buf,
			int8_t *dst_buf, int8_t *dst_result, uint64_t data_size);
void calc_reduction_fp32(enum hltests_nic_reduction_operation oper, float *src_buf, float *dst_buf,
			float *dst_result, uint64_t data_size);
void calc_reduction_bf16(enum hltests_nic_reduction_operation oper, struct bfloat16 *src_buf,
			struct bfloat16 *dst_buf, struct bfloat16 *dst_result, uint64_t data_size);
void calc_reduction_upscale_bf16(enum hltests_nic_reduction_operation oper,
				struct bfloat16 *src_buf, float *dst_buf, float *ref_buf,
				uint64_t data_size);
VOID fill_buffer_fp32(float *buf, uint64_t size);
void calc_reduction_downscale_bf16(enum hltests_nic_reduction_operation oper, float *src_buf,
				struct bfloat16 *dst_buf, struct bfloat16 *ref_buf,
				uint64_t data_size);
void calc_reduction_down_up_bf16(enum hltests_nic_reduction_operation oper, float *src_buf,
					float *dst_buf, float *ref_buf, uint64_t data_size);
void calc_reduction_reference(void *src_buf, void *dst_buf, void *ref_buf, uint64_t data_size,
				enum hltests_nic_reduction_datatype data_type,
				enum hltests_nic_reduction_operation red_op);

#endif /* _REDUCTION_TEST_H_*/
