// SPDX-License-Identifier: MIT

/*
 * Copyright 2021 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <math.h>
#include <fenv.h>
#include <limits.h>
#include <errno.h>
#include "hlthunk_nic_tests.h"
#include "reduction_test.h"

int fe_get_round(void)
{
	return FE_TONEAREST;
}

int fe_set_round(int val)
{
	return FE_TONEAREST;
}

/* sbs implements select bits x[high:low] */
uint32_t sbs(uint32_t x, uint8_t high, uint8_t low)
{
	return (high == 31) ? (x >> low) : ((x & ((1U << (high + 1)) - 1)) >> low);
}

/* cbs implements concatenate bits {x[31-pos:0],y[pos-1,0]} */
uint32_t cbs(uint32_t x, uint32_t y, uint8_t pos)
{
	return ((x << pos) | (y & (BIT(pos) - 1)));
}

/* ibs implements insert bits x[high:low] = y[high-low-1:0] */
uint32_t ibs(uint32_t x, uint32_t high, uint32_t low, uint32_t y)
{
	return (high == 31) ?
		       ((x & (BIT(low) - 1)) | (y << low)) :
		       ((x & (~(BIT(high + 1) - BIT(low)))) | ((y << low) & ((BIT(high + 1) - 1))));
}

bool is_inf_bfp16(uint16_t x)
{
	return ((sbs(x, 14, 7) == 0xFF) && (sbs(x, 6, 0) == 0));
}

bool is_inf_fp32(uint32_t x)
{
	return ((sbs(x, 30, 23) == 0xFF) && (sbs(x, 22, 0) == 0));
}

float bf16_to_f32(uint16_t input)
{
	uint32_t val_32b = 0;
	uint32_t *val_32b_p;
	float *val_f_p;

	/* On GCC 11.2 *( *)& syntax generates a false warning which treated as error, thus
	 * the explicit casting must be used
	 */
	val_32b = (uint32_t) input << 16;
	val_32b_p = &val_32b;
	val_f_p = (float *) val_32b_p;

	return *val_f_p;
}

uint32_t bf16_to_fp32(uint16_t input)
{
	return ((uint32_t)(input << 16));
}

bool is_zero_fp32(uint32_t x)
{
	return ((sbs(x, 30, 23) == 0x00) && (sbs(x, 22, 0) == 0));
}

bool is_nan_fp32(uint32_t x)
{
	return ((sbs(x, 30, 23) == 0xFF) && (sbs(x, 22, 0) != 0));
}

static bool is_nan_bf16(uint16_t x)
{
	return ((sbs(x, 14, 7) == 0xFF) && (sbs(x, 6, 0) != 0));
}

bool is_denorm_fp32(uint32_t x)
{
	return ((sbs(x, 30, 23) == 0x00) && (sbs(x, 22, 0) != 0));
}

/* initialize round_mode */
void set_rounding_mode(uint8_t round_mode)
{
	int current_round_mode = fe_get_round();
	int next_round_mode;

	switch (round_mode) {
	case RND_TO_0:
		next_round_mode = FE_TOWARDZERO;
		break;
	case RND_TO_PINF:
		next_round_mode = FE_UPWARD;
		break;
	case RND_TO_NINF:
		next_round_mode = FE_DOWNWARD;
		break;
	case RND_TO_NE:
		next_round_mode = FE_TONEAREST;
		break;
	default:
		next_round_mode = FE_TONEAREST;
		break;
	}

	if (current_round_mode != next_round_mode)
		fe_set_round(next_round_mode);
}

uint16_t fp32_to_bf16(float input, int rounding_mode, uint32_t sr_register)
{
	const uint32_t input_uint = *(const uint32_t *) &input;
	uint16_t res = 0;
	uint16_t out_sgn = sbs(input_uint, 31, 31);
	uint16_t out_exp = sbs(input_uint, 30, 23);
	uint16_t out_man = sbs(input_uint, 22, 16);
	bool out_g = (sbs(input_uint, 15, 15) == 1) ? 1 : 0;
	bool out_rs = (sbs(input_uint, 14, 0) != 0) ? 1 : 0;
	/* aligned left for comparing with LFSR[31:0] */
	uint32_t out_grs = sbs(input_uint, 15, 0) << 16;
	bool need_rnd = (((rounding_mode == RND_TO_PINF) && (out_rs || out_g) && (out_sgn == 0)) ||
		((rounding_mode == RND_TO_NINF) && (out_rs || out_g) && (out_sgn == 1)) ||
		((rounding_mode == RND_TO_NE) && ((out_g && out_rs) ||
		(out_g && !out_rs && (sbs(out_man, 0, 0) == 1)))) ||
		((rounding_mode == RND_HALF_AZ) && out_g) ||
		((rounding_mode == RND_SR) && (out_grs >= sr_register)));

	if (is_nan_fp32(input_uint)) {
		res = DEFAULT_NAN_BFP16;
	} else if (is_zero_fp32(input_uint) || is_inf_fp32(input_uint)) {
		/* zero and inf are checked separately to prevent stochastic round up */
		res = sbs(input_uint, 31, 16);
	} else {
		if (!is_denorm_fp32(input_uint) && !is_zero_fp32(input_uint))
			out_man = cbs(1, out_man, 7);
		if (need_rnd) {
			out_man = out_man + 1;
			/* denormal & normal */
			if (out_exp == 0) {
				if (sbs(out_man, 7, 7) == 1)
					out_exp = out_exp + 1;
			} else {
				if (sbs(out_man, 8, 8) == 1)
					out_exp = out_exp + 1;
			}
		}
		/* construct result */
		res = ibs(res, 15, 15, out_sgn);
		res = ibs(res, 14, 7, out_exp);
		res = ibs(res, 6, 0, out_man);
	}

	return res;
}

uint32_t add_fp32(uint32_t a, uint32_t b, uint8_t round_mode)
{
	uint32_t *res;
	float *a_f;
	float *b_f;
	float res_f;

	set_rounding_mode(round_mode);

	/* flush denormal inputs to zero */
	if (is_denorm_fp32(a))
		a = ibs(a, 30, 0, 0); /* a=+-0 */

	if (is_denorm_fp32(b))
		b = ibs(b, 30, 0, 0); /* b=+-0 */

	a_f = (float *) &a;
	b_f = (float *) &b;
	res_f = (*a_f) + (*b_f);
	res = (uint32_t *) &res_f;

	/* flush denormal output to zero */

	if (is_denorm_fp32(*res)) {
		/* flush result to 0 */
		if ((round_mode == RND_TO_PINF) && (sbs(*res, 31, 31) == 0))
			*res = 0x00800000; /* res=+min_normal */
		else if ((round_mode == RND_TO_NINF) && (sbs(*res, 31, 31) == 1))
			*res = 0x80800000; /* res=-min_normal */
		else
			*res = ibs(*res, 30, 0, 0); /* res=+-0 */
	}

	if (is_nan_fp32(*res))
		*res = DEFAULT_NAN_FP32; /* indefinite nan value */

	return *res;
}

static uint16_t add_bf16(uint16_t a, uint16_t b, uint8_t round_mode)
{
	uint32_t a_32bit = cbs(a, 0, 16);
	uint32_t b_32bit = cbs(b, 0, 16);
	uint32_t res_32bit;
	uint16_t res_16bit;
	float *a_f;

	res_32bit = add_fp32(a_32bit, b_32bit, round_mode);
	a_f = (float *) &res_32bit;
	res_16bit = fp32_to_bf16(*a_f, round_mode, 0);

	return res_16bit;
}

static uint8_t get_round_mode(void)
{
	int rounding_mode = fe_get_round();
	uint8_t rounding_mode_to_set = RND_TO_NE;

	switch (rounding_mode) {
	case FE_TONEAREST:
		rounding_mode_to_set = RND_TO_NE;
		break;
	case FE_UPWARD:
		rounding_mode_to_set = RND_TO_PINF;
		break;
	case FE_DOWNWARD:
		rounding_mode_to_set = RND_TO_NINF;
		break;
	case FE_TOWARDZERO:
		rounding_mode_to_set = RND_TO_0;
		break;
	default:
		break;
	}

	return rounding_mode_to_set;
}

static void add_bfloat16(struct bfloat16 *op1, struct bfloat16 *op2, struct bfloat16 *res)
{
	uint32_t fma_rounding_mode = get_round_mode();

	res->_raw = add_bf16(*(const uint16_t *) op1, *(const uint16_t *) op2,
				fma_rounding_mode);
}

static void sub_bfloat16(struct bfloat16 *op1, struct bfloat16 *op2, struct bfloat16 *res)
{
	uint32_t fma_rounding_mode = get_round_mode();

	res->_raw = add_bf16(op1->_raw, (op2->_raw) ^ SIGN_MASK_FP16, fma_rounding_mode);
}

static void max_bfloat16(const struct bfloat16 *op1, const struct bfloat16 *op2,
			struct bfloat16 *res)
{
	float op1_float = bf16_to_f32(*(const uint16_t *) op1);
	float op2_float = bf16_to_f32(*(const uint16_t *) op2);

	*res = (op1_float > op2_float) ? *op1 : *op2;
}

static void min_bfloat16(const struct bfloat16 *op1,  const struct bfloat16 *op2,
			struct bfloat16 *res)
{
	float op1_float = bf16_to_f32(*(const uint16_t *) op1);
	float op2_float = bf16_to_f32(*(const uint16_t *) op2);

	*res = (op1_float < op2_float) ? *op1 : *op2;
}

static void upconvert_bf16(const uint16_t *op, uint32_t *res)
{
	*res = bf16_to_fp32(*op);

	/* denormal floats are converted to +-0 (the sign bit is left as is) */
	if (is_denorm_fp32(*res))
		*res &= SIGN_MASK_FP32;
}

/* Fill the buffer with bfloat16 data. bfloat format:
 * bits     component
 * --------------------------
 *  15      sign
 *  14-7    exponent
 *  6-0     Mantissa/fraction
 */
VOID fill_buffer_bfloat16(struct bfloat16 *buf, uint64_t size)
{
	uint32_t res_32, i;
	uint16_t *rand_val;

	rand_val = hlthunk_malloc(size);
	assert_non_null(rand_val);

	hltests_fill_rand_values(rand_val, size);

	for (i = 0 ; i < (size / sizeof(uint16_t)) ; i++) {
		buf[i]._raw = 0;
		buf[i].sign = rand_val[i] & 15;
		buf[i].exp = (rand_val[i] >> 7) % 0x7f;
		buf[i].mantissa = rand_val[i] % 0x3f;
		/* convert twice to get valid values */
		upconvert_bf16(&buf[i]._raw, &res_32);
		buf[i]._raw = fp32_to_bf16((float) res_32, get_round_mode(), 0);

		/* If the converted value is not a valid number, change it to a known good
		 * number.
		 */
		if (is_inf_bfp16(buf[i]._raw) || is_nan_bf16(buf[i]._raw))
			buf[i]._raw = 0xA5A5;
	}

	hlthunk_free(rand_val);

	END_TEST;
}

/* To create valid FP32 data, we need to take the value from rand API and then cast it to float.
 * Previously, we were taking the value and then casting the pointer to that memory as float
 * pointer and using it. This resulted in invalid float values (denormal and NaN) and made it
 * difficult for calculation.
 */
VOID fill_buffer_fp32(float *buf, uint64_t size)
{
	uint32_t i, *rand_val;

	rand_val = hlthunk_malloc(size);
	assert_non_null(rand_val);

	hltests_fill_rand_values(rand_val, size);

	/* Since we are leveraging on the existing rand value generator, there might be cases
	 * it would generate float NaN or infinity. In those cases, replace it with known good
	 * float value
	 */
	for (i = 0 ; i < (size / sizeof(float)) ; i++) {
		if (is_nan_fp32(rand_val[i]) || is_inf_fp32(rand_val[i]))
			rand_val[i] = 0xA5A5A5A5;
		buf[i] = (float) rand_val[i];
	}

	hlthunk_free(rand_val);

	END_TEST;
}

void calc_reduction_int8(enum hltests_nic_reduction_operation oper, int8_t *src_buf,
			int8_t *dst_buf, int8_t *dst_result, uint64_t data_size)
{
	int8_t *op1 = dst_buf, *op2 = src_buf, *res = dst_result, max = SCHAR_MAX, min = SCHAR_MIN;
	uint64_t i;

	for (i = 0 ; i < data_size ; i++) {
		switch (oper) {
		case HLTESTS_NIC_REDUCTION_OP_ADDITION:
			if (*op1 < 0 && *op2 < 0)
				*res = (*op1 < min - (*op2)) ? min : *op1 + *op2;
			else
				*res = (*op1 > max - *op2) ? max : *op1 + *op2;
			break;
		case HLTESTS_NIC_REDUCTION_OP_SUBTRACTION:
			if (*op2 > 0)
				*res = (*op1 < min + *op2) ? min : *op1 - *op2;
			else
				*res = (*op1 > max + *op2) ? max : *op1 - *op2;
			break;
		case HLTESTS_NIC_REDUCTION_OP_MINIMUM:
			*res = (*op1 < *op2) ? *op1 : *op2;
			break;
		case HLTESTS_NIC_REDUCTION_OP_MAXIMUM:
			*res = (*op1 > *op2) ? *op1 : *op2;
			break;
		default:
			*res = 0xFF; /* error */
		}

		op1++, op2++;
		res++;
	}
}

void calc_reduction_fp32(enum hltests_nic_reduction_operation oper, float *src_buf, float *dst_buf,
			float *dst_result, uint64_t data_size)
{
	float *op1 = dst_buf, *op2 = src_buf, *res = dst_result;
	uint64_t i;

	for (i = 0 ; i < data_size / 4 ; i++) {
		switch (oper) {
		case HLTESTS_NIC_REDUCTION_OP_ADDITION:
			*res = *op1 + *op2;
			break;
		case HLTESTS_NIC_REDUCTION_OP_SUBTRACTION:
			*res = *op1 - *op2;
			break;
		case HLTESTS_NIC_REDUCTION_OP_MINIMUM:
			*res = (*op1 < *op2) ? *op1 : *op2;
			break;
		case HLTESTS_NIC_REDUCTION_OP_MAXIMUM:
			*res = (*op1 > *op2) ? *op1 : *op2;
			break;
		default:
			*res = 0xFF; /* error */
		}

		op1++, op2++;
		res++;
	}
}

void calc_reduction_bf16(enum hltests_nic_reduction_operation oper, struct bfloat16 *src_buf,
			struct bfloat16 *dst_buf, struct bfloat16 *ref_buf, uint64_t data_size)
{
	struct bfloat16 *op1 = dst_buf, *op2 =  src_buf, *ref = ref_buf;
	uint64_t bf16size = data_size / sizeof(struct bfloat16);
	uint64_t i;

	for (i = 0 ; i < bf16size ; i++) {
		switch (oper) {
		case HLTESTS_NIC_REDUCTION_OP_ADDITION:
			add_bfloat16(op1, op2, ref);
			break;
		case HLTESTS_NIC_REDUCTION_OP_SUBTRACTION:
			sub_bfloat16(op1, op2, ref);
			break;
		case HLTESTS_NIC_REDUCTION_OP_MINIMUM:
			min_bfloat16(op1, op2, ref);
			break;
		case HLTESTS_NIC_REDUCTION_OP_MAXIMUM:
			max_bfloat16(op1, op2, ref);
			break;
		/* error */
		default:
			break;
		}

		op1++, op2++, ref++;
	}
}

void calc_reduction_upscale_bf16(enum hltests_nic_reduction_operation oper,
				struct bfloat16 *src_buf, float *dst_buf, float *ref_buf,
				uint64_t data_size)
{
	uint16_t *op2 = (uint16_t *) src_buf;
	float *op1 = dst_buf, *res = ref_buf, op2f;
	uint32_t temp;
	uint64_t i;

	for (i = 0 ; i < data_size / sizeof(struct bfloat16) ; i++) {
		upconvert_bf16(op2, &temp);

		/* we are using temp as temporary buffer to hold the floating point data as uint32.
		 * To preserve the data without modifying the bits, we should copy the memory
		 * If we do a cast, the data bits get modified as per the float spec.
		 */
		memcpy(&op2f, &temp, sizeof(float));

		switch (oper) {
		case HLTESTS_NIC_REDUCTION_OP_ADDITION:
			*res = *op1 + op2f;
			break;
		case HLTESTS_NIC_REDUCTION_OP_SUBTRACTION:
			*res = *op1 - op2f;
			break;
		case HLTESTS_NIC_REDUCTION_OP_MINIMUM:
			*res = (*op1 < op2f) ? *op1 : op2f;
			break;
		case HLTESTS_NIC_REDUCTION_OP_MAXIMUM:
			*res = (*op1 > op2f) ? *op1 : op2f;
			break;
		default:
			*res = 0xFF; /* error */
			break;
		}

		op1++, op2++;
		res++;
	}
}

/* The downscaling happens on the Send side and the reduction operation (add, sub ..) happens
 * on the remote side. So, once we send 100 bytes from application, it gets downscaled to 50 bytes
 * on the send side HW before it gets transferred over RDMA network. Upon reaching the remote side,
 * the reduction operation is performed with this reduced number of bytes.
 * Here, the source buffer is a FP32 buffer which would be downscaled to a BF16 data by the NIC HW.
 * The reduction operation on the remote side would happen with this downscaled BF16 data and the
 * pre-existing BF16 data on the remote side dest buffer
 * Finally we compare the destination buffer with the reference buffer we calculate in the app
 */
void calc_reduction_downscale_bf16(enum hltests_nic_reduction_operation oper, float *src_buf,
				struct bfloat16 *dst_buf, struct bfloat16 *ref_buf,
				uint64_t data_size)
{
	struct bfloat16 bf16val;
	uint32_t i;

	for (i = 0 ; i < (data_size / sizeof(float)) ; i++) {
		bf16val._raw = fp32_to_bf16(*src_buf, 0, 0);

		switch (oper) {
		case HLTESTS_NIC_REDUCTION_OP_ADDITION:
			add_bfloat16(&bf16val, dst_buf, ref_buf);
			break;
		case HLTESTS_NIC_REDUCTION_OP_SUBTRACTION:
			sub_bfloat16(dst_buf, &bf16val, ref_buf);
			break;
		case HLTESTS_NIC_REDUCTION_OP_MINIMUM:
			min_bfloat16(&bf16val, dst_buf, ref_buf);
			break;
		case HLTESTS_NIC_REDUCTION_OP_MAXIMUM:
			max_bfloat16(&bf16val, dst_buf, ref_buf);
			break;
		default:
			break;
		}

		src_buf++, dst_buf++, ref_buf++;
	}
}

void calc_reduction_down_up_bf16(enum hltests_nic_reduction_operation oper, float *src_buf,
				float *dst_buf, float *ref_buf, uint64_t data_size)
{
	struct bfloat16 bf16val;
	float src_buf_down_up;
	uint32_t i, temp;

	for (i = 0 ; i < (data_size / sizeof(float)) ; i++) {
		bf16val._raw = fp32_to_bf16(*src_buf, 0, 0);
		upconvert_bf16(&bf16val._raw, &temp);

		/* we are using temp as temporary buffer to hold the floating point data as uint32.
		 * To preserve the data without modifying the bits, we should copy the memory
		 * If we do a cast, the data bits get modified as per the float spec.
		 */
		memcpy(&src_buf_down_up, &temp, sizeof(float));

		switch (oper) {
		case HLTESTS_NIC_REDUCTION_OP_ADDITION:
			*ref_buf = *dst_buf + src_buf_down_up;
			break;
		case HLTESTS_NIC_REDUCTION_OP_SUBTRACTION:
			*ref_buf = *dst_buf - src_buf_down_up;
			break;
		case HLTESTS_NIC_REDUCTION_OP_MINIMUM:
			*ref_buf = (*dst_buf < src_buf_down_up) ? *dst_buf : src_buf_down_up;
			break;
		case HLTESTS_NIC_REDUCTION_OP_MAXIMUM:
			*ref_buf = (*dst_buf > src_buf_down_up) ? *dst_buf : src_buf_down_up;
			break;
		default:
			*ref_buf = 0xFF; /* error */
			break;
		}

		src_buf++, dst_buf++, ref_buf++;
	}
}

void calc_reduction_reference(void *src_buf, void *dst_buf, void *ref_buf, uint64_t data_size,
				enum hltests_nic_reduction_datatype data_type,
				enum hltests_nic_reduction_operation red_op)
{
	switch (data_type) {
	case HLTESTS_NIC_REDUCTION_INT8:
		calc_reduction_int8(red_op, src_buf, dst_buf, ref_buf, data_size);
		break;
	case HLTESTS_NIC_REDUCTION_BF16:
		calc_reduction_bf16(red_op, src_buf, dst_buf, ref_buf, data_size);
		break;
	case HLTESTS_NIC_REDUCTION_FP32:
		calc_reduction_fp32(red_op, src_buf, dst_buf, ref_buf, data_size);
		break;
	case HLTESTS_NIC_REDUCTION_UPSCALING_BF16:
		/* convert src from bf16 to 32 and then calc the reference buffer, the reference
		 * buffer should be fp32 the dst_buf stays float32.
		 */
		calc_reduction_upscale_bf16(red_op, src_buf, dst_buf, ref_buf, data_size);
		break;
	case HLTESTS_NIC_REDUCTION_DOWNSCALING_TO_BF16:
		calc_reduction_downscale_bf16(red_op, src_buf, dst_buf, ref_buf, data_size);
		break;
	case HLTESTS_NIC_REDUCTION_BF16_DOWN_AND_UP:
		calc_reduction_down_up_bf16(red_op, src_buf, dst_buf, ref_buf, data_size);
		break;
	default:
		break;
	}
}
