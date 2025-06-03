/* SPDX-License-Identifier: MIT
 *
 * Copyright 2022 HabanaLabs, Ltd.
 * All Rights Reserved.
 *
 */

#ifndef INCLUDE_NIC_V1_1_H_
#define INCLUDE_NIC_V1_1_H_

struct nic_cqe_raw {
	uint32_t	data[4];
};

#define CQE_IS_VALID(cqe)		(((cqe)->data[0] >> 31) & 1)
#define CQE_IS_REQ(cqe)			(((cqe)->data[0] >> 24) & 1)
#define CQE_QPN(cqe)			((cqe)->data[0] & 0xFFFFFF)
#define CQE_SET_INVALID(cqe)		((cqe)->data[0] &= ~(1ull << 31))
#define CQE_WQE_IDX(cqe)		((cqe)->data[1])
#define CQE_TAG(cqe)			((cqe)->data[2])
#define CQE_RAW_PKT_SIZE(cqe)		((cqe)->data[3])

#endif /* INCLUDE_NIC_V1_1_H_ */
