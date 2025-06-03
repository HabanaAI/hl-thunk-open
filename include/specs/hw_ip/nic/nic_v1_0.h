/* SPDX-License-Identifier: MIT
 *
 * Copyright 2020 HabanaLabs, Ltd.
 * All Rights Reserved.
 *
 */

#ifndef INCLUDE_NIC_V1_0_H_
#define INCLUDE_NIC_V1_0_H_

struct nic_cqe_raw {
	uint64_t data;
};

#define CQE_IS_VALID(cqe)	(((cqe)->data >> 63) & 1)
#define CQE_TYPE(cqe)		(((cqe)->data >> 23) & 1)
#define CQE_RES_NIC(cqe)	(((cqe)->data >> 10) & 1)
#define CQE_RES_IMDT_21_0(cqe)	(((cqe)->data >> 32) & 0x3FFFFF)
#define CQE_RES_IMDT_31_22(cqe)	((cqe)->data & 0x3FF)
#define CQE_REQ_WQE_IDX(cqe)	(((cqe)->data >> 32) & 0x3FFFFF)
#define CQE_REQ_QPN(cqe)	((cqe)->data & 0x7FFFFF)
#define CQE_SET_INVALID(cqe)	((cqe)->data &= ~(1ull << 63))

#endif /* INCLUDE_NIC_V1_0_H_ */
