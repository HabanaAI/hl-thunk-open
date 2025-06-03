/* SPDX-License-Identifier: MIT */

/*
 * Copyright 2019-2023 HabanaLabs, Ltd.
 * All Rights Reserved.
 */
#ifndef _NIC_ROOT_H_
#define _NIC_ROOT_H_

/* TODO: SW-191297 include infiniband/driver.h instead */
enum ibv_gid_type_sysfs {
	IBV_GID_TYPE_SYSFS_IB_ROCE_V1,
	IBV_GID_TYPE_SYSFS_ROCE_V2,
};

/* TODO: SW-191297 include infiniband/driver.h instead */
int hlibv_query_gid_type(struct ibv_context *context, uint8_t port_num,
			 unsigned int index, enum ibv_gid_type_sysfs *type);

#endif /* _NIC_ROOT_H_*/
