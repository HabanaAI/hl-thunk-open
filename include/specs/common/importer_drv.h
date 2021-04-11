/* SPDX-License-Identifier: MIT
 *
 * Copyright 2021 HabanaLabs, Ltd.
 * All Rights Reserved.
 *
 */

#ifndef IMPORTER_DRV_H
#define IMPORTER_DRV_H

#include <linux/types.h>
#include <linux/ioctl.h>

struct hl_importer_reg_dmabuf_mr_in {
	__u64 offset;
	__u64 length;
	__u64 iova;
	__u32 fd;
	__u32 access_flags;
	__u64 res[4];
};

struct hl_importer_reg_dmabuf_mr_out {
	__u64 mr_handle;
	__u64 res[7];
};

union hl_importer_reg_dmabuf_mr_args {
	struct hl_importer_reg_dmabuf_mr_in in;
	struct hl_importer_reg_dmabuf_mr_out out;
};

struct hl_importer_dereg_mr_args {
	__u64 mr_handle;
	__u64 res[3];
};

struct hl_importer_write_to_mr_args {
	__u64 mr_handle;
	__u64 userptr;
	__u32 size;
	__u32 pad;
	__u64 res;
};

struct hl_importer_read_from_mr_args {
	__u64 mr_handle;
	__u64 userptr;
	__u32 size;
	__u32 pad;
	__u64 res;
};

/* Register the DMABUF and return an "MR" that is associated with it */
#define HL_IMPORTER_IOCTL_REG_DMABUF_MR \
			_IOWR('I', 0x01, union hl_importer_reg_dmabuf_mr_args)

#define HL_IMPORTER_IOCTL_DEREG_MR \
			_IOWR('I', 0x02, struct hl_importer_dereg_mr_args)

#define HL_IMPORTER_IOCTL_WRITE_TO_MR \
			_IOWR('I', 0x03, struct hl_importer_write_to_mr_args)

#define HL_IMPORTER_IOCTL_READ_FROM_MR \
			_IOWR('I', 0x04, struct hl_importer_read_from_mr_args)

#define HL_IMPORTER_COMMAND_START	0x01
#define HL_IMPORTER_COMMAND_END		0x05

#endif /* IMPORTER_DRV_H */
