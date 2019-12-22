// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>

#include "hlthunk.h"
#include "hlthunk_err_inject.h"
#include "libhlthunk_supp.h"

#define _GNU_SOURCE

#define PAGE_SHIFT_4KB			12
#define PAGE_SHIFT_64KB			16

#define PAGE_SIZE_4KB			(1UL << PAGE_SHIFT_4KB)
#define PAGE_SIZE_64KB			(1UL << PAGE_SHIFT_64KB)

hlthunk_public int hlthunk_err_inject_endless_command(int fd)
{
	struct hlthunk_asic_funcs *asic_funcs = hlthunk_get_asic_funcs(fd);
	struct hlthunk_pkt_info pkt_info;
	struct hlthunk_cb_obj *cb_obj;
	uint64_t seq = 0;
	uint32_t cb_size = 4096, offset = 0;
	int rc, i;

	if (!asic_funcs)
		return -ENODEV;

	cb_obj = hlthunk_create_cb_obj(fd, cb_size, 0);
	if (!cb_obj)
		return -ENOMEM;

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = false;
	pkt_info.mb = false;
	pkt_info.fence.dec_val = 1;
	pkt_info.fence.gate_val = 1;
	pkt_info.fence.fence_id = 0;
	offset = asic_funcs->add_fence_pkt(cb_obj->cb_ptr, offset, &pkt_info);
	rc = hlthunk_submit_and_wait_cs(fd, cb_obj, offset,
					asic_funcs->get_dma_down_qid
						  (DCORE_MODE_FULL_CHIP,
						   STREAM0),
					HL_WAIT_CS_STATUS_TIMEDOUT);

	/* Command lockup generates a soft reset, wait for it to finish */
	for (i = 0 ; i < 5 ; i++) {
		sleep(2);
		if (hlthunk_get_device_status_info(fd) !=
				    HL_DEVICE_STATUS_IN_RESET)
			break;
	}

	/* On success - no need to destroy the CB because device is in reset */
	if (rc)
		hlthunk_destroy_cb(fd, cb_obj);

	return rc;
}

hlthunk_public int hlthunk_err_inject_non_fatal_event(int fd, int *event_num)
{
	return -ENOTSUP;
}

hlthunk_public int hlthunk_err_inject_fatal_event(int fd, int *event_num)
{
	close(fd);

	return -ENOTSUP;
}

hlthunk_public int hlthunk_err_inject_loss_of_heartbeat(int fd)
{
	close(fd);

	return -ENOTSUP;
}

hlthunk_public int hlthunk_err_inject_thermal_event(int fd, int *event_num)
{
	return -ENOTSUP;
}
