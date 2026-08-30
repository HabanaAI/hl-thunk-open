/* SPDX-License-Identifier: MIT
 *
 * Copyright 2019-2023 HabanaLabs, Ltd.
 * All Rights Reserved.
 *
 */

#ifdef FS_DISABLED

#ifndef HLTHUNK_NIC_TESTS_EXT_H
#define HLTHUNK_NIC_TESTS_EXT_H

/* Maximum amount of Collective Scheduler resources */
#define HBLDV_MAX_NUM_COLL_SCHED_RESOURCES	256

/**
 * struct hbldv_coll_sched_resource - Collective Scheduler resource.
 * @id: The resource's absolute index in the chip.
 *      If a resource has multiple copies in each NMS, each copy will be exposed with a unique ID
 *      that can be devised through NMS index * (copies per NMS) + copy index.
 * @size: The size of the resource.
 * @pa_offs: Offset of the resource relative to the LBW address base.
 * @virt_addr: Process memory mapped address of resource.
 */
struct hbldv_coll_sched_resource {
	uint8_t id;
	size_t size;
	uint32_t pa_offs;
	void *virt_addr;
};

/**
 * struct hbldv_coll_sched_resource - Collective Scheduler resource.
 * @num_resources: How many resources have been allocated.
 * @rsrc: Array of allocated resources.
 */
struct hbldv_coll_sched_resources {
	int num_resources;
	struct hbldv_coll_sched_resource rsrc[HBLDV_MAX_NUM_COLL_SCHED_RESOURCES];
};

int hbldv_reserve_coll_sched_resources(struct ibv_context *context,
				       struct hbldv_coll_sched_resources *sched_resrc);

#endif
#endif
