/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef __SW_QUEUES_H__
#define __SW_QUEUES_H__

#include "arc_types.h"

/**
 * \file    sw_queues.h
 * \brief   Software Queues APIs
 */

struct sw_queue_node_t {
	void *data;
	struct sw_queue_node_t *next;
};

struct sw_queue_t {
	struct sw_queue_node_t head;
	struct sw_queue_node_t *tail;
};

void sw_queue_push(struct sw_queue_t *queue, struct sw_queue_node_t *node);
struct sw_queue_node_t* sw_queue_pop(struct sw_queue_t *queue);
struct sw_queue_node_t* sw_queue_remove(struct sw_queue_t *queue, void *data);

#endif /* __SW_QUEUES_H__ */
