// SPDX-License-Identifier: MIT

/*
 * Copyright 2022 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_nic_tests.h"

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <pthread.h>
#include <poll.h>
#include <fcntl.h>

#include <infiniband/hbldv.h>

#define HBL_IB_EQ_PORT_FIELD_MASK 0xFFFF
#define HBL_IB_EQ_PORT_FIELD_SIZE 16
#define HBL_IB_EQ_EVENT_TYPE_MASK 0xFFFF
#define HBL_IB_EQ_EVENT_TYPE_SIZE 16

static int parse_eqe(int fd, uint32_t port, struct hlthunk_nic_eq_poll_out *eqe)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	int is_error = 1;

	switch (eqe->ev_type) {
	case HL_NIC_EQ_EVENT_TYPE_CQ_ERR:
		printf("Port %u: got CQ %u error, PI 0x%x\n",
			port, eqe->idx, eqe->ev_data);
		break;
	case HL_NIC_EQ_EVENT_TYPE_QP_ERR:
		hdev->asic_funcs->nic_funcs->parse_eqe_qp_syndrome(port, eqe);
		break;
	case HL_NIC_EQ_EVENT_TYPE_DB_FIFO_ERR:
		printf("Port %u: got DB FIFO %u error\n", port, eqe->idx);
		break;
	case HL_NIC_EQ_EVENT_TYPE_CCQ:
		printf("Port %u: got completion on congestion CQ %u\n", port, eqe->idx);
		is_error = 0;
		break;
	case HL_NIC_EQ_EVENT_TYPE_WTD_SECURITY_ERR:
		printf("Port %u: got WTD security error on QP %u\n", port, eqe->idx);
		break;
	case HL_NIC_EQ_EVENT_TYPE_NUMERICAL_ERR:
		printf("Port %u: got numerical error on QP %u\n", port, eqe->idx);
		break;
	case HL_NIC_EQ_EVENT_TYPE_LINK_STATUS:
		printf("Port %u: got link %s\n", port, eqe->ev_data ? "up" : "down");
		is_error = 0;
		break;
	case HL_NIC_EQ_EVENT_TYPE_QP_ALIGN_COUNTERS:
		printf("Port %u: got QP align counters on QP %u\n", port, eqe->idx);
		is_error = 0;
		break;
	default:
		printf("Unknown event %u\n", eqe->ev_type);
	}

	return is_error;
}

static int parse_ib_eqe(struct hltests_nic_eq *eq, struct ibv_async_event *event)
{
	struct hltests_device *hdev = get_hdev_from_fd(eq->fd);
	struct hbldv_query_qp_attr dv_qp_attr = {};
	struct hlthunk_nic_eq_poll_out eqe;
	struct ibv_qp_init_attr init_attr;
	int attr_mask = IBV_QP_PORT;
	struct ibv_qp_attr attr;
	struct ibv_qp *evqp;
	struct ibv_cq *evcq;
	int is_error = 1;
	uint32_t port;

	/* We parse here events that we agreed to handle.
	 * There is no way to pass syndrome value to user via IBv and hence the syndrome
	 * for QP errors will be printed to the dmesg.
	 */
	switch (event->event_type) {
	case IBV_EVENT_QP_FATAL:
		evqp = event->element.qp;
		hbldv_query_qp(evqp, &dv_qp_attr);
		printf("QP fatal event for QP with handle %p, IBv qp num %d, qp state %d\n",
			evqp, dv_qp_attr.qp_num, evqp->state);
		eqe.idx = dv_qp_attr.qp_num;
		if (hlibv_query_qp(evqp, &attr, attr_mask, &init_attr)) {
			printf("Failed querying qp %d\n", eqe.idx);
			break;
		}

		/* TODO: SW-151494 - qp_access_flags is used as a placeholder for QP syndrome */
		eqe.ev_data = attr.qp_access_flags;
		port = attr.port_num;
		hdev->asic_funcs->nic_funcs->parse_eqe_qp_syndrome(port, &eqe);
		break;
	case IBV_EVENT_QP_REQ_ERR:
		evqp = event->element.qp;
		hbldv_query_qp(evqp, &dv_qp_attr);
		printf("QP Requestor error for QP with handle %p, IBv qp num %d, qp state %d\n",
			evqp, dv_qp_attr.qp_num, evqp->state);
		eqe.idx = dv_qp_attr.qp_num;
		if (hlibv_query_qp(evqp, &attr, attr_mask, &init_attr)) {
			printf("Failed querying qp %d\n", eqe.idx);
			break;
		}

		/* TODO: SW-151494 - qp_access_flags is used as a placeholder for QP syndrome */
		eqe.ev_data = attr.qp_access_flags;
		port = attr.port_num;
		hdev->asic_funcs->nic_funcs->parse_eqe_qp_syndrome(port, &eqe);
		break;
	/* TODO: SW-151494 - Mapping for HL_NIC_EQ_EVENT_TYPE_QP_ALIGN_COUNTERS */
	case IBV_EVENT_QP_LAST_WQE_REACHED:
		evqp = event->element.qp;
		hbldv_query_qp(evqp, &dv_qp_attr);
		printf("QP align counters with handle %p, IBv qp num %d, qp state %d\n",
			evqp, dv_qp_attr.qp_num, evqp->state);
		is_error = 0;
		break;
	case IBV_EVENT_CQ_ERR:
		evcq = event->element.cq;
		printf("CQ error for CQ with handle %p cqe %d\n", evcq, evcq->cqe);
		break;
	case IBV_EVENT_PORT_ACTIVE:
		printf("Link up, port %d\n", event->element.port_num);
		is_error = 0;
		break;
	case IBV_EVENT_PORT_ERR:
		printf("Link down, port %d\n", event->element.port_num);
		is_error = 0;
		break;
	/* TODO: SW-151494 - Mapping for HL_NIC_EQ_EVENT_TYPE_DB_FIFO_ERR */
	case IBV_EVENT_DEVICE_FATAL:
		if ((event->element.port_num & HBL_IB_EQ_PORT_FIELD_MASK)
		    == HBL_IB_EQ_PORT_FIELD_MASK)
			printf("Got FATAL EVENT error for ASID %u\n",
				event->element.port_num >> HBL_IB_EQ_PORT_FIELD_SIZE);
		else
			printf("Port %u: got DB FIFO %u error\n",
				event->element.port_num & HBL_IB_EQ_PORT_FIELD_MASK,
				event->element.port_num >> HBL_IB_EQ_PORT_FIELD_SIZE);
		break;
	/* TODO: SW-151494 - Mapping for HL_NIC_EQ_EVENT_TYPE_CCQ */
	case IBV_EVENT_SM_CHANGE:
		printf("Port %u: got completion on congestion CQ %u\n",
			event->element.port_num & HBL_IB_EQ_PORT_FIELD_MASK,
			event->element.port_num >> HBL_IB_EQ_PORT_FIELD_SIZE);
		is_error = 0;
		break;
	/* TODO: SW-151494 - Mapping for HL_NIC_EQ_EVENT_TYPE_WTD_SECURITY_ERR */
	case IBV_EVENT_PATH_MIG:
		evqp = event->element.qp;
		hbldv_query_qp(evqp, &dv_qp_attr);
		printf("got WTD security error on QP with handle %p, IBv qp num %d, qp state %d\n",
			evqp, dv_qp_attr.qp_num, evqp->state);
		break;
	/* TODO: SW-151494 - Mapping for HL_NIC_EQ_EVENT_TYPE_NUMERICAL_ERR */
	case IBV_EVENT_PATH_MIG_ERR:
		evqp = event->element.qp;
		hbldv_query_qp(evqp, &dv_qp_attr);
		printf("got numerical error on QP with handle %p, IBv qp num %d, qp state %d\n",
			evqp, dv_qp_attr.qp_num, evqp->state);
		break;
	/* TODO: SW-151494 - Mapping for HBL_CNI_EQ_EVENT_TYPE_LINK_SHUTDOWN */
	case IBV_EVENT_LID_CHANGE:
		printf("LINK SHUTDOWN event on ib port %u\n", event->element.port_num);
		is_error = 0;
		eq->link_shutdown_port = hltests_ibdev_to_nic_port_num(event->element.port_num);
		break;
	default:
		printf("Unknown event (%d)\n", event->event_type);
		break;
	}

	return is_error;
}

static void *nic_eq_th(void *args)
{
	struct hltests_nic_eq *eq = (struct hltests_nic_eq *) args;
	struct hlthunk_nic_eq_poll_out out;
	int rc, port, fd = eq->fd;

	while (1) {
		for (port = 0 ; port < eq->num_of_ports ; port++) {
			if (!(eq->ports_mask & BIT_ULL(port)))
				continue;

			rc = hlthunk_nic_eq_poll(fd, port, &out);
			if (rc)
				return NULL;

			switch (out.poll_status) {
			case HL_NIC_EQ_POLL_STATUS_SUCCESS:
				eq->is_error_event |= parse_eqe(fd, port, &out);
				break;
			case HL_NIC_EQ_POLL_STATUS_EQ_EMPTY:
				break;
			default:
				printf("WARN: EQ poll status is %d on port %d\n", out.poll_status,
					port);
			}
		}

		usleep(1000);
	}

	return args;
}

static void *nic_ib_eq_th(void *args)
{
	struct hltests_nic_eq *eq = (struct hltests_nic_eq *) args;
	struct ibv_async_event ibev = {0};
	struct pollfd pollfd;
	int flgs, rc;

	flgs = fcntl(eq->ibctx->async_fd, F_GETFL);
	rc = fcntl(eq->ibctx->async_fd, F_SETFL, flgs | O_NONBLOCK);

	if (rc) {
		printf("Error, failed to change file descriptor of async event queue\n");
		return NULL;
	}

	pollfd.fd = eq->ibctx->async_fd;
	pollfd.events = POLLIN;
	pollfd.revents = 0;

	while (1) {
		rc = poll(&pollfd, 1, 100);
		if (rc < 0) {
			printf("Failed to poll events\n");
			return NULL;
		} else if (!rc)
			continue;

		/* If we managed to poll, it doesn't guarantee that there is an event to read
		 * as it is possible in multi thread scenario to exit poll, but only one thread
		 * will manage to read the event, the rest should return to poll mode.
		 */
		rc = hlibv_get_async_event(eq->ibctx, &ibev);
		if (rc)
			continue;

		eq->is_error_event |= parse_ib_eqe(eq, &ibev);

		hlibv_ack_async_event(&ibev);
	}

	return args;
}

int nic_eq_poll(int fd, struct hltests_nic_eq *eq, struct ibv_context *ibctx)
{
	int rc;

	eq->num_of_ports = hltests_nic_get_max_num_of_ports(fd);
	eq->fd = fd;
	eq->ibctx = ibctx;

	rc = pthread_create(&eq->thread_id, NULL,
				hltests_nic_is_ibdev(fd) ? nic_ib_eq_th : nic_eq_th, eq);
	assert_int_equal(rc, 0);

	return 0;
}

int nic_eq_poll_stop(struct hltests_nic_eq *eq)
{
	void *retval;
	int rc;

	/* kill thread */
	rc = pthread_cancel(eq->thread_id);
	assert_int_equal(rc, 0);
	rc = pthread_join(eq->thread_id, &retval);
	assert_int_equal(rc, 0);
	assert_true(retval == PTHREAD_CANCELED);
	assert_int_equal(eq->is_error_event, 0);

	return 0;
}
