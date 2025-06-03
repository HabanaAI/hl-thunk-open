// SPDX-License-Identifier: MIT

/*
 * Copyright 2022 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_tests.h"

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>
#include <fcntl.h>

#define EXTENDED_DEVICE_RELEASE_WATCHDOG_TIMEOUT_SEC	300

struct mapped_mem {
	bool is_host;
	union {
		void *host_ptr;
		uint64_t device_handle;
	};
	uint64_t size;
	uint64_t va;
};

/* allocate and map mem on either host or device according to mem->is_host */
static int get_mapped_mem(int fd, struct mapped_mem *mem)
{
	if (mem->is_host) {
		mem->host_ptr = hlthunk_malloc(mem->size);
		if (!mem->host_ptr)
			return -ENOMEM;
		mem->va = hlthunk_host_memory_map(fd, mem->host_ptr, 0, mem->size);
	} else {
		mem->device_handle = hlthunk_device_memory_alloc(fd, mem->size, 0,
									NOT_CONTIGUOUS, false);
		if (!mem->device_handle)
			return -ENOMEM;
		mem->va = hlthunk_device_memory_map(fd, mem->device_handle, 0);
	}

	return 0;
}

static int free_mem(int fd, struct mapped_mem *mem)
{
	if (mem->is_host) {
		hlthunk_free(mem->host_ptr);
		return 0;
	}

	return hlthunk_device_memory_free(fd, mem->device_handle);
}

static int retrieve_page_fault_info(struct hltests_state *tests_state,
					struct hlthunk_page_fault_info *pgf_info)
{
	int fd = tests_state->fd, rc;

	memset(pgf_info, 0, sizeof(struct hlthunk_page_fault_info));

	pgf_info->mappings_buf = hlthunk_malloc(sizeof(struct hlthunk_user_mapping));
	if (!pgf_info->mappings_buf) {
		printf("Error: can't allocate mapping buffer\n");
		return -ENOMEM;
	}

	rc = hlthunk_get_page_fault_info(fd, pgf_info, 1);
	if (!rc)
		return 0;

	hlthunk_free(pgf_info->mappings_buf);
	/* regular ioctl fail */
	if (pgf_info->num_of_mappings == 0xFFFFFFFF) {
		printf("Error: can't retrieve page fault info\n");
		return rc;
	}

	/* ioctl failed because mappings buffer is too small need to allocate bigger one
	 * and try again
	 */
	if (pgf_info->num_of_mappings) {
		pgf_info->mappings_buf = hlthunk_malloc(pgf_info->num_of_mappings *
				sizeof(struct hlthunk_user_mapping));
		if (!pgf_info->mappings_buf) {
			printf("Error: can't allocate mapping buffer\n");
			return -ENOMEM;
		}
	}

	if (hltests_get_verbose_enabled())
		printf("try to get page fault info with %u mappings first attempt failed with %d\n",
			pgf_info->num_of_mappings, rc);

	rc = hlthunk_get_page_fault_info(fd, pgf_info, pgf_info->num_of_mappings);
	if (rc) {
		printf("Error: can't retrieve page fault info with %u mappings\n",
				pgf_info->num_of_mappings);

		if (pgf_info->num_of_mappings)
			hlthunk_free(pgf_info->mappings_buf);
	}

	return rc;
}

static int verify_page_fault_event(struct hltests_state *tests_state, uint64_t addr, bool is_pmmu)
{
	uint64_t expected_events, received_events;
	struct hlthunk_page_fault_info pgf_info;
	int fd = tests_state->fd, rc;

	expected_events = HL_NOTIFIER_EVENT_PAGE_FAULT |
				HL_NOTIFIER_EVENT_USER_ENGINE_ERR |
				HL_NOTIFIER_EVENT_DEVICE_RESET;
	rc = hltests_wait_for_events(tests_state, 0, expected_events, &received_events);
	if (rc) {
		printf("Failed waiting for page fault events. rc=%d expected 0x%lx got 0x%lx\n", rc,
				expected_events, received_events);
		return rc;
	}

	rc = retrieve_page_fault_info(tests_state, &pgf_info);
	if (rc)
		return rc;

	if (hltests_is_gaudi2(fd)) {
		if (is_pmmu) {
			addr &= 0xFFFFFFFFFFFFFF00;
			pgf_info.addr &= 0xFFFFFFFFFFFFFF00;
		} else {
			/* In HMMU HW scrambles bits 0-25 and this is the captured address */
			addr &= 0xFFFFFFFFFC000000;
		}
	}

	/*
	 * Addresses arriving to PMMU are always aligned to 128B
	 * Addresses read from the stlb/dtlb are always aligned to 128B
	 */
	if (hltests_is_gaudi3(fd)) {
		if (is_pmmu)
			addr &= 0xffffffffffffff80;
		else
			addr &= 0xfffffffffff00000;
	}

	if (addr != pgf_info.addr) {
		printf(
		"Mismatch in page fault address: retrieved (0x%"PRIx64"), expected (0x%"PRIx64")\n",
			pgf_info.addr, addr);
		return -EFAULT;
	}

	return 0;
}

static int trigger_mme_dma_page_fault(int fd, uint64_t dst_va, uint64_t long_addr,
						uint32_t qid, void *cb)
{
	uint32_t cb_size, mme_id = hltests_get_mme_id(fd, qid);
	uint64_t seq;

	cb_size = hltests_prepare_mme_dma_req(fd, cb, 0, long_addr, dst_va, mme_id, MME_DMA_SIZE);
	return hltests_submit_cb(fd, cb, cb_size, qid, 0, &seq);
}

static int trigger_qm_page_fault(int fd, uint64_t long_addr, uint32_t qid, void *cb)
{
	struct hltests_pkt_info pkt_info;
	uint32_t cb_size;
	uint64_t seq;

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.qid = qid;
	pkt_info.msg_long.address = long_addr;
	pkt_info.msg_long.value = 0xbaba0ded;
	cb_size = hltests_add_msg_long_pkt(fd, cb, 0, &pkt_info);

	return hltests_submit_cb(fd, cb, cb_size, qid, 0, &seq);
}

static int trigger_dma_page_fault(int fd, uint64_t long_addr, uint32_t qid, void *cb)
{
	struct hltests_pkt_info pkt_info;
	uint32_t cb_size;
	uint64_t seq;

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.dma.dst_addr = long_addr;
	pkt_info.dma.size = 4;
	pkt_info.dma.memset = 1;
	cb_size = hltests_add_dma_pkt(fd, cb, 0, &pkt_info);

	return hltests_submit_cb(fd, cb, cb_size, qid, 0, &seq);
}

static int trigger_sm_page_fault(int fd, uint64_t long_addr, uint32_t qid, void *cb)
{
	struct hltests_pkt_info pkt_info;
	struct hltests_monitor mon_info;
	uint32_t cb_size = 0;
	uint16_t sob, mon;
	uint64_t seq;

	sob = hltests_get_first_avail_sob(fd);
	mon = hltests_get_first_avail_mon(fd);

	hltests_clear_sobs(fd, 1);

	memset(&mon_info, 0, sizeof(mon_info));
	mon_info.qid = qid;
	mon_info.sob_id = sob;
	mon_info.mon_id = mon;
	mon_info.mon_address = long_addr;
	mon_info.sob_val = 1;
	mon_info.mon_payload = 1;
	mon_info.mon_mode = SOB_EQUAL;
	cb_size = hltests_add_monitor(fd, cb, cb_size, &mon_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id = sob;
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_ADD;
	cb_size = hltests_add_write_to_sob_pkt(fd, cb, cb_size, &pkt_info);

	return hltests_submit_cb(fd, cb, cb_size, qid, 0, &seq);

}

static int enable_error_info_capture(struct hltests_state *tests_state)
{
	struct hl_debug_args debug = {
		.op = HL_DEBUG_ENABLE_ERR_INFO_CAPTURE,
	};
	int rc;

	rc =  hlthunk_debug(tests_state->fd, &debug);
	if (rc)
		return rc;
	return hltests_reset_events(tests_state);
}

static int test_page_fault(struct hltests_state *tests_state, uint32_t qid, bool is_pmmu,
					enum err_trigger trigger)
{
	uint64_t mme_dst_va, long_addr, cb_size;
	struct mapped_mem mem = { 0 };
	int rc, fd = tests_state->fd;
	void *cb, *mme_dram_ptr = NULL;

	if (trigger == TRIG_MME_DMA_ERR)
		cb_size = hltests_get_mme_dma_cb_size(fd, 1, MME_DMA_SIZE);
	else
		cb_size = SZ_4K;

	cb = hltests_create_cb(fd, cb_size, INTERNAL, 0);
	if (!cb)
		return -ENOMEM;

	/* We want to test also the correctness of the captured address, to do so, it's better to
	 * modify address before each iteration. Doing it by using qid to calculate address.
	 */
	mem.size = ((qid % 10) + 1) * SZ_1M;
	mem.is_host = is_pmmu;
	rc = get_mapped_mem(fd, &mem);
	if (rc)
		return rc;

	if (trigger == TRIG_MME_DMA_ERR) {
		/*
		 * for mme dma page fault, we first allocate the dst va before unmapping the
		 * va that cause the page fault.
		 */
		mme_dram_ptr = hltests_allocate_device_mem(fd, MME_DMA_SIZE, 0,
						CONTIGUOUS);
		if (!mme_dram_ptr)
			return -ENOMEM;
		mme_dst_va = (uint64_t) (uintptr_t) mme_dram_ptr;
		long_addr = mem.va + mem.size - SZ_1M;
	} else {
		long_addr = mem.va + mem.size - sizeof(uint64_t);
	}

	/*
	 * We unmap the va and expect to generate a page fault.
	 * It is safer to only unmap the va and not yet free the memory.
	 */
	rc = hlthunk_memory_unmap(fd, mem.va);
	if (rc)
		return rc;

	switch (trigger) {
	case TRIG_QM_ERR:
		rc =  trigger_qm_page_fault(fd, long_addr, qid, cb);
		break;
	case TRIG_DMA_ERR:
		rc = trigger_dma_page_fault(fd, long_addr, qid, cb);
		break;
	case TRIG_SM_ERR:
		rc = trigger_sm_page_fault(fd, long_addr, qid, cb);
		break;
	case TRIG_MME_DMA_ERR:
		rc = trigger_mme_dma_page_fault(fd, mme_dst_va, long_addr, qid, cb);
		break;
	default:
		rc = -EINVAL;
		break;
	}

	if (rc) {
		printf("Failed triggering page fault for qid %u\n", qid);
		return rc;
	}

	rc = verify_page_fault_event(tests_state, long_addr, is_pmmu);
	if (rc) {
		printf("Failed verifying page fault for qid %u\n", qid);
		hltests_destroy_cb(fd, cb);
		return rc;
	}

	/* Cleanup */
	rc = hltests_destroy_cb(fd, cb);
	if (rc) {
		printf("Failed to destroy cb (%d)\n", rc);
		return rc;
	}
	if (mme_dram_ptr) {
		/*
		 * since we don't wait for the mme to finish, we wait here,
		 * to make sure we don't free it before mme finish
		 */
		sleep(WAIT_FOR_CS_DEFAULT_TIMEOUT / 1000000);
		rc = hltests_free_device_mem(fd, mme_dram_ptr);
		if (rc) {
			printf("Failed to free mme dst ptr (%d)\n", rc);
			return rc;
		}
	}

	rc = free_mem(fd, &mem);
	if (rc) {
		printf("Failed to free memory (%d)\n", rc);
		return rc;
	}

	return 0;
}

static int verify_razwi_event(struct hltests_state *tests_state, enum err_trigger type,
			      uint64_t addr, uint16_t qid)
{
	struct hlthunk_event_record_engine_err engine_err;
	struct hlthunk_event_record_razwi_event razwi;
	uint64_t expected_events, received_events;
	int fd = tests_state->fd, rc;
	struct hltests_device *hdev;
	uint16_t engine_id = 0;

	hdev = get_hdev_from_fd(fd);

	expected_events = HL_NOTIFIER_EVENT_RAZWI |
				HL_NOTIFIER_EVENT_USER_ENGINE_ERR |
				HL_NOTIFIER_EVENT_DEVICE_RESET;
	rc = hltests_wait_for_events(tests_state, 0, expected_events, &received_events);
	if (rc) {
		printf("Failed waiting for razwi events. rc=%d expected 0x%lx got 0x%lx\n", rc,
				expected_events, received_events);
		return rc;
	}

	rc = hlthunk_get_event_record(fd, HLTHUNK_RAZWI_EVENT, &razwi);
	if (rc) {
		printf("Failed retrieving razwi event, err = %d\n", rc);
		return rc;
	}

	if (hltests_is_gaudi2(fd) &&
			((type == RAZWI_TYPE_ADDR_DEC) || (type == RAZWI_TYPE_HBW_RR)))
		addr &= 0xFFFFFFFFFFFFFF00;

	if (addr != razwi.addr) {
		printf(
		"Mismatch in razwi address: retrieved (0x%"PRIx64"), expected (0x%"PRIx64")\n",
			razwi.addr, addr);
		return -EFAULT;
	}

	rc = hlthunk_get_event_record(fd, HLTHUNK_ENGINE_EVENT, &engine_err);
	if (rc) {
		printf("Failed retrieving engine error event, err = %d\n", rc);
		return rc;
	}

	engine_id = hdev->asic_funcs->qid_to_eid(qid);

	if (engine_id != engine_err.engine_id) {
		printf("Mismatch with engine id: retrieved %u, expected %u\n",
							engine_err.engine_id, engine_id);
		return -EFAULT;
	}

	return 0;
}

static int trigger_and_verify_razwi(void **state, uint32_t qid, enum err_trigger type)
{
	struct hltests_state *tests_state = *state;
	struct hltests_pkt_info pkt_info;
	uint32_t cb_size = 0;
	uint64_t seq, addr;
	void *cb;
	int rc;

	addr = hltests_get_razwi_addr(tests_state->fd, type);
	/* We want to change razwi address in each iteration for better test coverage */
	if (addr == ULONG_MAX || !addr) {
		printf("%s: bad RAZWI type %u\n", __func__, type);
		return -EINVAL;
	}
	addr += ((qid % 10) * 4);

	cb = hltests_create_cb(tests_state->fd, SZ_4K, EXTERNAL, 0);
	if (!cb)
		return -ENOMEM;

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.msg_long.address = addr;
	pkt_info.msg_long.value = 0x1234abcd;
	cb_size = hltests_add_msg_long_pkt(tests_state->fd, cb, cb_size, &pkt_info);

	hltests_submit_cb(tests_state->fd, cb, cb_size, qid, 0, &seq);

	rc = verify_razwi_event(tests_state, type, addr, qid);
	if (rc) {
		printf("Razwi test failed for qid %u\n", qid);
		return rc;
	}

	/* Cleanup */
	rc = hltests_destroy_cb(tests_state->fd, cb);
	if (rc) {
		printf("Failed to destroy cb\n");
		return rc;
	}

	return 0;
}

static int set_device_release_watchdog_timeout(int fd, uint32_t timeout, uint32_t *old_timeout)
{
	char pci_bus_id[13], path[128], parent_device[16], timeout_str[16] = "";
	int rc = 0, device_idx, parent_device_fd, debugfs_fd;
	ssize_t size;

	if (!can_open_debugfs(true))
		return -EACCES;

	rc = hlthunk_get_pci_bus_id_from_fd(fd, pci_bus_id, sizeof(pci_bus_id));
	if (rc) {
		printf("Failed to get PCI bus ID from fd\n");
		return rc;
	}

	device_idx = hlthunk_get_device_index_from_pci_bus_id(pci_bus_id);
	if (device_idx < 0) {
		printf("Failed to get device index from PCI bus ID\n");
		return -ENODEV;
	}

	snprintf(path, sizeof(path), "/sys/class/accel/accel%d/device/parent_device", device_idx);
	parent_device_fd = open(path, O_RDONLY);
	if (parent_device_fd == -1) {
		printf("Failed to open sysfs parent_device\n");
		return -EPERM;
	}

	size = read(parent_device_fd, parent_device, sizeof(parent_device));
	if (size <= 0) {
		close(parent_device_fd);
		printf("Failed to read from sysfs parent_device, rc %zd\n", size);
		return -errno;
	}

	parent_device[strcspn(parent_device, "\n")] = '\0'; /* remove trailing newline character */
	close(parent_device_fd);

	snprintf(path, sizeof(path), "/sys/kernel/debug/accel/%s/device_release_watchdog_timeout",
			parent_device);

	errno = 0;

	debugfs_fd = open(path, O_RDWR);
	if (debugfs_fd == -1) {
		printf("Failed to open debugfs device_release_watchdog_timeout)\n");
		return -errno;
	}

	if (old_timeout) {
		size = read(debugfs_fd, timeout_str, sizeof(timeout_str));
		if (size < 0) {
			printf("Failed to read from debugfs device_release_watchdog_timeout\n");
			rc = -errno;
			goto close_debugfs_fd;
		}
		*old_timeout = strtol(timeout_str, NULL, 10);
	}

	snprintf(timeout_str, sizeof(timeout_str), "%u", timeout);
	size = write(debugfs_fd, timeout_str, strlen(timeout_str) + 1);
	if (size < 0) {
		printf("Failed to write to debugfs device_release_watchdog_timeout\n");
		rc = -errno;
	}

close_debugfs_fd:
	close(debugfs_fd);

	return rc;
}

typedef int (*neg_test_func_t)(void **, uint32_t, enum err_trigger);

static int call_neg_test_func(void **state, neg_test_func_t neg_test_func, uint32_t qid,
					enum err_trigger type, bool recover_after_each_test)
{
	struct hltests_state *tests_state = *state;
	int rc;

	/* if we don't recover after each test we should re-enable capture error */
	if (!recover_after_each_test) {
		rc = enable_error_info_capture(tests_state);
		if (rc) {
			printf("Failed enabling error info capture\n");
			return rc;
		}
	}

	rc = neg_test_func(state, qid, type);
	if (rc)
		return rc;

	if (!recover_after_each_test)
		return 0;

	/* Recovery */
	rc = hltests_teardown_and_setup(tests_state);
	if (rc)
		return rc;

	/* Sanity check after the recovery */
	if (!hltests_is_device_idle_and_operational(tests_state->fd)) {
		printf("Failed to recover device!\n");
		return -EBUSY;
	}
	return 0;
}

VOID neg_test_iterator(void **state, neg_test_func_t neg_test_func, enum err_trigger type)
{
	struct hltests_state *tests_state = *state;
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;
	bool recover_after_each_test = !hltests_is_pldm(tests_state->fd),
			verbose = hltests_get_verbose_enabled();
	uint32_t qid, cnt, old_timeout;
	int rc, i;

	/* Increase the device release wathcdog timeout if skipping recovery between iterations */
	if (!recover_after_each_test) {
		rc = set_device_release_watchdog_timeout(tests_state->fd,
						EXTENDED_DEVICE_RELEASE_WATCHDOG_TIMEOUT_SEC,
						&old_timeout);
		assert_int_equal(rc, 0);
	}

	/*
	 * HBW msg-long is not supported for pqm, so we skip pdma qid for such tests.
	 * SW-165197: undefined opcode fails for pqm, after solving this, we should not
	 * skip undef opcode tests for pqm
	 */
	if (hltests_is_gaudi3(tests_state->fd) && type == TRIG_QM_ERR)
		goto skip_pqm;

	if (type == TRIG_MME_DMA_ERR)
		goto iter_mme;

	qid = hltests_get_dma_down_qid(tests_state->fd, STREAM0);
	if (verbose)
		printf("iterator: operate on dma down\n");
	rc = call_neg_test_func(state, neg_test_func, qid, type, recover_after_each_test);
	assert_int_equal(rc, 0);

	/* Sync manager tested only with pdma down */
	if (type == TRIG_SM_ERR)
		goto end_test;

	qid = hltests_get_dma_up_qid(tests_state->fd, STREAM0);
	if (verbose)
		printf("iterator: operate on dma up\n");
	rc = call_neg_test_func(state, neg_test_func, qid, type, recover_after_each_test);
	assert_int_equal(rc, 0);

skip_pqm:
	cnt = hltests_get_ddma_cnt(tests_state->fd);
	if (verbose)
		printf("iterator: operate on %u edma engines\n", cnt);
	for (i = 0 ; i < cnt ; i++) {
		qid = hltests_get_ddma_qid(tests_state->fd, i, STREAM0);
		rc = call_neg_test_func(state, neg_test_func, qid, type, recover_after_each_test);
		assert_int_equal(rc, 0);
	}

	/* No more testing for dma type */
	if (type == TRIG_DMA_ERR)
		goto end_test;

	cnt = hltests_get_tpc_cnt(tests_state->fd);
	if (verbose)
		printf("iterator: operate on %u tpc engines\n", cnt);
	for (i = 0 ; i < cnt ; i++)
		if (hw_ip->tpc_enabled_mask_ext & BIT_ULL(i)) {
			qid = hltests_get_tpc_qid(tests_state->fd, i, STREAM0);
			rc = call_neg_test_func(state, neg_test_func, qid, type,
					recover_after_each_test);
			assert_int_equal(rc, 0);
		}

iter_mme:
	cnt = hltests_get_mme_cnt(tests_state->fd, hw_ip->mme_master_slave_mode);
	if (verbose)
		printf("iterator: operate on %u mme engines\n", cnt);
	for (i = 0 ; i < cnt ; i++) {
		/* In Gaudi2, MME1/3 ARCs function as scheduler ARCs */
		if (hltests_is_gaudi2(tests_state->fd) &&
				!hltests_is_legacy_mode_enabled(tests_state->fd) && (i & 0x1))
			continue;

		if (hw_ip->mme_enabled_mask & BIT_ULL(i)) {
			qid = hltests_get_mme_qid(tests_state->fd, i, STREAM0);
			rc = call_neg_test_func(state, neg_test_func, qid, type,
							recover_after_each_test);
			assert_int_equal(rc, 0);
		}
	}

end_test:
	/*
	 * If we don't recover after each test, we should perform a recovery after all
	 * iterations are done and before moving on to the next test.
	 */
	if (!recover_after_each_test) {
		rc = hltests_teardown_and_setup(tests_state);
		assert_int_equal(rc, 0);

		/* Sanity check after the recovery */
		assert_true(hltests_is_device_idle_and_operational(tests_state->fd));

		rc = set_device_release_watchdog_timeout(tests_state->fd, old_timeout, NULL);
		assert_int_equal(rc, 0);
	}

	END_TEST;
}

static int trigger_and_verify_pmmu_page_fault(void **state, uint32_t qid, enum err_trigger type)
{
	struct hltests_state *tests_state = *state;

	return test_page_fault(tests_state, qid, true, type);
}

static int trigger_and_verify_hmmu_page_fault(void **state, uint32_t qid, enum err_trigger type)
{
	struct hltests_state *tests_state = *state;

	return test_page_fault(tests_state, qid, false, type);
}

VOID test_trigger_and_verify_rr_lbw_razwi(void **state)
{
	struct hltests_state *tests_state = *state;

	/* TODO - remove this once SW-172363 is resolved */
	if (hltests_is_gaudi3(tests_state->fd)) {
		printf("Temporarily skipping test due to SW-172363\n");
		skip();
	}

	END_TEST_FUNC(neg_test_iterator(state, trigger_and_verify_razwi, RAZWI_TYPE_LBW_RR));
}

VOID test_trigger_and_verify_rr_hbw_razwi(void **state)
{
	struct hltests_state *tests_state = *state;

	/* TODO - remove this once we configured HBW RR */
	if (hltests_is_gaudi3(tests_state->fd)) {
		printf("HBW RR not configured yet for Gaudi3, temporarily skipping test\n");
		skip();
	}

	END_TEST_FUNC(neg_test_iterator(state, trigger_and_verify_razwi, RAZWI_TYPE_HBW_RR));
}

VOID test_trigger_and_verify_addr_dec_razwi(void **state)
{
	struct hltests_state *tests_state = *state;

	/* TODO - remove this once SW-140711 */
	if (hltests_is_gaudi3(tests_state->fd)) {
		printf("Temporarily skipping test for Gaudi3\n");
		skip();
	}

	END_TEST_FUNC(neg_test_iterator(state, trigger_and_verify_razwi, RAZWI_TYPE_ADDR_DEC));
}

VOID test_trigger_pmmu_qm_page_fault(void **state)
{

	END_TEST_FUNC(neg_test_iterator(state, trigger_and_verify_pmmu_page_fault, TRIG_QM_ERR));
}

VOID test_trigger_pmmu_dma_page_fault(void **state)
{
	END_TEST_FUNC(neg_test_iterator(state, trigger_and_verify_pmmu_page_fault, TRIG_DMA_ERR));
}

VOID test_trigger_pmmu_sm_page_fault(void **state)
{
	END_TEST_FUNC(neg_test_iterator(state, trigger_and_verify_pmmu_page_fault, TRIG_SM_ERR));
}

VOID test_trigger_hmmu_qm_page_fault(void **state)
{
	END_TEST_FUNC(neg_test_iterator(state, trigger_and_verify_hmmu_page_fault, TRIG_QM_ERR));
}

VOID test_trigger_hmmu_dma_page_fault(void **state)
{
	END_TEST_FUNC(neg_test_iterator(state, trigger_and_verify_hmmu_page_fault, TRIG_DMA_ERR));
}

VOID test_trigger_hmmu_sm_page_fault(void **state)
{
	END_TEST_FUNC(neg_test_iterator(state, trigger_and_verify_hmmu_page_fault, TRIG_SM_ERR));
}

VOID test_trigger_hmmu_mme_dma_page_fault(void **state)
{
	struct hltests_state *tests_state = *state;

	if (!hltests_is_mme_dma_enabled(tests_state->fd)) {
		printf("no mme dma - skip\n");
		skip();
	}

	END_TEST_FUNC(neg_test_iterator(state,
		trigger_and_verify_hmmu_page_fault, TRIG_MME_DMA_ERR));
}

static int verify_undefined_opcode_event(struct hltests_state *tests_state, uint32_t qid)
{
	struct hlthunk_event_record_undefined_opcode undef_opcode;
	uint64_t received_events, expected_events;
	int fd = tests_state->fd, rc;

	expected_events = HL_NOTIFIER_EVENT_USER_ENGINE_ERR | HL_NOTIFIER_EVENT_DEVICE_RESET |
				HL_NOTIFIER_EVENT_UNDEFINED_OPCODE;
	rc = hltests_wait_for_events(tests_state, 0, expected_events, &received_events);
	if (rc) {
		printf("Failed waiting to undef opcode events qid=%u expected=0x%lx got 0x%lx\n",
				qid, expected_events, received_events);
		return rc;
	}

	memset(&undef_opcode, 0, sizeof(undef_opcode));

	return hlthunk_get_event_record(fd, HLTHUNK_UNDEFINED_OPCODE, &undef_opcode);
}

static int trigger_and_verify_undefined_opcode(void **state, uint32_t qid,
						enum err_trigger trigger)
{
	struct hltests_state *tests_state = *state;
	struct hltests_pkt_info pkt_info;
	uint64_t seq;
	void *cb;
	int rc, fd = tests_state->fd, cb_size;
	struct hltests_device *hdev = get_hdev_from_fd(fd);

	cb = hltests_create_cb(fd, SZ_4K, INTERNAL, 0);
	assert_non_null(cb);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	cb_size = hdev->asic_funcs->add_undef_opcode_pkt(cb, 0, &pkt_info);

	rc = hltests_submit_cb(fd, cb, cb_size, qid, 0, &seq);
	assert_int_equal(rc, 0);

	rc = verify_undefined_opcode_event(tests_state, qid);
	assert_int_equal(rc, 0);

	rc = hltests_destroy_cb(fd, cb);
	assert_int_equal(rc, 0);

	return rc;
}

VOID test_undefined_opcode_qm(void **state)
{
	END_TEST_FUNC(neg_test_iterator(state, trigger_and_verify_undefined_opcode,
							TRIG_QM_ERR));
}

static uint64_t get_pb_secured_lbw_addr(int fd)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);

	return hdev->asic_funcs->get_pb_secured_addr();
}

static int test_msg_long_to_sec_addr(struct hltests_state *tests_state, uint32_t qid)
{
	uint64_t seq, expected_events, received_events;
	struct hltests_pkt_info pkt_info;
	int rc, fd = tests_state->fd;
	uint32_t cb_size = 0;
	void *cb;

	cb = hltests_create_cb(fd, SZ_4K, INTERNAL, 0);
	if (!cb)
		return -ENOMEM;

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.qid = qid;
	pkt_info.msg_long.address = get_pb_secured_lbw_addr(fd);
	pkt_info.msg_long.value = 0xcafe0000;
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	rc = hltests_submit_cb(fd, cb, cb_size, qid, 0, &seq);
	if (rc)
		return rc;

	expected_events = HL_NOTIFIER_EVENT_USER_ENGINE_ERR | HL_NOTIFIER_EVENT_DEVICE_RESET;
	rc = hltests_wait_for_events(tests_state, 0, expected_events, &received_events);
	if (rc) {
		printf("Failed waiting for user engine events. rc=%d expected=0x%lx got 0x%lx\n",
				rc, expected_events, received_events);
		return rc;
	}

	return hltests_destroy_cb(fd, cb);
}

VOID test_mme_qm_wr_to_sec_addr(void **state)
{
	struct hltests_state *tests_state = *state;
	int fd = tests_state->fd, rc;
	uint32_t qid, old_timeout;
	uint8_t mme_id, mme_cnt;

	if (!tests_state->lkd_security ||
			/* SW-181592: On Gaudi3 devices with secured
			 * FW loaded, driver's security is disabled as well.
			 */
			(hltests_is_gaudi3(fd) && tests_state->hw_ip.security_enabled)) {
		printf("Driver security is disabled - skipping test\n");
		skip();
	}

	if (!tests_state->mme) {
		printf("MMEs are disabled - skipping test\n");
		skip();
	}

	if (hltests_is_pldm(fd)) {
		rc = set_device_release_watchdog_timeout(fd,
						EXTENDED_DEVICE_RELEASE_WATCHDOG_TIMEOUT_SEC,
						&old_timeout);
		assert_int_equal(rc, 0);
	}

	mme_cnt = hltests_get_mme_cnt(fd, tests_state->hw_ip.mme_master_slave_mode);
	for (mme_id = 0 ; mme_id < mme_cnt ; mme_id++) {
		/* In Gaudi2, MME1/3 ARCs function as scheduler ARCs */
		if (hltests_is_gaudi2(fd) && !hltests_is_legacy_mode_enabled(fd) && (mme_id & 0x1))
			continue;

		if (tests_state->hw_ip.mme_enabled_mask & (0x1ULL << mme_id)) {
			qid = hltests_get_mme_qid(fd, mme_id, STREAM0);
			rc = test_msg_long_to_sec_addr(tests_state, qid);
			assert_int_equal(rc, 0);
		}
	}

	/* Recovery is necessary since addressing a secured address is likely to
	 * trigger an event, which might be followed by a STOP_ON_ERR routine.
	 */
	rc = hltests_teardown_and_setup(tests_state);
	assert_int_equal(rc, 0);

	/* Sanity check after the recovery */
	assert_true(hltests_is_device_idle_and_operational(tests_state->fd));

	if (hltests_is_pldm(fd)) {
		rc = set_device_release_watchdog_timeout(tests_state->fd, old_timeout, NULL);
		assert_int_equal(rc, 0);
	}

	END_TEST;
}

VOID test_tpc_qm_wr_to_sec_addr(void **state)
{
	struct hltests_state *tests_state = *state;
	int fd = tests_state->fd, rc;
	uint32_t qid, old_timeout;
	uint8_t tpc_id, tpc_cnt;

	/* TODO - remove skip after SW-149112 is resolved */
	if (hltests_is_gaudi3(fd)) {
		printf("Test is temporarily skipped\n");
		skip();
	}

	if (!tests_state->lkd_security ||
			/* SW-181592: On Gaudi3 devices with secured
			 * FW loaded, driver's security is disabled as well.
			 */
			(hltests_is_gaudi3(fd) && tests_state->hw_ip.security_enabled)) {
		printf("Driver security is disabled - skipping test\n");
		skip();
	}

	if (!tests_state->hw_ip.tpc_enabled_mask_ext) {
		printf("TPCs are disabled - skipping test\n");
		skip();
	}

	if (hltests_is_pldm(fd)) {
		rc = set_device_release_watchdog_timeout(fd,
						EXTENDED_DEVICE_RELEASE_WATCHDOG_TIMEOUT_SEC,
						&old_timeout);
		assert_int_equal(rc, 0);
	}

	tpc_cnt = hltests_get_tpc_cnt(fd);
	for (tpc_id = 0 ; tpc_id < tpc_cnt ; tpc_id++) {
		if (tests_state->hw_ip.tpc_enabled_mask_ext & (0x1ULL << tpc_id)) {
			qid = hltests_get_tpc_qid(fd, tpc_id, STREAM0);
			rc = test_msg_long_to_sec_addr(tests_state, qid);
			assert_int_equal(rc, 0);
		}
	}

	/* Recovery is necessary since addressing a secured address is likely to
	 * trigger an event, which might be followed by a STOP_ON_ERR routine.
	 */
	rc = hltests_teardown_and_setup(tests_state);
	assert_int_equal(rc, 0);

	/* Sanity check after the recovery */
	assert_true(hltests_is_device_idle_and_operational(tests_state->fd));

	if (hltests_is_pldm(fd)) {
		rc = set_device_release_watchdog_timeout(tests_state->fd, old_timeout, NULL);
		assert_int_equal(rc, 0);
	}

	END_TEST;
}

VOID test_sm_mon_wr_to_sec_addr(void **state)
{
	struct hltests_state *tests_state = *state;
	struct hltests_pkt_info pkt_info;
	struct hltests_monitor mon_info;
	uint64_t seq, expected_events;
	uint32_t dma_qid, cb_size = 0;
	int rc, fd = tests_state->fd;
	uint16_t sob, mon;
	void *cb;

	if (!tests_state->lkd_security ||
			/* SW-181592: On Gaudi3 devices with secured
			 * FW loaded, driver's security is disabled as well.
			 */
			(hltests_is_gaudi3(fd) && tests_state->hw_ip.security_enabled)) {
		printf("Driver security is disabled - skipping test\n");
		skip();
	}

	cb = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	assert_non_null(cb);

	dma_qid = hltests_get_dma_down_qid(fd, STREAM0);
	sob = hltests_get_first_avail_sob(fd);
	mon = hltests_get_first_avail_mon(fd);

	hltests_clear_sobs(fd, 1);

	memset(&mon_info, 0, sizeof(mon_info));
	mon_info.qid = dma_qid;
	mon_info.sob_id = sob;
	mon_info.mon_id = mon;
	mon_info.mon_address = get_pb_secured_lbw_addr(fd);
	mon_info.sob_val = 1;
	mon_info.mon_payload = 0xcafe0000;
	mon_info.mon_mode = SOB_EQUAL;
	cb_size = hltests_add_monitor(fd, cb, cb_size, &mon_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = dma_qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id = sob;
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_ADD;
	cb_size = hltests_add_write_to_sob_pkt(fd, cb, cb_size, &pkt_info);

	rc = hltests_submit_cb(fd, cb, cb_size, dma_qid, 0, &seq);
	assert_int_equal(rc, 0);

	expected_events = HL_NOTIFIER_EVENT_USER_ENGINE_ERR | HL_NOTIFIER_EVENT_DEVICE_RESET;
	rc = hltests_wait_for_events(tests_state, 0, expected_events, NULL);
	assert_int_equal(rc, 0);

	rc = hltests_destroy_cb(fd, cb);
	assert_int_equal(rc, 0);

	/* Device recovery */
	rc = hltests_teardown_and_setup(tests_state);
	assert_int_equal(rc, 0);

	/* Sanity check after the recovery */
	assert_true(hltests_is_device_idle_and_operational(tests_state->fd));

	END_TEST;
}

VOID test_edma_qm_wr_to_sec_addr(void **state)
{
	struct hltests_state *tests_state = *state;
	int fd = tests_state->fd, rc;
	uint32_t qid, old_timeout;
	uint8_t edma_id, edma_cnt;

	if (!tests_state->lkd_security ||
			/* SW-181592: On Gaudi3 devices with secured
			 * FW loaded, driver's security is disabled as well.
			 */
			(hltests_is_gaudi3(fd) && tests_state->hw_ip.security_enabled)) {
		printf("Driver security is disabled - skipping test\n");
		skip();
	}

	if (!tests_state->hw_ip.edma_enabled_mask) {
		printf("EDMAs are disabled - skipping test\n");
		skip();
	}

	if (hltests_is_pldm(fd)) {
		rc = set_device_release_watchdog_timeout(fd,
						EXTENDED_DEVICE_RELEASE_WATCHDOG_TIMEOUT_SEC,
						&old_timeout);
		assert_int_equal(rc, 0);
	}

	edma_cnt = hltests_get_ddma_cnt(fd);
	for (edma_id = 0 ; edma_id < edma_cnt ; edma_id++) {
		qid = hltests_get_ddma_qid(fd, edma_id, STREAM0);
		rc = test_msg_long_to_sec_addr(tests_state, qid);
		assert_int_equal(rc, 0);
	}

	/* Recovery is necessary since addressing a secured address is likely to
	 * trigger an event, which might be followed by a STOP_ON_ERR routine.
	 */
	rc = hltests_teardown_and_setup(tests_state);
	assert_int_equal(rc, 0);

	/* Sanity check after the recovery */
	assert_true(hltests_is_device_idle_and_operational(tests_state->fd));

	if (hltests_is_pldm(fd)) {
		rc = set_device_release_watchdog_timeout(tests_state->fd, old_timeout, NULL);
		assert_int_equal(rc, 0);
	}

	END_TEST;
}

VOID test_pdma_qm_wr_to_sec_addr(void **state)
{
	struct hltests_state *tests_state = *state;
	int fd = tests_state->fd, rc;
	uint32_t qid;

	if (!tests_state->lkd_security ||
			/* SW-181592: On Gaudi3 devices with secured
			 * FW loaded, driver's security is disabled as well.
			 */
			(hltests_is_gaudi3(fd) && tests_state->hw_ip.security_enabled)) {
		printf("Driver security is disabled - skipping test\n");
		skip();
	}

	/* TODO - iterate over all PDMA QMAN (PQM) channels to get full coverage,
	 * yet only after SW-103484 is resolved (all PDMA channels are supported).
	 */
	qid = hltests_get_dma_down_qid(fd, STREAM0);
	rc = test_msg_long_to_sec_addr(tests_state, qid);
	assert_int_equal(rc, 0);

	/* Recovery is necessary since addressing a secured address is likely to
	 * trigger an event, which might be followed by a STOP_ON_ERR routine.
	 */
	rc = hltests_teardown_and_setup(tests_state);
	assert_int_equal(rc, 0);

	/* Sanity check after the recovery */
	assert_true(hltests_is_device_idle_and_operational(tests_state->fd));

	END_TEST;
}

VOID test_pdma_eng_rd_from_sec_addr(void **state)
{
	uint32_t cb_size = 0, dma_size = sizeof(uint32_t), dma_qid;
	uint64_t dst_data_dev_va, seq, expected_events;
	struct hltests_state *tests_state = *state;
	struct hltests_pkt_info pkt_info;
	int rc, fd = tests_state->fd;
	void *cb, *dst_data;

	if (!tests_state->lkd_security) {
		printf("Driver security is disabled - skipping test\n");
		skip();
	}

	if (!hltests_is_gaudi3(fd) ||
			/* SW-181592: On Gaudi3 devices with secured
			 * FW loaded, driver's security is disabled as well.
			 */
			(hltests_is_gaudi3(fd) && tests_state->hw_ip.security_enabled)) {
		printf("Test is for gaudi3 only - skip\n");
		skip();
	}

	cb = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	assert_non_null(cb);

	dma_qid = hltests_get_dma_down_qid(fd, STREAM0);

	/* Set PDMA channel as LBW (deliberately sent under a unique CS) */
	cb_size = hltests_add_pdma_ch_bw_config_pkt(fd, cb, cb_size, dma_qid, true);
	rc = hltests_submit_and_wait_cs(fd, cb, cb_size, dma_qid,
				DESTROY_CB_FALSE, HL_WAIT_CS_STATUS_COMPLETED);
	assert_int_equal(rc, 0);

	/* Allocate buffer on host for data transfer */
	dst_data = hltests_allocate_host_mem(fd, dma_size, NOT_HUGE_MAP);
	assert_non_null(dst_data);
	*(uint32_t *)dst_data = 0xcafecafe;
	dst_data_dev_va = hltests_get_device_va_for_host_ptr(fd, dst_data);

	/* LBW --> HBW */

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = dma_qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.dma.src_addr = get_pb_secured_lbw_addr(fd);
	pkt_info.dma.dst_addr = dst_data_dev_va;
	pkt_info.dma.size = dma_size;
	pkt_info.dma.dma_dir = DMA_DIR_SRAM_TO_HOST;
	cb_size = hltests_add_dma_pkt(fd, cb, 0, &pkt_info);

	rc = hltests_submit_cb(fd, cb, cb_size, dma_qid, 0, &seq);
	assert_int_equal(rc, 0);

	expected_events = HL_NOTIFIER_EVENT_USER_ENGINE_ERR | HL_NOTIFIER_EVENT_DEVICE_RESET;
	rc = hltests_wait_for_events(tests_state, 0, expected_events, NULL);
	assert_int_equal(rc, 0);

	/* Verify that the DMA engine failed changing the value saved in dest */
	assert_int_equal(0xcafecafe, *(uint32_t *)dst_data);

	/* Normally, we should return the user channel to work in HBW mode.
	 * In this test, however, we skip it since the PDMA engine halts (as
	 * a part of the STOP_ON_ERR), so there's no point of doing so.
	 * PDMA halt will eventually be followed by a reset that returns all
	 * user channels back to work in HBW mode.
	 */

	rc = hltests_destroy_cb(fd, cb);
	assert_int_equal(rc, 0);

	rc = hltests_free_host_mem(fd, dst_data);
	assert_int_equal(rc, 0);

	/* Recovery is necessary since addressing a secured address is likely to
	 * trigger an event, which might be followed by a STOP_ON_ERR routine.
	 */
	rc = hltests_teardown_and_setup(tests_state);
	assert_int_equal(rc, 0);

	/* Sanity check after the recovery */
	assert_true(hltests_is_device_idle_and_operational(tests_state->fd));

	END_TEST;
}

VOID test_tdr_deadlock(void **state)
{
	END_TEST_FUNC(hltests_tdr_deadlock_test(state, false));
}

VOID test_tdr_deadlock_and_recovery(void **state)
{
	END_TEST_FUNC(hltests_tdr_deadlock_test(state, true));
}

/* It is possible to generate TPC event (core TPC not the TPC QM)
 * without need for a TPC kernel by writing to the TPC cause register.
 * When generating interrupts this way, the tpc_intr_mask register is ignored
 * so we can generate any interrupt regardless of it's bit in the tpc_intr_mask.
 * The tpc_intr_mask register is used only when core raises the interrupt.
 */
int test_generate_tpc_event(struct hltests_state *tests_state, int tpc_idx, int err_idx)
{
	uint64_t expected_events, received_events;
	uint32_t err_mask = BIT(err_idx);
	int fd = tests_state->fd, rc;

	/* this will generate the interrupt */
	WRITE32(hltests_get_tpc_intr_cause_reg(fd, tpc_idx), err_mask);

	expected_events = HL_NOTIFIER_EVENT_USER_ENGINE_ERR | HL_NOTIFIER_EVENT_DEVICE_RESET;
	rc = hltests_wait_for_events(tests_state, 0, expected_events, &received_events);

	if (rc) {
		printf("Failed waiting for events for tpc %d. rc=%d expected=0x%lx got 0x%lx\n",
				tpc_idx, rc, expected_events, received_events);
		return rc;
	}

	/* Recovery */
	rc = hltests_teardown_and_setup(tests_state);
	if (rc)
		return rc;

	/* Sanity check after the recovery */
	if (!hltests_is_device_idle_and_operational(tests_state->fd)) {
		printf("Failed to recover device!\n");
		return -EBUSY;
	}

	return 0;
}

VOID test_tpc_event(void **state)
{
	struct hltests_state *tests_state = *state;
	int fd, err_idx = 0, rc, cnt, i;

	fd = tests_state->fd;

	/* TODO - remove this once SW-182688 is resolved */
	if (hltests_is_gaudi3(tests_state->fd)) {
		printf("Temporarily skipping test due to SW-182688\n");
		skip();
	}

	if (!can_open_debugfs(false)) {
		printf("debugfs not initialized (need sudo) - skip\n");
		skip();
	}

	if (!hltests_is_gaudi2(fd) && !hltests_is_gaudi3(fd)) {
		printf("test is for gaudi2 and gaudi3 only - skip\n");
		skip();
	}

	cnt = hltests_get_tpc_cnt(tests_state->fd);
	for (i = 0 ; i < cnt ; i++) {
		if (tests_state->hw_ip.tpc_enabled_mask_ext & BIT_ULL(i)) {
			rc = test_generate_tpc_event(tests_state, i, err_idx);
			assert_int_equal(rc, 0);
		}
	}

	END_TEST;
}

#ifndef HLTESTS_LIB_MODE

const struct CMUnitTest negative_tests[] = {
	/* RAZWI */
	cmocka_unit_test_setup(test_trigger_and_verify_rr_lbw_razwi,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_trigger_and_verify_rr_hbw_razwi,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_trigger_and_verify_addr_dec_razwi,
				hltests_ensure_device_operational),

	/* Page Fault */
	cmocka_unit_test_setup(test_trigger_pmmu_qm_page_fault,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_trigger_pmmu_dma_page_fault,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_trigger_pmmu_sm_page_fault,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_trigger_hmmu_qm_page_fault,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_trigger_hmmu_dma_page_fault,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_trigger_hmmu_sm_page_fault,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_trigger_hmmu_mme_dma_page_fault,
				hltests_ensure_device_operational),

	/* Undefined Opcode */
	cmocka_unit_test_setup(test_undefined_opcode_qm, hltests_ensure_device_operational),

	/* Secured Address Access */
	cmocka_unit_test_setup(test_mme_qm_wr_to_sec_addr, hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_tpc_qm_wr_to_sec_addr, hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_edma_qm_wr_to_sec_addr, hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_pdma_qm_wr_to_sec_addr, hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_pdma_eng_rd_from_sec_addr, hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_sm_mon_wr_to_sec_addr, hltests_ensure_device_operational),

	/* TDR */
	cmocka_unit_test_setup(test_tdr_deadlock, hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_tdr_deadlock_and_recovery, hltests_ensure_device_operational),

	/* Miscellaneous */
	cmocka_unit_test_setup(test_tpc_event, hltests_ensure_device_operational)
};

static const char *const usage[] = {
	"negative_tests [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = ARRAY_SIZE(negative_tests);

	hltests_parser(argc, argv, usage, HLTEST_DEVICE_MASK_DONT_CARE,
			negative_tests, num_tests);

	if (!hltests_get_parser_run_disabled_tests()) {
		printf("negative tests should run with --disabled option\n");
		return 0;
	}
	if (!hltests_get_parser_events_listener()) {
		printf("events listener must be enabled for negative tests\n");
		return 0;
	}

	hltests_set_capabilities_mask(CAP_ARC_FW_LOAD_SCHED_MASK |
				CAP_ARC_FW_LOAD_MME_MASK |
				CAP_ARC_FW_LOAD_EDMA_MASK |
				CAP_ARC_FW_LOAD_TPC_MASK |
				CAP_ARC_FW_LOAD_PDMA_MASK |
				CAP_MME_DMA_MASK);

	return hltests_run_group_tests("negative_tests", negative_tests, num_tests,
					hltests_setup, hltests_teardown);
}

#endif /* HLTESTS_LIB_MODE */
