// SPDX-License-Identifier: MIT

/*
 * Copyright 2022 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_tests.h"

#include <stdio.h>
#include <pthread.h>
#include <errno.h>

static int hltests_cq_queue_init(int fd, struct hltests_cq_queue *cqq,
					struct sm_global_counters *counters)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;
	struct hltests_cb *cq_cb;
	int rc;

	cqq->pi = 0;
	cqq->ci = 0;
	cqq->length = 4096;
	cqq->cqid = asic->cq_db_get_available_cq(fd);
	cqq->intid = hltests_get_first_avail_interrupt(fd);
	counters->reserved_interrupts++;

	/* Setting HBW memory for cq HBW write */
	cq_cb = &cqq->cq_cb;
	cq_cb->cb_size = sizeof(uint32_t) * cqq->length;
	cqq->log2_size = HL_LOG2(cq_cb->cb_size);

	rc = hlthunk_request_mapped_command_buffer(fd, cq_cb->cb_size, &cq_cb->cb_handle);
	assert_int_equal(rc, 0);

	cq_cb->ptr = hltests_mmap(fd, cq_cb->cb_size, cq_cb->cb_handle);
	assert_ptr_not_equal(cq_cb->ptr, MAP_FAILED);

	rc = hlthunk_get_mapped_cb_device_va_by_handle(fd, cq_cb->cb_handle, &cqq->cq_device_va);
	assert_int_equal(rc, 0);

	memset(cq_cb->ptr, 0, cq_cb->cb_size);
	cqq->data = cq_cb->ptr;

	return 0;
}

int hltests_completion_db_teardown(int fd, struct hltests_completion_db *cq_db)
{
	int rc = 0, tmp_rc;

	cq_db->cq_ready = false;

	tmp_rc = hltests_munmap(fd, cq_db->cqq.cq_cb.ptr, cq_db->cqq.cq_cb.cb_size);
	if (tmp_rc && !rc)
		rc = tmp_rc;

	tmp_rc = hlthunk_destroy_command_buffer(fd, cq_db->cqq.cq_cb.cb_handle);
	if (tmp_rc && !rc)
		rc = tmp_rc;

	tmp_rc = hltests_munmap(fd, cq_db->cq_cb.ptr, cq_db->cq_cb.cb_size);
	if (tmp_rc && !rc)
		rc = tmp_rc;

	tmp_rc = hlthunk_destroy_command_buffer(fd, cq_db->cq_cb.cb_handle);
	if (tmp_rc && !rc)
		rc = tmp_rc;

	hlthunk_free(cq_db->cqs);

	pthread_mutex_destroy(&cq_db->db_lock);
	pthread_mutex_destroy(&cq_db->wait_lock);

	return rc;
}

int hltests_completion_db_init(int fd, struct hltests_completion_db *cq_db)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	const struct hltests_asic_funcs *asic = hdev->asic_funcs;
	struct sm_global_counters *counters = &hdev->counters;
	struct hltests_cq_config cq_config;
	struct hltests_pkt_info pkt_info;
	int rc, i;
	uint32_t cb_size = 0, dma_qid;
	struct hltests_completion_db_e *cq_dbe;
	struct hltests_cb *cq_cb;
	uint64_t cq_device_va;
	void *cb;

	/* Initialize the next sequence number to be allocated for CQ completion.
	 * Such that once completion achieved, submitter id could be extracted
	 * uniquely from the sequence id (lets us distinguish the completions
	 * from multiple submitters).
	 * 0 will be reserved for *unused*.
	 */
	cq_db->next_seq = 1;
	cq_db->max_num_of_cs = 512;

	rc = pthread_mutex_init(&cq_db->db_lock, NULL);
	if (rc) {
		printf("Failed to init CQ DB mutex\n");
		return rc;
	}

	rc = pthread_mutex_init(&cq_db->wait_lock, NULL);
	if (rc) {
		printf("Failed to init CQ DB wait mutex\n");
		pthread_mutex_destroy(&cq_db->db_lock);
		return rc;
	}

	cb = hltests_create_cb(fd, SZ_16K, EXTERNAL, 0);
	if (!cb) {
		pthread_mutex_destroy(&cq_db->db_lock);
		pthread_mutex_destroy(&cq_db->wait_lock);
		return -ENOMEM;
	}

	cq_db->intid = hltests_get_first_avail_interrupt(fd);
	counters->reserved_interrupts++;
	cq_db->cqid = asic->cq_db_get_available_cq(fd);

	/* Allocating data base to hold info about command submission */
	cq_db->cqs = hlthunk_malloc(sizeof(struct hltests_completion_db_e) * cq_db->max_num_of_cs);
	assert_non_null(cq_db->cqs);

	/* Setting HBW memory for cq HBW write */
	cq_cb = &cq_db->cq_cb;
	cq_cb->cb_size = sizeof(uint64_t);

	rc = hlthunk_request_mapped_command_buffer(fd, cq_cb->cb_size, &cq_cb->cb_handle);
	assert_int_equal(rc, 0);

	cq_cb->ptr = hltests_mmap(fd, cq_cb->cb_size, cq_cb->cb_handle);
	assert_ptr_not_equal(cq_cb->ptr, MAP_FAILED);

	rc = hlthunk_get_mapped_cb_device_va_by_handle(fd, cq_cb->cb_handle, &cq_device_va);
	assert_int_equal(rc, 0);

	*(uint64_t *) cq_cb->ptr = 0;
	cq_db->submission_cnt = 0;
	cq_db->curr_cnt = 0;

	dma_qid = hltests_get_dma_down_qid(fd, STREAM0);

	/* Set up the cq */
	memset(&cq_config, 0, sizeof(cq_config));
	cq_config.fd = fd;
	cq_config.qid = dma_qid;
	cq_config.cq_address = cq_device_va;
	cq_config.cq_size_log2 = CQ_SIZE_LOG_2;
	cq_config.cq_id = cq_db->cqid;
	cq_config.interrupt_id = cq_db->intid;
	cq_config.inc_mode = 1;
	cb_size = hltests_add_cq_config_pkt(fd, cb, cb_size, &cq_config);

	hltests_cq_queue_init(fd, &cq_db->cqq, counters);

	cq_db->sync_sob = asic->cq_db_get_available_sob(fd);
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = dma_qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.write_to_sob.value = 0;
	pkt_info.write_to_sob.mode = SOB_SET;
	pkt_info.write_to_sob.sob_id = cq_db->sync_sob;
	cb_size = hltests_add_write_to_sob_pkt(fd, cb, cb_size, &pkt_info);
	cq_db->sync_sob_val = 1;

	/* Set up the cq */
	memset(&cq_config, 0, sizeof(cq_config));
	cq_config.qid = dma_qid;
	cq_config.cq_address = cq_db->cqq.cq_device_va;
	cq_config.cq_size_log2 = cq_db->cqq.log2_size;
	cq_config.cq_id = cq_db->cqq.cqid;
	cq_config.inc_mode = 0;
	cb_size = hltests_add_cq_db_set_cq_queue_pkt(fd, cb, cb_size, &cq_config, cq_db->sync_sob);

	for (i = 0 ; i < cq_db->max_num_of_cs ; ++i) {
		cq_dbe = &cq_db->cqs[i];
		cq_dbe->payload = i + 1;
		cq_dbe->sob[0] = asic->cq_db_get_available_sob(fd);
		cq_dbe->sob[1] = asic->cq_db_get_available_sob(fd);

		/* Clear chosen SOBs before using them */
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.qid = dma_qid;
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_FALSE;
		pkt_info.write_to_sob.value = 0;
		pkt_info.write_to_sob.mode = SOB_SET;
		pkt_info.write_to_sob.sob_id = cq_dbe->sob[0];
		cb_size = hltests_add_write_to_sob_pkt(fd, cb, cb_size, &pkt_info);

		/* Message Barrier should be true only in the last packet */
		pkt_info.write_to_sob.sob_id = cq_dbe->sob[1];
		pkt_info.mb = MB_TRUE;
		cb_size = hltests_add_write_to_sob_pkt(fd, cb, cb_size, &pkt_info);

		cq_dbe->counter_mon = asic->cq_db_get_available_mon(fd);
		cq_dbe->queue_mon = asic->cq_db_get_available_mon(fd);
		cq_dbe->job_completed = false;
	}

	/* TODO: make some virtual function, don't use if */
	if (hltests_is_gaudi2(fd))
		rc = hltests_submit_and_wait_legacy_cs(fd, cb, cb_size, dma_qid,
				DESTROY_CB_FALSE, HL_WAIT_CS_STATUS_COMPLETED);
	else
		rc = hltests_submit_and_wait_cs(fd, cb, cb_size, dma_qid,
				DESTROY_CB_FALSE, HL_WAIT_CS_STATUS_COMPLETED);

	if (rc)
		goto err_free_cq_mem;

	hltests_destroy_cb(fd, cb);

	cq_db->cq_ready = true;

	return 0;

err_free_cq_mem:
	hltests_completion_db_teardown(fd, cq_db);
	hltests_destroy_cb(fd, cb);

	return rc;
}

static int hltests_cq_db_alloc_n(int fd, struct hltests_completion_db *cq_db,
					size_t n, uint64_t *new_seq)
{
	size_t idx0 = cq_db->idx, seq_idx = 0, i, j;

	if (!n)
		return -EINVAL;

	assert_int_equal(pthread_mutex_lock(&cq_db->db_lock), 0);

	/* Iterate through all database indices, trying to allocate n new sequence values */
	do {
		if (!cq_db->cqs[cq_db->idx].seq) {
			new_seq[seq_idx] = cq_db->next_seq + seq_idx;
			cq_db->cqs[cq_db->idx].seq = new_seq[seq_idx];
			cq_db->submission_cnt++;
			cq_db->cqs[cq_db->idx].target_value = cq_db->submission_cnt;
			seq_idx++;
		}

		cq_db->idx = (cq_db->idx + 1) % cq_db->max_num_of_cs;

		if (seq_idx == n) {
			cq_db->next_seq += n;
			goto unlock;
		}
	} while (cq_db->idx != idx0);

	/* didn't find enough - roll back */
	for (i = 0 ; i < cq_db->max_num_of_cs ; ++i) {
		for (j = 0 ; j < seq_idx ; ++j) {
			if (cq_db->cqs[i].seq == new_seq[j])
				cq_db->cqs[i].seq = 0;
		}
	}

unlock:
	assert_int_equal(pthread_mutex_unlock(&cq_db->db_lock), 0);

	return seq_idx == n ? 0 : -ENOMEM;
}

static struct hltests_completion_db_e *cq_db_get_entry(int fd,
				struct hltests_completion_db *cq_db, uint64_t seq)
{
	size_t i;

	/* get a CS entry out of CS database.
	 * We support multiple CS submissions.
	 */
	for (i = 0 ; i < cq_db->max_num_of_cs ; ++i)
		if (cq_db->cqs[i].seq == seq)
			return &cq_db->cqs[i];

	return NULL;
}

static void hltests_cq_patch_cb(int fd, bool is_first_cb_in_cs,
		struct hltests_cs_chunk *chunk, uint32_t num_of_chunks,
		struct hltests_completion_db *cq_db, struct hltests_completion_db_e *cq_dbe)
{
	struct hltests_monitor mon_info;
	struct hltests_pkt_info pkt_info;
	uint32_t *cb_size = &chunk->cb_size;
	void *cb = chunk->cb_ptr;

	/*
	 * Arm cq monitor - it is not really important who does it, so
	 * let it be CB 0.
	 */
	if (is_first_cb_in_cs) {
		cq_dbe->active_sob = !cq_dbe->active_sob;

		/* What we need to do here:
		 * Reset the sob from the previous run;
		 * Set a new sob as active;
		 * Arm monitor to wait for the new sob;
		 */
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.qid = chunk->queue_index;
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_FALSE;
		pkt_info.write_to_sob.sob_id = cq_dbe->sob[!cq_dbe->active_sob];
		pkt_info.write_to_sob.value = 0;
		pkt_info.write_to_sob.mode = SOB_SET;
		*cb_size = hltests_add_write_to_sob_pkt(fd, cb, *cb_size, &pkt_info);

		memset(&mon_info, 0, sizeof(mon_info));
		mon_info.qid = chunk->queue_index;
		mon_info.sob_id = cq_dbe->sob[cq_dbe->active_sob];
		mon_info.mon_id = cq_dbe->queue_mon;
		mon_info.sob_val = num_of_chunks;
		mon_info.mon_payload = cq_dbe->payload;
		mon_info.cq_enable = 1;
		mon_info.cq_id = cq_db->cqq.cqid;
		mon_info.mon_mode = SOB_EQUAL;
		*cb_size = hltests_add_monitor(fd, cb, *cb_size, &mon_info);

		cq_dbe->expected_active_sob_val = num_of_chunks;

		memset(&mon_info, 0, sizeof(mon_info));
		mon_info.qid = chunk->queue_index;
		mon_info.sob_id = cq_db->sync_sob;
		mon_info.mon_id = cq_dbe->counter_mon;
		mon_info.sob_val = cq_db->sync_sob_val;
		mon_info.mon_payload = 1;
		mon_info.cq_enable = 1;
		mon_info.cq_id = cq_db->cqid;
		mon_info.mon_mode = SOB_EQUAL;
		*cb_size = hltests_add_monitor(fd, cb, *cb_size, &mon_info);

		cq_dbe->expected_sync_sob_val = cq_db->sync_sob_val;
		cq_db->sync_sob_val++;
	}

	/* Patch CB - add sync object inc to the end */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = chunk->queue_index;
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id = cq_dbe->sob[cq_dbe->active_sob];
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_ADD;
	*cb_size = hltests_add_write_to_sob_pkt(fd, cb, *cb_size, &pkt_info);
}

static int hltests_cq_db_release_n(int fd, struct hltests_completion_db *cq_db,
				       size_t n, uint64_t *seq_arr)
{
	size_t i, j;

	assert_int_equal(pthread_mutex_lock(&cq_db->db_lock), 0);

	/* release n CSs back to the pool */
	for (i = 0 ; i < cq_db->max_num_of_cs ; ++i) {
		for (j = 0 ; j < n ; ++j) {
			if (cq_db->cqs[i].seq == seq_arr[j])
				cq_db->cqs[i].seq = 0;
		}
	}

	assert_int_equal(pthread_mutex_unlock(&cq_db->db_lock), 0);

	return 0;
}

int hltests_submit_job(int fd, struct hltests_cs_chunk *arr, uint32_t arr_size,
					uint64_t *seq, pthread_mutex_t *lock,
					int (*submitter)(int, struct hltests_cs_chunk *))
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct hltests_completion_db_e *cq_dbe;
	struct hltests_completion_db *cq_db;
	int rc, i;

	if (!arr_size)
		return 0;

	cq_db = &hdev->completion_db;

	rc = hltests_cq_db_alloc_n(fd, cq_db, 1, seq);
	if (rc)
		return -ENOMEM;


	cq_dbe = cq_db_get_entry(fd, cq_db, *seq);
	assert_non_null(cq_dbe);

	assert_int_equal(pthread_mutex_lock(lock), 0);

	for (i = 0 ; i < arr_size ; i++) {
		/* Unlike in legacy mode, cb size of cs_chunk is changed before submission in
		 * hltests_cq_patch_cb. Since it is common in tests to send the same CS multiple
		 * times, it is necessary to save the original size, and set back to it
		 * after submission.
		 */
		uint32_t orig_cb_size = arr[i].cb_size;

		hltests_cq_patch_cb(fd, !i, &arr[i], arr_size, cq_db, cq_dbe);

		rc = submitter(fd, &arr[i]);
		if (rc) {
			arr[i].cb_size = orig_cb_size;
			hltests_cq_db_release_n(fd, cq_db, 1, seq);
			goto unlock;
		}

		arr[i].cb_size = orig_cb_size;
	}

unlock:
	assert_int_equal(pthread_mutex_unlock(lock), 0);

	return rc;
}

static void release_pending_cqq_job(struct hltests_completion_db *c, uint32_t idx)
{
	c->cqs[c->cqq.data[idx] - 1].job_completed = true;
	c->cqq.data[idx] = 0;
}

static void release_all_pending_cqq_jobs(struct hltests_completion_db *c)
{
	int i;

	if (c->cqq.ci < c->cqq.pi) {
		for (i = c->cqq.ci ; i < c->cqq.pi ; i++)
			release_pending_cqq_job(c, i);
	/* In case of PI wrap around */
	} else if (c->cqq.ci > c->cqq.pi) {
		/* Loop from CI till end of buffer */
		for (i = c->cqq.ci ; i < c->cqq.length ; i++)
			release_pending_cqq_job(c, i);
		/* Loop from start of buffer till PI */
		for (i = 0 ; i < c->cqq.pi ; i++)
			release_pending_cqq_job(c, i);
	}

	c->cqq.ci = c->cqq.pi;
}

static void get_time_usec(uint64_t *usec)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);

	*usec = (USEC_PER_SEC * t.tv_sec) + (t.tv_nsec / NSEC_PER_USEC);
}

static void time_usec_to_timespec(uint64_t us, struct timespec *t)
{
	t->tv_sec = us / USEC_PER_SEC;
	t->tv_nsec = (us % USEC_PER_SEC) * NSEC_PER_USEC;
}

static int wait_for_interrupt_mutex(int fd, struct hltests_completion_db *cq_db,
				struct hltests_completion_db_e *cq_dbe, uint64_t seq,
				uint64_t timeout_us)
{
	int rc;

	if (pthread_mutex_trylock(&cq_db->wait_lock) == 0) {
		rc = hltests_wait_for_interrupt_by_handle(fd, cq_db->cq_cb.cb_handle, 0,
								cq_dbe->target_value,
								cq_db->intid, timeout_us);

		if (rc == HL_WAIT_CS_STATUS_COMPLETED) {
			/* wait for interrupts completes successfully, now need to check
			 * which jobs were completed.
			 */
			cq_db->curr_cnt = *(uint64_t *)cq_db->cq_cb.ptr;
			cq_db->cqq.pi = cq_db->curr_cnt % cq_db->cqq.length;

			release_all_pending_cqq_jobs(cq_db);
			pthread_mutex_unlock(&cq_db->wait_lock);
		} else {
			const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

			printf(
				"Failed waiting on: dbe_sob %u -> q_mon %u -> cqq_cqid %u -> sync_sob %u -> cnt_mon %u -> cq %u\n",
					cq_dbe->sob[cq_dbe->active_sob],
					cq_dbe->queue_mon, cq_db->cqq.cqid, cq_db->sync_sob,
					cq_dbe->counter_mon, cq_db->cqid);
			if (hltests_get_verbose_enabled() && asic->debug_completion)
				asic->debug_completion(fd, cq_dbe->sob[cq_dbe->active_sob],
								cq_db->sync_sob,
								cq_dbe->expected_active_sob_val,
								cq_dbe->expected_sync_sob_val);
			fflush(stdout);
			/* wait fails, if staus is busy, keep the job in db */
			if (rc != HL_WAIT_CS_STATUS_BUSY)
				hltests_cq_db_release_n(fd, cq_db, 1, &seq);
			pthread_mutex_unlock(&cq_db->wait_lock);
			return rc;
		}
	}

	return 0;
}

int hltests_wait_for_job(int fd, uint64_t seq, int64_t timeout_us)
{
	struct hltests_device *hdev;
	struct hltests_completion_db_e *cq_dbe;
	struct hltests_completion_db *cq_db;
	struct timespec t;
	uint64_t t1, t2;
	int rc;

	hdev = get_hdev_from_fd(fd);
	cq_db = &hdev->completion_db;
	cq_dbe = cq_db_get_entry(fd, cq_db, seq);

	if (!cq_dbe)
		return -ENOENT;

	do {
		/* In case this specific job has been completed */
		if (cq_dbe->job_completed) {
			cq_dbe->job_completed = false;
			hltests_cq_db_release_n(fd, cq_db, 1, &seq);
			return HL_WAIT_CS_STATUS_COMPLETED;
		}

		get_time_usec(&t1);
		/* Only one thread will wait for interrupt */
		rc = wait_for_interrupt_mutex(fd, cq_db, cq_dbe, seq, timeout_us);
		if (rc)
			return rc;

		time_usec_to_timespec(timeout_us, &t);

		/* Wait for wait_for_interrupt completion, in case of multiple threads waiting on
		 * it, all waiting threads will take the lock almost at the same time. Each thread
		 * will take the lock and will release it immediatlly to the next one.
		 * Corner case which is not handled and need to be considered :
		 * Thread A took the wait lock so thread B is waiting here. Once A wait finished
		 * and it releases A and B locks and then the wait lock. Before B took the wait
		 * lock, new thread appears, C, and takes the lock. In that case, although B is
		 * already completed, user will get an indication about it only after C will release
		 * the lock.
		 */
		if (pthread_mutex_timedlock(&cq_db->wait_lock, &t) == 0)
			pthread_mutex_unlock(&cq_db->wait_lock);

		get_time_usec(&t2);
		timeout_us -= (t2 - t1);

	} while (timeout_us > 0);

	return HL_WAIT_CS_STATUS_BUSY;
}
