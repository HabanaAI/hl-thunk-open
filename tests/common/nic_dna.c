// SPDX-License-Identifier: MIT

/*
 * Copyright 2019-2023 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_nic_tests.h"
#include "ini.h"

#include <unistd.h>
#include <fcntl.h>

#define DNA_REM_BUFF_SIZE	256
#define DNA_PRBS_PATTERN	0x55555555AAAAAAAA
#define DNA_QPC_DUMP_SIZE	SZ_4K
#define DNA_CMD_SIZE		20

static int nic_dna_parser(void *user, const char *section, const char *name, const char *value)
{
	struct hltests_nic_dna_cfg *cfg = (struct hltests_nic_dna_cfg *)user;

	if (MATCH("dna", "iterations"))
		cfg->num_iterations = strtoul(value, NULL, 0);
	else if (MATCH("dna", "rank"))
		cfg->rank = strtoul(value, NULL, 0);
	else if (MATCH("dna", "port"))
		cfg->port = strtoul(value, NULL, 0);
	else if (MATCH("dna", "dump_rem_buf"))
		cfg->dump_buf = strtoul(value, NULL, 0);

	return 1;
}

static int nic_dna_debugfs_trigger_prbs(int fd, uint8_t rank, uint32_t port, uint64_t rem_buf_phys)
{
	ssize_t size;
	int rc = 0, tmp_fd;
	char path[PATH_MAX];
	char val_str[20] = "";

	snprintf(path, PATH_MAX, "/sys/kernel/debug/habanalabs_cn/hbl_cn0/nic_dna_prbs_trigger");

	tmp_fd = open(path, O_RDWR);
	if (tmp_fd == -1) {
		E("Failed to open debugfs nic_dna_prbs_trigger\n");
		return errno;
	}

	sprintf(val_str, "%u %u 0x%lx", rank, port, rem_buf_phys);
	size = write(tmp_fd, val_str, strlen(val_str) + 1);
	if (size < 0) {
		E("Failed to write nic_dna_prbs_trigger\n");
		rc = errno;
		goto out;
	}

out:
	close(tmp_fd);

	return rc;
}

static int nic_dna_debugfs_allocate_host_memory(int fd, uint64_t *rem_buf_phys)
{
	ssize_t size;
	int rc = 0, tmp_fd;
	char path[PATH_MAX];
	char val_str[20] = "";

	snprintf(path, PATH_MAX, "/sys/kernel/debug/habanalabs_cn/hbl_cn0/nic_dna_alloc_host_mem");

	tmp_fd = open(path, O_RDWR);
	if (tmp_fd == -1) {
		E("Failed to open debugfs nic_dna_alloc_host_mem\n");
		return errno;
	}

	sprintf(val_str, "%u", 1);
	size = write(tmp_fd, val_str, strlen(val_str) + 1);
	if (size < 0) {
		E("Failed to write nic_dna_alloc_host_mem\n");
		rc = errno;
		goto out;
	}

	memset(val_str, 0, 20);

	size = read(tmp_fd, (void *)rem_buf_phys, sizeof(*rem_buf_phys));
	if (size < 0) {
		E("Failed to read nic_dna_alloc_host_mem\n");
		rc = errno;
		goto out;
	}

out:
	close(tmp_fd);

	return rc;
}

static int nic_dna_debugfs_read_host_memory(int fd, uint8_t *rem_buf)
{
	ssize_t size;
	int rc = 0, tmp_fd;
	char path[PATH_MAX];

	snprintf(path, PATH_MAX, "/sys/kernel/debug/habanalabs_cn/hbl_cn0/nic_dna_read_host_mem");

	tmp_fd = open(path, O_RDWR);
	if (tmp_fd == -1) {
		E("Failed to open debugfs nic_dna_read_host_mem\n");
		return errno;
	}

	size = read(tmp_fd, rem_buf, 256);
	if (size < 0) {
		E("Failed to write nic_dna_read_host_mem\n");
		rc = errno;
		goto out;
	}

out:
	close(tmp_fd);

	return rc;
}

static int nic_dna_debugfs_free_host_memory(int fd)
{
	ssize_t size;
	int rc = 0, tmp_fd;
	char path[PATH_MAX];
	char val_str[20] = "";

	snprintf(path, PATH_MAX, "/sys/kernel/debug/habanalabs_cn/hbl_cn0/nic_dna_free_host_mem");

	tmp_fd = open(path, O_RDWR);
	if (tmp_fd == -1) {
		E("Failed to open debugfs nic_dna_free_host_mem\n");
		return errno;
	}

	sprintf(val_str, "%u", 1);
	size = write(tmp_fd, val_str, strlen(val_str) + 1);
	if (size < 0) {
		E("Failed to write nic_dna_free_host_mem\n");
		rc = errno;
		goto out;
	}

out:
	close(tmp_fd);

	return rc;
}

static int nic_dna_parse_qpc_pi(const char *qpc, uint32_t *pi)
{
	char *pi_ptr = 0, *arg_ptr = 0, *save_ptr = 0;

	pi_ptr = strstr(qpc, "\nPI");
	assert_non_null(pi_ptr);

	arg_ptr = strtok_r(pi_ptr, ":", &save_ptr);
	assert_non_null(arg_ptr);

	arg_ptr = strtok_r(NULL, "\n", &save_ptr);
	assert_non_null(arg_ptr);

	*pi = strtoul(arg_ptr, NULL, 16);

	return 0;
}

static int nic_dna_read_qp_context(int fd, uint32_t port, uint32_t qp, char *qpc, uint32_t max_size)
{
	ssize_t size;
	char path[PATH_MAX] = {0}, cmd[DNA_CMD_SIZE] = {0};
	int dbgfs_fd, cmd_size;

	/* write to nic_dna_qp debugfs file to set qp_info before reading qpc
	 * echo <port> <qpn> <is_req> <is_full_print> <force_read> > nic_dna_qp
	 */
	snprintf(path, PATH_MAX, "/sys/kernel/debug/habanalabs_cn/hbl_cn0/nic_dna_qp");
	dbgfs_fd = open(path, O_RDWR);
	assert_in_range(dbgfs_fd, 0, INT_MAX);

	/* prepare qpc command */
	cmd_size = snprintf(cmd, DNA_CMD_SIZE, "%u %u 1 0 0", port, qp);

	/* write command */
	size = write(dbgfs_fd, cmd, cmd_size);
	assert_in_range(size, 0, INT_MAX);

	/* read and parse from qpc */
	size = read(dbgfs_fd, qpc, max_size - 1);
	assert_in_range(size, 1, INT_MAX);

	qpc[size] = '\0';

	close(dbgfs_fd);

	return 0;
}

static int nic_dna_read_qp_pi(int fd, uint32_t port, uint16_t qp, uint32_t *pi)
{
	char qpc[DNA_QPC_DUMP_SIZE] = {};
	int rc;

	rc = nic_dna_read_qp_context(fd, port, 0, qpc, sizeof(qpc));
	assert_int_equal(rc, 0);

	rc = nic_dna_parse_qpc_pi(qpc, pi);
	assert_int_equal(rc, 0);

	return 0;
}

int nic_dna_run(int fd)
{
	uint8_t **rem_buf_arr, *tmp_rem_buf, rank, num_iterations, num_cmpr_iterations;
	uint32_t port, pi0_base, pi0, pi0_diff, pi1_base, pi1, pi1_diff;
	struct hltests_nic_dna_cfg cfg;
	uint64_t rem_buf_phys, rem_val;
	const char *config_filename;
	bool dump_rem_buf;
	int rc, i, j;

	config_filename = hltests_get_config_filename();

	if (config_filename) {
		if (ini_parse(config_filename, nic_dna_parser, &cfg) < 0)
			fail_msg("Can't load %s\n", config_filename);

		rank = cfg.rank;
		port = cfg.port;
		num_iterations = cfg.num_iterations;
		dump_rem_buf = cfg.dump_buf;
	} else {
		W("no cfg file was provided, using defaults\n");

		rank = 0;
		port = 3;
		num_iterations = 100;
		dump_rem_buf = false;
	}

	/* Currently, the rank must be set to 0 */
	assert_int_equal(rank, 0);

	nic_dna_read_qp_pi(fd, port, 0, &pi0_base);
	nic_dna_read_qp_pi(fd, port, 1, &pi1_base);

	num_cmpr_iterations = DNA_REM_BUFF_SIZE / sizeof(uint64_t);
	ALLOC_2D_ARR(rem_buf_arr, num_iterations, DNA_REM_BUFF_SIZE);

	I("Going to trigger %u transactions to rank %u via port %u\n", num_iterations, rank, port);

	for (i = 0 ; i < num_iterations ; i++) {
		D("Iteration %d:\n", i);

		D("Going to allocate host memory through debugfs\n");
		rc = nic_dna_debugfs_allocate_host_memory(fd, &rem_buf_phys);
		if (rc)
			E("Failed to alloc host memory via debugfs\n");
		assert_int_equal(rc, 0);

		D("Buffer was allocated (physical address 0x%lx)\n", rem_buf_phys);

		D("Going to trigger PRBS for DNA through debugfs from port %u to rank %u\n",
		  port, rank);
		rc = nic_dna_debugfs_trigger_prbs(fd, rank, port, rem_buf_phys);
		if (rc) {
			E("Failed to trigger dna transaction via debugfs - going to free host "
			  "memory via debugfs\n");
			nic_dna_debugfs_free_host_memory(fd);
		}
		assert_int_equal(rc, 0);

		D("PRBS was triggered successfully\n");

		/* Sleep for 10 msecs to let the data to be written into memory*/
		usleep(10000);

		D("Going to read host memory through debugfs\n");
		rc = nic_dna_debugfs_read_host_memory(fd, rem_buf_arr[i]);
		if (rc)
			E("Failed to alloc host memory via debugfs\n");
		assert_int_equal(rc, 0);

		D("Going to free host memory through debugfs\n");
		rc = nic_dna_debugfs_free_host_memory(fd);
		if (rc)
			E("Failed to free host memory via debugfs\n");
		assert_int_equal(rc, 0);

		if (dump_rem_buf) {
			tmp_rem_buf = rem_buf_arr[i];

			I("Remote buffer:\n");
			for (j = 0 ; j < num_cmpr_iterations ; j++) {
				rem_val = *((uint64_t *)tmp_rem_buf);
				I("rem_buf_%u 0x%lx\n", j, rem_val);
				tmp_rem_buf += sizeof(uint64_t);
			}
		}

		D("Comparing data\n");
		tmp_rem_buf = rem_buf_arr[i];
		for (j = 0 ; j < num_cmpr_iterations ; j++) {
			rem_val = *((uint64_t *)tmp_rem_buf);
			if (rem_val != DNA_PRBS_PATTERN) {
				E("Failed on data compare - iter %d, rem_val 0x%lx"
				  " (expected 0x%lx)\n", j, rem_val, DNA_PRBS_PATTERN);
				assert_true(false);
			}

			tmp_rem_buf += sizeof(uint64_t);
		}

		D("Data compare passed successfully\n");
	}

	nic_dna_read_qp_pi(fd, port, 0, &pi0);
	nic_dna_read_qp_pi(fd, port, 1, &pi1);

	pi0_diff = pi0 - pi0_base;
	pi1_diff = pi1 - pi1_base;

	I("PI of QPC0 was incremented in %u\n", pi0_diff);
	I("PI of QPC1 was incremented in %u\n", pi1_diff);

	/* Check that the sum of both PIs is equal to the number of iterations */
	assert_int_equal(pi0_diff + pi1_diff, num_iterations);

	/* Check that the difference between both PIs is maximum 1 */
	assert_true(abs((int)(pi0_diff - pi1_diff)) <= 1);

	FREE_2D_ARR(rem_buf_arr, num_iterations);

	return 0;
}
