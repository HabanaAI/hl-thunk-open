// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_tests.h"
#include "hlthunk_nic_tests.h"
#include "hlthunk_nic_tests_ext.h"

#include <byteswap.h>
#include <errno.h>
#include <fcntl.h>
#include <immintrin.h>
#include <linux/mman.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>
#include <stdarg.h>

#include <infiniband/verbs.h>
#include <infiniband/hbldv.h>

#define CC_CMD_SIZE			20
#define CC_QPC_SIZE			4000
#define CC_POST_MSGS			3
#define CC_SQ_MAX_ELEMENTS_NUM		64

#define CC_BBR_VALID_BIT_BURST_SIZE	0
#define CC_BBR_VALID_BIT_SQN		1
#define CC_BBR_VALID_BIT_CONG_WIN	2
#define CC_BBR_VALID_BIT_PACE_TIME	3

#define CC_SWIFT_VALID_BIT_TARGET_DELAY	0
#define CC_SWIFT_VALID_BIT_AI		1
#define CC_SWIFT_VALID_BIT_BETA		2
#define CC_SWIFT_VALID_BIT_MAX_MDF	3

#define CC_MSG_TYPE_BBR			0
#define CC_MSG_TYPE_SWIFT		1

#define CC_PLDM_QPC_VALIDATION_TO_USEC	(1000 * 2)

#define NIC_USER_CQ_SLEEP_USEC		1000

#define NIC_SOB_SLEEP_USEC		100
#define NIC_SOB_ASIC_TIMEOUT_USEC	(10 * 60 * 1000000)	/* 10 minutes */
 /* 15 seconds = ~10 mins in ASIC */
#define NIC_SOB_PLDM_SIM_TIMEOUT_USEC	(NIC_SOB_ASIC_TIMEOUT_USEC / 40)

#define DB_FIFO_TIMEOUT_SEC		10 /* Timeout for DB_FIFO entry consume */
#define DB_FIFO_SLEEP_USEC		1000

/* NIC garbage collector */
struct node {
	void *ptr;
	struct node *next;
};

struct nic_mem_list {
	struct node *head;
};

static struct nic_mem_list cb_list;
static struct nic_mem_list hmem_list;
static struct nic_mem_list dmem_list;

static int get_nic_info(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_mac_addr_info info;
	int fd = tests_state->fd, rc, i;

	rc = hlthunk_get_mac_addr_info(fd, &info);
	if (rc) {
		printf("failed to get MAC addresses %d\n", rc);
		return rc;
	}

	tests_state->nic_ports_mask = info.mask[0];

	for (i = 0 ; i < HL_INFO_MAC_ADDR_MAX_NUM ; i++)
		if (info.mask[i / 64] & (1ull << (i % 64)))
			memcpy(tests_state->mac_addrs[i].addr,
				info.array[i].addr, ETH_ALEN);

	return 0;
}

static int set_app_params(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_nic_user_set_app_params_in set_app_params_in = {};
	int rc, fd = tests_state->fd;
	uint32_t port, max_ports;

	/* Gaudi1 doesn't support set_app_params ioctl */
	if (hltests_is_gaudi(fd))
		return 0;

	set_app_params_in.advanced = 1;
	max_ports = hltests_nic_get_max_num_of_ports(fd);

	for (port = 0 ; port < max_ports ; port++) {
		if (!(tests_state->nic_ports_mask & BIT_ULL(port)))
			continue;

		rc = hlthunk_nic_user_set_app_params(fd, port, &set_app_params_in);
		assert_int_equal(rc, 0);
	}

	return 0;
}

bool hltests_nic_is_ibdev(int fd)
{
	return get_hdev_from_fd(fd)->ibdev;
}

uint32_t hltests_nic_to_ibdev_port_num(int fd, uint32_t hl_port_num)
{
	return get_hdev_from_fd(fd)->hl_to_ib_port_map[hl_port_num];
}

int hltests_ibdev_to_nic_port_num(int ib_port_num)
{
	assert_true(ib_port_num > 0);
	return ib_port_num - 1;
}

uint64_t hltests_nic_to_ibdev_port_mask(int fd, uint64_t hl_port_mask)
{
	uint32_t ibdev_port_num, hl_port_num, max_num_of_ports;
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	uint64_t ibdev_port_mask = 0x0;

	max_num_of_ports = hltests_nic_get_max_num_of_ports(fd);

	for (hl_port_num = 0 ; hl_port_num < max_num_of_ports ; hl_port_num++) {
		if (!(hl_port_mask & BIT(hl_port_num)))
			continue;

		ibdev_port_num = hdev->hl_to_ib_port_map[hl_port_num];
		assert_int_not_equal_ret_val(ibdev_port_num, 0, 0);

		ibdev_port_mask |= BIT_ULL(ibdev_port_num);
	}

	return ibdev_port_mask;
}

static int ibdev_init(struct hltests_state *tests_state)
{
	uint32_t ib_port_num, max_num_of_ports, i;
	int rc, device_idx, fd = tests_state->fd;
	char pci_bus_id[13], ib_devname[16] = {};
	struct ibv_device **dev_list;
	struct hltests_device *hdev;
	uint64_t nic_ports_mask;
	int num_of_device;

	hdev = get_hdev_from_fd(fd);
	if (!hdev) {
		printf("Failed to get hdev from file descriptor %d\n", fd);
		return -ENODEV;
	}

	rc = hlthunk_get_pci_bus_id_from_fd(fd, pci_bus_id, sizeof(pci_bus_id));
	if (rc)
		return rc;

	device_idx = hlthunk_get_device_index_from_pci_bus_id(pci_bus_id);
	if (device_idx < 0)
		return -ENODEV;

	snprintf(ib_devname, sizeof(ib_devname), "hbl_%d", device_idx);

	dev_list = hlibv_get_device_list(&num_of_device);
	tests_state->dev_list = dev_list;

	if (num_of_device <= 0)
		return 0;

	for (i = 0 ; dev_list[i] ; ++i) {
		if (!strcmp(hlibv_get_device_name(dev_list[i]), ib_devname)) {
			hdev->ibdev = dev_list[i];
			break;
		}
	}

	nic_ports_mask = tests_state->nic_ports_mask;
	max_num_of_ports = hltests_nic_get_max_num_of_ports(fd);

	hdev->hl_to_ib_port_map = hlthunk_malloc(max_num_of_ports * sizeof(uint32_t));
	assert_non_null(hdev->hl_to_ib_port_map);

	ib_port_num = 0;
	for (i = 0 ; i < max_num_of_ports ; i++) {
		if (!(nic_ports_mask & BIT(i)))
			continue;

		ib_port_num++;
		hdev->hl_to_ib_port_map[i] = ib_port_num;
	}

	return 0;
}

static void ibdev_fini(struct hltests_state *tests_state)
{
	struct hltests_device *hdev = get_hdev_from_fd(tests_state->fd);

	if (hdev->hl_to_ib_port_map)
		hlthunk_free(hdev->hl_to_ib_port_map);
	if (tests_state->dev_list)
		hlibv_free_device_list(tests_state->dev_list);
}

uint32_t hltests_nic_convert_mtu_to_ibv_mtu(uint32_t mtu)
{
	switch (mtu) {
	case 256:
		return IBV_MTU_256;
	case 512:
		return IBV_MTU_512;
	case 1024:
		return IBV_MTU_1024;
	case 2048:
		return IBV_MTU_2048;
	case 4096:
		return IBV_MTU_4096;
	case 8192:
		return HBL_IB_MTU_8192;
	default:
		return IBV_MTU_4096;
	}
}

int hltests_nic_setup(void **state)
{
	struct hltests_state *tests_state;
	struct hltests_device *hdev;
	int rc, fd;

	rc = hltests_setup(state);
	if (rc)
		return rc;

	tests_state = (struct hltests_state *) *state;
	fd = tests_state->fd;

	hdev = get_hdev_from_fd(fd);
	if (!hdev) {
		printf("Failed to get hdev from file descriptor %d\n", fd);
		return -ENODEV;
	}

	rc = hdev->asic_funcs->nic_funcs->asic_priv_init(hdev, NULL, 0);
	if (rc)
		return rc;

	rc = get_nic_info(state);
	if (rc)
		return rc;

	return set_app_params(state);
}

int hltests_nic_teardown(void **state)
{
	return hltests_teardown(state);
}

int hltests_root_nic_setup(void **state)
{
	struct hltests_state *tests_state;
	struct hltests_device *hdev;
	int rc, fd;

	rc = hltests_setup(state);
	if (rc)
		return rc;

	tests_state = (struct hltests_state *) *state;
	fd = tests_state->fd;

	/* This call is valid only for FS family where there is a VRAM file that can be
	 * modified. Hence if file doesn't exist don't fail the test.
	 * As we don't support buffer splits we will allocate everything on VRAM0, hence
	 * set it to have 1GB of memory.
	 */
	rc = hltests_set_vram_size(fd, SZ_1G, 0);
	assert_true(rc == 0 || rc == -ENOENT);

	rc = hlthunk_get_hw_ip_info(fd, &tests_state->hw_ip);
	assert_int_equal(rc, 0);

	hdev = get_hdev_from_fd(fd);
	if (!hdev) {
		printf("Failed to get hdev from file descriptor %d\n", fd);
		return -ENODEV;
	}

	rc = get_nic_info(state);
	if (rc)
		return rc;

	rc = ibdev_init(tests_state);
	if (rc)
		return rc;

	if (!hltests_nic_is_ibdev(fd))
		hdev->asic_funcs->nic_funcs->asic_priv_init(hdev, NULL, 0);

	return 0;
}

int hltests_root_nic_teardown(void **state)
{
	struct hltests_state *tests_state;
	int fd;

	if (!*state)
		return -EINVAL;

	tests_state = (struct hltests_state *) *state;
	fd = tests_state->fd;

	if (hltests_is_gaudi3(fd))
		hltests_nic_debugfs_set_coll_lag_size(fd, DEFAULT_COLL_LAG_SIZE);

	ibdev_fini(tests_state);

	return hltests_teardown(state);
}

void hltests_nic_print_time_elapsed(struct timespec *base, char *str,
					enum hltests_nic_verbose_level verbose)
{
	struct timespec now;

	if (verbose == VERBOSE_NONE)
		return;

	clock_gettime(CLOCK_MONOTONIC_RAW, &now);

	printf("%s: %.2fs\n", str, get_timediff_sec(base, &now));
	fflush(stdout);

	*base = now;
}

static int mem_list_push(struct nic_mem_list *mem_list, void *ptr)
{
	struct node *node;

	node = hlthunk_malloc(sizeof(*node));
	assert_non_null(node);

	node->ptr = ptr;

	if (!mem_list->head) {
		mem_list->head = node;
		return 0;
	}

	node->next = mem_list->head;
	mem_list->head = node;

	return 0;
}

static void *mem_list_pop(struct nic_mem_list *mem_stack)
{
	struct node *node;
	void *ptr;

	if (!mem_stack->head)
		return NULL;

	ptr = mem_stack->head->ptr;

	node = mem_stack->head->next;
	hlthunk_free(mem_stack->head);
	mem_stack->head = node;

	return ptr;
}

int hltests_nic_cb_list_push(void *cb)
{
	return mem_list_push(&cb_list, cb);
}

void *hltests_nic_cb_list_pop(void)
{
	return mem_list_pop(&cb_list);
}

int hltests_nic_hmem_list_push(void *buf)
{
	return mem_list_push(&hmem_list, buf);
}

void *hltests_nic_hmem_list_pop(void)
{
	return mem_list_pop(&hmem_list);
}

int hltests_nic_dmem_list_push(void *buf)
{
	return mem_list_push(&dmem_list, buf);
}

void *hltests_nic_dmem_list_pop(void)
{
	return mem_list_pop(&dmem_list);
}

int hltests_nic_debugfs_write(int fd, const char *name, const char *format, ...)
{
	char path[PATH_MAX], pci_bus_id[13], val_str[128];
	int rc = 0, tmp_fd, device_idx;
	ssize_t size;
	va_list arg;
	size_t len;

	rc = hlthunk_get_pci_bus_id_from_fd(fd, pci_bus_id, sizeof(pci_bus_id));
	if (rc)
		return -ENODEV;

	device_idx = hlthunk_get_device_index_from_pci_bus_id(pci_bus_id);
	if (device_idx < 0)
		return -ENODEV;

	snprintf(path, PATH_MAX, "/sys/kernel/debug/habanalabs_cn/hbl_cn%d/%s", device_idx, name);

	/* errno is not updated by `vsnprintf`, zero it out to prevent confusion in error prints */
	errno = 0;

	va_start(arg, format);
	rc = vsnprintf(val_str, ARRAY_SIZE(val_str), format, arg);
	va_end(arg);

	if (rc < 0) {
		E("Failed to format string");
		return -1;
	}

	len = (size_t)rc;

	/* clear rc, which would have a positive return value from vsnprintf */
	rc = 0;

	if (len >= ARRAY_SIZE(val_str)) {
		E("Formatted string truncated!");
		return -1;
	}

	tmp_fd = open(path, O_RDWR);
	if (tmp_fd < 0) {
		E("Failed to open debugfs %s", name);
		return -errno;
	}

	size = write(tmp_fd, val_str, len + 1);
	if (size < 0) {
		E("Failed to write %s", name);
		rc = -errno;
	}

	close(tmp_fd);
	return rc;
}

/**
 * hltests_nic_debugfs_read() - Reads a value from CN driver debugfs.
 * @fd: Current device's fd.
 * @name: Name of debugfs entry.
 * @format: scanf like format.
 * @va_args: scanf like arguments.
 *
 * Return: negative value on error, else amount of arguments parsed.
 */
int hltests_nic_debugfs_read(int fd, const char *name, const char *format, ...)
{
	char path[PATH_MAX], pci_bus_id[13], val_str[128];
	int rc = 0, tmp_fd, device_idx;
	ssize_t size;
	va_list arg;

	rc = hlthunk_get_pci_bus_id_from_fd(fd, pci_bus_id, sizeof(pci_bus_id));
	if (rc)
		return -ENODEV;

	device_idx = hlthunk_get_device_index_from_pci_bus_id(pci_bus_id);
	if (device_idx < 0)
		return -ENODEV;

	snprintf(path, PATH_MAX, "/sys/kernel/debug/habanalabs_cn/hbl_cn%d/%s", device_idx, name);

	tmp_fd = open(path, O_RDONLY);
	if (tmp_fd < 0) {
		E("Failed to open %s", name);
		return -errno;
	}

	size = read(tmp_fd, val_str, sizeof(val_str));

	close(tmp_fd);

	if (size < 0 || size >= sizeof(val_str)) {
		E("Failed to read debugfs %s [rc %zd]", name, size);
		return -errno;
	}

	val_str[size] = '\0';

	va_start(arg, format);
	rc = vsscanf(val_str, format, arg);
	va_end(arg);

	return rc;
}

int hltests_nic_debugfs_trigger_link_shutdown_event(int fd, uint32_t hbl_port)
{
	return hltests_nic_debugfs_write(fd, "nic_trigger_link_shutdown", "%u", hbl_port);
}

int hltests_nic_debugfs_set_coll_lag_size(int fd, uint32_t coll_lag_size)
{
	ssize_t size;
	int rc = 0, tmp_fd, device_idx;
	char path[PATH_MAX], pci_bus_id[13];
	char val_str[10] = "";

	rc = hlthunk_get_pci_bus_id_from_fd(fd, pci_bus_id, sizeof(pci_bus_id));
	if (rc)
		return -ENODEV;

	device_idx = hlthunk_get_device_index_from_pci_bus_id(pci_bus_id);
	if (device_idx < 0)
		return -ENODEV;

	snprintf(path, PATH_MAX, "/sys/kernel/debug/habanalabs_cn/hbl_cn%d/nic_coll_lag_size",
			device_idx);

	tmp_fd = open(path, O_RDWR);
	if (tmp_fd == -1) {
		printf("Failed to open debugfs nic_coll_lag_size\n");
		return errno;
	}

	sprintf(val_str, "%u", coll_lag_size);
	size = write(tmp_fd, val_str, strlen(val_str) + 1);
	if (size < 0) {
		printf("Failed to write coll_lag_size\n");
		rc = errno;
		goto out;
	}

out:
	close(tmp_fd);
	return rc;
}

int hltests_nic_debugfs_inject_rx_err(int fd, uint8_t drop_percent)
{
	char pci_bus_id[13], path[200], drop_percent_str[64];
	int device_idx, rc = 0, debugfs_inject_rx_err_fd;
	ssize_t size;

	rc = hlthunk_get_pci_bus_id_from_fd(fd, pci_bus_id, sizeof(pci_bus_id));
	if (rc)
		return -ENODEV;

	device_idx = hlthunk_get_device_index_from_pci_bus_id(pci_bus_id);
	if (device_idx < 0)
		return -ENODEV;

	sprintf(path, "/sys/kernel/debug/habanalabs_cn/hbl_cn%d/nic_inject_rx_err", device_idx);

	debugfs_inject_rx_err_fd = open(path, O_WRONLY);
	if (debugfs_inject_rx_err_fd == -1)
		return -EPERM;

	sprintf(drop_percent_str, "%d", drop_percent);

	size = write(debugfs_inject_rx_err_fd, drop_percent_str, strlen(drop_percent_str) + 1);
	if (size < 0) {
		close(debugfs_inject_rx_err_fd);
		return -errno;
	}

	close(debugfs_inject_rx_err_fd);
	return 0;
}

/**
 * hltests_nic_debugfs_get_user_asid() - Returns the user ASID of the currently open IB context.
 * @test_state: Pointer to a structure containing the current test state.
 *
 * Return: the user ASIC of the currently open IB context.
 * Note: If there are multiple contexts open on the same device, the returned ASID might not be
 *       correct.
 */
int64_t hltests_nic_debugfs_get_user_asid(struct hltests_state *test_state)
{
	uint64_t value;
	int rc;

	rc = hltests_nic_debugfs_read(test_state->fd, "nic_user_asid", "%lu", &value);
	if (rc < 0)
		return rc;

	/* Expect rc to be equal to amount of arguments matched */
	if (rc != 1)
		return -1;

	return (int64_t)value;
}

int hltests_nic_wait_for_cleanup(void)
{
	printf("\nWait for cleanup - press 'c' to continue\n");
	fflush(stdout);

	while (1) {
		int c = getchar();

		assert_int_not_equal(c, EOF);
		if (c == 'c')
			break;
	}

	return 0;
}

void hltests_nic_parse_mac(uint8_t *mac, const char *value)
{
	char tmp[3] = {0};
	int i;

	for (i = 0 ; i < ETH_ALEN ; i++) {
		memcpy(tmp, value + (i * 3), 2);
		mac[i] = (uint8_t)strtoul(tmp, NULL, 16);
	}
}

void hltests_nic_copy_mac_reverse(uint8_t *dst, const uint8_t *src)
{
	int i;

	for (i = 0 ; i < ETH_ALEN ; i++)
		dst[i] = src[(ETH_ALEN - 1) - i];
}

void hltests_nic_stringify_mac(char *buf, uint8_t *mac)
{
	sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2],
		mac[3], mac[4], mac[5]);
}

/*
 * hltests_nic_get_default_cfg - Get device specific default test
 * configuration parameters.
 *
 * @fd: Habanalabs device open file descriptor
 * @cfg: Configuration structure specific to a device test.
 * @id: Test for which default configuration is requested.
 *
 * Returns 0 on success and error on failure.
 */
int hltests_nic_get_default_cfg(int fd, void *cfg, enum hltests_nic_id id)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	return asic->nic_funcs->get_default_cfg(cfg, id);
}

int hltests_nic_run_wtd(int fd, void *p_in)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	return asic->nic_funcs->run_wtd(fd, p_in);
}

int hltests_nic_run_coll_op(int fd, void *comm_group)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	return asic->nic_funcs->run_coll_op(comm_group);
}

int hltests_nic_run_coll_op_new(int fd, struct hltests_nic_coll_comm_group_new *comm_group)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	return asic->nic_funcs->run_coll_op_new(comm_group);
}

int hltests_nic_run_lag_op(struct hltests_nic_lag_op_params *params)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(params->params->fd)->asic_funcs;

	assert_non_null(asic->nic_funcs->run_lag_op);
	return asic->nic_funcs->run_lag_op(params);
}

int hltests_nic_run_lag_completion_op(struct hltests_nic_lag_completion_op_params *params)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(params->params->fd)->asic_funcs;

	assert_non_null(asic->nic_funcs->run_lag_completion_op);
	return asic->nic_funcs->run_lag_completion_op(params);
}

uint32_t hltests_nic_get_max_num_of_ports(int fd)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	return asic->nic_funcs->get_max_num_of_ports();
}

uint64_t hltests_nic_get_port_mask(int fd)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	return asic->nic_funcs->get_port_mask();
}

uint32_t hltests_nic_get_base_qid(int fd)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	return asic->nic_funcs->get_base_qid();
}

uint32_t hltests_nic_get_wq_offset(int fd, int port, uint32_t conn_id)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	return asic->nic_funcs->get_wq_offset(fd, port, conn_id);
}

void hltests_nic_fill_wqe(int fd, void *p_in)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	asic->nic_funcs->fill_wqe(fd, p_in);
}

void *hltests_nic_get_swqe(int fd, void *swq, uint32_t offset)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	return asic->nic_funcs->get_swqe(swq, offset);
}

void *hltests_nic_get_rwqe(int fd, void *rwq, uint32_t offset)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	return asic->nic_funcs->get_rwqe(rwq, offset);
}

uint8_t hltests_nic_get_swqe_size(int fd)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	return asic->nic_funcs->get_swqe_size();
}

uint8_t hltests_nic_get_rwqe_size(int fd)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	return asic->nic_funcs->get_rwqe_size();
}

int hltests_nic_get_min_conn_id(int fd, uint32_t port)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	return asic->nic_funcs->get_min_conn_id(fd, port);
}

int hltests_nic_get_max_conn_id(int fd, uint32_t port)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	return asic->nic_funcs->get_max_conn_id(fd, port);
}

int hltests_get_max_num_of_qps(int fd, uint32_t port)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	return asic->nic_funcs->get_max_num_of_qps(fd, port);
}

uint32_t hltests_nic_get_min_coll_conn_id(int fd, bool is_scale_out)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	return asic->nic_funcs->get_min_coll_conn_id(fd, is_scale_out);
}

uint32_t hltests_nic_get_max_coll_conn_id(int fd, bool is_scale_out)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	return asic->nic_funcs->get_max_coll_conn_id(fd, is_scale_out);
}

uint32_t hltests_nic_get_coll_qps_offset(int fd, uint32_t port)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	return asic->nic_funcs->get_coll_qps_offset(fd, port);
}

uint32_t hltests_nic_get_sob_value(struct hltests_state *tests_state, uint32_t sob_idx)
{
	int fd = tests_state->fd;
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	if (asic->get_sob_value)
		return asic->get_sob_value(fd, sob_idx);

	uint64_t sob_base_addr = hltests_get_sob_base_addr(fd);
	uint64_t sob_addr = sob_base_addr + (sob_idx * sizeof(uint32_t));

	return READ32(sob_addr);
}

int hltests_nic_wait_on_sob(int fd, uint32_t sob_idx, struct hltests_state *tests_state, int value,
			    const struct hltests_nic_eq *eq)
{
	int64_t timeout_us = 0;
	uint32_t sob_value = hltests_nic_get_sob_value(tests_state, sob_idx);

	if (hltests_is_simulator(fd) || hltests_is_pldm(fd))
		timeout_us = NIC_SOB_PLDM_SIM_TIMEOUT_USEC;
	else
		timeout_us = NIC_SOB_ASIC_TIMEOUT_USEC;

	if (value < 0 || value > MAX_SOB_VAL) {
		printf("Expected SOB value out of valid range. Value: %d\n", value);
		return -EINVAL;
	}

	while (sob_value != (uint32_t)value) {
		if (timeout_us <= 0) {
			printf("Timeout waiting on sob. Expected: %d Current: %d\n",
					value, sob_value);
			return -ETIMEDOUT;
		}

		/* In case there is an error event arrived to the EQ we should fail */
		if (eq->is_error_event) {
			printf("Error event arrived on EQ, aborting\n");
			return -ECOMM;
		}

		usleep(NIC_SOB_SLEEP_USEC);
		timeout_us -= NIC_SOB_SLEEP_USEC;
		sob_value = hltests_nic_get_sob_value(tests_state, sob_idx);
	}

	return 0;
}

void hltests_nic_pre_setup_ctx(int fd, struct hltests_nic_requester_conn_ctx *req_ctx)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	asic->nic_funcs->pre_setup_ctx(fd, req_ctx);
}

void hltests_nic_pre_setup_default_ctx_rdv(int fd, struct hltests_nic_requester_conn_ctx *req_ctx,
						enum hltests_nic_test_opcode test_opcode,
						bool is_rdv_send, bool swq_granularity)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	asic->nic_funcs->pre_setup_default_ctx_rdv(fd, req_ctx, test_opcode, is_rdv_send,
							swq_granularity);
}

int hltests_nic_setup_ctx_lpbk(int fd, int port,
			       struct hltests_nic_requester_conn_ctx *req_ctx,
			       struct hltests_nic_responder_conn_ctx *res_ctx,
			       uint32_t conn, struct hltests_nic_lpbk_cfg *cfg)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	return asic->nic_funcs->setup_ctx_lpbk(fd, port, req_ctx, res_ctx, conn, cfg);
}

int hltests_nic_setup_ctx_e2e(int fd, int port,
			      struct hltests_nic_requester_conn_ctx *req_ctx,
			      struct hltests_nic_responder_conn_ctx *res_ctx,
			      struct hltests_nic_e2e_cfg *cfg)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	return asic->nic_funcs->setup_ctx_e2e(fd, port, req_ctx, res_ctx, cfg);
}

void hltests_nic_setup_default_ctx_rdv(int fd, int port,
				       struct hltests_nic_requester_conn_ctx *req_ctx,
				       struct hltests_nic_responder_conn_ctx *res_ctx,
				       bool is_rdv_send, uint32_t conn_id, bool swq_granularity)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	asic->nic_funcs->setup_default_ctx_rdv(fd, port, req_ctx, res_ctx, is_rdv_send, conn_id,
						swq_granularity);
}

/* User CQ per port polling thread. */
void *hltests_nic_user_cq_port_poll(void *args)
{
	struct hltests_nic_port_cq *port_cq = (struct hltests_nic_port_cq *) args;
	struct hltests_nic_cq *cq = port_cq->thread_params.cq;
	pthread_spinlock_t *cq_lock = &cq->user_cq.cq_lock;
	struct hl_nic_cqe *cq_sw_arr = cq->cq_buf, cqe;
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(cq->fd)->asic_funcs;
	_Atomic uint32_t *user_cqe_cnt = (_Atomic uint32_t *)&cq->user_cq.cqe_cnt;
	uint32_t user_cqe_cnt_local, cq_buf_len = (uint32_t)cq->cq_buf_len,
		cq_pi, hw_ci = 0, __hw_ci = 0, hw_pi = 0,
		*hw_pi_ptr = port_cq->pi_ptr, port;
	int fd = cq->fd;

	port = (uint32_t)port_cq->thread_params.port;
	__sync_fetch_and_add(&cq->user_cq.thread_count, 1);

	while (1) {
		if (hw_pi == hw_ci) {
			/* Read HW PI via mmaped user CQ PI memory buffer. */
			hw_pi = *hw_pi_ptr;

			if (hw_pi == hw_ci) {
				/* Sleep is needed for pthread_cancel() to stop the thread */
				usleep(NIC_USER_CQ_SLEEP_USEC);
				continue;
			}
		}

		__hw_ci = asic->nic_funcs->get_user_cqe(fd, &cqe, port_cq, hw_ci);

		/* Check if we have new CQEs. */
		if (__hw_ci == hw_ci) {
			usleep(NIC_USER_CQ_SLEEP_USEC);
			continue;
		}

		hw_ci = __hw_ci;

		pthread_spin_lock(cq_lock);

		/* Copy asic agnostic CQE to common buffer. */
		cq_pi = cq->cq_pi++ & (cq_buf_len - 1);
		memcpy(&cq_sw_arr[cq_pi], &cqe, sizeof(cqe));

		user_cqe_cnt_local = atomic_fetch_add(user_cqe_cnt, 1);
		if (user_cqe_cnt_local >= (cq_buf_len - 1))
			printf("CQ overflow, port %d\n", port);

		pthread_spin_unlock(cq_lock);
	}

	return args;
}

static int ibv_create_user_cq(int fd, struct ibv_context *ibctx, uint32_t port_num,
			      uint32_t num_cqes, struct hltests_nic_cq *cq)
{
	struct hltests_nic_port_cq *port_cq = &cq->user_cq.port_cq[port_num];
	struct hbldv_query_cq_attr cq_query_attr = {};
	struct ibv_cq *ibvcq;
	int rc;

	switch (cq->type) {
	case HLTESTS_NIC_CQ_TYPE_PORT: {
		struct hbldv_cq_attr cq_attr = {
			.port_num = (uint8_t)hltests_nic_to_ibdev_port_num(fd, port_num),
		};

		ibvcq = hbldv_create_cq(ibctx, (int)num_cqes, NULL, 0, &cq_attr);
		assert_ptr_not_equal(ibvcq, NULL);
		break;
	}
	case HLTESTS_NIC_CQ_TYPE_DEVICE:
		ibvcq = hlibv_create_cq(ibctx, (int)num_cqes, NULL, 0, 0);
		assert_ptr_not_equal(ibvcq, NULL);
		break;
	default:
		E("Invalid cq type: %u", cq->type);
		fail();
		return -1;
	}

	rc = hbldv_query_cq(ibvcq, &cq_query_attr);
	assert_int_equal(rc, 0);

	assert_ptr_equal(ibvcq, cq_query_attr.ibvcq);

	port_cq->ibvcq = cq_query_attr.ibvcq;
	port_cq->pi_ptr = cq_query_attr.pi_cpu_addr;
	port_cq->cq_buf = cq_query_attr.mem_cpu_addr;
	port_cq->regs_ptr = cq_query_attr.regs_cpu_addr;
	port_cq->regs_offset = cq_query_attr.regs_offset;
	port_cq->id = cq_query_attr.cq_num;

	return 0;
}

static int user_cq_alloc(int fd, struct hlthunk_nic_user_cq_id_alloc_out *alloc_out,
			 uint32_t port_num)
{
	struct hlthunk_nic_user_cq_id_alloc_in alloc_in = {};
	int rc;

	memset(alloc_out, 0, sizeof(*alloc_out));

	alloc_in.port = port_num;
	rc = hlthunk_nic_user_cq_id_alloc(fd, &alloc_in, alloc_out);
	assert_int_equal(rc, 0);

	return 0;
}

static int user_cq_set(int fd, uint32_t port_num, uint32_t num_cqes, uint32_t cq_id,
		       struct hlthunk_nic_user_cq_id_set_out *set_out)
{
	struct hlthunk_nic_user_cq_id_set_in set_in = {};
	int rc;

	memset(set_out, 0, sizeof(*set_out));

	set_in.port = port_num;
	set_in.num_of_cqes = num_cqes;
	set_in.id = cq_id;
	rc = hlthunk_nic_user_cq_id_set(fd, &set_in, set_out);
	assert_int_equal(rc, 0);

	return 0;
}

static int user_cq_resource_mmap(int fd, uint32_t cq_size,
				 struct hlthunk_nic_user_cq_id_set_out *set_out,
				 struct hltests_nic_port_cq *port_cq)
{
	/* HW configuration space on simulator is not MMIO. Hence, we cannot mmap it */
	if (!hltests_is_simulator(fd)) {
		port_cq->regs_ptr = hltests_mmap(fd, SZ_4K, (off_t)set_out->regs_handle);
		assert_ptr_not_equal(port_cq->regs_ptr, MAP_FAILED);
	}

	/* Mmap user CQ port buffers. */
	port_cq->cq_buf = hltests_mmap(fd, cq_size, (off_t)set_out->mem_handle);
	assert_ptr_not_equal(port_cq->cq_buf, MAP_FAILED);

	/* Mmap port user CQ memory PI */
	port_cq->pi_ptr = hltests_mmap(fd, SZ_4K, (off_t)set_out->pi_handle);
	assert_ptr_not_equal(port_cq->pi_ptr, MAP_FAILED);

	return 0;
}

/**
 * hltests_nic_user_cq_create - Config HW and start polling user CQs on all ports.
 * @fd: Device file descriptor.
 * @cq: Common CQ test structs. For both CQ user and drv.
 *
 * Note: Applicable only for Gaudi2 and future asics.
 */
int hltests_nic_user_cq_create(int fd, struct hltests_nic_cq *cq)
{
	struct hlthunk_nic_user_cq_id_alloc_out alloc_out;
	struct hlthunk_nic_user_cq_id_set_out set_out;
	uint32_t size, cq_buf_len, i, max_ports;
	struct hltests_nic_port_cq *port_cq;
	struct ibv_context *ibctx;
	int rc, thread_count = 0;
	pthread_t thread_id;

	/* With port CQ we create a CQ on each port, with device CQ we create only one CQ */
	switch (cq->type) {
	case HLTESTS_NIC_CQ_TYPE_PORT:
		max_ports = hltests_nic_get_max_num_of_ports(fd);
		break;
	case HLTESTS_NIC_CQ_TYPE_DEVICE:
		max_ports = 1;
		break;
	default:
		E("Invalid cq type: %u", cq->type);
		fail();
		return -1;
	}

	cq->fd = fd;

	cq->user_cq.port_cq = hlthunk_malloc(max_ports * sizeof(struct hltests_nic_port_cq));
	assert_non_null(cq->user_cq.port_cq);

	/* Allocate user CQ common buffer. */
	cq->cq_buf = calloc(cq->cq_buf_len, sizeof(struct hl_nic_cqe));
	assert_non_null(cq->cq_buf);

	pthread_spin_init(&cq->user_cq.cq_lock, PTHREAD_PROCESS_PRIVATE);
	cq->user_cq.thread_count = 0;

	/* Size of asic specific port user CQ buffer. */
	cq_buf_len = cq->user_cq.cq_buf_len;
	size = cq_buf_len * cq->user_cq.raw_cqe_size;

	ibctx = cq->ibctx;

	for (i = 0 ; i < max_ports ; i++) {
		if (!(cq->user_cq.port_mask[0] & BIT(i)) && cq->type == HLTESTS_NIC_CQ_TYPE_PORT)
			continue;

		port_cq = &cq->user_cq.port_cq[i];

		if (hltests_nic_is_ibdev(fd)) {
			rc = ibv_create_user_cq(fd, ibctx, i, cq_buf_len, cq);
			assert_int_equal(rc, 0);
		} else {
			rc = user_cq_alloc(fd, &alloc_out, i);
			assert_int_equal(rc, 0);

			rc = user_cq_set(fd, i, cq_buf_len, alloc_out.id, &set_out);
			assert_int_equal(rc, 0);

			rc = user_cq_resource_mmap(fd, size, &set_out, port_cq);
			assert_int_equal(rc, 0);

			port_cq->regs_offset = set_out.regs_offset;
			port_cq->id = alloc_out.id;
		}

		port_cq->cq_buf_len = cq_buf_len;

		switch (cq->type) {
		case HLTESTS_NIC_CQ_TYPE_PORT:
			port_cq->port = (int)i;
			port_cq->thread_params.port = (int)i;
			break;
		case HLTESTS_NIC_CQ_TYPE_DEVICE:
			port_cq->port = DEVICE_CQ_PORT_IDX;
			port_cq->thread_params.port = DEVICE_CQ_PORT_IDX;
			break;
		default:
			E("Invalid cq type: %u", cq->type);
			fail();
		}

		port_cq->thread_params.cq = cq;

		/* Start polling user CQ port buffers. */
		rc = pthread_create(&thread_id, NULL, cq->user_cq.user_cq_port_poll, port_cq);
		assert_int_equal(rc, 0);

		port_cq->thread_id = thread_id;
		port_cq->enabled = true;
		thread_count++;
	}

	/* Wait till all port polling threads are scheduled. */
	while (cq->user_cq.thread_count < thread_count)
		usleep(NIC_USER_CQ_SLEEP_USEC);

	return 0;
}

int hltests_nic_cq_create(int fd, struct hltests_nic_cq *cq)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;
	int rc;

	rc = asic->nic_funcs->user_cq_create(fd, cq);
	assert_int_equal(rc, 0);

	return 0;
}

static int ibv_destroy_user_cq(struct hltests_nic_port_cq *port_cq)
{
	int rc;

	rc = hlibv_destroy_cq(port_cq->ibvcq);
	assert_int_equal(rc, 0);

	return 0;
}

static int unmap_cq_resources(int fd, struct hltests_nic_port_cq *port_cq, uint32_t cq_size)
{
	int rc;

	/* Unmap user CQ CI UMR HW block. */
	if (!hltests_is_simulator(fd)) {
		rc = hltests_munmap(fd, port_cq->regs_ptr, SZ_4K);
		assert_int_equal(rc, 0);
	}

	/* Unmap port user CQ buffer */
	rc = hltests_munmap(fd, port_cq->cq_buf, cq_size);
	assert_int_equal(rc, 0);

	/* Unmap port user CQ PI memory. */
	rc = hltests_munmap(fd, port_cq->pi_ptr, SZ_4K);
	assert_int_equal(rc, 0);

	return 0;
}

static int unset_user_cq(int fd, uint32_t port_num, uint32_t cq_id)
{
	struct hlthunk_nic_user_cq_id_unset_in unset_in = {};
	int rc;

	unset_in.port = port_num;
	unset_in.id = cq_id;

	rc = hlthunk_nic_user_cq_id_unset(fd, &unset_in);
	assert_int_equal(rc, 0);

	return 0;
}

/**
 * hltests_user_cq_destroy - Stop user CQ polling and release corresponding HW and SW resources.
 * @fd: Device file descriptor.
 * @cq: Common CQ test structs. For both CQ user and drv.
 *
 * Note: Applicable only for Gaudi2 and future asics.
 */
int hltests_nic_user_cq_destroy(int fd, struct hltests_nic_cq *cq)
{
	uint32_t size, i, max_ports;
	void *retval;
	int rc;

	/* With port CQ we create a CQ on each port, with device CQ we create only one CQ */
	switch (cq->type) {
	case HLTESTS_NIC_CQ_TYPE_PORT:
		max_ports = hltests_nic_get_max_num_of_ports(fd);
		break;
	case HLTESTS_NIC_CQ_TYPE_DEVICE:
		max_ports = 1;
		break;
	default:
		E("Invalid cq type: %u", cq->type);
		fail();
		return -1;
	}

	size = cq->user_cq.cq_buf_len * cq->user_cq.raw_cqe_size;

	for (i = 0 ; i < max_ports ; i++) {
		if (!(cq->user_cq.port_mask[0] & BIT(i)) && cq->type == HLTESTS_NIC_CQ_TYPE_PORT)
			continue;

		struct hltests_nic_port_cq *port_cq = &cq->user_cq.port_cq[i];

		/* Stop all port polling threads and wait till exit. */
		rc = pthread_cancel(port_cq->thread_id);
		assert_int_equal(rc, 0);
		rc = pthread_join(port_cq->thread_id, &retval);
		assert_int_equal(rc, 0);
		assert_true(retval == PTHREAD_CANCELED);

		if (hltests_nic_is_ibdev(fd)) {
			rc = ibv_destroy_user_cq(port_cq);
			assert_int_equal(rc, 0);
		} else {
			rc = unmap_cq_resources(fd, port_cq, size);
			assert_int_equal(rc, 0);

			rc = unset_user_cq(fd, i, port_cq->id);
			assert_int_equal(rc, 0);
		}
	}

	pthread_spin_destroy(&cq->user_cq.cq_lock);

	free(cq->cq_buf);
	free(cq->user_cq.port_cq);

	return 0;
}

int hltests_nic_cq_destroy(int fd, struct hltests_nic_cq *cq)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;
	int rc;

	rc = asic->nic_funcs->user_cq_destroy(fd, cq);
	assert_int_equal(rc, 0);

	return 0;
}

/**
 * user_cq_poll() - Wait for new CQEs to arrive in common CQ buffer.
 * @fd: Device file descriptor
 * @cq: Common CQ test structs. For both CQ user and drv.
 * @cqe_ci: Output consumer index referencing the 1st CQE.
 * @num_of_cqes: Output number of CQEs that were polled.
 * @timeout_us: Exit after timeout (usec) even if no CQEs available.
 *
 * Return: Zero on success, negative value for failure.
 */
static int user_cq_poll(int fd, struct hltests_nic_cq *cq, uint32_t *cqe_ci,
				uint32_t *num_of_cqes, uint64_t timeout_us)
{
	struct timespec now;
	struct timespec later;
	uint32_t num_cqes;

	clock_gettime(CLOCK_MONOTONIC, &now);

	later.tv_sec = now.tv_sec + (time_t)(timeout_us / USEC_PER_SEC);
	later.tv_nsec = now.tv_nsec + (time_t)((timeout_us % USEC_PER_SEC) * NSEC_PER_USEC);

	while (1) {
		clock_gettime(CLOCK_MONOTONIC, &now);

		/* Return with error if timed out. */
		if (later.tv_sec <= now.tv_sec)
			return -ETIME;

		/* read the cqe count atomically */
		num_cqes = atomic_load(&cq->user_cq.cqe_cnt);
		if (num_cqes) {
			if (num_cqes >= ((uint32_t)cq->cq_buf_len - 1))
				return -EOVERFLOW;

			*cqe_ci = cq->cq_ci;
			break;
		}

		/* in case there are no cqes goto sleep */
		usleep(NIC_USER_CQ_SLEEP_USEC);
	}

	*num_of_cqes = num_cqes;

	return 0;
}

int hltests_nic_cq_poll(int fd, struct hltests_nic_cq *cq, uint32_t num_cqes_req, void *cq_buf_out,
			uint32_t *num_cqes_out, uint64_t timeout_us)
{
	uint32_t cqe_ci, num_cqes, residual_cqes = 0;
	int rc;

	rc = user_cq_poll(fd, cq, &cqe_ci, &num_cqes, timeout_us);
	if (rc < 0)
		return rc;

	/* cq->cq_buf is now filled with (num_cqes) cqes starting from cqe_ci. we copy them to the
	 * tests buffer cqe_buf_out[]. we copy the smaller(num_cqes, num_cqes_req)
	 */
	num_cqes = (num_cqes_req <= num_cqes) ? num_cqes_req : num_cqes;

	/* in case of wraparound, we split the copy to 2 steps */
	if (cqe_ci + num_cqes > cq->cq_buf_len)
		residual_cqes = (uint32_t)cq->cq_buf_len - cqe_ci;

	if (residual_cqes) {
		memcpy(cq_buf_out, (struct hl_nic_cqe *) (cq->cq_buf) + cqe_ci,
			sizeof(struct hl_nic_cqe) * residual_cqes);
		cqe_ci = 0;
	}

	memcpy((struct hl_nic_cqe *) cq_buf_out + residual_cqes,
		(struct hl_nic_cqe *) (cq->cq_buf) + cqe_ci,
		sizeof(struct hl_nic_cqe) * (num_cqes - residual_cqes));

	/* update consumer index. */
	atomic_fetch_sub(&cq->user_cq.cqe_cnt, num_cqes);

	cq->cq_ci = (cq->cq_ci + num_cqes) & ((uint32_t)cq->cq_buf_len - 1);
	*num_cqes_out = num_cqes;

	return 0;
}

int hltests_nic_ccqs_create(int fd, struct hltests_nic_ccq ccqs[], uint32_t ccq_buf_len,
				int max_n_ports, uint64_t port_mask,
				struct hltests_nic_db_fifo_data **db_fifos)
{
	uint32_t port;

	/* create cc completion and submission queues per port */
	for (port = 0 ; port < max_n_ports ; port++) {
		if (!(port_mask & BIT_ULL(port)))
			continue;

		/* create cc completion queue */
		ccqs[port].fd = fd;
		ccqs[port].port = port;
		ccqs[port].ccq_buf_len = ccq_buf_len;
		hltests_nic_ccq_create_and_map(&ccqs[port]);

		ccqs[port].cc_sq = db_fifos[port];
	}

	return 0;
}

int hltests_nic_ccqs_destroy(int fd, struct hltests_nic_ccq ccqs[], int max_n_ports,
			     uint64_t port_mask)
{
	uint32_t port;

	for (port = 0 ; port < max_n_ports ; port++) {
		if (!(port_mask & BIT_ULL(port)))
			continue;

		if (!ccqs[port].ccq_buf)
			continue;

		hltests_nic_ccq_unmap_and_destroy(&ccqs[port]);
	}

	return 0;
}

int hltests_nic_ccq_create_and_map(struct hltests_nic_ccq *ccq)
{
	struct hlthunk_nic_user_ccq_set_out out = {};
	struct hlthunk_nic_user_ccq_set_in in = {};
	size_t ccq_buf_len = ccq->ccq_buf_len;
	uint32_t port = ccq->port;
	int fd = ccq->fd;

	in.port = port;
	in.num_of_entries = (uint32_t)ccq_buf_len;
	assert_int_equal(hlthunk_nic_user_ccq_set(fd, &in, &out), 0);

	ccq->ccq_handle = out.ccq_handle;
	ccq->ccq_pi_handle = out.ccq_pi_handle;

	/* map the ccq buffer to user space */
	ccq->ccq_buf = hltests_mmap(fd, (ccq_buf_len * sizeof(struct hltests_nic_ccqe)),
			(off_t)ccq->ccq_handle);
	assert_ptr_not_equal(ccq->ccq_buf, MAP_FAILED);

	memset(ccq->ccq_buf, 0, (ccq_buf_len * sizeof(struct hltests_nic_ccqe)));

	/* map the ccq pi to user space */
	ccq->ccq_pi_mem = hltests_mmap(fd, SZ_4K, (off_t)ccq->ccq_pi_handle);
	assert_ptr_not_equal(ccq->ccq_pi_mem, MAP_FAILED);

	memset(ccq->ccq_pi_mem, 0, SZ_4K);

	return 0;
}

int hltests_nic_ccq_unmap_and_destroy(struct hltests_nic_ccq *ccq)
{
	size_t size = ccq->ccq_buf_len * sizeof(struct hltests_nic_ccqe);

	assert_int_equal(hltests_munmap(ccq->fd, ccq->ccq_buf, size), 0);

	assert_int_equal(hltests_munmap(ccq->fd, ccq->ccq_pi_mem, SZ_4K), 0);

	assert_int_equal(hlthunk_nic_user_ccq_unset(ccq->fd, ccq->port), 0);

	return 0;
}

int hltests_nic_ccq_poll(struct hltests_nic_ccq *ccq, uint32_t starting_qp, uint32_t qps_per_port)
{
	struct hltests_nic_ccqe *ccqe;

	ccq->ccq_pi = *(uint32_t *) ccq->ccq_pi_mem;

	if (ccq->ccq_ci == ccq->ccq_pi)
		return -ENOENT;

	/* HW does not reset PI to 0 once ccq_buf_len is reached. Therefore, maintain CI bounds. */
	ccqe = (struct hltests_nic_ccqe *) ccq->ccq_buf + (ccq->ccq_ci & (ccq->ccq_buf_len - 1));
	if (!ccqe->bits.valid)
		return -EFAULT;

	assert_in_range(ccqe->bits.qpn, starting_qp, starting_qp + qps_per_port - 1);

	/* set valid bit to false, in case pi has a wraparound and reaches this element again */
	ccqe->bits.valid = 0;
	ccq->ccq_ci = ccq->ccq_ci + 1;

	return 0;
}

static bool cc_sq_is_full(int fd, struct hltests_nic_db_fifo_data *cc_sq)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;
	uint32_t produced;
	uint8_t sq_msg_num_elements;

	sq_msg_num_elements = sizeof(struct hltests_nic_cc_sq_bbr_msg) /
				asic->nic_funcs->get_db_fifo_element_size();

	produced = (cc_sq->pi - (*(uint32_t *) cc_sq->ci_cpu_ptr) + CC_SQ_MAX_ELEMENTS_NUM) &
			(CC_SQ_MAX_ELEMENTS_NUM - 1);

	return (CC_SQ_MAX_ELEMENTS_NUM - produced) < sq_msg_num_elements;
}

static int read_qp_context(int fd, uint32_t port, uint32_t qp, char *qpc, uint32_t max_size)
{

	char path[PATH_MAX] = {0}, pci_bus_id[13] = {0}, cmd[CC_CMD_SIZE] = {0};
	int dbgfs_fd, device_idx;
	size_t cmd_size;
	ssize_t size;

	/* write to nic_qp debug fs file to set qp_info before reading qpc
	 * echo <port> <qpn> <is_req> <is_full_print> <force_read> > nic_qp
	 */
	assert_int_equal(hlthunk_get_pci_bus_id_from_fd(fd, pci_bus_id, sizeof(pci_bus_id)), 0);

	device_idx = hlthunk_get_device_index_from_pci_bus_id(pci_bus_id);
	assert_in_range(device_idx, 0, INT_MAX);

	snprintf(path, PATH_MAX, "/sys/kernel/debug/habanalabs_cn/hbl_cn%d/nic_qp", device_idx);
	dbgfs_fd = open(path, O_RDWR);
	assert_in_range(dbgfs_fd, 0, INT_MAX);

	/* prepare qpc command */
	cmd_size = (size_t)snprintf(cmd, CC_CMD_SIZE, "%u %u 1 1 1", port, qp);

	/* write command */
	size = write(dbgfs_fd, cmd, cmd_size);
	assert_in_range(size, 0, INT_MAX);

	/* read and parse cc from qpc */
	size = read(dbgfs_fd, qpc, max_size - 1);
	assert_in_range(size, 1, INT_MAX);

	qpc[size] = '\0';

	close(dbgfs_fd);

	return 0;
}

static int parse_debugfs_qpc_tlv(char *tlv_ptr, char *field_name, char **tlv_saveptr,
					uint32_t *value)
{
	char *type_ptr, *local_tlv_ptr, *arg_ptr;

	local_tlv_ptr = strstr(tlv_ptr, field_name);
	assert_non_null(local_tlv_ptr);

	type_ptr = strtok_r(local_tlv_ptr, ":", tlv_saveptr);
	assert_non_null(type_ptr);

	arg_ptr = strtok_r(0, "\n", tlv_saveptr);
	*value = (uint32_t)strtoul(arg_ptr, NULL, 16);

	return 0;
}

static int validate_cc_bbr_conf(int fd, struct hltests_nic_post_cc_bbr_msg *cc_msg)
{
	char qpc[CC_QPC_SIZE] = {0};
	uint32_t cc_arg = 0;
	char *saveptr;

	assert_int_equal(read_qp_context(fd, cc_msg->port, cc_msg->qp, qpc, sizeof(qpc)), 0);

	/* parse all CC related parameters from QPC. Order matters, and parsing will be done in
	 * order of appearance in QPC.
	 */

	/* parse cc pace time */
	parse_debugfs_qpc_tlv(qpc, "pacing time", &saveptr, &cc_arg);
	/* due to slowness of PLDM, QPC might not be updated yet. Therefore, try again. */
	if (cc_arg != cc_msg->pace_time && hltests_is_pldm(fd)) {
		struct timespec base, now;

		clock_gettime(CLOCK_MONOTONIC_RAW, &base);
		now = base;
		while (get_timediff_usec(&base, &now) < CC_PLDM_QPC_VALIDATION_TO_USEC) {
			assert_int_equal(read_qp_context(fd, cc_msg->port, cc_msg->qp, qpc,
								sizeof(qpc)), 0);

			/* parse cc pace time */
			parse_debugfs_qpc_tlv(qpc, "pacing time", &saveptr, &cc_arg);
			if (cc_arg == cc_msg->pace_time)
				break;

			usleep(100);
			clock_gettime(CLOCK_MONOTONIC_RAW, &now);
		}
	}
	assert_int_equal(cc_arg, cc_msg->pace_time);

	 /* parse cc burst size */
	parse_debugfs_qpc_tlv(saveptr, "burst size", &saveptr, &cc_arg);
	assert_int_equal(cc_arg, cc_msg->burst_size);

	/* parse cong window */
	parse_debugfs_qpc_tlv(saveptr, "congestion window", &saveptr, &cc_arg);
	assert_int_equal(cc_arg, cc_msg->cong_win);

	return 0;
}

static int validate_cc_swift_conf(int fd, struct hltests_nic_post_cc_swift_msg *cc_msg)
{
	char qpc[CC_QPC_SIZE] = {0};
	uint32_t cc_arg = 0;
	char *saveptr;

	/* parse all CC related parameters from QPC. Order matters, and parsing will be done in
	 * order of appearance in QPC.
	 */
	assert_int_equal(read_qp_context(fd, cc_msg->port, cc_msg->qp, qpc, sizeof(qpc)), 0);
	 /* parse max_mdf */
	parse_debugfs_qpc_tlv(qpc, "MAX MDF", &saveptr, &cc_arg);
	/* due to slowness of PLDM, QPC might not be updated yet. Therefore, try again. */
	if (cc_arg != cc_msg->max_mdf && hltests_is_pldm(fd)) {
		struct timespec base, now;

		clock_gettime(CLOCK_MONOTONIC_RAW, &base);
		now = base;
		while (get_timediff_usec(&base, &now) < CC_PLDM_QPC_VALIDATION_TO_USEC) {
			assert_int_equal(read_qp_context(fd, cc_msg->port, cc_msg->qp, qpc,
								sizeof(qpc)), 0);

			/* parse cc pace time */
			parse_debugfs_qpc_tlv(qpc, "MAX MDF", &saveptr, &cc_arg);
			if (cc_arg == cc_msg->max_mdf)
				break;

			usleep(100);
			clock_gettime(CLOCK_MONOTONIC_RAW, &now);
		}
	}
	assert_int_equal(cc_arg, cc_msg->max_mdf);

	/* parse beta_nom */
	parse_debugfs_qpc_tlv(saveptr, "BETA nominator", &saveptr, &cc_arg);
	assert_int_equal(cc_arg, cc_msg->beta_nom);

	/* parse target_delay */
	parse_debugfs_qpc_tlv(saveptr, "target delay", &saveptr, &cc_arg);
	assert_int_equal(cc_arg, cc_msg->target_delay);

	/* parse beta_denom */
	parse_debugfs_qpc_tlv(saveptr, "BETA de-nominator", &saveptr, &cc_arg);
	assert_int_equal(cc_arg, cc_msg->beta_denom);

	/* parse ai */
	parse_debugfs_qpc_tlv(saveptr, "AI", &saveptr, &cc_arg);
	assert_int_equal(cc_arg, cc_msg->ai);

	return 0;
}

static int post_cc_bbr(struct hltests_state *tests_state, struct hltests_nic_db_fifo_data *cc_sq,
			uint32_t port, struct hltests_nic_post_cc_bbr_msg *msg)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(tests_state->fd)->asic_funcs;
	struct hltests_nic_db_fifo_packet db_fifo_packet;
	uint8_t sq_msg_num_elements, valid_mask = 0;
	struct hltests_nic_cc_sq_bbr_msg sq_msg;
	uint64_t *reg_addr;

	assert_int_equal(cc_sq_is_full(tests_state->fd, cc_sq), 0);

	memset(&sq_msg, 0, sizeof(sq_msg));

	reg_addr = ((uint64_t *) ((uint8_t *) cc_sq->regs_cpu_ptr + cc_sq->regs_offset));

	/* set a valid bit in valid_mask to denote each
	 * value this command will set
	 */
	valid_mask |= u8_safe((msg->burst_size) ? BIT(CC_BBR_VALID_BIT_BURST_SIZE) : 0);
	valid_mask |= u8_safe(BIT(CC_BBR_VALID_BIT_SQN));
	valid_mask |= u8_safe((msg->cong_win) ? BIT(CC_BBR_VALID_BIT_CONG_WIN) : 0);
	valid_mask |= u8_safe(BIT(CC_BBR_VALID_BIT_PACE_TIME));

	sq_msg.bits.burst_size =	msg->burst_size & GENMASK(21, 0);
	sq_msg.bits.msg =		CC_MSG_TYPE_BBR;
	sq_msg.bits.sqn =		(uint8_t)msg->sqn;
	sq_msg.bits.cong_win =		msg->cong_win & GENMASK(23, 0);
	sq_msg.bits.pace_time =		(uint16_t)msg->pace_time;
	sq_msg.bits.qp =		msg->qp & GENMASK(23, 0);
	sq_msg.bits.valid_mask =	valid_mask & GENMASK(3, 0);

	db_fifo_packet.packet = &sq_msg;
	db_fifo_packet.size = sizeof(sq_msg);
	hltests_nic_write_descriptor_to_db_fifo(tests_state, cc_sq, &db_fifo_packet, port, false);

	sq_msg_num_elements = sizeof(sq_msg) / asic->nic_funcs->get_db_fifo_element_size();

	/* Due to a HW bug in gaudi2, the ci is updated from 0 to 1 in the first consumption. From
	 * then on it is incremented by sq_msg_num_elements as expected. Therefore, increment pi in
	 * the same manner.
	 */

	if ((cc_sq->pi > 0) || (!hltests_is_gaudi2(tests_state->fd)))
		cc_sq->pi = (cc_sq->pi + sq_msg_num_elements) & (CC_SQ_MAX_ELEMENTS_NUM - 1);
	else
		cc_sq->pi = 1;

	return 0;
}

static int post_cc_swift(struct hltests_state *tests_state, struct hltests_nic_db_fifo_data *cc_sq,
				uint32_t port, struct hltests_nic_post_cc_swift_msg *msg)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(tests_state->fd)->asic_funcs;
	struct hltests_nic_db_fifo_packet db_fifo_packet;
	uint8_t sq_msg_num_elements, valid_mask = 0;
	struct hltests_nic_cc_sq_swift_msg sq_msg;
	uint64_t *reg_addr;

	assert_int_equal(cc_sq_is_full(tests_state->fd, cc_sq), 0);

	memset(&sq_msg, 0, sizeof(sq_msg));

	reg_addr = ((uint64_t *) ((uint8_t *) cc_sq->regs_cpu_ptr + cc_sq->regs_offset));

	/* set a valid bit in valid_mask to denote each
	 * value this command will set
	 */
	#define CC_SWIFT_VALID_BIT_TARGET_DELAY	0
	#define CC_SWIFT_VALID_BIT_AI		1
	#define CC_SWIFT_VALID_BIT_BETA		2
	#define CC_SWIFT_VALID_BIT_MAX_MDF	3

	valid_mask |= u8_safe((msg->target_delay) ? BIT(CC_SWIFT_VALID_BIT_TARGET_DELAY) : 0);
	valid_mask |= u8_safe((msg->ai)	? BIT(CC_SWIFT_VALID_BIT_AI) : 0);
	valid_mask |= u8_safe((msg->beta_nom) ? BIT(CC_SWIFT_VALID_BIT_BETA) : 0);
	valid_mask |= u8_safe((msg->max_mdf) ? BIT(CC_SWIFT_VALID_BIT_MAX_MDF) : 0);

	sq_msg.bits.ai			= (uint8_t)msg->ai;
	sq_msg.bits.msg			= CC_MSG_TYPE_SWIFT;
	sq_msg.bits.max_mdf		= (uint8_t)msg->max_mdf;
	sq_msg.bits.target_delay	= msg->target_delay & GENMASK(21, 0);
	sq_msg.bits.beta_nom		= (uint8_t)msg->beta_nom;
	sq_msg.bits.beta_denom		= (uint8_t)msg->beta_denom;
	sq_msg.bits.qp			= msg->qp & GENMASK(23, 0);
	sq_msg.bits.valid_mask		= valid_mask & GENMASK(3, 0);

	db_fifo_packet.packet = &sq_msg;
	db_fifo_packet.size = sizeof(sq_msg);
	hltests_nic_write_descriptor_to_db_fifo(tests_state, cc_sq, &db_fifo_packet, port, false);

	sq_msg_num_elements = sizeof(sq_msg) / asic->nic_funcs->get_db_fifo_element_size();

	cc_sq->pi = (cc_sq->pi + sq_msg_num_elements) & (CC_SQ_MAX_ELEMENTS_NUM - 1);

	return 0;
}

int hltests_nic_post_cc(struct hltests_state *tests_state, struct hltests_nic_ccqs_poll_info *info,
			uint32_t port, bool add_swift_msg, uint32_t qp)
{
	uint32_t i, db_fifo_entry_size, num_entries_to_consume, num_of_cc_msgs = CC_POST_MSGS;
	struct hltests_device *hdev = get_hdev_from_fd(tests_state->fd);
	struct hltests_nic_post_cc_swift_msg cc_swift_msg = {};
	struct hltests_nic_db_fifo_data *cc_sq = info->ccqs[port].cc_sq;
	struct hltests_nic_post_cc_bbr_msg cc_br_msg = {};
	int rc;

	cc_br_msg.qp = qp;
	cc_br_msg.burst_size = 8;
	cc_br_msg.cong_win = 1000;
	db_fifo_entry_size = hdev->asic_funcs->nic_funcs->get_db_fifo_entry_size();

	/* set such a number of entries which will force hltests_user_db_wait_entry_consume to wait
	 * until db fifo is empty.
	 */
	num_entries_to_consume = cc_sq->fifo_size / db_fifo_entry_size - 1;

	for (i = 0; i < num_of_cc_msgs; i++) {
		if (!cc_sq->regs_cpu_ptr)
			continue;

		cc_br_msg.sqn = i;
		cc_br_msg.port = port;

		/* send a different pace_time each message in order to validate that the
		 * pace time was actually updated
		 */
		cc_br_msg.pace_time = 1 + i;

		post_cc_bbr(tests_state, cc_sq, port, &cc_br_msg);

		rc = hltests_nic_user_db_wait_entry_consume(cc_sq, db_fifo_entry_size,
								num_entries_to_consume, 0);
		assert_int_equal(rc, 0);

		validate_cc_bbr_conf(tests_state->fd, &cc_br_msg);

		if (add_swift_msg) {
			cc_swift_msg.port	= port;
			cc_swift_msg.qp		= qp;
			cc_swift_msg.ai		= 4;
			cc_swift_msg.beta_nom	= 4;
			cc_swift_msg.beta_denom = 5;
			cc_swift_msg.max_mdf	= 2 + i;

			cc_swift_msg.target_delay = 200 + i;

			post_cc_swift(tests_state, cc_sq, port, &cc_swift_msg);

			rc = hltests_nic_user_db_wait_entry_consume(cc_sq, db_fifo_entry_size,
									num_entries_to_consume, 0);
			assert_int_equal(rc, 0);

			validate_cc_swift_conf(tests_state->fd, &cc_swift_msg);
		}
	}

	return 0;
}

int hltests_nic_create_db_packet(struct hltests_nic_db_fifo_packet *db, uint32_t wqe_pi,
					uint32_t qpn, uint32_t port)
{
	struct hltests_nic_user_db *user_db;

	user_db = (struct hltests_nic_user_db *) malloc(sizeof(*user_db));
	assert_non_null(user_db);

	memset(user_db, 0, sizeof(*user_db));

	user_db->wqe_pi = wqe_pi & GENMASK(21, 0);
	user_db->qpn = qpn & GENMASK(23, 0);
	user_db->port = (uint8_t)port;

	db->packet = user_db;
	db->size = sizeof(*user_db);

	return 0;
}

uint32_t hltests_nic_add_bulk_doorbell_pkt(int fd, void *buf, uint32_t buf_size, int nic,
					   uint64_t conn_id, uint64_t db_val)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	return asic->nic_funcs->add_bulk_doorbell_pkt(buf, buf_size, nic, conn_id, db_val);
}

uint64_t hltests_nic_get_db_fifo_umr(int fd, uint32_t port, uint32_t db_fifo_id)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	assert_non_null_ret_val(asic->nic_funcs->get_db_fifo_umr, 0);
	return asic->nic_funcs->get_db_fifo_umr(fd, port, db_fifo_id);
}

uint64_t hltests_nic_get_db_fifo_dup(int fd, uint32_t port, uint32_t db_fifo_id)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	assert_non_null_ret_val(asic->nic_funcs->get_db_fifo_dup, 0);
	return asic->nic_funcs->get_db_fifo_dup(fd, port, db_fifo_id);
}

void hltests_nic_write_desc_to_db_fifo_default(struct hltests_state *tests_state,
					       struct hltests_nic_db_fifo_data *db_fifo,
					       struct hltests_nic_db_fifo_packet *db_fifo_packet,
					       uint32_t port, bool is_dup)
{
	int fd = tests_state->fd;
	uint32_t *db_cpu_ptr, i;
	uint64_t reg_addr;
	uint32_t *descriptor = db_fifo_packet->packet;

	D("Submitting packet to db fifo, port: %u, fifo id: %u, message size: %u", port,
	  db_fifo->id, db_fifo_packet->size);

	if (is_dup) {
		reg_addr = hltests_nic_get_db_fifo_dup(fd, port, db_fifo->id);

		for (i = 0 ; i < db_fifo_packet->size / sizeof(uint32_t) ; i++) {
			WRITE32(reg_addr, *(descriptor + i));
			READ32(reg_addr); /* flush */
		}
	} else if (hltests_is_simulator(fd)) {
		reg_addr = hltests_nic_get_db_fifo_umr(fd, port, db_fifo->id) +
								db_fifo->regs_offset;

		for (i = 0 ; i < db_fifo_packet->size / sizeof(uint32_t) ; i++)
			WRITE32(reg_addr + i * sizeof(uint32_t), *(descriptor + i));
	} else {
		db_cpu_ptr =
			(uint32_t *) ((uint8_t *) db_fifo->regs_cpu_ptr + db_fifo->regs_offset);

		for (i = 0 ; i < db_fifo_packet->size / sizeof(uint32_t) ; i++)
			/* In Gaudi2/3 we should write to the exact register address.
			 * In newer ASICs we should write to the base address.
			 */
			*(db_cpu_ptr + i) = *(descriptor + i);
	}
}

void hltests_nic_write_descriptor_to_db_fifo(struct hltests_state *tests_state,
					     struct hltests_nic_db_fifo_data *db_fifo,
					     struct hltests_nic_db_fifo_packet *db_fifo_packet,
					     uint32_t port, bool is_dup)
{
	int fd = tests_state->fd;
	struct hltests_device *hdev = get_hdev_from_fd(fd);

	hdev->asic_funcs->nic_funcs->write_desc_to_db_fifo(tests_state, db_fifo, db_fifo_packet,
							   port, is_dup);
}

int hltests_nic_user_db_wait_entry_consume(struct hltests_nic_db_fifo_data *db_fifo,
						uint32_t db_fifo_entry_size,
						uint32_t pi_granularity, uint32_t extra_guard)
{
	uint32_t occupied_entries = 0, fifo_entries_amount, *ci_ptr, time_diff;
	struct timespec base, now;

	ci_ptr = (uint32_t *) db_fifo->ci_cpu_ptr;

	/* The PI and CI are increased in entries consumed while fifo_size is in bytes. */
	fifo_entries_amount = db_fifo->fifo_size / db_fifo_entry_size;

	clock_gettime(CLOCK_MONOTONIC_RAW, &base);

	/* We want to leave at least 1 full DWQ entry (=pi_granularity),
	 * free between PI and CI. The free space is calculated by
	 * calculating the delta of the total entries amount allocated for the
	 * fifo and the delta of PI and CI where we take into
	 * account the possibility for CI to be bigger than PI. Result is
	 * wrapped around the allocated fifo entries amount.
	 */
	do {
		occupied_entries = (fifo_entries_amount + db_fifo->pi - *ci_ptr)
					& (fifo_entries_amount - 1);

		clock_gettime(CLOCK_MONOTONIC_RAW, &now);
		time_diff = (uint32_t) get_timediff_sec(&base, &now);
		assert_true(time_diff < DB_FIFO_TIMEOUT_SEC);
		usleep(DB_FIFO_SLEEP_USEC);
	} while ((fifo_entries_amount - occupied_entries) <= (pi_granularity + extra_guard));

	return 0;
}

int hltests_nic_submit_user_fifo(struct hltests_nic_test_params *params, uint32_t port,
					struct hltests_nic_db_fifo_packet *user_fifo_packet)
{
	struct hltests_nic_db_fifo_data *user_fifo;
	struct hltests_nic_asic_funcs *nic_funcs;
	struct hltests_state *tests_state;
	struct hltests_device *hdev;
	uint32_t fifo_idx, num_entries, entry_size, pi_granularity, extra_guard = 0;
	int fd, rc;

	tests_state = params->test_ctx->tests_state;
	fd = params->fd;
	hdev = get_hdev_from_fd(fd);
	nic_funcs = hdev->asic_funcs->nic_funcs;

	fifo_idx = 0;
	entry_size = nic_funcs->get_db_fifo_entry_size();

	user_fifo = &params->user_fifos[fifo_idx][port];
	pi_granularity = user_fifo_packet->size / entry_size;

	/* In gaudi2 there was a HW bug where the CI lag by 1 entry, hence total delta PI-CI
	 * should be 2.
	 */
	if (hltests_is_gaudi2(fd))
		extra_guard = 1;

	/* Wait till there is enough free space available in the user fifo before pushing a new
	 * entry
	 */
	rc = hltests_nic_user_db_wait_entry_consume(user_fifo, entry_size, pi_granularity,
							extra_guard);
	if (rc)
		return rc;

	hltests_nic_write_descriptor_to_db_fifo(tests_state, user_fifo, user_fifo_packet, port,
						false);

	/* Update FIFO pi */
	if (hltests_is_gaudi2(fd)) {
		num_entries = user_fifo->fifo_size / entry_size;
		user_fifo->pi = (user_fifo->pi + pi_granularity) & (num_entries - 1);
	} else {
		/* In Gaudi3 the DB FIFO CI is a free run counter of 11 bits */
		user_fifo->pi = (user_fifo->pi + pi_granularity) & (DB_FIFO_CI_FREE_RUN - 1);
	}

	return 0;
}

int hltests_nic_config_reduction(int fd, enum hltests_nic_reduction_operation red_op,
					enum hltests_nic_reduction_datatype red_data_type,
					uint64_t *reduction)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	return asic->nic_funcs->config_reduction(fd, red_op, red_data_type, reduction);
}

int hltests_nic_get_mac_loopback_mask(int fd, uint64_t *mask)
{
	ssize_t size;
	int rc = 0, tmp_fd, device_idx;
	char buf[20], path[PATH_MAX], pci_bus_id[13];

	rc = hlthunk_get_pci_bus_id_from_fd(fd, pci_bus_id, sizeof(pci_bus_id));
	if (rc)
		return -ENODEV;

	device_idx = hlthunk_get_device_index_from_pci_bus_id(pci_bus_id);
	if (device_idx < 0)
		return -ENODEV;

	snprintf(path, PATH_MAX, "/sys/kernel/debug/habanalabs_cn/hbl_cn%d/nic_mac_loopback",
			device_idx);

	tmp_fd = open(path, O_RDWR);
	if (tmp_fd == -1) {
		printf("Failed to open debugfs MAC loopback\n");
		return errno;
	}

	size = read(tmp_fd, buf, sizeof(buf));
	if (size < 0 || size >= sizeof(buf)) {
		printf("Failed to read debugfs MAC loopback [rc %zd]\n", size);
		rc = errno;
		goto out;
	}

	buf[size] = '\0';
	*mask = strtoull(buf, NULL, 16);
out:
	close(tmp_fd);

	return rc;
}

void hltests_nic_build_vxlan_header(struct hltests_nic_vxlan_header *vxlan_hdr)
{
	vxlan_hdr->flags = 0x08;
	vxlan_hdr->vxlan_nw_id = 0xA5A5A5;
}

void hltests_nic_build_gre_header(struct hltests_nic_gre_header *gre_hdr)
{
	uint16_t gre_enet_bridge = GRE_ETHERNET_BRIDGING;

	hltests_endian_swap_values(&gre_enet_bridge, 2, ENDIAN_SWAP_16);
	gre_hdr->protocol = gre_enet_bridge;
	gre_hdr->version = 0;
	gre_hdr->sequence = 0;
	gre_hdr->key_present = 1;
	gre_hdr->checksum = 0;
	gre_hdr->flowid = 0x0A;
	gre_hdr->vsid = 0x5A5A5A;
}

int hltests_nic_submit_wtd(struct hltests_nic_test_params *params)
{
	const struct hltests_nic_asic_funcs *nic_funcs;
	int fd = params->fd;

	nic_funcs = get_hdev_from_fd(fd)->asic_funcs->nic_funcs;

	return nic_funcs->submit_wtd(params);
}

int hltests_nic_submit_db(struct hltests_nic_test_params *params)
{
	const struct hltests_nic_asic_funcs *nic_funcs;
	int fd = params->fd;

	nic_funcs = get_hdev_from_fd(fd)->asic_funcs->nic_funcs;

	return nic_funcs->submit_db(params);
}

/* Log wrappers */
#if !defined(NDEBUG)

/**
 * We defined these macros to redirect the real functions to these wrappers, now that we're
 * implementing the wrappers, we want to undef them so that we can actually call the real functions.
 */
#undef hlibv_create_qp
#undef hbldv_modify_qp
#undef hbldv_set_port_ex

struct ibv_qp *__hlibv_create_qp_wrapper(struct ibv_pd *pd, struct ibv_qp_init_attr *qp_init_attr)
{
	D("hlibv_create_qp  - qp_type: [%u], max_send_wr: [%u]", qp_init_attr->qp_type,
	  qp_init_attr->cap.max_send_wr);
	return hlibv_create_qp(pd, qp_init_attr);
}

int __hbldv_modify_qp_wrapper(struct ibv_qp *ibqp, struct ibv_qp_attr *attr, int attr_mask,
			      struct hbldv_qp_attr *hl_attr)
{
	D(
	  "hbldv_modify_qp - qp_state: [%u], port_num: [%u], is_coll: [%u], qp_num_hint: [%u] wq_type: [%u], wq_granularity: [%u]",
	  attr->qp_state, attr->port_num, !!(hl_attr->caps & HBLDV_QP_CAP_COLL),
	  hl_attr->qp_num_hint, hl_attr->wq_type, hl_attr->wq_granularity);
	return hbldv_modify_qp(ibqp, attr, attr_mask, hl_attr);
}

int __hbldv_set_port_ex(struct ibv_context *context, struct hbldv_port_ex_attr *attr)
{
	enum hbldv_wq_array_type i;

	D("hbldv_set_port_ex - port_num: %u, wq_arr_attr: {", attr->port_num);
	for (i = 0; i < HBLDV_WQ_ARRAY_TYPE_MAX; i++) {
		D(
		  "\t[%u] = {max_num_of_wqes_in_wq: %2u, max_num_of_wqs: %u, mem_id: %u, swq_granularity: %u}",
		  i, attr->wq_arr_attr[i].max_num_of_wqes_in_wq,
		  attr->wq_arr_attr[i].max_num_of_wqs, attr->wq_arr_attr[i].mem_id,
		  attr->wq_arr_attr[i].swq_granularity);
	}
	D("}");

	return hbldv_set_port_ex(context, attr);
}
#endif /* !defined (NDEBUG) */

void hltests_nic_hexdump(const uint8_t *buf, uint32_t buf_len, const char *fmt, ...)
{
	va_list args;
	uint32_t i, grp_size = 2, bytes_per_line = 16;

	printf("buf: %p len: %u ", buf, buf_len);
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);

	for (i = 0; i < buf_len; i++) {
		if (!(i % bytes_per_line))
			printf("\n%04x:", i);
		if (i % grp_size)
			printf("%02x", buf[i]);
		else
			printf(" %02x", buf[i]);
	}

	printf("\n");
}
