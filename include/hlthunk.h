/* SPDX-License-Identifier: MIT
 *
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 *
 */

#ifndef HLTHUNK_H
#define HLTHUNK_H

#ifdef __cplusplus
extern "C" {
#endif

#include <uapi/misc/habanalabs.h>

#include <stdint.h>
#include <stdbool.h>

#define hlthunk_public  __attribute__((visibility("default")))

#define HLTHUNK_MAX_MINOR		16
#define HLTHUNK_DEV_NAME_PRIMARY	"/dev/hl%d"
#define HLTHUNK_DEV_NAME_CONTROL	"/dev/hl_controlD%d"

enum hlthunk_node_type {
	HLTHUNK_NODE_PRIMARY,
	HLTHUNK_NODE_CONTROL,
	HLTHUNK_NODE_MAX
};

enum hlthunk_device_name {
	HLTHUNK_DEVICE_GOYA,
	HLTHUNK_DEVICE_PLACEHOLDER1,
	HLTHUNK_DEVICE_PLACEHOLDER2,
	HLTHUNK_DEVICE_INVALID,
	HLTHUNK_DEVICE_DONT_CARE,
	HLTHUNK_DEVICE_MAX
};

struct hlthunk_hw_ip_info {
	uint64_t sram_base_address;
	uint64_t dram_base_address;
	uint64_t dram_size;
	uint32_t sram_size;
	uint32_t num_of_events;
	uint32_t device_id; /* PCI Device ID */
	uint32_t armcp_cpld_version;
	uint32_t psoc_pci_pll_nr;
	uint32_t psoc_pci_pll_nf;
	uint32_t psoc_pci_pll_od;
	uint32_t psoc_pci_pll_div_factor;
	uint16_t tpc_enabled_mask;
	uint8_t dram_enabled;
	uint8_t armcp_version[HL_INFO_VERSION_MAX_LEN];
};

struct hlthunk_cs_in {
	void *chunks_restore;
	void *chunks_execute;
	uint32_t num_chunks_restore;
	uint32_t num_chunks_execute;
	uint32_t flags;
};

struct hlthunk_cs_out {
	uint64_t seq;
	uint32_t status;
};

/**
 * This function opens the habanalabs device according to specified busid, or
 * according to the device name, if busid is NULL. If busid is specified but
 * the device can't be opened, the function fails.
 * @param device_name name of the device that the user wants to open
 * @param busid pci address of the device on the host pci bus
 * @return file descriptor handle or negative value in case of error
 */
hlthunk_public int hlthunk_open(enum hlthunk_device_name device_name,
				const char *busid);

/**
 * This function opens the habanalabs control device according to specified
 * busid, or according to the requested device id number, if busid is NULL. If
 * busid is specified but the device can't be opened, the function fails.
 * @param dev_id the dev_id number of the control device as appears in /dev/.
 * The control devices appear like this:
 * /dev/hl_controlD0
 * /dev/hl_controlD1
 * ...
 * So the dev_id represents the number that appear at the name of the node.
 * Note it is different from the minor number
 * @param busid pci address of the device on the host pci bus
 * @return file descriptor handle or negative value in case of error
 */
hlthunk_public int hlthunk_open_control(int dev_id, const char *busid);

/**
 * This function closes an open file descriptor
 * @param fd file descriptor handle
 * @return the return value of the close() syscall
 */
hlthunk_public int hlthunk_close(int fd);

/**
 * This function retrieves the PCI device ID of a specific device through the
 * INFO IOCTL call
 * @param fd file descriptor handle of habanalabs main or control device
 * @return PCI device ID of the acquired device
 */
hlthunk_public enum hl_pci_ids hlthunk_get_device_id_from_fd(int fd);

/**
 * This function returns the matching device name (ASIC type) of a specific
 * device through the INFO IOCTL call
 * @param fd file descriptor handle of habanalabs main or control device
 * @return enumeration value that represents the ASIC type of the acquired
 * device
 */
hlthunk_public enum hlthunk_device_name hlthunk_get_device_name_from_fd(int fd);

/**
 * This function retrieves the PCI bus ID of a specific device
 * @param fd file descriptor handle of habanalabs main device
 * @param pci_bus_id null-terminated string for the device in the following
 * format: [domain]:[bus]:[device].[function] where domain, bus, device, and
 * function are all hexadecimal values. pci_bus_id should be large enough to
 * store 13 characters including the NULL-terminator.
 * @param len maximum length of string to store in pci_bus_id
 * @return 0 for success, negative value for failure
 */
hlthunk_public int hlthunk_get_pci_bus_id_from_fd(int fd, char *pci_bus_id,
							int len);

/* TODO: split the INFO functions into several "logic" functions */
hlthunk_public int hlthunk_get_hw_ip_info(int fd,
					struct hlthunk_hw_ip_info *hw_ip);
hlthunk_public enum hl_device_status hlthunk_get_device_status_info(int fd);
hlthunk_public bool hlthunk_is_device_idle(int fd);
hlthunk_public int hlthunk_get_busy_engines_mask(int fd, uint32_t *mask);
hlthunk_public int hlthunk_get_info(int fd, struct hl_info_args *info);

hlthunk_public int hlthunk_request_command_buffer(int fd, uint32_t cb_size,
							uint64_t *cb_handle);

hlthunk_public int hlthunk_destroy_command_buffer(int fd, uint64_t cb_handle);

hlthunk_public int hlthunk_command_submission(int fd, struct hlthunk_cs_in *in,
						struct hlthunk_cs_out *out);

hlthunk_public int hlthunk_wait_for_cs(int fd, uint64_t seq,
					uint64_t timeout_us, uint32_t *status);

hlthunk_public uint64_t hlthunk_device_memory_alloc(int fd, uint64_t size,
						bool contiguous, bool shared);

hlthunk_public int hlthunk_device_memory_free(int fd, uint64_t handle);

hlthunk_public uint64_t hlthunk_device_memory_map(int fd, uint64_t handle,
							uint64_t hint_addr);
hlthunk_public uint64_t hlthunk_host_memory_map(int fd, void *host_virt_addr,
						uint64_t hint_addr,
						uint64_t host_size);

hlthunk_public int hlthunk_memory_unmap(int fd, uint64_t device_virt_addr);
hlthunk_public int hlthunk_debug(int fd, struct hl_debug_args *debug);

hlthunk_public void *hlthunk_malloc(int size);
hlthunk_public void hlthunk_free(void *pt);

/* Functions for random number generation */

hlthunk_public void *hlthunk_random_create(unsigned long seed);
hlthunk_public void hlthunk_random_destroy(void *state);
hlthunk_public unsigned long hlthunk_random(void *state);
hlthunk_public double hlthunk_random_double(void *state);

/* Functions for hash table implementation */

hlthunk_public void *hlthunk_hash_create(void);
hlthunk_public int hlthunk_hash_destroy(void *t);
hlthunk_public int hlthunk_hash_lookup(void *t, unsigned long key,
					void **value);
hlthunk_public int hlthunk_hash_insert(void *t, unsigned long key, void *value);
hlthunk_public int hlthunk_hash_delete(void *t, unsigned long key);
hlthunk_public int hlthunk_hash_next(void *t, unsigned long *key, void **value);
hlthunk_public int hlthunk_hash_first(void *t, unsigned long *key,
					void **value);

#ifdef __cplusplus
}   //extern "C"
#endif

#endif /* HLTHUNK_H */
