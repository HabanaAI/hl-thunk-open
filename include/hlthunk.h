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
	uint8_t tpc_enabled_mask;
	uint8_t dram_enabled;
	uint8_t armcp_version[HL_INFO_VERSION_MAX_LEN];
	uint8_t card_name[HL_INFO_CARD_NAME_MAX_LEN];
};

struct hlthunk_dram_usage_info {
	uint64_t dram_free_mem;
	uint64_t ctx_dram_mem;
};

struct hlthunk_clk_rate {
	uint32_t cur_clk_rate_mhz;
	uint32_t max_clk_rate_mhz;
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

/**
 * This function retrieves the device index of a specific device
 * @param busid null-terminated string of the device PCI bus ID in the following
 * format: [domain]:[bus]:[device].[function] where domain, bus, device, and
 * function are all hexadecimal values.
 * @return device index for success, negative value for failure
 */
hlthunk_public int hlthunk_get_device_index_from_pci_bus_id(const char *busid);

/**
 * This function retrieves H/W IP information for a specific device
 * @param fd file descriptor handle of habanalabs main device
 * @param hw_ip info pointer to H/W IP information structure
 * @return 0 for success, negative value for failure
 */
hlthunk_public int hlthunk_get_hw_ip_info(int fd,
					struct hlthunk_hw_ip_info *hw_ip);

/**
 * This function retrieves DRAM usage information for a specific device
 * @param fd file descriptor handle of habanalabs main device
 * @param dram_usage pointer to DRAM usage information structure
 * @return 0 for success, negative value for failure
 */
hlthunk_public int hlthunk_get_dram_usage(int fd,
				struct hlthunk_dram_usage_info *dram_usage);

/**
 * This function retrieves the status of a specific device
 * @param fd file descriptor handle of habanalabs main device
 * @return enumeration value that represents the status of the acquired device
 */
hlthunk_public enum hl_device_status hlthunk_get_device_status_info(int fd);

/**
 * This function checks whether a specific device is idle
 * @param fd file descriptor handle of habanalabs main device
 * @return true if the acquired device is idle, false otherwise
 */
hlthunk_public bool hlthunk_is_device_idle(int fd);

/**
 * This function retrieves a busy engines bitmask of a specific device
 * @param fd file descriptor handle of habanalabs main device
 * @param mask pointer to uint32_t to store the bitmask
 * @return 0 for success, negative value for failure
 */
hlthunk_public int hlthunk_get_busy_engines_mask(int fd, uint32_t *mask);

/**
 * This function retrieves the device utilization as percentage in the last
 * Xms period.
 * @param fd file descriptor handle of habanalabs main device
 * @param period_ms the period value in ms. Valid values are 100-1000, with
 * resolution of 100.
 * @rate pointer to uint32_t to store the utilization rate as percentage.
 * @return 0 for success, negative value for failure
 */
hlthunk_public int hlthunk_get_device_utilization(int fd, uint32_t period_ms,
						uint32_t *rate);

/**
 * This function retrieves the h/w events array
 * @param fd file descriptor handle of habanalabs main device
 * @param aggregate whether to retrieve from last reset or from loading of the
 * driver (aggregate mode)
 * @hw_events_arr_size size of hw_events_arr, in bytes
 * @hw_events_arr pointer to array of uint32_t to store the result.
 * @return 0 for success, negative value for failure
 */
hlthunk_public int hlthunk_get_hw_events_arr(int fd, bool aggregate,
			uint32_t hw_events_arr_size, uint32_t *hw_events_arr);

/**
 * This function retrieves the ASIC current and maximum clock rate, in MHz
 * @param fd file descriptor handle of habanalabs main device
 * @param cur_clk_mhz pointer to memory that will be filled by the function
 * with the current clock rate in MHz
 * @param max_clk_mhz pointer to memory that will be filled by the function
 * with the maximum clock rate in MHz
 * @return 0 for success, negative value for failure
 */
hlthunk_public int hlthunk_get_clk_rate(int fd, uint32_t *cur_clk_mhz,
					uint32_t *max_clk_mhz);

/**
 * This function retrieves miscellaneous information of a specific device
 * @param fd file descriptor handle of habanalabs main device
 * @param info pointer to device information structure
 * @return 0 for success, negative value for failure
 */
hlthunk_public int hlthunk_get_info(int fd, struct hl_info_args *info);

/**
 * This function creates a command buffer for a specific device
 * @param fd file descriptor handle of habanalabs main device
 * @param cb_size size of command buffer
 * @param cb_handle pointer to uint64_t to store the command buffer handle
 * @return 0 for success, negative value for failure
 */
hlthunk_public int hlthunk_request_command_buffer(int fd, uint32_t cb_size,
							uint64_t *cb_handle);

/**
 * This function destroys a command buffer for a specific device
 * @param fd file descriptor handle of habanalabs main device
 * @param cb_handle handle of the command buffer
 * @return 0 for success, negative value for failure
 */
hlthunk_public int hlthunk_destroy_command_buffer(int fd, uint64_t cb_handle);

/**
 * This function submits a set of jobs to a specific device
 * @param fd file descriptor handle of habanalabs main device
 * @param in pointer to command submission input structure
 * @param out pointer to command submission output structure
 * @return 0 for success, negative value for failure
 */
hlthunk_public int hlthunk_command_submission(int fd, struct hlthunk_cs_in *in,
						struct hlthunk_cs_out *out);

/**
 * This function waits until a command submission of a specific device has
 * finished executing
 * @param fd file descriptor handle of habanalabs main device
 * @param seq sequence number of command submission
 * @param timeout_us absolute timeout to wait in microseconds
 * @param status pointer to uint32_t to store the wait status
 * @return 0 for success, negative value for failure
 */
hlthunk_public int hlthunk_wait_for_cs(int fd, uint64_t seq,
					uint64_t timeout_us, uint32_t *status);

/**
 * This function allocates DRAM memory on the device
 * @param fd file descriptor of the device on which to allocate the memory
 * @param size how much memory to allocate
 * @param contiguous whether the memory area will be physically contiguous
 * @param shared whether this memory can be shared with other user processes
 * on the device
 * @return opaque handle representing the memory allocation. 0 is returned
 * upon failure
 */
hlthunk_public uint64_t hlthunk_device_memory_alloc(int fd, uint64_t size,
						bool contiguous, bool shared);

/**
 * This function frees DRAM memory that was allocated on the device using
 * hlthunk_device_memory_alloc
 * @param fd file descriptor of the device that this memory belongs to
 * @param handle the opaque handle that represents this memory
 * @return 0 for success, negative value for failure
 */
hlthunk_public int hlthunk_device_memory_free(int fd, uint64_t handle);

/**
 * This function asks the driver to map a previously allocated DRAM memory
 * to the device's MMU and to allocate for it a VA in the device address space
 * @param fd file descriptor of the device that this memory belongs to
 * @param handle the opaque handle that represents this memory
 * @param hint_addr the user can request from the driver that the VA will be
 * a specific address. The driver doesn't have to comply to this request but
 * will take it under consideration
 * @return VA in the device address space. 0 is returned upon failure
 */
hlthunk_public uint64_t hlthunk_device_memory_map(int fd, uint64_t handle,
							uint64_t hint_addr);

/**
 * This function asks the driver to map a previously allocated host memory
 * to the device's MMU and to allocate for it a VA in the device address space
 * @param fd file descriptor of the device that this memory will be mapped to
 * @param host_virt_addr the user's VA of memory area on the host
 * @param hint_addr the user can request from the driver that the device VA will
 * be a specific address. The driver doesn't have to comply to this request but
 * will take it under consideration
 * @param host_size the size of the memory area
 * @return VA in the device address space. 0 is returned upon failure
 */
hlthunk_public uint64_t hlthunk_host_memory_map(int fd, void *host_virt_addr,
						uint64_t hint_addr,
						uint64_t host_size);

/**
 * This function unmaps a mapping in the device's MMU that was previously done
 * using either hlthunk_device_memory_map or hlthunk_host_memory_map
 * @param fd file descriptor of the device that contains the mapping
 * @param device_virt_addr the VA in the device address space representing
 * the device or host memory area
 * @return 0 for success, negative value for failure
 */
hlthunk_public int hlthunk_memory_unmap(int fd, uint64_t device_virt_addr);

/**
 * This function enables and retrieves debug traces of a specific device
 * @param fd file descriptor handle of habanalabs main device
 * @param debug pointer to debug parameters structure
 * @return 0 for success, negative value for failure
 */
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
