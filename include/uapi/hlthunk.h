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

#include <misc/habanalabs.h>

#include <stdint.h>
#include <stdbool.h>

#define hlthunk_public  __attribute__((visibility("default")))

#define HLTHUNK_MAX_MINOR		256
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
	HLTHUNK_DEVICE_GAUDI,
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
	uint32_t cpld_version;
	uint32_t psoc_pci_pll_nr;
	uint32_t psoc_pci_pll_nf;
	uint32_t psoc_pci_pll_od;
	uint32_t psoc_pci_pll_div_factor;
	uint8_t tpc_enabled_mask;
	uint8_t dram_enabled;
	uint8_t cpucp_version[HL_INFO_VERSION_MAX_LEN];
	uint32_t module_id;
	uint8_t card_name[HL_INFO_CARD_NAME_MAX_LEN];
	uint64_t dram_page_size;
};

struct hlthunk_dram_usage_info {
	uint64_t dram_free_mem;
	uint64_t ctx_dram_mem;
};

struct hlthunk_pll_frequency_info {
	uint16_t output[HL_PLL_NUM_OUTPUTS];
};

struct hlthunk_reset_count_info {
	uint32_t hard_reset_count;
	uint32_t soft_reset_count;
};

struct hlthunk_time_sync_info {
	uint64_t device_time;
	uint64_t host_time;
};

struct hlthunk_sync_manager_info {
	uint32_t first_available_sync_object;
	uint32_t first_available_monitor;
};

struct hlthunk_pci_counters_info {
	uint64_t rx_throughput;
	uint64_t tx_throughput;
	uint32_t replay_cnt;
};

#define HLTHUNK_CLK_THROTTLE_POWER	0x1
#define HLTHUNK_CLK_THROTTLE_THERMAL	0x2

struct hlthunk_clk_throttle_info {
	uint32_t clk_throttle_reason_bitmask;
};

struct hlthunk_energy_info {
	uint64_t total_energy_consumption;
};

struct hlthunk_cs_in {
	void *chunks_restore;
	void *chunks_execute;
	uint32_t num_chunks_restore;
	uint32_t num_chunks_execute;
	uint32_t flags;
	uint64_t seq;
};

struct hlthunk_cs_out {
	uint64_t seq;
	uint32_t status;
};

struct hlthunk_signal_in {
	void *chunks_restore;
	uint32_t num_chunks_restore;
	uint32_t queue_index;
	uint32_t flags;
};

struct hlthunk_signal_out {
	uint64_t seq;
	uint32_t status;
};

struct hlthunk_wait_for_signal {
	uint64_t *signal_seq_arr;
	uint32_t signal_seq_nr; /* value of 1 is currently supported */
	uint32_t queue_index;
	uint32_t flags; /* currently unused */
	uint32_t collective_engine_id;
};

struct hlthunk_wait_in {
	void *chunks_restore;
	uint32_t num_chunks_restore;
	uint64_t *hlthunk_wait_for_signal;
	uint32_t num_wait_for_signal; /* value of 1 is currently supported */
	uint32_t flags;
};

struct hlthunk_wait_out {
	uint64_t seq;
	uint32_t status;
};

struct hlthunk_functions_pointers {
	/*
	 * Functions that will be wrapped with profiler code to enable
	 * profiling
	 */
	int (*fp_hlthunk_command_submission)(int fd, struct hlthunk_cs_in *in,
						struct hlthunk_cs_out *out);
	int (*fp_hlthunk_open)(enum hlthunk_device_name device_name,
				const char *busid);
	int (*fp_hlthunk_close)(int fd);
	int (*fp_hlthunk_profiler_start)(int fd);
	int (*fp_hlthunk_profiler_stop)(int fd);
	int (*fp_hlthunk_profiler_get_trace)(int fd, void *buffer,
						uint64_t *size,
						uint64_t *num_entries);

	/* Function for the profiler to use */
	uint64_t (*fp_hlthunk_device_memory_alloc)(int fd, uint64_t size,
						bool contiguous, bool shared);
	int (*fp_hlthunk_device_memory_free)(int fd, uint64_t handle);
	uint64_t (*fp_hlthunk_device_memory_map)(int fd, uint64_t handle,
							uint64_t hint_addr);
	uint64_t (*fp_hlthunk_host_memory_map)(int fd, void *host_virt_addr,
						uint64_t hint_addr,
						uint64_t host_size);
	int (*fp_hlthunk_memory_unmap)(int fd, uint64_t device_virt_addr);
	int (*fp_hlthunk_debug)(int fd, struct hl_debug_args *debug);
	int (*fp_hlthunk_request_command_buffer)(int fd, uint32_t cb_size,
							uint64_t *cb_handle);
	int (*fp_hlthunk_destroy_command_buffer)(int fd, uint64_t cb_handle);
	int (*fp_hlthunk_wait_for_cs)(int fd, uint64_t seq,
					uint64_t timeout_us, uint32_t *status);
	enum hlthunk_device_name (*fp_hlthunk_get_device_name_from_fd)(int fd);
	int (*fp_hlthunk_get_pci_bus_id_from_fd)(int fd, char *pci_bus_id,
							int len);
	int (*fp_hlthunk_get_device_index_from_pci_bus_id)(const char *busid);
	void* (*fp_hlthunk_malloc)(int size);
	void (*fp_hlthunk_free)(void *pt);
	int (*fp_hlthunk_signal_submission)(int fd,
					struct hlthunk_signal_in *in,
					struct hlthunk_signal_out *out);
	int (*fp_hlthunk_wait_for_signal)(int fd,
					struct hlthunk_wait_in *in,
					struct hlthunk_wait_out *out);
	int (*fp_hlthunk_get_time_sync_info)(int fd,
					struct hlthunk_time_sync_info *info);
	int (*fp_hlthunk_get_cs_counters_info)(int fd,
					struct hl_info_cs_counters *info);
	void (*fp_hlthunk_profiler_destroy)(void);
	int (*fp_hlthunk_request_mapped_command_buffer)(int fd,
					uint32_t cb_size, uint64_t *cb_handle);
	int (*fp_hlthunk_wait_for_collective_sig)(int fd,
					struct hlthunk_wait_in *in,
					struct hlthunk_wait_out *out);
	int (*fp_hlthunk_get_cb_usage_count)(int fd, uint64_t cb_handle,
						uint32_t *usage_cnt);
};

struct hlthunk_debugfs {
	int addr_fd;
	int data_fd;
	int clk_gate_fd;
	char clk_gate_val[32];
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
 * This function opens the habanalabs device according to a specified module id.
 * This API is relevant only for ASICs that support this property
 * @param module_id a number representing the module_id in the host machine
 * @return file descriptor handle or negative value in case of error
 */
hlthunk_public int hlthunk_open_by_module_id(uint32_t module_id);

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
hlthunk_public uint32_t hlthunk_get_device_id_from_fd(int fd);

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
hlthunk_public int hlthunk_get_busy_engines_mask(int fd, uint64_t *mask);

/**
 * This function retrieves the PLL frequency of a specific device.
 * @param fd file descriptor handle of habanalabs device
 * @param index the index of the specified PLL
 * @param frequency pointer to frequency structure to store the frequency in MHz
 * in each of the available outputs. if a certain output is not available a 0
 * value will be set
 * @return 0 upon success or negative value in case of error
 */
hlthunk_public int hlthunk_get_pll_frequency(int fd, uint32_t index,
				struct hlthunk_pll_frequency_info *frequency);

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
 * This function retrieves the number of times the device had been hard or soft
 * reset since the last time the driver was loaded
 * @param fd file descriptor handle of habanalabs main device
 * @param info pointer to memory that will be filled by the function
 * with the current reset counts.
 * @return 0 for success, negative value for failure
 */
hlthunk_public int hlthunk_get_reset_count_info(int fd,
					struct hlthunk_reset_count_info *info);

/**
 * This function retrieves the device's time alongside the host's time
 * for synchronization
 * @param fd file descriptor handle of habanalabs main device
 * @param info pointer to memory that will be filled by the function with the
 * device's and host's times
 * @return 0 for success, negative value for failure
 */
hlthunk_public int hlthunk_get_time_sync_info(int fd,
					struct hlthunk_time_sync_info *info);

/**
 * This function retrieves the device's sync manager information
 * @param fd file descriptor handle of habanalabs main device
 * @dcore_id dcore id to fetch relevant sm info from
 * @param info pointer to memory that will be filled by the function with the
 * sync manager information
 * @return 0 for success, negative value for failure
 */
hlthunk_public int hlthunk_get_sync_manager_info(int fd, int dcore_id,
					struct hlthunk_sync_manager_info *info);

/**
 * This function retrieves the device's cs counters information
 * @param fd file descriptor handle of habanalabs main device
 * @param info pointer to memory that will be filled by the function with the
 * cs counters
 * @return 0 for success, negative value for failure
 */
hlthunk_public int hlthunk_get_cs_counters_info(int fd,
					struct hl_info_cs_counters *info);

/**
 * This function retrieves the device's pci counters information
 * @param fd file descriptor handle of habanalabs main device
 * @param info pointer to memory that will be filled by the function with the
 * pci counters information
 * @return 0 for success, negative value for failure
 */
hlthunk_public int hlthunk_get_pci_counters_info(int fd,
					struct hlthunk_pci_counters_info *info);

/**
 * This function retrieves the device's clock throttling inforamtion
 * @param fd file descriptor handle of habanalabs main device
 * @param info pointer to memory that will be filled by the function with the
 * clock throttling information
 * @return 0 for success, negative value for failure
 */
hlthunk_public int hlthunk_get_clk_throttle_info(int fd,
					struct hlthunk_clk_throttle_info *info);

/**
 * This function retrieves the device's total energy consumption
 * in millijoules (mJ), since the driver was loaded.
 * @param fd file descriptor handle of habanalabs main device
 * @param info pointer to memory, where to fill the total energy consumption
 * info.
 * @return 0 for success, negative value for failure
 */
hlthunk_public int hlthunk_get_total_energy_consumption_info(int fd,
				struct hlthunk_energy_info *info);

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
 * This function retrieves the usage count of a CB for a specific device
 * @param fd file descriptor handle of habanalabs main device
 * @param cb_handle handle of the CB
 * @param usage_cnt pointer to uint32_t to store the usage count of the CB
 * @return 0 for success, negative value for failure
 */
hlthunk_public int hlthunk_get_cb_usage_count(int fd, uint64_t cb_handle,
						uint32_t *usage_cnt);

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
 * @param timeout_us absolute timeout to wait in microseconds. If the timeout
 * value is 0, the driver won't sleep at all. It will check the status of the
 * CS and return immediately
 * @param status pointer to uint32_t to store the wait status
 * @return 0 for success, negative value for failure
 */
hlthunk_public int hlthunk_wait_for_cs(int fd, uint64_t seq,
					uint64_t timeout_us, uint32_t *status);

/**
 * This function waits until a command submission of a specific device has
 * finished executing
 * @param fd file descriptor handle of habanalabs main device
 * @param seq sequence number of command submission
 * @param timeout_us absolute timeout to wait in microseconds. If the timeout
 * value is 0, the driver won't sleep at all. It will check the status of the
 * CS and return immediately
 * @param status pointer to uint32_t to store the wait status
 * @timestamp: nanoseconds timestamp recorded once cs is completed
 * @return 0 for success, negative value for failure
 */
hlthunk_public int hlthunk_wait_for_cs_with_timestamp(int fd, uint64_t seq,
					uint64_t timeout_us, uint32_t *status,
					uint64_t *timestamp);

/**
 * This function submits a job of a signal CS to a specific device
 * @param fd file descriptor handle of habanalabs main device
 * @param in pointer to a signal command submission input structure
 * @param out pointer to a  signal command submission output structure
 * @return 0 for success, negative value for failure
 */
hlthunk_public int hlthunk_signal_submission(int fd,
					struct hlthunk_signal_in *in,
					struct hlthunk_signal_out *out);

/**
 * This function submits a job of a  wait CS to a specific device
 * @param fd file descriptor handle of habanalabs main device
 * @param in pointer to a wait command submission input structure
 * @param out pointer to a wait command submission output structure
 * @return 0 for success, negative value for failure. ULLONG_MAX is returned if
 * the given signal CS was already completed. Undefined behavior if the given
 * seq is not of a  signal CS
 */
hlthunk_public int hlthunk_wait_for_signal(int fd,
					struct hlthunk_wait_in *in,
					struct hlthunk_wait_out *out);

/**
 * This function submits a job of a  wait CS to a specific device
 * @param fd file descriptor handle of habanalabs main device
 * @param in pointer to a wait command submission input structure
 * @param out pointer to a wait command submission output structure
 * @return 0 for success, negative value for failure. ULLONG_MAX is returned if
 * the given signal CS was already completed. Undefined behavior if the given
 * seq is not of a  signal CS
 */
hlthunk_public int hlthunk_wait_for_collective_signal(int fd,
					struct hlthunk_wait_in *in,
					struct hlthunk_wait_out *out);

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

/**
 * This function returns a pointer to a char array containing the version. The
 * char array should be freed using hlthunk_free
 * @return valid pointer on success or null in case of error
 */
hlthunk_public char *hlthunk_get_version(void);

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


/**
 * This function starts an API controlled profiling session on a device
 * @param fd file descriptor of the device to start profiling on
 * @return 0 on success or negative value in case of error
 */
hlthunk_public int hlthunk_profiler_start(int fd);

/**
 * This function stops an API controlled profiling session on a device
 * @param fd file descriptor of the device to stop profiling on
 * @return 0 on success or negative value in case of error
 */
hlthunk_public int hlthunk_profiler_stop(int fd);

/**
 * This function retrieves the profiler trace created in an API controlled
 * profiling session. This function should be called first with buffer = null
 * in order to get the trace size, allocate the buffer according to this size
 * and call again with the buffer allocated
 * @param fd file descriptor of the device to get the trace from
 * @param buffer a buffer to copy to trace to, if buffer = null then only
 * retrieves the trace size and amount of entries.
 * The ruturned buffer is built in the following format:
 * [synTraceEvent enries][chars][size_t num][size_t version]
 * num: Amount of synTraceEvent entries
 * version: Synprof parser version
 * @param size out param for the amount of bytes copied to buffer (or the trace
 * size if buffer = null)
 * @param num_entries pointer to the returned number of entries in the trace
 * buffer
 * @return 0 on success or negative value in case of error
 */
hlthunk_public int hlthunk_profiler_get_trace(int fd, void *buffer,
					uint64_t *size, uint64_t *num_entries);

/**
 * This function destroys profiler instance if it existed
 * As long as env var HABANA_PROFILE=1, the profiler will reinitialize
 * on the next hlthunk_open call
 */
hlthunk_public void hlthunk_profiler_destroy(void);

/**
 * This function opens the debug file system of the habanalabs device already
 * opened via the hlthunk_open routine.
 * @param fd The file descriptor of the device as returned from the call to
 * the hlthunk_open routine.
 * @param debugfs The debug-fs information filled by the open routine.
 * @return 0 upon success or negative value in case of error
 */
hlthunk_public int hlthunk_debugfs_open(int fd,
					struct hlthunk_debugfs *debugfs);

/**
 * Using debugfs, this function returns the 32bit value read from the
 * device address space at the specified address.
 * @param debugfs Pointer to the device debug-fs information.
 * @param full_address The 64 bit address in the device address space to read
 * the from
 * @param val The vslue read from the given address
 * @return 0 upon success or negative value in case of error
 */
hlthunk_public int hlthunk_debugfs_read(struct hlthunk_debugfs *debugfs,
					uint64_t full_address, uint32_t *val);

/**
 * Using debugfs, this function writes the 32bit value to the specified address
 * in the device address space
 * @param debugfs Pointer to the device debug-fs information.
 * @param full_address The address in the device address space to writ the value
 * to.
 * @param val The vale to write.
 * @return 0 upon success or negative value in case of error
 */
hlthunk_public int hlthunk_debugfs_write(struct hlthunk_debugfs *debugfs,
					 uint64_t full_address, uint32_t val);

/**
 * This function closes the open debug file system of the habanalabs device.
 * @param debugfs Pointer to the debug-fs information as filled by the
 * hlthunk_debugfs_open routine
 * @return 0 upon success or negative value in case of error
 */
hlthunk_public int hlthunk_debugfs_close(struct hlthunk_debugfs *debugfs);

#ifdef __cplusplus
}   //extern "C"
#endif

#endif /* HLTHUNK_H */
