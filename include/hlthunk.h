/*
 * Copyright (c) 2019 HabanaLabs Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
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

enum hlthunk_device_name {
	HLTHUNK_DEVICE_GOYA,
	HLTHUNK_DEVICE_INVALID
};

hlthunk_public int hlthunk_open(enum hlthunk_device_name device_name,
				const char *busid);
hlthunk_public int hlthunk_close(int fd);
hlthunk_public enum hl_pci_ids hlthunk_get_device_id_from_fd(int fd);

/* TODO: split the INFO functions into several "logic" functions */
hlthunk_public int hlthunk_get_hw_ip_info(int fd,
					struct hlthunk_hw_ip_info *hw_ip);
hlthunk_public enum hl_device_status hlthunk_get_device_status_info(int fd);
hlthunk_public bool hlthunk_is_device_idle(int fd);
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

hlthunk_public void* hlthunk_malloc(int size);
hlthunk_public void hlthunk_free(void *pt);

/* Functions for random number generation */

hlthunk_public void *hlthunk_random_create(unsigned long seed);
hlthunk_public void hlthunk_random_destroy(void *state);
hlthunk_public unsigned long hlthunk_random(void *state);
hlthunk_public double hlthunk_random_double(void *state);

/* Functions for hash table implementation */

hlthunk_public void* hlthunk_hash_create(void);
hlthunk_public int hlthunk_hash_destroy(void *t);
hlthunk_public int hlthunk_hash_lookup(void *t, unsigned long key, void **value);
hlthunk_public int hlthunk_hash_insert(void *t, unsigned long key, void *value);
hlthunk_public int hlthunk_hash_delete(void *t, unsigned long key);
hlthunk_public int hlthunk_hash_next(void *t, unsigned long *key, void **value);
hlthunk_public int hlthunk_hash_first(void *t, unsigned long *key, void **value);

#ifdef __cplusplus
}   //extern "C"
#endif

#endif /* HLTHUNK_H */
