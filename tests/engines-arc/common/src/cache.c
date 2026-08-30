/*
 * Copyright (C) 2021 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */

#include <arc_reg.h>

typedef unsigned int uintptr_t;

#define CTRL_IM_MASK	0x40
#define CTRL_LM_MASK	0x80

typedef union {
	void *ptr;
	uintptr_t addr;
} uintptr2;

unsigned _dc_line_size(void)
{
	unsigned d_cache_build = _lr(D_CACHE_BUILD);
	unsigned bsize = (d_cache_build >> 16) & 0xf;
	return 16 << bsize;
}

// returns the input address aligned back to the start of a cache line
uintptr_t __dc_line_addr(uintptr_t addr)
{
	unsigned addr_mask = ~(_dc_line_size() - 1);
	return (addr & addr_mask);
}


static int _dc_invalidate_line_int(uintptr_t addr)
{
	unsigned dc_ctrl;
	uintptr_t inv_addr = __dc_line_addr(addr);

	_sr(inv_addr, DC_IVDL);
	_nop();
	_nop();
	_nop();
	dc_ctrl = _lr(DC_CTRL);
	/* check success bit (SB) here.  However, the spec is not clear on how
	 * SB will be reflected if the line is not present in the cache.  We don't
	 * want to reflect an error if the line is not present, so we ignore SB.
	 * return (dc_ctrl & CTRL_SB_MASK) == CTRL_SB_MASK;
	 */
	dc_ctrl = 0;
	return dc_ctrl;
}

int __dc_do_for_each_line(void *block_ptr, unsigned size)
{
	int stat = 0;
	uintptr2 ui;
	unsigned line_size = _dc_line_size();
	ui.ptr = block_ptr;
	uintptr_t addr = ui.addr;
	uintptr_t first_line = __dc_line_addr(addr);
	uintptr_t end_addr = addr + size - 1;
	uintptr_t last_line = __dc_line_addr(end_addr);

	for (addr = first_line; addr <= last_line; addr += line_size) {
		stat = _dc_invalidate_line_int(addr);
		if (stat != 0)
			break;
	}

	return stat;
}

int _dc_invalidate_block(void *addr, unsigned size, int flush_dirty)
{
	int stat = 0;

	unsigned dc_ctrl_save = _lr(DC_CTRL);
	unsigned dc_ctrl = 0;

	if (flush_dirty)
		dc_ctrl = (CTRL_IM_MASK | CTRL_LM_MASK);

	_sr(dc_ctrl, DC_CTRL);

	stat = __dc_do_for_each_line(addr, size);

	_sr(dc_ctrl_save, DC_CTRL);

	return stat;
}
