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

#include "libhlthunk.h"

#define _GNU_SOURCE

#include <errno.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int hlthunk_debug_level = HLTHUNK_DEBUG_LEVEL_NA;

static int hlthunk_ioctl(int fd, unsigned long request, void *arg)
{
	int ret;

	do {
		ret = ioctl(fd, request, arg);
	} while (ret == -1 && (errno == EINTR || errno == EAGAIN));

	return ret;
}

static const char* hlthunk_get_device_name_by_type(int type)
{
	switch (type) {
	case HLTHUNK_NODE_PRIMARY:
		return HLTHUNK_DEV_NAME_PRIMARY;
	default:
		return NULL;
	}
}

static int hlthunk_open_by_busid(const char *busid, int type)
{
	const char *dev_name = hlthunk_get_device_name_by_type(type);

	if (!dev_name)
		return -1;

	return -1;
}

static int hlthunk_open_minor(int minor, const char *dev_name)
{
	char buf[64];
	int fd;

	sprintf(buf, dev_name, minor);
	if ((fd = open(buf, O_RDWR | O_CLOEXEC, 0)) >= 0)
		return fd;
	return -errno;
}

static int hlthunk_open_device(int type)
{
	int fd, i;
	const char *dev_name = hlthunk_get_device_name_by_type(type);

	if (!dev_name)
		return -1;

	for (i = 0 ; i < HLTHUNK_MAX_MINOR ; i++)
		if ((fd = hlthunk_open_minor(i, dev_name)) >= 0)
			return fd;

	return -1;
}

int hlthunk_open(const char *busid)
{
	if (busid) {
		int fd = hlthunk_open_by_busid(busid, HLTHUNK_NODE_PRIMARY);
		if (fd >= 0)
			return fd;
	}

	return hlthunk_open_device(HLTHUNK_NODE_PRIMARY);
}

int hlthunk_close(int fd)
{
	return close(fd);
}

int hlthunk_public hlthunk_get_info(int fd, struct hl_info_args *info)
{
	return hlthunk_ioctl(fd, HL_IOCTL_INFO, info);
}

int hlthunk_public hlthunk_command_buffer(int fd, union hl_cb_args *cb)
{
	return hlthunk_ioctl(fd, HL_IOCTL_CB, cb);
}

int hlthunk_public hlthunk_command_submission(int fd, union hl_cs_args *cs)
{
	return hlthunk_ioctl(fd, HL_IOCTL_CS, cs);
}

int hlthunk_public hlthunk_wait_for_cs(int fd, union hl_wait_cs_args *wait_for_cs)
{
	return hlthunk_ioctl(fd, HL_IOCTL_WAIT_CS, wait_for_cs);
}

int hlthunk_public hlthunk_memory(int fd, union hl_mem_args *mem)
{
	return hlthunk_ioctl(fd, HL_IOCTL_MEMORY, mem);
}

int hlthunk_public hlthunk_debug(int fd, struct hl_debug_args *debug)
{
	return hlthunk_ioctl(fd, HL_IOCTL_DEBUG, debug);
}
