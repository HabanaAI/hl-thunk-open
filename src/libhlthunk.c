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
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int hlthunk_debug_level;
unsigned long kmd_open_count;
pthread_mutex_t hlthunk_mutex = PTHREAD_MUTEX_INITIALIZER;

static int hlthunk_ioctl(int fd, unsigned long request, void *arg)
{
	int ret;

	do {
		ret = ioctl(fd, request, arg);
	} while (ret == -1 && (errno == EINTR || errno == EAGAIN));

	return ret;
}

/* Normally libraries don't print messages. For debugging purpose, we'll
 * print messages if an environment variable, HLTHUNK_DEBUG_LEVEL, is set.
 */
static void init_debug_level(void)
{
	char *envvar;
	int debug_level;

	hlthunk_debug_level = HLTHUNK_DEBUG_LEVEL_DEFAULT;

	envvar = getenv("HLTHUNK_DEBUG_LEVEL");
	if (envvar) {
		debug_level = atoi(envvar);
		if (debug_level >= HLTHUNK_DEBUG_LEVEL_ERR &&
				debug_level <= HLTHUNK_DEBUG_LEVEL_DEBUG)
			hlthunk_debug_level = debug_level;
	}
}

HLTHUNK_STATUS HLTHUNKAPI hlthunk_open_device(int device_id, int *fd)
{
	HLTHUNK_STATUS rc;
	char *device_name;

	if (asprintf(&device_name, "/dev/hl%d", device_id) == -1) {
		pr_err("Failed to allocate memory for device name\n");
		return HLTHUNK_STATUS_NO_MEMORY;
	}

	pthread_mutex_lock(&hlthunk_mutex);

	if (kmd_open_count == 0) {
		init_debug_level();

		*fd = open(device_name, O_RDWR | O_CLOEXEC);

		if (*fd != -1) {
			kmd_open_count = 1;
		} else {
			rc = HLTHUNK_STATUS_KMD_IO_CHANNEL_NOT_OPENED;
			goto open_failed;
		}
	} else {
		kmd_open_count++;
		rc = HLTHUNK_STATUS_KERNEL_ALREADY_OPENED;
	}

open_failed:
	pthread_mutex_unlock(&hlthunk_mutex);

	free(device_name);

	return rc;
}

HLTHUNK_STATUS HLTHUNKAPI hlthunk_close_device(int fd)
{
	HLTHUNK_STATUS rc;

	pthread_mutex_lock(&hlthunk_mutex);

	if (kmd_open_count > 0)	{
		if (--kmd_open_count == 0)
			close(fd);

		rc = HLTHUNK_STATUS_SUCCESS;
	} else
		rc = HLTHUNK_STATUS_KMD_IO_CHANNEL_NOT_OPENED;

	pthread_mutex_unlock(&hlthunk_mutex);

	return rc;
}

