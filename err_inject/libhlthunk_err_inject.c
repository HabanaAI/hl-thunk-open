// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include <errno.h>
#include <unistd.h>

#include "hlthunk.h"
#include "hlthunk_err_inject.h"

#define _GNU_SOURCE

hlthunk_public int hlthunk_err_inject_endless_command(int fd)
{
	return -ENOTSUP;
}

hlthunk_public int hlthunk_err_inject_non_fatal_event(int fd, int *event_num)
{
	return -ENOTSUP;
}

hlthunk_public int hlthunk_err_inject_fatal_event(int fd, int *event_num)
{
	close(fd);

	return -ENOTSUP;
}

hlthunk_public int hlthunk_err_inject_loss_of_heartbeat(int fd)
{
	close(fd);

	return -ENOTSUP;
}

hlthunk_public int hlthunk_err_inject_thermal_event(int fd, int *event_num)
{
	return -ENOTSUP;
}
