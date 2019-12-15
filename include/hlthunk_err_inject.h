// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */
#ifndef HLTHUNK_ERR_INJECT_H
#define HLTHUNK_ERR_INJECT_H

#ifdef __cplusplus
extern "C" {
#endif

#include "hlthunk.h"

hlthunk_public int hlthunk_err_inject_endless_command(int fd);

hlthunk_public int hlthunk_err_inject_non_fatal_event(int fd, int *event_num);

hlthunk_public int hlthunk_err_inject_fatal_event(int *fd, int *event_num);

hlthunk_public int hlthunk_err_inject_loss_of_heartbeat(int fd);

hlthunk_public int hlthunk_err_inject_thermal_event(int fd, int *event_num);

#ifdef __cplusplus
}   //extern "C"
#endif

#endif /* HLTHUNK_ERR_INJECT_H */
