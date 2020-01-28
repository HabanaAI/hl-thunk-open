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

/**
 * This function sends a command that will never end to the habanalabs device
 * @param fd the file descriptor of the already opened habanalabs device
 * @return 0 when such command was submitted successfully, negative value in
 * case of an error.
 */
hlthunk_public int hlthunk_err_inject_endless_command(int fd);

/**
 * This function injects a non-fatal event (an event that the driver does not
 * need to hard-reset the chip in order to recover from it) to the habanalabs
 * device
 * @param fd the file descriptor of the already opened habanalabs device
 * @param event_num the event number in the driver triggered  by the
 * injected error
 * @return 0 when the command was submitted successfully, negative value in
 * case of an error.
 */
hlthunk_public int hlthunk_err_inject_non_fatal_event(int fd, int *event_num);

/**
 * This function injects a fatal event (an event that the requires a hard-reset
 * in order to recover from it)
 * Note, this is a destructive operation. The file-descriptor passed will not
 * be usable after this call.
 * @param fd the file descriptor of the already opened habanalabs device
 * @param event_num the event number in the driver triggered by this error
 * @return 0 when the command was submitted successfully, negative value in
 * case of an error.
 */
hlthunk_public int hlthunk_err_inject_fatal_event(int fd, int *event_num);

/**
 * This function causes a loss of heartbeat situation which should be
 * recognized by the driver and handled as a fatal event by it.
 * Note, this is a destructive operation. The file-descriptor passed will not
 * be usable after this call.
 * @param fd the file descriptor of the already opened habanalabs device
 * @return 0 when the command was submitted successfully, negative value in case
 * of an error.
 */
hlthunk_public int hlthunk_err_inject_loss_of_heartbeat(int fd);

/**
 * This function causes an overheat situation which should be recognized and
 * handled by the driver and system monitoring tools.
 * @param fd the file descriptor of the already opened habanalabs device
 * @return 0 when the command was submitted successfully, negative value in case
 * of an error.
 */
hlthunk_public int hlthunk_err_inject_thermal_event(int fd);

/**
 * This function ceases the overheat situation caused by the
 * hlthunk_err_inject_thermal_event routine.
 * @param fd the file descriptor of the already opened habanalabs device
 * @return 0 when the command was submitted successfully, negative value in case
 * of an error.
 */
hlthunk_public int hlthunk_err_eject_thermal_event(int fd);

#ifdef __cplusplus
}   //extern "C"
#endif

#endif /* HLTHUNK_ERR_INJECT_H */
