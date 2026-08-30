/* SPDX-License-Identifier: MIT
 *
 * Copyright 2024 HabanaLabs, Ltd.
 * All Rights Reserved.
 *
 */

#ifndef CONFIG_ITERATOR_H
#define CONFIG_ITERATOR_H

#include <stdio.h>

struct config_iterator;

/**
 * struct config_limit -  config limits
 * @start: the first valid configuration value.
 * @end: the last valid configuration value.
 */
struct config_limit {
	size_t start;
	size_t end;
};

/**
 * config_iterator_init() - initializes the config iterator.
 * @limits: an array of limits, with the upper and lower limit of each config.
 * @limits_len: the length of the limits array.
 * Returns: a pointer to the config iterator.
 *
 * LIFETIME: `limits` is stored inside the iterator, so it must outlive the iterator.
 */
struct config_iterator *config_iterator_init(const struct config_limit *limits, size_t limits_len);

/**
 * config_iterator_destroy() - destroys the config iterator.
 * @config_iterator: the config iterator to destroy.
 */
void config_iterator_destroy(struct config_iterator *config_iterator);

/**
 * config_iterator_first() - Returns the current state of the config without advancing the state.
 * @config_iterator: the config iterator to get config from.
 * Returns: a pointer to the current configuration, NULL if reached the end of the iterator.
 */
const size_t *config_iterator_current(struct config_iterator *config_iterator);

/**
 * config_iterator_next() - Advances the state and returns the new state of the config.
 * @config_iterator: the config iterator advance.
 * Returns: a pointer to the current configuration, NULL if reached the end of the iterator.
 */
const size_t *config_iterator_next(struct config_iterator *config_iterator);

#endif /* CONFIG_ITERATOR_H */
