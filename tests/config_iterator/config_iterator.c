// SPDX-License-Identifier: MIT

#include "config_iterator.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include "hlthunk_tests.h"
#include <time.h>

/**
 * struct config_iterator -  config iterator data structure.
 * @limit: an array of limits of the config iterator.
 * @configs: current state of the configurations.
 * @configs_len: the lengths of the configurations array.
 * @is_exhausted: is the iterator exhausted.
 */
struct config_iterator {
	const struct config_limit *limits;
	size_t *configs;
	size_t configs_len;
	bool is_exhausted;
};

struct config_iterator *config_iterator_init(const struct config_limit *limits, size_t limits_len)
{
	/* Validate limits */
	for (size_t i = 0; i < limits_len; i++) {
		if (limits[i].end < limits[i].start) {
			W("Config at index %zu doesn't satisfy end >= start, end: %zu, start: %zu",
			  i, limits[i].end, limits[i].start);
			return NULL;
		}
	}

	struct config_iterator *iter = calloc(1, sizeof(struct config_iterator));

	if (!iter)
		return NULL;

	iter->configs = calloc(limits_len, sizeof(*iter->configs));
	if (!iter->configs)
		goto configs_alloc_failed;

	iter->limits = limits;
	iter->configs_len = limits_len;
	iter->is_exhausted = false;

	for (size_t i = 0; i < limits_len; i++)
		iter->configs[i] = iter->limits[i].start;

	return iter;

configs_alloc_failed:
	free(iter);
	return NULL;
}

void config_iterator_destroy(struct config_iterator *iter)
{
	free(iter->configs);
	free(iter);
}

const size_t *config_iterator_current(struct config_iterator *iter)
{
	if (iter->is_exhausted)
		return NULL;

	return iter->configs;
}

const size_t *config_iterator_next(struct config_iterator *iter)
{
	for (size_t i = 0; i < iter->configs_len; i++) {
		iter->configs[i]++;

		if (iter->configs[i] <= iter->limits[i].end)
			return iter->configs;

		iter->configs[i] = iter->limits[i].start;
	}

	iter->is_exhausted = true;

	return NULL;
}
