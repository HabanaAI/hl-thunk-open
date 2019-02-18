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

#ifndef HLTHUNK_TESTS_H
#define HLTHUNK_TESTS_H

#include <hlthunk_tests_atomic.h>

#include <sys/types.h>
#include <sys/mman.h>

struct hlthunk_tests_state {
	int fd;
};

struct hlthunk_tests_asic_funcs {
};

struct hlthunk_tests_device {
	const struct hlthunk_tests_asic_funcs *asic_funcs;
	int fd;
	atomic_t refcnt;
};

int hlthunk_tests_init(void);
void hlthunk_tests_fini(void);
int hlthunk_tests_open(const char *busid);
int hlthunk_tests_close(int fd);

void *hlthunk_tests_mmap(int fd, size_t len, off_t offset);
int hlthunk_tests_munmap(void *addr, size_t length);

void goya_tests_set_asic_funcs(struct hlthunk_tests_device *hdev);

#endif /* HLTHUNK_TESTS_H */
