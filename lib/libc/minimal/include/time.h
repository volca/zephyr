/*
 * Copyright (c) 2017 Intel Corporation
 * Copyright (c) 2019 Peter Bigot Consulting, LLC
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_LIB_LIBC_MINIMAL_INCLUDE_TIME_H_
#define ZEPHYR_LIB_LIBC_MINIMAL_INCLUDE_TIME_H_

#include <stdint.h>
#include <bits/restrict.h>

/* Minimal time.h to fulfill the requirements of certain libraries
 * like mbedTLS and to support time APIs.
 */

#ifdef __cplusplus
extern "C" {
#endif

struct tm {
	int tm_sec;
	int tm_min;
	int tm_hour;
	int tm_mday;
	int tm_mon;
	int tm_year;
	int tm_wday;
	int tm_yday;
	int tm_isdst;
};

typedef int64_t time_t;
typedef int32_t suseconds_t;

struct timespec {
	time_t tv_sec;
	long tv_nsec;
};

/*
 * Conversion between civil time and UNIX time.  The companion
 * localtime() and inverse mktime() are not provided here since they
 * require access to time zone information.
 */
struct tm *gmtime(const time_t *timep);
struct tm *gmtime_r(const time_t *_MLIBC_RESTRICT timep,
		    struct tm *_MLIBC_RESTRICT result);

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_LIB_LIBC_MINIMAL_INCLUDE_STDIO_H_ */
