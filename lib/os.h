/*
mksef.c

Created:	December 2015 by Philip Homburg <philip@f-src.phicoh.com>

OS specific defines
*/

#ifndef SEF__OS_H
#define SEF__OS_H

#ifdef ARCH_BSD

#define _XOPEN_SOURCE 500

#define __BSD_VISIBLE	1	/* How to get this right? */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

typedef uint8_t uint8_T;
typedef uint16_t uint16_T;
typedef uint32_t uint32_T;
typedef uint64_t uint64_T;

#define _NORETURN __attribute__((noreturn))

#endif /* ARCH_BSD */

#ifdef ARCH_LINUX

#define _XOPEN_SOURCE 500

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/time.h>

#define DEV_RANDOM	"/dev/urandom"

typedef uint8_t uint8_T;
typedef uint16_t uint16_T;
typedef uint32_t uint32_T;
typedef uint64_t uint64_T;

#define _NORETURN __attribute__((noreturn))

#endif /* ARCH_LINUX */

#ifdef ARCH_MINIX

#define _MINIX_SOURCE
#define _POSIX_C_SOURCE 2

#include <stdint.h>
#include <stdlib.h>

#include <minix/minlib.h>

typedef uint8_t uint8_T;
typedef uint16_t uint16_T;
typedef uint32_t uint32_T;
typedef unsigned long long uint64_T;

#endif /* ARCH_MINIX */

#ifdef ARCH_OSX

#define POSIX_2000	/* Check what we really need */

#define _DARWIN_C_SOURCE

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

typedef uint8_t uint8_T;
typedef uint16_t uint16_T;
typedef uint32_t uint32_T;
typedef uint64_t uint64_T;

#define _NORETURN __attribute__((noreturn))

#endif /* ARCH_OSX */

void os_random(void *data, size_t len);

#endif /* SEF__OS_H */
