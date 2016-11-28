/*
os.h

Operating system specific includes and defines

Created:	Feb 2005 by Philip Homburg for NAH6
*/

#ifndef OS_H
#define OS_H

#ifdef __minix

#ifdef __minix_vmd
#define _POSIX_C_SOURCE 2
#define _MINIX_SOURCE
#else
#define _MINIX
#endif

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <utime.h>
#include <sys/stat.h>
#include <sys/wait.h>

#ifdef __minix_vmd
#include <sys/ioctl.h>
#include <sys/syslog.h>
#else
#define _BYTEORDER_32	0x04030201
void openlog(const char *, int, int);
#define	LOG_PID		0x01
#define	LOG_DAEMON	(3<<3)	/* system daemons */
int setlogmask(int);
#define	LOG_UPTO(pri)	((1 << ((pri)+1)) - 1)
int syslog(int level, char *fmt, ...);
int vsyslog(int level, char *fmt, va_list ap);
#define LOG_ERR		3
#define LOG_INFO	6
#define	LOG_NOTICE	5
#define	LOG_DEBUG	7	/* debug-level messages */
size_t strlcat(char *_dst, const char *_src, size_t _siz);
size_t strlcpy(char *_dst, const char *_src, size_t _siz);
#define initgroups(n,b) 0
#endif

size_t strlcat(char *_dst, const char *_src, size_t _siz);
size_t strlcpy(char *_dst, const char *_src, size_t _siz);

typedef int U16_t;

#endif /* __minix */

#ifdef ARCH_LINUX

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <utime.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

typedef uint8_t u8_t;
typedef uint16_t u16_t;
typedef uint32_t u32_t;
typedef int U16_t;

#endif /* ARCH_LINUX */

#ifdef ARCH_SOLARIS

#define POSIX_2000	/* Check what we really need */

#endif /* ARCH_SOLARIS */

#ifdef ARCH_BSD

#define POSIX_2000	/* Check what we really need */

#endif /* ARCH_BSD */

#ifdef ARCH_OSX

#define POSIX_2000	/* Check what we really need */

#define _DARWIN_C_SOURCE

#endif /* ARCH_OSX */

#ifdef POSIX_2000

#include <assert.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <utime.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#define _NSIG _sys_siglistn

typedef uint8_t u8_t;
typedef uint16_t u16_t;
typedef uint32_t u32_t;
typedef int U16_t;

/* Note to self: make up your mind */
typedef uint8_t u_int8_t;
typedef uint32_t u_int32_t;
typedef uint64_t u_int64_t;

#endif /* POSIX_2000 */

/* Provided by libos.a */
void os_random_data(void *data, size_t len);
void *os_malloc(char *label, size_t size);
void *os_realloc(char *label, void *buf, size_t size);
void os_free(void *buf);

#endif /* OS_H */

/*
 * $PchId: os.h,v 1.6 2012/01/27 15:58:53 philip Exp $
 */
