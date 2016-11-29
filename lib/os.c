/*
os.c
*/

#include "os.h"
#include "os_crypto.h"

#ifndef DEV_RANDOM
/* Most operating systems are sensible, Linux is an exception */
#define DEV_RANDOM	"/dev/random"
#endif

void os_random(void *data, size_t len)
{
	static int fd= -1;

	char *cp;
	ssize_t r;

	if (fd == -1)
	{
		fd= open(DEV_RANDOM, O_RDONLY);
		if (fd == -1)
		{
			syslog(LOG_ERR, "unable to open random device '%s': %s",
				DEV_RANDOM, strerror(errno));
			exit(1);
		}
	}

	for (cp= data; len > 0; cp += r, len -= r)
	{
		r= read(fd, cp, len);
		if (r <= 0)
		{
			syslog(LOG_ERR, "error reading from random device: %s",
				r == 0 ? "unexpected EOF" : strerror(errno));
			exit(1);
		}
	}
}
