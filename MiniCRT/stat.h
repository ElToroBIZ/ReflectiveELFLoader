#ifndef STAT_H
#define STAT_H 1
#include "CRT.h"

__attribute__((always_inline)) int crt_stat(const char *path, void *buf);

#ifdef LINUX

	#ifdef x86

	#endif

	#ifdef ARM

	#endif

#ifdef x86_64
__attribute__((always_inline)) int
crt_stat(const char *path, void *buf)
{
	long ret;
	asm volatile ("syscall" :
		"=a" (ret) :
		"a" (4), "D" (path), "S" (buf) :
		"memory"
	);
	if (ret < 0)
	{
		ret = -1;
	}
	return (int)ret;
}
#endif

#endif

#ifdef FREEBSD

	#ifdef x86

	#endif

	#ifdef ARM

	#endif

	#ifdef x86_64

	#endif
#endif

#endif






