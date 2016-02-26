#ifndef CLOSE_H
#define CLOSE_H 1
#include "CRT.h"

int linux_close(int fd);


#ifdef LINUX

	#ifdef x86

	#endif

	#ifdef ARM

	#endif

#ifdef x86_64

__attribute__((always_inline)) int
crt_close(int fd)
{

	long ret;
	asm volatile ("syscall" : "=a" (ret) : "a" (__NR_close),
		      "D" (fd):
		      "cc", "memory", "rcx",
		      "r8", "r9", "r10", "r11" );
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






