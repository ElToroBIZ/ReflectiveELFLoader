#ifndef OPEN_H
#define OPEN_H 1
#include "CRT.h"

__attribute__((always_inline)) int crt_open(const char *pathname, unsigned long flags, unsigned long mode);

#ifdef LINUX

	#ifdef x86

	#endif

	#ifdef ARM

	#endif

#ifdef x86_64
__attribute__((always_inline)) int 
crt_open (const char *pathname, unsigned long flags, unsigned long mode)
{

	long ret;
	__asm__ volatile ("syscall" : "=a" (ret) : "a" (__NR_open),
		      "D" (pathname), "S" (flags), "d" (mode) :
		      "cc", "memory", "rcx",
		      "r8", "r9", "r10", "r11" );
	if (ret < 0)
	{
		ret = -1;
	}

	return (int) ret;
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






