#ifndef MUNMAP_H
#define MUNMAP_H 1
#include "CRT.h"

__attribute__((always_inline)) int crt_munmap(void *start, unsigned long length);

#ifdef LINUX

	#ifdef x86

	#endif

	#ifdef ARM

	#endif

#ifdef x86_64
__attribute__((always_inline)) int
crt_munmap(void *start, unsigned long length)
{

	long ret;
	asm volatile ("syscall" : "=a" (ret) : "a" (__NR_munmap),
		      "D" (start), "S" (length) :
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






