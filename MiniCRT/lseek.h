#ifndef LSEEK_H
#define LSEEK_H 1
#include "CRT.h"

int crt_lseek(int fd, unsigned int offset, unsigned int origin);

#ifdef LINUX

	#ifdef x86

	#endif

	#ifdef ARM

	#endif

#ifdef x86_64
__attribute__((always_inline)) int 
crt_lseek(int fd, unsigned int offset, unsigned int origin)
{

	long ret;
	__asm__ volatile ("syscall" : "=a" (ret) : "a" (__NR_lseek),
		      "D" (fd), "S" (offset), "d" (origin) :
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






