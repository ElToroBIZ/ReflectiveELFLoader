/* Misc Functions */

#ifndef MMAP_H
#define MMAP_H 1
#include "CRT.h"

__attribute__((always_inline)) void* crt_mmap(void *start, unsigned long length, int prot, int flags, int fd, unsigned long offset);

#ifdef LINUX

	#ifdef x86

	#endif

	#ifdef ARM

	#endif

#ifdef x86_64

__attribute__((always_inline)) void*
crt_mmap(void *start, unsigned long length, int prot, int flags, int fd, unsigned long offset)
{
	void *ret;
	register long r10 asm("r10") = flags;
	register long r9 asm("r9") = offset;
	register long r8 asm("r8") = fd;

	__asm__ volatile ("syscall" : "=a" (ret) : "a" (__NR_mmap),
		      "D" (start), "S" (length), "d" (prot), "r" (r8), "r" (r9), "r" (r10) : 
		      "cc", "memory", "rcx", "r11");

	return ret;
	
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




