/* Misc Functions */

#ifndef MISC_H
#define MISC_H 1
#include "CRT.h"

__attribute__((always_inline)) void * crt_memcpy(void *dest, const void *src, unsigned long n);
__attribute__((always_inline)) unsigned long crt_strlen(const char *s);
__attribute__((always_inline)) void crt_copy_in(int fd, void *address);
__attribute__((always_inline)) unsigned int crt_hash(unsigned char *word);

__attribute__((always_inline)) unsigned long
crt_strlen(const char *s)
{
	unsigned long r = 0;
	for (; s && *s; ++s, ++r);
	return r;
}

__attribute__((always_inline)) void
crt_copy_in(int fd, void *address)
{
	int cc;
	off_t offset = 0;
	char buf[1024];

	while (0 < (cc = read(fd, buf, sizeof(buf))))
	{
		crt_memcpy((address + offset), buf, cc);
		offset += cc;
	}
}

__attribute__((always_inline)) void *
crt_memcpy(void *dest, const void *src, unsigned long n)
{
	unsigned long i;
	unsigned char *d = (unsigned char *)dest;
	unsigned char *s = (unsigned char *)src;

	for (i = 0; i < n; ++i)
		d[i] = s[i];

	return dest;
}

__attribute__((always_inline)) unsigned int
crt_hash(unsigned char *word)
{
    unsigned int hash = 0;
    for (int i = 0 ; word[i] != '\0' && word[i] != '@'; i++)
    {
        hash = 31*hash + word[i];
    }
    return hash;
}

#endif




