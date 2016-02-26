/* String Functions */


#ifndef POINTER_H
#define POINTER_H 1
#include "CRT.h"
__attribute__((always_inline)) uint64_t crt_convert_pointer(unsigned char *x, unsigned int len);

__attribute__((always_inline)) uint64_t 
crt_convert_pointer(unsigned char *x, unsigned int len)
{
	uint64_t pointer = 0;
	uint64_t z = 1;
	uint64_t temp = 0;
	unsigned int i = 0;

	for(int i = 0; i < len; i++)
		z *= 16;

	for(int i = 0; i < len; i++)
	{
		if(*x > 60)
		{
			temp = *x - 87;
		}
		else
		{
			temp = *x - 48;
		}


		if(z == 1)
		{
			temp = temp;
		}
		else 
		{
			z = z / 16;
			temp = temp * z;
		}

		pointer += temp;
		temp = 0;
		x++;
	}

	return pointer;
}

#endif




