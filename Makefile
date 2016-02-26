CC	= gcc
CFLAGS	= -std=gnu99 -w

.PHONY: x86 x86_64
	
x86_64:
	$(CC) $(CFLAGS) -Dx86_64 -DLINUX -o Reflective-ELF-Loader ReflectiveElfLoader.c -I MiniCRT/

