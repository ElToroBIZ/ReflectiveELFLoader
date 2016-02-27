CC	= gcc
CFLAGS	= -std=gnu99 -w

.PHONY: x86 x86_64
	
x86_64: sample-library.so
	$(CC) $(CFLAGS) -Dx86_64 -DLINUX -o Reflective-ELF-Loader ReflectiveElfLoader.c -I MiniCRT/


sample-library.so: test/sample-library.c
	$(CC) $(CFLAGS) -D_GNU_SOURCE -shared -o sample-library.so -fPIC test/sample-library.c
