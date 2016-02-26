
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>

/* Forward declare these functions */
void* __libc_dlopen_mode(const char*, int);
void* __libc_dlsym(void*, const char*);
int   __libc_dlclose(void*);

int main(int argc, char **argv) {
	void *handle;
        double (*puts)(char *);
        char *error;

        handle = __libc_dlopen_mode("libc.so.6", RTLD_LAZY);
        if (!handle) {
            exit(1);
        }

        puts = __libc_dlsym(handle, "puts");

        (*puts)("Hello World");
        __libc_dlclose(handle);
    }
