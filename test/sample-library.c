#include <stdio.h>
#include <dlfcn.h>

/*
 * hello()
 *
 * Hello world function exported by the sample library.
 *
 */

void hello()
{
	printf("ELF Loader Module Works!\n");
}

/*
 * loadMsg()
 *
 * This function is automatically called when the sample library is injected
 * into a process. It calls hello() to output a message indicating that the
 * library has been loaded.
 *
 */

__attribute__((constructor))
void loadMsg()
{
	hello();
}
