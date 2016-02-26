#include "MiniCRT/read.h"
#include "MiniCRT/pointer.h"
#include "MiniCRT/mmap.h"
#include "MiniCRT/misc.h"
#include "MiniCRT/open.h"
#include "MiniCRT/munmap.h"
#include "MiniCRT/mmap.h"
#include "MiniCRT/stat.h"
#include "MiniCRT/lseek.h"
#include "MiniCRT/close.h"
#include "MiniCRT/CRT.h"

#include "ReflectiveElfLoader.h"

#include <dlfcn.h>

//Hashes of strings for comparison
#define DYNSYM_HASH  853548892
#define DYNSTR_HASH  0x32e01ec6
#define GOTPLT_HASH  0xb6fb15a8

//Function hashes
#define DLOPEN_HASH 145572495
#define DLCLOSE_HASH 1940953487
#define DLSYM_HASH 3689182238

__attribute__((always_inline)) unsigned int find_section_by_hash(unsigned int hash, Elf64_Shdr *sections, unsigned char *SH_STRTAB, unsigned int numSections);
__attribute__((always_inline)) unsigned int check_elf_magic(Elf64_Ehdr *elfHdr);

void ReflectiveLoader()
{
	//Important Information On Elf Binary To Be Loaded
	Elf64_Ehdr *myElfHeader;
	void *MyBaseAddr;

	//Libc info
	Elf64_Ehdr *libcElfHeader;
	Elf64_Shdr *SeclibcDynSym, *SeclibcDynStr; 
	
	unsigned char *libcBaseAddr, *libcBaseAddrEnd;

	void *libcMapped = NULL;
	unsigned char *SH_STRTAB = NULL;

	//Utility variables
	int success = 0, counter = 0;
	int fd = 0; 
	struct stat sb;

	//Variables String Parsing
	unsigned char *pos = NULL, *begin = NULL, *startBaseAddr = NULL, *endBaseAddr = NULL, *perms = NULL, *libName = NULL,
				  *startLibName = NULL;
	unsigned int len = 0, index = 0;
	int EndOfFile = 0;
    ssize_t r = 0;
	char buf[850];
	//End String Parsing

	//Done this way so relocations are not required :/ maybe there is a better way, but I know this works
	//compiler just generates a bunch of mov instructions and writes the string onto the stack that way
	char x[16];
	x[0]  =   '/';
	x[1]  =   'p';
	x[2]  =   'r';
	x[3]  =   'o';
	x[4]  =   'c';
	x[5]  =   '/';
	x[6]  =   's';
	x[7]  =   'e';
	x[8]  =   'l';
	x[9]  =   'f';
	x[10] =   '/';
	x[11] =   'm';
	x[12] =   'a';
 	x[13] =   'p';
	x[14] =   's';
	x[15] =  '\0'; 

	char libcName[6];
	libcName[0] = 'l';
	libcName[1] = 'i';
	libcName[2] = 'b';
	libcName[3] = 'c';
	libcName[4] = '-';
	libcName[5] = '\0'; 	

	//Zero out buffer
	for(int i = 0; i < 850; i++)
		*(buf + i) = 0;

	//Find shared object elf header
	unsigned char *IP;
	#ifdef x86_64
	__asm__("leaq (%%rip), %0;": "=r"(IP));
	#endif

	#ifdef x86

	#endif

	#ifdef ARM

	#endif

	while(true)
	{
		if(check_elf_magic((Elf64_Ehdr *)IP))
		{
			break;
		}	
		IP--;
	}

	myElfHeader = (void *)IP;

	//Do a few minor checks on the ELF header
    if (myElfHeader->e_ident[EI_VERSION] != EV_CURRENT) 
	{
		return;
    }    
	if (myElfHeader->e_type != ET_EXEC && myElfHeader->e_type != ET_DYN) 
	{
		return;
    }

	//open /proc/self/maps so we can find the base address of libc
	fd = crt_open(&x[0],  0, 0);

	if(fd == -1)
	{
		return; //open failed
	}
	
	r = crt_read(fd, &buf[0], 850);

	if(r == -1)
	{
		return; //read failed
	}

	//String parsing without a C library..
	for(;;)
	{
		pos = &buf;
		len = 0;

		while((*pos != '\n' && pos != '\0') && pos < &buf[850])
		{	
			pos++;
			len++;
		}

		if(len == 850)
		{
			break;	
		}

        pos = &buf;
	   	begin = pos;
	   
	   	//parse a single entry in the list
	   	for(int i = 0; i < len; i++)
	   	{

			//find start address of the library
			if(*pos == '-' && startBaseAddr == NULL)
			{
				startBaseAddr = begin;
				*pos = '\0';
				begin = ++pos;
				continue;
			}

			//find end address of the library
			if(*pos == ' ' && startBaseAddr != NULL && endBaseAddr == NULL)
			{
				endBaseAddr = begin;
				*pos = '\0';
				begin = ++pos;
				continue;
			}
			
			//find permissions for library
			if(*pos == ' ' && endBaseAddr != NULL && perms == NULL)
			{
				perms = begin;
				*pos = '\0';
				begin = ++pos;
				continue;
			}
			
			//find library name skipping over junk we don't care about in the file
			if(*pos == '/' && perms != NULL)
			{
				//find the last / in the file so we can check name against libcName
				while(*pos != '\n')
				{

					if(*pos == '/' || *pos == '\0')
					{
						if(startLibName == NULL)
						{
							startLibName = pos;
						}
						begin = pos;
					}
					pos++;
				}

				*pos == '\0';

				//if we found a module	
				if(*begin == '/')
				{
					begin++;

					//check libc name against loaded module name
					for(int b = 0; b < crt_strlen(libcName); b++)
					{
						if(*(begin + b) == libcName[b])
						{	
							printf("%c", *(begin+b));
							success = 1;
						}
						else
						{
							success = -1;
							break;
						}
					}
				}

				//else we found the stack or heap or something which doesn't have a / in it
				else
				{
					break;
				}


				//okay so the library name matched but we gotta check the permissions to
				//make sure this is the text section of the libc library and not the data section or something like that
				if(success == 1)
				{
					printf("Checking libc permissions..\n");
					success = 0;

					for(int z = 0; z < 4; z++)
					{
						if(*perms == 'x')
						{
							success = 1;
							break;
						}
						perms++;
					}
				}
				break;
	
			}
			pos++;
 		}		

	    //found libc text section now we can parse it
		if(success == 1)
		{

			//if there is a new line character that somehow got leftover from previous entry
			if(*startBaseAddr == '\n')
			{
				startBaseAddr++;
			}
			libcBaseAddr = (void *)crt_convert_pointer(startBaseAddr, crt_strlen(startBaseAddr));
			libcBaseAddrEnd = (void *)crt_convert_pointer(endBaseAddr, crt_strlen(endBaseAddr));
			break;
		}
		
		counter = 0;

		//remove the entry we just read and move other data to front of the buffer
		for(int i = len + 1; i < 850; i++)
		{
			buf[counter] = buf[i];
			buf[i] = 0;
			counter++;
		}
		
		success = 0;

		//reset all of our pointers to null
		pos = NULL, begin = NULL, startBaseAddr = NULL, endBaseAddr = NULL, perms = NULL, libName = NULL;
		startLibName = NULL;
		
		if(EndOfFile != 1) //check if we got to end of file then we don't need to read anymore data
		{
			r = crt_read(fd, &buf[850 - len], len);

			if(r == -1)
			{
				return; //read failed
			}
			else if(r == 0)
			{
				EndOfFile = 1;
			}
		}
	}

	if(success == 1)
	{
		libcElfHeader = (Elf64_Ehdr *)libcBaseAddr;
		success = 0;

		if(!check_elf_magic(libcElfHeader))
		{
			return;
		}

		printf("is valid ELF Header\n");
	}
	else
	{
		return;
	}

	printf("Base address of libc is %p\n", libcBaseAddr);

	//find the section header string table (shstrtab)
	if(libcElfHeader->e_shstrndx == SHN_UNDEF) 
	{
		printf("shstrndx is SHN_UNDEF\n");
		printf("%d\n", libcElfHeader->e_shstrndx);
		return; //doesn't have section header strtab
	}

	if(libcElfHeader->e_shnum == 0)
	{
		printf("File has no sections\n");
		return;
	}

	if(libcElfHeader->e_shentsize != sizeof(Elf64_Shdr))
	{
		printf("Elf64_Shdr size is != to e_shentsize\n");
		return;
	}
	
	//null terminate libc path
	begin = startLibName;
	for(;;)
	{
		if(*begin == '\n' || *begin == '\0')
		{
			*begin = '\0';
			break;
		}
		begin++;
	}	

	//Close previously opened file
	close(fd);

	//Open libc after getting libc path
	fd = crt_open(startLibName,  0, 0);

	if(fd == -1)
	{
		printf("Failed to open libc file on disk..");
		return; 
	}

	printf("%s\n", startLibName);

	//Get file size of libc
	if (0 > crt_stat(startLibName, &sb))
	{
		return;
	}
	printf("libc size is %d\n", sb.st_size);

	//Create memory map to load libc file into
	libcMapped = crt_mmap(NULL, sb.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

	if(libcMapped == -1)
	{
		printf("mmap failed to create anonymous memory mapping for libc file..\n");
		return;
	}

	//Copy libc file on disk into memory map for parsing
	crt_copy_in(fd, libcMapped);
	crt_close(fd);

	printf("libc Mapped address is %p\n", libcMapped);

	//Find SH_STRTAB for LIBC
	Elf64_Shdr *libcElfSections = libcMapped + libcElfHeader->e_shoff;
	SH_STRTAB = libcMapped + libcElfSections[libcElfHeader->e_shstrndx].sh_offset;

	

	//extern void *__libc_dlsym   (void *__map, const char *__name);
	void* (*__libc_dlsym)(void *, char *);

	//extern void *__libc_dlopen_mode  (const char *__name, int __mode);
	void* (*__libc_dlopen_mode)(char *, int mode);
	
	//extern int   __libc_dlclose (void *__map);
	int (*__libc_dlclose)(void *);
	
	//Find .dynsym table for libc
	index = find_section_by_hash(DYNSYM_HASH, libcElfSections, SH_STRTAB, libcElfHeader->e_shnum);

	if(index == -1)
	{
		printf("Did not find section..\n");
		return;
	}

	SeclibcDynSym = (Elf64_Shdr *)&libcElfSections[index];
	Elf64_Sym *libcDynSym = SeclibcDynSym->sh_addr + libcBaseAddr;
	
	printf("dynsym is %p\n", libcDynSym);

	//find .dynstr table for libc
	index = find_section_by_hash(DYNSTR_HASH, libcElfSections, SH_STRTAB, libcElfHeader->e_shnum);

	if(index == -1)
	{
		printf("Did not find section 2..\n");
		return;
	}

	SeclibcDynStr = (Elf64_Shdr *)&libcElfSections[index];	
	unsigned char *libcDYNSTR = SeclibcDynStr->sh_addr + libcBaseAddr;
	
	printf("dynsym is %p\n", libcDYNSTR);

	//find __libc_dlopen_mode and __libc_dlsym
	for(int i = 0; i < (SeclibcDynSym->sh_size / SeclibcDynSym->sh_entsize); i++)
	{
		if(crt_hash(libcDynSym[i].st_name + libcDYNSTR) == DLOPEN_HASH)
			__libc_dlopen_mode = libcDynSym[i].st_value + libcBaseAddr;
		if(crt_hash(libcDynSym[i].st_name + libcDYNSTR) == DLCLOSE_HASH)
			__libc_dlclose = libcDynSym[i].st_value + libcBaseAddr;
		if(crt_hash(libcDynSym[i].st_name + libcDYNSTR) == DLSYM_HASH)
			__libc_dlsym = libcDynSym[i].st_value + libcBaseAddr;
	}

	printf("dlopen %p\n", __libc_dlopen_mode);
	printf("dlsym %p\n", __libc_dlsym);
	printf("dlclose %p\n", __libc_dlclose);

	if(__libc_dlsym == NULL || __libc_dlopen_mode == NULL | __libc_dlclose == NULL)
		return;

	//use these functions this to find malloc function
	void *handle = __libc_dlopen_mode("libc.so.6", RTLD_LAZY);
	int (*my_puts)(char *) = __libc_dlsym(handle, "puts");
	(*my_puts)("Hello World");

	//use these functions to find mprotect


	//calculate amount of memory to allocate for segments


	//Alloc this memory on the heap


	//Make it RWX (living on the edge)


	//Map program segments into memory


	//dlopen DT_NEEDED libraries


	//loop through resolve imported functions (in PLT)

	
	//Perform relocations on binary


	//unmap mapped libc on disk file

	
	//Transfer control to shared object init

}


void main()
{
	ReflectiveLoader();
}


/* Find elf section given a name and hash */
__attribute__((always_inline)) unsigned int
find_section_by_hash(unsigned int sectionHash, Elf64_Shdr *sections, unsigned char *SH_STRTAB, unsigned int numSections)
{
	printf("called\n");
	for(int i = 0; i < numSections; i++)
	{
		unsigned char *sectionName = SH_STRTAB + sections[i].sh_name;
		printf("Checking name %s\n", sectionName);
		if(crt_hash(sectionName) == sectionHash)
		{
			printf("found %s\n", sectionName);
			return i;
		}
	}
	return -1;
}

/* check elf header */
__attribute__((always_inline)) unsigned int
check_elf_magic(Elf64_Ehdr *elfHdr)
{
	if(elfHdr->e_ident[0] == 0x7f)
	{
		if(elfHdr->e_ident[1] == 0x45)
		{
			if(elfHdr->e_ident[2] == 0x4c)
			{
				if(elfHdr->e_ident[3] == 0x46)
				{
					return 1;
				}
			}
		}
	}

	return 0;
}



