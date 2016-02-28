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

//Section Name Hashes
#define DYNSYM_HASH  853548892
#define DYNSTR_HASH  0x32e01ec6
#define GOTPLT_HASH  0xb6fb15a8

#define RELAPLT_HASH 2199925792
#define RELADYN_HASH 2199914657
#define DYNAMIC_HASH 689664081

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
	//End Variables String Parsing

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
	crt_close(fd);

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

	//find __libc_dlopen_mode and __libc_dlsym and __libc_dlclose
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

	char CLIB[10];
	CLIB[0] = 'l';
	CLIB[1] = 'i';
	CLIB[2] = 'b';
	CLIB[3] = 'c';
	CLIB[4] = '.';
	CLIB[5] = 's';
	CLIB[6] = 'o';
	CLIB[7] = '.';
	CLIB[8] = '6';
	CLIB[9] = '\0';

	char calloc_s[7];
	calloc_s[0] = 'c';
	calloc_s[1] = 'a';
	calloc_s[2] = 'l';
	calloc_s[3] = 'l';
	calloc_s[4] = 'o';
	calloc_s[5] = 'c';
	calloc_s[6] = '\0';

	char mprotect_s[8];
	mprotect_s[0] = 'm';
	mprotect_s[1] = 'p';
	mprotect_s[2] = 'r';
	mprotect_s[3] = 'o';
	mprotect_s[4] = 't';
	mprotect_s[5] = 'e';
	mprotect_s[6] = 'c';
	mprotect_s[7] = 't';
	mprotect_s[8] = '\0';

	//use these functions this to find malloc function
	void *handle = __libc_dlopen_mode(&CLIB, RTLD_LAZY);

    if (!handle) {
		printf("Invalid Handle\n");
		return;
	}

	int (*my_puts)(char *) = __libc_dlsym(handle, "puts");
	(*my_puts)("Hello World");

	//Resolve mprotect function using dlsym
	int (*libc_mprotect)(void *addr, size_t len, int prot) = __libc_dlsym(handle, &mprotect_s);
	
	//Resolve malloc function using dlsym
	void* (*libc_calloc)(size_t, size_t size) = __libc_dlsym(handle, &calloc_s);

/* DEBUG TO TEST LOADING CAPABILITIES WE JUST MAP IN FILE FROM DISK (NOT TESTING INJECTION ATM SO I CAN USE PRINTF!!!) */
	fd = crt_open("sample-library.so",  0, 0);
	if(fd == -1)
	{
		printf("Failed to open SAMPLE target");
		return; 
	}

	if (0 > crt_stat("sample-library.so", &sb))
	{
		return;
	}
	printf("sample-target size is %d\n", sb.st_size);

	void *meMapped = crt_mmap(NULL, sb.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

	if(meMapped == -1)
	{
		printf("mmap failed to create anonymous memory mapping...\n");
		return;
	}

	//Copy libc file on disk into memory map for parsing
	crt_copy_in(fd, meMapped);
	crt_close(fd);

	printf("DEBUG SAMPLE TARGET Mapped address is %p\n", meMapped);

	myElfHeader = (Elf64_Ehdr *)meMapped;

	if(!check_elf_magic(myElfHeader))
	{
		printf("DEBUG SAMPLE TARGET ELF MAGIC ERROR!!!");
		return;
	}
/* DEBUG */

	//calculate amount of memory to allocate for segments
	unsigned int size = 0, numPages; 
	Elf64_Phdr *segments = myElfHeader->e_phoff + (void *)myElfHeader;

	printf("number of program headers is %d\n", myElfHeader->e_phnum);

	for(int i = 0; i < myElfHeader->e_phnum; i++)
	{
		if(segments[i].p_type == PT_LOAD)
		{
			printf("Found PT_LOAD Segment\n");

			if(segments[i].p_memsz > segments[i].p_align)
			{
				numPages = 1 + (segments[i].p_memsz - segments[i].p_memsz % segments[i].p_align) / segments[i].p_align;
			}			
			else
			{
				numPages = 1;
			}				
			
			size += segments[i].p_align * numPages;
			printf("number of program align size pages is %d\n", numPages);
		}

	}

	printf("FINAL module memory size is %08x\n", size);

	size += 0x2000; //padding
	
	//Alloc this memory on the heap
	void *myProcessImage = (*libc_calloc)(1, size);
	
	if(myProcessImage == NULL)
	{
		printf("Failed to malloc memory to load process\n");
		return;
	}

	printf("Allocated memory for shared object at %p\n", myProcessImage);
	unsigned long temp = (unsigned long)myProcessImage & 0x00000FFF;
	myProcessImage += (0x1000 - temp);
	printf("Process base address is at %p\n", myProcessImage);

	//Make it RWX
	r = (*libc_mprotect)(myProcessImage, size - (0x1000 - temp), PROT_READ | PROT_WRITE | PROT_EXEC);

	if(r != 0)
	{
		printf("Call to mprotect failed returned %d\n", r);
		return;
	}

	printf("Mapping program segments into memory\n");

	//Map program segments into memory
	for(int i = 0; i < myElfHeader->e_phnum; i++)
	{
		//Copy loadable segments into memory
		if(segments[i].p_type == PT_LOAD)
		{
			printf("PT_LOAD Segment loaded at %p\n", segments[i].p_vaddr + myProcessImage);
			crt_memcpy(myProcessImage + segments[i].p_vaddr, (void *)myElfHeader + segments[i].p_offset, segments[i].p_filesz);
		}

	}

	if(!check_elf_magic((Elf64_Ehdr *)myProcessImage))
	{
		printf("ELF MAGIC ERROR!!!\n");
		return;
	}

	//Important Information On Shared Object that is being loaded into memory
	void (*myEntryPoint)();	
	unsigned char *myDYNSTR;

	Elf64_Shdr *myElfSections;
	Elf64_Shdr *myDynamicSec;
	Elf64_Shdr *myDynStrSec;
	Elf64_Shdr *myRelaPLTSec;
	Elf64_Shdr *myRelaDynSec;
	Elf64_Shdr *myGOTPLTSec;

	Elf64_Dyn *myDynamic; 
	
	Elf64_Rela *myRelaPLT;
	Elf64_Rela *myRelaDyn;

	Elf64_Sym *myDynSym;

	void *myGOTPLT;

	//Find my SH_STRTAB
	myElfSections = (void *)myElfHeader + myElfHeader->e_shoff;
	SH_STRTAB = (void *)myElfHeader + myElfSections[myElfHeader->e_shstrndx].sh_offset;

	//find my .dynamic section
	index = find_section_by_hash(DYNAMIC_HASH, myElfSections, SH_STRTAB, myElfHeader->e_shnum);

	if(index == -1)
	{
		printf("Did not find section..\n");
		return;
	}

	myDynamicSec = (Elf64_Shdr *)&myElfSections[index];
	myDynamic = myDynamicSec->sh_addr + myProcessImage;

	//find my .dynstr
	index = find_section_by_hash(DYNSTR_HASH, myElfSections, SH_STRTAB, myElfHeader->e_shnum);

	if(index == -1)
	{
		printf("Did not find section..\n");
		return;
	}

	myDynStrSec = (Elf64_Shdr *)&myElfSections[index];
	myDYNSTR = myDynStrSec->sh_addr + myProcessImage;

	//find my .rela.plt section
	index = find_section_by_hash(RELAPLT_HASH, myElfSections, SH_STRTAB, myElfHeader->e_shnum);

	if(index == -1)
	{
		printf("Did not find section..\n");
		return;
	}

	myRelaPLTSec = (Elf64_Shdr *)&myElfSections[index];
	myRelaPLT = myRelaPLTSec->sh_addr + myProcessImage;

	//find my .rela.dyn section
	index = find_section_by_hash(RELADYN_HASH, myElfSections, SH_STRTAB, myElfHeader->e_shnum);

	if(index == -1)
	{
		printf("Did not find section..\n");
		return;
	}

	myRelaDynSec = (Elf64_Shdr *)&myElfSections[index];
	myRelaDyn = myRelaDynSec->sh_addr + myProcessImage;

	//find my .got.plt section TODO: MIGHT NOT BE NEEDED!
	index = find_section_by_hash(GOTPLT_HASH, myElfSections, SH_STRTAB, myElfHeader->e_shnum);

	if(index == -1)
	{
		printf("Did not find section..\n");
		return;
	}

	myGOTPLTSec = (Elf64_Shdr *)&myElfSections[index];
	myGOTPLT = myGOTPLTSec->sh_addr + myProcessImage;

	//find DT_INIT (entrypoint)
	for(int i = 0; myDynamic[i].d_tag != DT_NULL; i++)
	{
		if(myDynamic[i].d_tag == DT_INIT)
		{
			myEntryPoint = myDynamic[i].d_un.d_ptr + myProcessImage;
			printf("INIT FUNCTION AT %p\n", myEntryPoint);
			
		}
	}

	//find DT_SYMTAB
	for(int i = 0; myDynamic[i].d_tag != DT_NULL; i++)
	{
		if(myDynamic[i].d_tag == DT_SYMTAB)
		{
		index = find_section_by_hash(DYNSYM_HASH, myElfSections, SH_STRTAB, myElfHeader->e_shnum);

		if(index == -1)	
		{
			printf("Did not find section..\n");
			return;
		}

		myDynSym = myDynamic[i].d_un.d_ptr + myProcessImage;
		printf("DT_SYMTAB AT %p\n", myDynSym);
			
		}
	}

	//dlopen DT_NEEDED libraries
	unsigned int numNeededLibraries = 0;
	unsigned int* libHandles = NULL; //hope this doesn't break stuff compiler was complaining so I made it shut up by making void * to unsigned int *..
	unsigned int z = 0;

	//Count number of DT_NEEDED entries
	for(int i = 0; myDynamic[i].d_tag != DT_NULL; i++)
	{
		if(myDynamic[i].d_tag == DT_NEEDED)
		{
			numNeededLibraries++;
			printf("DT_NEEDED %s\n", myDynamic[i].d_un.d_ptr + myDYNSTR);
		}
	}

	libHandles = (*libc_calloc)(sizeof(void *), numNeededLibraries);

	if(libHandles == NULL)
	{
		printf("calloc returned null...\n");
		return;
	}

	//Open all libraries required by the shared object in order to execute
	for(int i = 0; myDynamic[i].d_tag != DT_NULL && z < numNeededLibraries; i++)
	{
		if(myDynamic[i].d_tag == DT_NEEDED)
		{
			libHandles[z] = __libc_dlopen_mode(myDynamic[i].d_un.d_ptr + myDYNSTR, RTLD_LAZY);
			printf("opened library %p\n", libHandles[z]);
			if(!libHandles[z])
			{
				printf("Failed to open library %s\n", myDynamic[i].d_un.d_ptr + myDYNSTR);
			}

			z++;
		}
	}

	//Perform relocations (.rela.dyn)
	for(int i = 0; i < myRelaDynSec->sh_size / sizeof(Elf64_Rela); i++)
	{
		//Cannot use switch because compiler might generate a jump table
		//Page 72 of http://www.x86-64.org/documentation/abi.pdf
		if(ELF64_R_TYPE(myRelaDyn[i].r_info) == R_X86_64_NONE)
		{
			//TODO: Implement if needed
		} 
		else if(ELF64_R_TYPE(myRelaDyn[i].r_info) == R_X86_64_64)
		{
			printf("Professing Relocation of Type R_x86_64_64 for %s ", myDynSym[ELF64_R_SYM(myRelaDyn[i].r_info)].st_name + myDYNSTR);
			index = ELF64_R_SYM(myRelaDyn[i].r_info);
			*((uint64_t *) (myRelaDyn[i].r_offset + myProcessImage)) = myDynSym[index].st_value + myRelaDyn[i].r_addend;
			printf("with index %d and value of %08x\n", index, myDynSym[index].st_value);
		}
		else if(ELF64_R_TYPE(myRelaDyn[i].r_info) == R_X86_64_PC32)
		{
			//TODO: Implement if needed
		}
		else if(ELF64_R_TYPE(myRelaDyn[i].r_info) == R_X86_64_GOT32)
		{
			//TODO: Implement if needed
		}
		else if(ELF64_R_TYPE(myRelaDyn[i].r_info) == R_X86_64_PLT32)
		{
			//TODO: Implement if needed
		}
		else if(ELF64_R_TYPE(myRelaDyn[i].r_info) == R_X86_64_COPY)
		{
			//TODO: Implement if needed
		}
		else if(ELF64_R_TYPE(myRelaDyn[i].r_info) == R_X86_64_GLOB_DAT)
		{
			printf("Professing Relocation of Type R_x86_64_GLOB_DAT for %s\n", myDynSym[ELF64_R_SYM(myRelaDyn[i].r_info)].st_name + myDYNSTR);
			//TODO: Implement ITS NEEDED!!
			
		}
		else if(ELF64_R_TYPE(myRelaDyn[i].r_info) == R_X86_64_JUMP_SLOT)
		{
			//TODO: Implement if needed
		}
		else if(ELF64_R_TYPE(myRelaDyn[i].r_info) == R_X86_64_RELATIVE)
		{
			printf("Professing Relocation of Type R_x86_64_RELATIVE for %s\n", myDynSym[ELF64_R_SYM(myRelaDyn[i].r_info)].st_name + myDYNSTR);
			index = ELF64_R_SYM(myRelaDyn[i].r_info);
			*((uint64_t *) (myRelaDyn[i].r_offset + myProcessImage)) = myDynSym[index].st_value;
		}
		else if(ELF64_R_TYPE(myRelaDyn[i].r_info) == R_X86_64_GOTPCREL)
		{
			//TODO: Implement if needed
		}
		else if(ELF64_R_TYPE(myRelaDyn[i].r_info) == R_X86_64_32)
		{
			//TODO: Implement if needed
		}
		else if(ELF64_R_TYPE(myRelaDyn[i].r_info) == R_X86_64_32S)
		{
			//TODO: Implement if needed
		}
		else if(ELF64_R_TYPE(myRelaDyn[i].r_info) == R_X86_64_16)
		{
			//TODO: Implement if needed
		}
		else if(ELF64_R_TYPE(myRelaDyn[i].r_info) == R_X86_64_PC16)
		{
			//TODO: Implement if needed
		}
		else if(ELF64_R_TYPE(myRelaDyn[i].r_info) == R_X86_64_8)
		{
			//TODO: Implement if needed
		}
		else if(ELF64_R_TYPE(myRelaDyn[i].r_info) == R_X86_64_PC8)
		{
			//TODO: Implement if needed
		}
		else if(ELF64_R_TYPE(myRelaDyn[i].r_info) == R_X86_64_DTPMOD64)
		{
			//TODO: Implement if needed
		}
		else if(ELF64_R_TYPE(myRelaDyn[i].r_info) == R_X86_64_DTPOFF64)
		{
			//TODO: Implement if needed
		}	
		else if(ELF64_R_TYPE(myRelaDyn[i].r_info) == R_X86_64_TPOFF64)
		{
			//TODO: Implement if needed
		}
		else if(ELF64_R_TYPE(myRelaDyn[i].r_info) == R_X86_64_TLSGD)
		{
			//TODO: Implement if needed
		}
		else if(ELF64_R_TYPE(myRelaDyn[i].r_info) == R_X86_64_TLSLD)
		{
			//TODO: Implement if needed
		}
		else if(ELF64_R_TYPE(myRelaDyn[i].r_info) == R_X86_64_DTPOFF32)
		{
			//TODO: Implement if needed
		}
		else if(ELF64_R_TYPE(myRelaDyn[i].r_info) == R_X86_64_GOTTPOFF)
		{
			//TODO: Implement if needed
		}
		else if(ELF64_R_TYPE(myRelaDyn[i].r_info) == R_X86_64_TPOFF32)
		{
			//TODO: Implement if needed
		}
		else if(ELF64_R_TYPE(myRelaDyn[i].r_info) == R_X86_64_PC64)
		{
			//TODO: Implement if needed
		}
		else if(ELF64_R_TYPE(myRelaDyn[i].r_info) == R_X86_64_GOTOFF64)
		{
			//TODO: Implement if needed
		}
		else if(ELF64_R_TYPE(myRelaDyn[i].r_info) == R_X86_64_GOTPC32)
		{
			//TODO: Implement if needed
		}
		else if(ELF64_R_TYPE(myRelaDyn[i].r_info) == R_X86_64_SIZE32)
		{
			//TODO: Implement if needed
		}
		else if(ELF64_R_TYPE(myRelaDyn[i].r_info) == R_X86_64_SIZE64)
		{
			//TODO: Implement if needed
		}
		else if(ELF64_R_TYPE(myRelaDyn[i].r_info) == R_X86_64_GOTPC32_TLSDESC)
		{
			//TODO: Implement if needed
		}
		else if(ELF64_R_TYPE(myRelaDyn[i].r_info) == R_X86_64_TLSDESC_CALL)
		{
			//TODO: Implement if needed
		}
		else if(ELF64_R_TYPE(myRelaDyn[i].r_info) == R_X86_64_TLSDESC)
		{
			//TODO: Implement if needed
		}
		else if(ELF64_R_TYPE(myRelaDyn[i].r_info) == R_X86_64_IRELATIVE)
		{
			//TODO: Implement if needed
		}
	}
	
	//Resolve PLT references
	for(int i = 0; i < myRelaPLTSec->sh_size / sizeof(Elf64_Rela); i++)
	{
		if(ELF64_R_TYPE(myRelaPLT[i].r_info) == R_X86_64_JUMP_SLOT)
		{
			void *funcaddr;
			char *symName;
			//Get Index into symbol table for relocation
			index = ELF64_R_SYM(myRelaPLT[i].r_info);

			symName = myDynSym[index].st_name + myDYNSTR;

			//If symbol is a local symbol write the address of it into the .got.plt
			if(ELF64_ST_TYPE(myDynSym[index].st_info) == STT_FUNC && myDynSym[index].st_shndx != SHN_UNDEF)
			{
				printf("Symbol type is STT_FUNC AND st_shndx IS NOT STD_UNDEF for %s\n", symName);
				*((unsigned long *)(myRelaPLT[i].r_offset + myProcessImage)) = (unsigned long *)(myDynSym[index].st_value + myProcessImage);
			}
			//TODO: I think I know how to handle gmon_start
			//We need to lookup the symbol searching through DT_NEEDED libraries
			else 
			{
				for(int x = 0; x < numNeededLibraries; x++)
				{
					//not going to worry about __gmon_start__ https://stackoverflow.com/questions/12697081/what-is-gmon-start-symbol just don't compile with -pg flag?!?..)
					if(crt_hash(symName) == 2390853288) //skip gmon_start entry we don't need it
					{
						printf("skipping gmon_start..\n");
						break; 
					}
	
					//TODO: Close handle for handle and use libHandles array
					funcaddr = __libc_dlsym(handle, symName);
					printf("Looking up symbol for %s function address is %p\n", symName, funcaddr);
					if(funcaddr != NULL)
					{
						*((unsigned long *)(myRelaPLT[i].r_offset + myProcessImage)) = (unsigned long )((unsigned long)funcaddr);
						printf("Wrote %p to %p\n", funcaddr, (unsigned long *)(myRelaPLT[i].r_offset + myProcessImage));
						break;
					}									
				}
			}	
		}
	}

	//Transfer control to shared object init

	//TODO: Find actual entrypoint constructor somehow? because __init does not seem to be it! probably a structure that needs to be parsed to find the constructor
	myEntryPoint = myProcessImage + 0x712;
	printf("Transfering control to entry point! %p\n", myEntryPoint);
	myEntryPoint();

	//Should never get here should probably clean up the stack though... 
	//TODO: Better cleanup? Going to wait until I design injection to figure this out might just save registers and restore after injection?
	//TODO: unmap mapped libc on disk file TODO: DLCLOSE HANDLE AND FREE ANY MEMORY ETC

}


void main()
{
	ReflectiveLoader();
}


/* Find elf section given a name and hash */
__attribute__((always_inline)) unsigned int
find_section_by_hash(unsigned int sectionHash, Elf64_Shdr *sections, unsigned char *SH_STRTAB, unsigned int numSections)
{
	//printf("called\n");
	for(int i = 0; i < numSections; i++)
	{
		unsigned char *sectionName = SH_STRTAB + sections[i].sh_name;
		//printf("Checking name %s\n", sectionName);
		if(crt_hash(sectionName) == sectionHash)
		{
		//	printf("found %s\n", sectionName);
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



