#include <elf.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#define DYNSYM_HASH 0x2923cc52
#define DYNSTR_HASH 0x32e01ec6
#define GOTPLT_HASH 0xb6fb15a8

__attribute__((always_inline)) void * memcpy(void *dest, const void *src, unsigned long n);
__attribute__((always_inline)) uint64_t convert_to_64bit_pointer(unsigned char *x, unsigned int len);
__attribute__((always_inline)) unsigned long strlen(const char *s);
__attribute__((always_inline)) int linux_read(int fd, char *buffer, unsigned long bufferlen);
__attribute__((always_inline)) int linux_open (const char *pathname, unsigned long flags, unsigned long mode);
__attribute__((always_inline)) unsigned int hash(unsigned char *x);
__attribute__((always_inline)) int linux_lseek(int fd, unsigned int offset, unsigned int origin);
__attribute__((always_inline)) int linux_stat(const char *path, void *buf);
__attribute__((always_inline)) void *linux_mmap(void *start, unsigned long length, int prot, int flags, int fd, unsigned long offset);
__attribute__((always_inline)) unsigned int find_section_by_hash(unsigned int hash, Elf64_Shdr *sections, unsigned char *SH_STRTAB, unsigned int numSections);
__attribute__((always_inline)) unsigned int check_elf_magic(Elf64_Ehdr *elfHdr);

static void ReflectiveLoader()
{
	unsigned char *IP;
	void *MyBaseAddr;
    	unsigned char *libcBaseAddr, *libcBaseAddrEnd;
	void *libcMapped = NULL;
	int success = 0, counter = 0;
	unsigned char *SH_STRTAB = NULL;

	unsigned char *pos = NULL, *begin = NULL, *startBaseAddr = NULL, *endBaseAddr = NULL, *perms = NULL, *libName = NULL,
				  *startLibName = NULL;

	unsigned int len = 0, index = 0;

	int fd = 0, EndOfFile = 0;
	Elf64_Ehdr *myElfHeader, *libcElfHeader;
	Elf64_Shdr *libcGOTPLT, *libcDynSym, *libcDynStr; 
	ssize_t r = 0;

	unsigned int sectionHeaderSize;
	struct stat sb;

	void *__dl_runtime_resolve;

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

 	char buf[850];

	//Zero out buffer
	for(int i = 0; i < 850; i++)
		*(buf + i) = 0;

	//Search backward in memory to ELF magic
	__asm__("leaq (%%rip), %0;": "=r"(IP));

	while(true)
	{
		if(((Elf64_Ehdr *)IP)->e_ident[0] == 0x7f)
		{
			if(((Elf64_Ehdr *)IP)->e_ident[1] == 0x45)
			{
				if(((Elf64_Ehdr *)IP)->e_ident[2] == 0x4c)
				{
					if(((Elf64_Ehdr *)IP)->e_ident[3] == 0x46)
					{
						printf("Found elf header\n");
						break;
					}
				}
			}
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
	fd = linux_open(&x[0],  0, 0);

	if(fd == -1)
	{
		return;
	}
	
	r = linux_read(fd, &buf[0], 850);

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
					for(int b = 0; b < strlen(libcName); b++)
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

			libcBaseAddr = (void *)convert_to_64bit_pointer(startBaseAddr, strlen(startBaseAddr));
			libcBaseAddrEnd = (void *)convert_to_64bit_pointer(endBaseAddr, strlen(endBaseAddr));
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
			r = linux_read(fd, &buf[850 - len], len);

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

	//calculate size of libc Section Header
	sectionHeaderSize = libcElfHeader->e_shnum * libcElfHeader->e_shentsize;
	
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
	linux_close(fd);

	//Open libc after getting libc path
	fd = linux_open(startLibName,  0, 0);

	if(fd == -1)
	{
		printf("Failed to open libc file on disk..");
		return; 
	}

	printf("%s\n", startLibName);

	//Get file size of libc
	if (0 > linux_stat(startLibName, &sb))
	{
		return;
	}
	printf("libc size is %d\n", sb.st_size);

	//Create memory map to load libc file into
	libcMapped = linux_mmap(NULL, sb.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

	if(libcMapped == -1)
	{
		printf("mmap failed to create anonymous memory mapping for libc file..\n");
		return;
	}

	//Copy libc file on disk into memory map for parsing
	copy_in(fd, libcMapped);
	linux_close(fd);

	printf("libc Mapped address is %p\n", libcMapped);

	//Find SH_STRTAB for LIBC
	Elf64_Shdr *libcElfSections = libcMapped + libcElfHeader->e_shoff;
	SH_STRTAB = libcMapped + libcElfSections[libcElfHeader->e_shstrndx].sh_offset;

	//Find .got.plt
	index = find_section_by_hash(GOTPLT_HASH, libcElfSections, SH_STRTAB, libcElfHeader->e_shnum);
	libcGOTPLT = (Elf64_Shdr *)&libcElfSections[index];

	//Get pointer to __dl_runtime_resolve always stored in third (GOT[2]) entry in got.plt
	//Will probably break if libc is Full RELRO?!? Ugh.. Not going to worry about that for now ^^
	__dl_runtime_resolve;
	memcpy(&__dl_runtime_resolve, (void *)(libcGOTPLT->sh_addr + libcBaseAddr + sizeof(void *) * 2), sizeof(void *));
	printf("__dl_runtime_resolve is %p\n", __dl_runtime_resolve);
    
	printf("Found Section %s at index %d\n", (libcElfSections[index].sh_name + SH_STRTAB), index);

	//Get pointer to linkmap structure (stored in GOT[1])

	//Map program segments into memory (Malloc?!?!) (TODO: map a legitimate file into memory and then hollow it out?? So we don't have RWX on the heap :P)

	//Perform relocations on binary

	//Store linkmap pointer in GOT[1] and _dl_runtime_resolve in GOT[2] of mapped program

	//unmap mapped libc on disk file

	//unmap self from memory?

	//Transfer control to program entry point

	//Pray?!?!


	
}



void main()
{
	ReflectiveLoader();
}


__attribute__((always_inline)) unsigned int
find_section_by_hash(unsigned int sectionHash, Elf64_Shdr *sections, unsigned char *SH_STRTAB, unsigned int numSections)
{
	for(int i = 0; i < numSections; i++)
	{
		unsigned char *sectionName = SH_STRTAB + sections[i].sh_name;
		if(hash(sectionName) == sectionHash)
		{
			return i;
		}
	}
}

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


__attribute__((always_inline)) int
linux_munmap(void *start, unsigned long length)
{

	long ret;
	asm volatile ("syscall" : "=a" (ret) : "a" (__NR_munmap),
		      "D" (start), "S" (length) :
		      "cc", "memory", "rcx",
		      "r8", "r9", "r10", "r11" );
	if (ret < 0)
	{
		ret = -1;
	}
	return (int)ret;
}

__attribute__((always_inline)) int
linux_close(int fd)
{

	long ret;
	asm volatile ("syscall" : "=a" (ret) : "a" (__NR_close),
		      "D" (fd):
		      "cc", "memory", "rcx",
		      "r8", "r9", "r10", "r11" );
	if (ret < 0)
	{
		ret = -1;
	}
	return (int)ret;
}

__attribute__((always_inline)) void
copy_in(int fd, void *address)
{
	int cc;
	off_t offset = 0;
	char buf[1024];

	while (0 < (cc = linux_read(fd, buf, sizeof(buf))))
	{
		memcpy((address + offset), buf, cc);
		offset += cc;
	}
}

__attribute__((always_inline)) void *
memcpy(void *dest, const void *src, unsigned long n)
{
	unsigned long i;
	unsigned char *d = (unsigned char *)dest;
	unsigned char *s = (unsigned char *)src;

	for (i = 0; i < n; ++i)
		d[i] = s[i];

	return dest;
}

__attribute__((always_inline)) uint64_t 
convert_to_64bit_pointer(unsigned char *x, unsigned int len)
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

__attribute__((always_inline)) unsigned long
strlen(const char *s)
{
	unsigned long r = 0;
	for (; s && *s; ++s, ++r);
	return r;
}

__attribute__((always_inline)) int
linux_read(int fd, char *buffer, unsigned long bufferlen)
{

	long ret;
	__asm__ volatile ("syscall" : "=a" (ret) : "a" (__NR_read),
		      "D" (fd), "S" (buffer), "d" (bufferlen) :
		      "cc", "memory", "rcx",
		      "r8", "r9", "r10", "r11" );
	if (ret < 0)
	{
		ret = -1;
	}
	return (int)ret;
}

__attribute__((always_inline)) int 
linux_open (const char *pathname, unsigned long flags, unsigned long mode)
{

	long ret;
	__asm__ volatile ("syscall" : "=a" (ret) : "a" (__NR_open),
		      "D" (pathname), "S" (flags), "d" (mode) :
		      "cc", "memory", "rcx",
		      "r8", "r9", "r10", "r11" );
	if (ret < 0)
	{
		ret = -1;
	}

	return (int) ret;
}

__attribute__((always_inline)) int 
linux_lseek(int fd, unsigned int offset, unsigned int origin)
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

__attribute__((always_inline)) unsigned int
hash(unsigned char *word)
{
    unsigned int hash = 0;
    for (int i = 0 ; word[i] != '\0' && word[i] != '@'; i++)
    {
        hash = 31*hash + word[i];
    }
    return hash;
}


__attribute__((always_inline)) int
linux_stat(const char *path, void *buf)
{
	long ret;
	asm volatile ("syscall" :
		"=a" (ret) :
		"a" (4), "D" (path), "S" (buf) :
		"memory"
	);
	if (ret < 0)
	{
		ret = -1;
	}
	return (int)ret;
}

__attribute__((always_inline)) void*
linux_mmap(void *start, unsigned long length, int prot, int flags, int fd, unsigned long offset)
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
