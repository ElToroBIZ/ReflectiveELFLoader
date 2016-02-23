# ReflectiveELFLoader
Code for diskless loading of ELF Shared Library using Reflective DLL Injection

Goals

1. Support x86, x86_64, and ARM architectures
2. Work on Linux and FreeBSD

TODO

1. finish implementing loading portion (relocations, mapping program header segments, resolving symbols) for x86_64
2. Once x86_64 is done implement on x86 and ARM 
3. Better way to test this thing?

What ifs?

1. Libc is RELRO so you can't get a pointer to _dl_runtime_resolve function? Is this likely?
2. GRSecurity hardening restricts information in /proc/*/maps files.. just not going to worry about grsecurity for now..Aint nobody got time for compiling a custom hardened kernel anyway (at least not sane person :P)
