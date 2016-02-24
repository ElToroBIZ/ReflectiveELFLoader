# ReflectiveELFLoader
Code for diskless loading of ELF Shared Library using Reflective DLL Injection

Goals

1. Support x86, x86_64, and ARM architectures
2. Work on Linux and FreeBSD

TODO

1. finish implementing loading portion (relocations, mapping program header segments, resolving symbols) for x86_64
2. Once x86_64 is done implement on x86 and ARM 
3. Better way to test this thing?
4. Write junit tests for individual components
5. find a better way to do string parsing (without C library...)
6. clean up code general
7. need to work on Shuriken component (its in other github repo)
8. working on seperating code into different files (already got this done have to push it to master branch once  I test it)
9. Write test library which uses this application
10.Investigate differences between Linux and FreeBSD dynamic linking, etc. which could cause some issues. 
11. Write system call wrappers for x86 and ARM
12. Look into "What ifs?"
13. Write some example code which compiles a shared object embeds it as an array into another program and then that program injects it into a test process, write this test along with bash script to launch it?
14. document how things work and future improvements?

EHH maybe not these.. unless someone really wants to add them in
15. Investigate hollowing out another process/library and then placing code into there so heap memory is not RWX! In some places)
16. Destroy/obfuscate elf header to prevent scanning for ELF magic, etc.?!?!?!. Seems too advanced/malicious for a proof of concept so probably not, but if you implement it and want to add it in then sure why not I guess.. Same with 15 also

What ifs?

1. Libc is RELRO so you can't get a pointer to _dl_runtime_resolve function? Is this likely?
2. GRSecurity hardening restricts information in /proc/*/maps files.. just not going to worry about grsecurity for now..Aint nobody got time for compiling a custom hardened kernel anyway (at least not sane person :P)
