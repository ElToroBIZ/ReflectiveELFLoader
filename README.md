# ReflectiveELFLoader
Code for diskless loading of ELF Shared Library using Reflective DLL Injection technique. Currently, this is only designed to work on x86_64 (AMD64) architecture on Linux. I was originally hoping to be able to expand this to other architectures and FreeBSD. However, I do not have time to implement this on other architectures and since I only need it to work on x86_64 on Linux this is the only portion I have implemented.

If you are interested in contributing to add support for more architectures (x86, ARM, MIPS, etc.) please contact me and I can help to provide guidance on this. I would like this to be a useful tool for others so if you do expand on this tool please release your improvements for others to use also. 

Caveats

Certain GRSecurity protections can break this is they are enabled. I have not tried to bypass these protections as I do not need to bypass them at this point in time. If, in the future, I do need to then I will find a way to bypass them and get it working on GRSecurity protected systems also.

TODO

1. Finish implementing loading portion
2. Start on injection portion
