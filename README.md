# PSAPI for Windows 98/SE

The code is taked from [KernelEx](http://kernelex.sourceforge.net/),
I've improved some things and made a CMakefile.

## Building

I mainly build it with MinGW-W64 cross compiler on Linux, MinGW-W64 on windows should work too.
I'm not sure about MSVC, but versions newer than VS2005 will generate binaries that are not
compatible with Windows 98.

Assuming you have a working MinGW-W64 cross compiler on Linux and CMake installed:

```sh
mkdir build
cd build
../configure-for-release.sh ..
make
```

## Download

A better idea is to download the binary from the
[releases page](https://github.com/sherpya/psapi/releases)


## Licensing

The first version is 4.5.12, starting from the original KernelEx version of psapi.

Since most of the code comes from KernelEx, it is released under its original license **GPLv2**
