# Description

This is a combination of two exploits to spawn ssh server on iPhone 4
(iPhone 3,1) running iOS 7.1.2 by loading a html document into
builtin Safari browser.

First one is using a bug in JavaScriptCore engine described in  
https://www.thezdi.com/blog/2018/4/12/inverting-your-assumptions-a-guide-to-jit-comparisons
by Jasiel Spelman to get initial code execution under MobileSafari process.

The second one is a vulnerability in xnu described by Ian Beer in
https://bugs.chromium.org/p/project-zero/issues/detail?id=882. It is used
to obtain arbitrary kernel read/write.

# Files

* *build* --- a bash script to build the binary code.
* *clean* --- a bash script to clean up build artifacts
* *dep*   --- contains files we want to deploy once we get read/write 
	  access to the file system.
* *index.html* --- Mobile Safari exploit.
* *loader.c* --- small stab to map mach-o file into rwx memory end load
		it via dyld.
* *macho_to_bin.py* --- a python scrip used to extract binary code
		for our macho loader.
* *macho.m* --- privilege escalation (PE) exploit.
* *utils.m*  --- utility functions used by our PE.
* *offsets.h* --- contains kernel structures offsets.
* *shell.m* --- post exploitation.
* *task.c* --- skimmed file from original Ian Beer report to call *mach_ports_register* trap.
* *tools* --- some command line tools we deploy along with core utils.

# Post exploitation

Once the file system is remounted the exploit downloads a shell,
shell script, tar utility, simple tool to download files via
http called iget and xz archive decompressor.

The shell script downloads a tar containing gnu core utils, grep, findutils
and a dropbear ssh server. It extracts files from the archive and spawns ssh server.

We use https://github.com/tpoechtrager/cctools-port to compile all the tools 
on a machine running debian linux. The cctools provides arm-apple-darwin11-clang
compiler to build binaries for iOS.

To be able to compile all the tools we need an extra header
[crt_externs.h](https://opensource.apple.com/source/Libc/Libc-320/include/crt_externs.h)
to be placed under <SDK Path>/usr/include.

As shell we use [oksh](https://github.com/ibara/oksh). 
It compiled without any issues in our setup:
	CC=arm-apple-darwin11-clang ./configure --host=arm-apple-darwin11
	make

Same applies to: [gnu core utils](https://ftp.gnu.org/gnu/coreutils/coreutils-8.32.tar.xz),
[grep](https://ftp.gnu.org/gnu/grep/grep-3.4.tar.xz),
[findutils](https://ftp.gnu.org/pub/gnu/findutils/findutils-4.7.0.tar.xz) and
[xz](https://tukaani.org/xz/xz-embedded-20120222.tar.gz).

To build [dropbear](https://matt.ucc.asn.au/dropbear/releases/dropbear-2019.78.tar.bz2) ssh server:
	CC=arm-apple-darwin11-clang ./configure --host=arm-apple-darwin11 --disable-wtmp --disable-lastlog
	make program=DROPBEAR

# Usage

To spawn an ssh server on iPhone3,1 running iOS 7.1.2, you need to adjust 
*HOST_ROOT* definition in shell.m file to the url where you want to host the exploits. 
Then use *build* script to compile the project. Host the root directory of the project as the url *HOST_ROOT*
and visit the url via built in Mobile Safari browser and wait till it closes. In case of failure
you might ether see a diagnostic popup in the browser or experience phone reboot.

