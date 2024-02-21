#!/bin/bash

if [ ! -d build ]; then
	mkdir build
	mkdir build/elf
	mkdir build/dyn_debug
	mkdir build/disasm
fi

if [ ! -d debug_info ]; then
	mkdir debug_info
	mkdir debug_info/libc
	mkdir debug_info/ld
fi

libc_str=`readelf -n /lib/x86_64-linux-gnu/libc.so.6 | grep 'Build ID:'`
ld_str=`readelf -n /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 | grep 'Build ID:'`

libc_buildid=${libc_str:14}
ld_buildid=${ld_str:14}

libc_debug_dir=${libc_buildid:0:2}
ld_debug_dir=${ld_buildid:0:2}

libc_debug_file=${libc_buildid:2}.debug
ld_debug_file=${ld_buildid:2}.debug

if [ ! -f ./debug_info/libc/${libc_debug_file} ] && [ ! -f ./debug_info/ld/${ld_debug_file} ]; then
	cp /usr/lib/debug/.build-id/${libc_debug_dir}/${libc_debug_file} ./debug_info/libc/${libc_debug_file}
	cp /usr/lib/debug/.build-id/${ld_debug_dir}/${ld_debug_file} ./debug_info/ld/${ld_debug_file}

	cp /lib/x86_64-linux-gnu/libc.so.6 ./debug_info/libc/libc.so.6
	cp /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 ./debug_info/ld/ld-linux-x86-64.so.2

	echo -e "\033[32m\033[1m[+] Successfully created local debug info file.\033[0m"
else
	echo -e "\033[32m\033[1m[+] The local debug info file exists.\033[0m"
fi

make -j8


