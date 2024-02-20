#!/bin/bash

if [ ! -d build ]; then
	mkdir build
	mkdir build/elf
	mkdir build/dyn_debug
	mkdir build/disasm
fi

make -j8


