#ifndef DISASM_H
#define DISASM_H

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <cstring>
#include <iostream>

#include <inttypes.h>
#include <capstone/capstone.h>

#include "../elf/loader_elf.h"

using namespace std;

void disasm(char* byte_codes, unsigned long long addr, int num, int line);

#endif
