#ifndef DISASM_H
#define DISASM_H

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <cstring>
#include <iostream>

#include <inttypes.h>
#include <capstone/capstone.h>

using namespace std;

void execute_disasm(char* byte_codes, int num);
void disasm(char* byte_codes, unsigned long long addr, int num);

#endif
