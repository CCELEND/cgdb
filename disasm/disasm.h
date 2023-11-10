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
#include "../dyn_debug/dyn_fun.h"

using namespace std;

void disasm(char* byte_codes, unsigned long long addr, int num, int line);
void call_disasm(char* byte_codes, unsigned long long addr, int num, string call_fun_name);
void show_disasm(pid_t pid, unsigned long long rip_val);
void disasm_mne_op(char* byte_codes, unsigned long long addr, int num, int line);
unsigned long long get_next_instruct_addr(char* byte_codes, unsigned long long addr, int num);

#endif
