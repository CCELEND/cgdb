#ifndef DISASM_H
#define DISASM_H

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <cstring>
#include <iostream>

#include <inttypes.h>
#include <capstone/capstone.h>

#include "../types.h"
#include "../elf/loader_elf.h"
#include "../dyn_debug/dyn_fun.h"

using namespace std;

void bp_disasm(pid_t pid, u64  addr);
void call_disasm(char* byte_codes, u64  addr, s32 num, string call_fun_name);
void show_disasm(pid_t pid, u64  rip_val);
void disasm_mne_op(char* byte_codes, u64  addr, s32 num, s32 line);
u64  get_next_instruct_addr(char* byte_codes, u64  addr, s32 num);

#endif
