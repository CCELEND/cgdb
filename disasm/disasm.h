#ifndef DISASM_H
#define DISASM_H

#include <inttypes.h>
#include <capstone/capstone.h>

#include "../need_include.h"
#include "../elf/loader_elf.h"
#include "../dyn_debug/dyn_fun.h"

using namespace std;

extern csh handle;

bool judg_jump(char* mnemonic);
void bp_disasm(pid_t pid, u64 addr);
void call_disasm(char* byte_codes, u64  addr, s32 num, string call_fun_name);
void show_disasm(pid_t pid, u64 rip_val);
void disasm_mne_op(char* byte_codes, u64  addr, s32 num, s32 line);
u64  get_next_instruct_addr(char* byte_codes, u64 addr, s32 num);

#endif
