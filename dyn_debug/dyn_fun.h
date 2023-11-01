#ifndef DYN_FUN_H
#define DYN_FUN_H

#include <stdio.h>
#include <string>
#include <stdint.h>
#include <vector>
#include <iostream>
#include <sstream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <fstream>

#include "../elf/loader_elf.h"
#include "../disasm/disasm.h"

using namespace std;

// LONG 型数据的长度8个字节
#define LONG_SIZE 8
// 注入断点中断指令的长度，8个字节
#define CODE_SIZE 8

// 当前命令所有参数
extern vector<string> myargv;
// 当前命令字符串
extern string cmd;

extern string dis_fun_name;

// 一些 vma 地址
extern unsigned long long elf_base;
extern unsigned long long elf_code_start;
extern unsigned long long elf_code_end;
extern unsigned long long libc_base;
extern unsigned long long libc_code_start;
extern unsigned long long libc_code_end;
extern unsigned long long ld_base;
extern unsigned long long ld_code_start;
extern unsigned long long ld_code_end;
extern unsigned long long vdso_code_start;
extern unsigned long long vdso_code_end;

extern unsigned long long heap_base;
extern unsigned long long heap_end;
extern unsigned long long stack_base;
extern unsigned long long stack_end;

extern unsigned long long glibc_fun_start;
extern unsigned long long glibc_fun_end;

extern unsigned long long disasm_addr;
extern unsigned long long next_disasm_addr;
extern bool disasm_addr_synchronous;

extern map<string, unsigned long long> fun_start;
extern map<string, unsigned long long> fun_end;

extern map<string, unsigned long long> plt_fun_end;

// 断点结构体，包含有需要插入断点的地址，断点地址处的指令备份，以及断点的状态
struct break_point {
    unsigned long long addr;
    char backup[CODE_SIZE];
    bool break_point_state;
    // 构造函数初始化结构体
    break_point(): addr(0), break_point_state(false) {}
};
// 断点结构体列表
extern struct break_point break_point_list[8];
// ni 断点结构体
extern struct break_point ni_break_point;

// run api, help args
void argparse();
void show_help();
void run_dyn_debug(string fname, Binary *bin);

// regs
void get_regs(pid_t pid, struct user_regs_struct* regs);
void show_regs(pid_t pid, struct user_regs_struct* regs);
void regs_disasm_info(pid_t pid, struct user_regs_struct* regs);

// stack
void show_stack(pid_t pid, struct user_regs_struct* regs);

// addr handle
void flag_addr_printf(unsigned long long addr, bool addr_flag);
void show_addr_data(pid_t pid, int num , unsigned long long addr);
void show_addr_point(pid_t pid, unsigned long long address, bool addr_flag);
void get_addr_data(pid_t pid, unsigned long long addr, char* str, int len);
void put_addr_data(pid_t pid, unsigned long long addr, char* str, int len);
void print_bytes(const char* tip, char* codes, int len);
unsigned long long get_addr_val(pid_t pid, unsigned long long addr);
bool judg_addr_code(unsigned long long addr);
void val_to_string(unsigned long long val);


// dyn_elf
string get_map_key_value(map<string, unsigned long long>& Map, 
    unsigned long long fun_plt_addr);
void map_fun_start(pid_t pid, Binary *bin);
void map_fun_end(pid_t pid, Binary *bin);
void map_plt_fun_end(pid_t pid);
void dyn_show_elf_lib_plt();

string addr_get_fun(unsigned long long fun_addr);
string addr_get_plt_fun(unsigned long long plt_fun_addr);
string addr_get_glibc_fun(unsigned long long glib_addr);
string addr_get_glibc_plt_fun(unsigned long long glib_addr);

unsigned long long get_fun_addr(char* fun_name, Binary* bin);
unsigned long long get_fun_end_addr(pid_t pid, unsigned long long fun_addr);
unsigned long long get_glibc_fun_end(unsigned long long glibc_fun_addr);

int addr_get_fun_offset(unsigned long long addr);
int addr_get_plt_fun_offset(unsigned long long addr);
int addr_get_glibc_fun_offset(unsigned long long addr);


// break point
int break_point_handler(pid_t pid, int status, break_point& bp, bool showbp_flag);
void break_point_inject(pid_t pid, break_point& bp);
void set_break_point(pid_t pid, char* bp_fun, Binary *bin);
void set_ni_break_point(pid_t pid, unsigned long long addr);
void break_point_delete(pid_t pid, int num);

// vmmap
void show_vmmap(pid_t pid);
void get_vma_address(pid_t pid);

// info
void arg_error(const char* fname);
void err_exit(const char* msg);
void err_info(const char* msg);
void note_info(const char* msg);
void good_info(const char* msg);

#endif