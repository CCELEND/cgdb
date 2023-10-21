#ifndef DYN_FUN_H
#define DYN_FUN_H

#include <stdio.h>
#include <string>
#include <stdint.h>
#include <vector>
#include <iostream>
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

// LONG 型数据的长度8个字节
#define LONG_SIZE 8

// 注入断点中断指令的长度，8个字节
#define CODE_SIZE 8
using namespace std;

//声明存储当前命令所有参数
extern vector<string> myargv;
//声明当前命令字符串
extern string cmd;

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
extern unsigned long long stack_base;
extern unsigned long long stack_end;

//断点结构体，包含有需要插入断点的地址，对断点地址处的指令进行备份，以及用来标记是否有断点存在的
struct break_point {
    unsigned long long addr;
    char backup[CODE_SIZE];
    bool break_point_state;

    break_point(): addr(0), break_point_state(false) {}
};
extern struct break_point break_point_list[8];

// 解析参数
void argparse();
//显示帮助信息
void show_help();
void run_dyn_debug(string fname, Binary *bin);


void get_show_regs(pid_t pid, struct user_regs_struct* regs);
void regs_disasm_info(pid_t pid, struct user_regs_struct* regs);
int get_rip_codes(pid_t pid, unsigned long long addr, char* codes);

void show_stack(pid_t pid, struct user_regs_struct* regs);


void flag_addr_printf(unsigned long long addr, bool addr_flag);
void show_addr_data(pid_t pid, int num , unsigned long long addr);
void get_addr_data(pid_t pid, unsigned long long addr, char* str, int len);
void put_addr_data(pid_t pid, unsigned long long addr, char* str, int len);
void print_bytes(const char* tip, char* codes, int len);
unsigned long long get_addr_val(pid_t pid, unsigned long long addr);


// void show_memory(pid_t pid, unsigned long long addr, long offset = 0, int nbytes = 40);

int break_point_handler(pid_t pid, int status, break_point& bp);
void set_break_point(pid_t pid, char* bp_fun, Binary *bin);
void break_point_inject(pid_t pid, break_point& bp);
void break_point_delete(pid_t pid, int num);


void show_vmmap(pid_t pid);
void get_vma_address(pid_t pid);


void arg_error(const char* fname);
void err_exit(const char* msg);
void err_info(const char* msg);
void note_info(const char* msg);
void good_info(const char* msg);


#endif