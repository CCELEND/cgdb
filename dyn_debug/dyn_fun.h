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
#include <fstream>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <termios.h>

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

extern string fname;

// extern string dis_fun_name;

// 一些 vma 地址
extern unsigned long long elf_base;
extern unsigned long long elf_code_start;
extern unsigned long long elf_code_end;
extern unsigned long long elf_ini_start;
extern unsigned long long elf_ini_end;
extern unsigned long long elf_rodata_start;
extern unsigned long long elf_rodata_end;

extern unsigned long long libc_base;
extern unsigned long long libc_code_start;
extern unsigned long long libc_code_end;
extern unsigned long long ld_base;
extern unsigned long long ld_code_start;
extern unsigned long long ld_code_end;
extern unsigned long long vdso_code_start;
extern unsigned long long vdso_code_end;

extern unsigned long long ld_data_start;
extern unsigned long long ld_data_end;
extern unsigned long long libc_data_start;
extern unsigned long long libc_data_end;

extern unsigned long long heap_base;
extern unsigned long long heap_end;
extern unsigned long long stack_base;
extern unsigned long long stack_end;

// 每次反汇编的开始地址
extern unsigned long long disasm_addr;
extern unsigned long long next_disasm_addr;
extern bool disasm_addr_synchronous;

extern map<string, unsigned long long> elf_fun_start;
extern map<string, unsigned long long> elf_fun_end;
extern map<string, unsigned long long> elf_plt_fun_end;

extern struct user_regs_struct regs;
extern struct user_regs_struct last_regs;

struct fun_frame {
    unsigned long long fun_start_addr;
    unsigned long long fun_end_addr;
    string fun_name;
    fun_frame(): fun_start_addr(0), fun_end_addr(0), fun_name("") {}
};
struct fun_info_type {
    struct fun_frame fun_list[0x10];
    int fun_num;
    fun_info_type(): fun_num(0) {}
};
// regs 窗口的函数信息
extern struct fun_info_type regs_fun_info;
// 反汇编窗口的函数信息
extern struct fun_info_type dis_fun_info;
// flow_change 的函数信息
extern struct fun_info_type flow_change_fun_info;

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
void run_dyn_debug(Binary* bin);

// regs
void get_regs (pid_t pid, struct user_regs_struct* regs);
void show_regs(pid_t pid, struct user_regs_struct* regs);
void regs_disasm_info(pid_t pid, struct user_regs_struct* regs);
void copy_regs_to_last_regs(struct user_regs_struct* last_regs, 
    struct user_regs_struct* regs);

// stack
void show_stack(pid_t pid, struct user_regs_struct* regs);
void show_num_stack(pid_t pid, struct user_regs_struct* regs, int num);

// void show_regs_dis_stack_info(pid_t pid);
void show_regs_dis_stack_info(pid_t pid, struct user_regs_struct* regs);

// addr handle
unsigned long long get_addr_val(pid_t pid, unsigned long long addr);
bool judg_addr_code(unsigned long long addr);

void val_to_string(unsigned long long val);
void flag_addr_printf(unsigned long long addr, bool addr_flag);
void show_addr_data (pid_t pid, int num , unsigned long long addr);
void show_addr_point(pid_t pid, unsigned long long addr, bool addr_flag);
void get_addr_data(pid_t pid, unsigned long long addr, char* str, int len);
void put_addr_data(pid_t pid, unsigned long long addr, char* str, int len);
void print_bytes(const char* tip, char* codes, int len);

// dyn_elf
string get_map_key_value(map<string, unsigned long long>& Map, 
    unsigned long long fun_plt_addr);
string addr_get_fun(struct fun_info_type* fun_info, unsigned long long addr);
unsigned long long get_fun_end(pid_t pid, unsigned long long fun_addr);

// elf_fun
string addr_get_elf_fun(unsigned long long elf_fun_addr);
void map_fun_start(pid_t pid, Binary* bin);
void map_fun_end  (pid_t pid, Binary* bin);
unsigned long long get_elf_fun_addr(char* fun_name, Binary* bin);
int addr_get_elf_fun_offset(unsigned long long addr);


// elf_plt_fun
string addr_get_elf_plt_fun(unsigned long long elf_plt_fun_addr);
void show_elf_plt_fun();
void map_plt_fun_end(pid_t pid);
int addr_get_elf_plt_fun_offset(unsigned long long addr);


// glibc_fun
string addr_get_glibc_fun(unsigned long long glibc_fun_addr, 
    unsigned long long* glibc_fun_start);
unsigned long long get_glibc_fun_end(unsigned long long glibc_fun_addr, 
    string fun_name);

// glibc_plt_fun
string addr_get_glibc_plt_fun(unsigned long long glibc_plt_fun_addr);

//
string addr_get_elf_init(unsigned long long elf_init_addr);
string addr_get_elf_fini(unsigned long long elf_fini_addr);

// glibc data
string addr_get_glibc_data(unsigned long long glibc_data_addr);

// fun list
void show_fun_list (struct fun_info_type* fun_info);
void clear_fun_list(struct fun_info_type* fun_info);
void set_fun_list  (struct fun_info_type* fun_info, unsigned long long fun_addr);
int  addr_get_fun_offset(struct fun_info_type* fun_info, unsigned long long addr);

// break point
int  break_point_handler(pid_t pid, int status, break_point& bp, 
    bool showbp_flag);
void break_point_inject(pid_t pid, break_point& bp);
void set_break_point   (pid_t pid, char* bp_fun, Binary* bin);
void set_ni_break_point(pid_t pid, unsigned long long addr);
void break_point_delete(pid_t pid, int idx);

// vmmap
void get_vma_address(pid_t pid);
void show_vmmap(pid_t pid);

// elf rodata
void set_elf_rdata(Binary* bin);

// info
void arg_error(const char* cgdb);
void err_exit (const char* msg);
void err_info (const char* msg);
void note_info(const char* msg);
void good_info(const char* msg);
void show_str (int count);

#endif