#ifndef DYN_FUN_H
#define DYN_FUN_H

#include "../need_include.h"
#include "../elf/loader_elf.h"
#include "../disasm/disasm.h"

using namespace std;

// LONG 型数据的长度8个字节
#define LONG_SIZE 8
// 注入断点中断指令的长度，8个字节
#define CODE_SIZE 8

#define KEYCODE_U 183
// #define KEYCODE_D 184
// #define KEYCODE_R 185
// #define KEYCODE_L 186

// 当前命令所有参数
extern vector<string> myargv;
// 当前命令字符串
extern string cmd;
extern string old_cmd;
extern string fname;

// 一些 vma 地址
extern u64 elf_base;
extern u64 elf_code_start;
extern u64 elf_code_end;
extern u64 elf_data_start;
extern u64 elf_data_end;
extern u64 elf_ini_start;
extern u64 elf_ini_end;
extern u64 elf_rodata_start;
extern u64 elf_rodata_end;

extern u64 heap_base;
extern u64 heap_end;
extern u64 stack_base;
extern u64 stack_end;

extern u64 libc_base;
extern u64 libc_code_start;
extern u64 libc_code_end;
extern u64 libc_data_start;
extern u64 libc_data_end;

extern u64 ld_base;
extern u64 ld_code_start;
extern u64 ld_code_end;
extern u64 ld_data_start;
extern u64 ld_data_end;

extern u64 vdso_code_start;
extern u64 vdso_code_end;


// 每次反汇编的开始地址
extern u64 disasm_addr;
extern u64 next_disasm_addr;
extern bool disasm_addr_synchronous;

extern map<string, u64> elf_fun_start;
extern map<string, u64> elf_fun_end;
extern map<string, u64> elf_plt_fun_end;

extern struct user_regs_struct regs;
extern struct user_regs_struct last_regs;
extern struct user_regs_struct fun_args_regs;

struct fun_frame {
    u64 fun_start_addr;
    u64 fun_end_addr;
    string fun_name;
    fun_frame(): fun_start_addr(0), fun_end_addr(0), fun_name("") {}
};
struct fun_info_type {
    struct fun_frame fun_list[0x10];
    s32 fun_num;
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
    u64 addr;
    char backup[CODE_SIZE];
    bool break_point_state;
    // 构造函数初始化结构体
    break_point(): addr(0), break_point_state(false) {}
};
// 断点结构体列表
extern struct break_point break_point_list[8];
// ni 断点结构体
extern struct break_point ni_break_point;

// 帮助和参数信息
// arg_help.cc
void argparse();
void show_help();
// 运行动态调试
// run_debug.cc
void run_dyn_debug(Binary* bin);

// 寄存器信息处理
// regs.cc
void get_regs (pid_t pid, struct user_regs_struct* regs);
void show_regs(pid_t pid, struct user_regs_struct* regs);
void regs_disasm_info(pid_t pid, struct user_regs_struct* regs);
void copy_regs_to_last_regs(struct user_regs_struct* last_regs, 
    struct user_regs_struct* regs);

// 栈信息
// stack.cc
void show_stack(pid_t pid, struct user_regs_struct* regs);
void show_num_stack(pid_t pid, struct user_regs_struct* regs, int num);

// 显示寄存器，反汇编，栈信息
// show_info.cc
void show_regs_dis_stack_info(pid_t pid, struct user_regs_struct* regs);

// 地址数据处理
// addr_data_handler.cc
string get_addr_file_base(u64 addr, u64* base_addr);
u64 get_addr_val(pid_t pid, u64 addr);
bool judg_addr_code(u64 addr);
void val_to_string(u64 val);
void flag_addr_printf(u64 addr, bool addr_flag);
void show_addr_data (pid_t pid, s32 num , u64 addr);
void show_addr_point(pid_t pid, u64 addr, bool addr_flag);
void get_addr_data(pid_t pid, u64 addr, char* str, s32 len);
void put_addr_data(pid_t pid, u64 addr, char* str, s32 len);
void print_bytes(char* codes, s32 len);

// dyn_elf.cc
string addr_get_fun(struct fun_info_type* fun_info, u64 addr);
string get_fun(u64 addr, u64* fun_start_addr);
u64 get_fun_end(pid_t pid, u64 fun_addr);

// elf 函数
// elf_fun.cc
string addr_get_elf_fun(u64 elf_fun_addr);
void dyn_show_elf_fun();
void map_fun_end  (pid_t pid);
s32 addr_get_elf_fun_offset(u64 addr);
u64 get_elf_fun_addr(char* fun_name);

// elf plt 函数
// elf_plt_fun.cc
string addr_get_elf_plt_fun(u64 elf_plt_fun_addr);
void dyn_show_elf_plt_fun();
void map_plt_fun_end(pid_t pid);
int  addr_get_elf_plt_fun_offset(u64 addr);

// elf 文件函数指针初始化，析构函数处理
// elf_init_fini_array.cc
string addr_get_elf_init(u64 elf_init_addr);
string addr_get_elf_fini(u64 elf_fini_addr);

// elf 文件只读数据段处理
// elf_rdata.cc
void set_elf_rdata(Binary* bin);

// glibc 函数
// glibc_fun.cc
string addr_get_glibc_fun(u64 glibc_fun_addr, 
    u64* glibc_fun_start);
u64 get_glibc_fun_end(u64 glibc_fun_addr, 
    string fun_name);

// glibc plt 函数
// glibc_plt_fun.cc
string addr_get_glibc_plt_fun(u64 glibc_plt_fun_addr);

// glibc 数据段处理
// glibc_data.cc
string addr_get_glibc_data(u64 glibc_data_addr);

// 函数列表信息
// fun_list.cc
void show_fun_list (struct fun_info_type* fun_info);
void clear_fun_list(struct fun_info_type* fun_info);
void set_fun_list  (struct fun_info_type* fun_info, u64 fun_addr);
int  addr_get_fun_offset(struct fun_info_type* fun_info, u64 addr);

// 断点处理
// break_point.cc
int  break_point_handler(pid_t pid, s32 status, break_point& bp, 
    bool showbp_flag);
void break_point_inject(pid_t pid, break_point& bp);
// void set_break_point   (pid_t pid, char* bp_fun);
void set_break_point   (pid_t pid, u64 break_point_addr);
void set_ni_break_point(pid_t pid, u64 addr);
void break_point_delete(pid_t pid, s32 idx);


// 虚拟内存地址空间
// vma.cc
void get_vma_address(pid_t pid);
void show_vmmap(pid_t pid);

// 调用函数参数
// fun_args.cc
void show_fun_args(pid_t pid,
    struct user_regs_struct* regs, struct user_regs_struct* fun_args_regs);
void set_fun_args_regs(struct user_regs_struct* regs, 
    struct user_regs_struct* fun_args_regs);

// 显示调用函数信息
// fun_call.cc
void show_elf_fun_call(pid_t pid, char* elf_fun_name);

// 提示信息
// info.cc
void arg_error(const char* cgdb);
void err_exit (const char* msg);
void err_info (const char* msg);
void note_info(const char* msg);
void good_info(const char* msg);
void show_str (s32 count);

#endif