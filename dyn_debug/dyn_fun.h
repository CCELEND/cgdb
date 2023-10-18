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

#include "../load_elf/loader_elf.h"

//LONG型数据的长度8个字节
#define LONG_SIZE 8 
//注入断点中断指令的长度，8个字节
#define CODE_SIZE 8
using namespace std;

//声明存储当前命令所有参数
extern vector<string> myargv;
//声明当前命令字符串
extern string cmd;

//断点结构体，包含有需要插入断点的地址，对断点地址处的指令进行备份，以及用来标记是否有断点存在的变量
struct break_point {
    unsigned long long addr;
    char backup[CODE_SIZE];
    bool break_point_mode;
};

//解析参数
void argparse();

//输出寄存器值
void show_regs(pid_t child, struct user_regs_struct* regs);

int get_rip_data(pid_t child, unsigned long long addr, char* codes);

//从子进程指定地址获取指定长度的数据，长度单位为字节
void get_data(pid_t child, unsigned long long addr, char* str, int len);

//将数据插入子进程指定地址处
void put_data(pid_t child, unsigned long long addr, char* str, int len);

//打印字节
void print_bytes(const char* tip, char* codes, int len);

//显示指定地址处指定长度的内存内容
void show_memory(pid_t pid, unsigned long long addr, long offset = 0, int nbytes = 40);

//判断断点是否命中
int wait_break_point(pid_t pid, int status, break_point& bp);

//给子进程注入断点
void break_point_inject(pid_t pid, break_point& bp);

//从当前子进程的虚拟地址范围获取子进程的起始地址
void get_base_address(pid_t pid, unsigned long long& base_addr);

void get_vmmap(pid_t pid);

//显示帮助信息
void show_help();

void arg_error(const char* fname);

void err_exit(const char* msg);

void err_info(const char* msg);

void note_info(const char* msg);

void good_info(const char* msg);

void run_elf_debug(std::string fname, Binary *bin);

#endif