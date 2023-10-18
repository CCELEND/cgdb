#include "dyn_fun.h"
#include "../elf/loader_elf.h"
#include "../disasm/disasm.h"

unsigned long long elf_base = 0;
unsigned long long libc_base = 0;
unsigned long long ld_base = 0;
unsigned long long stack_base = 0;

void regs_disasm_info(pid_t pid, struct user_regs_struct* regs){
    int num;
    char rip_instruct[64];

    // 存储子进程当前寄存器的值
    get_show_regs(pid, regs);
    num = get_rip_data(pid, regs->rip, rip_instruct);
    execute_disasm(rip_instruct, num);
}

void run_dyn_debug(std::string fname, Binary *bin)
{
    pid_t pid;
    Symbol *sym;
    // unsigned long long elf_base;
    // unsigned long long libc_base;

    break_point break_point = {
        //默认不进入断点模式
        .break_point_mode = false 
    };
    int status, num;

    // fork 子进程
    switch (pid = fork()) {
        // fork 子进程失败
        case -1:
            err_exit("Failed to create subprocess!");
        // 处理子进程
        case 0:
            if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0) {
                err_exit("Ptrace error in subprocess!");
            }
            // .data 返回一个指向数组中第一个元素的指针，该指针在向量内部使用
            if (execl(fname.data(), fname.data(), nullptr)) {
                err_exit("Execl error in subprocess!");
            }
            //子进程，没有成功执行
            printf("\033[31m\033[1m[-] Invalid input command: %s\033[0m\n", fname.c_str());
            exit(3);
        default:{
            printf("[+] Tracked process pid: \033[32m%d\033[0m\n", pid);
            sleep(1);
            // 获取子进程的起始虚拟地址
            get_base_address(pid);
            printf("[+] Base addr: 0x%llx\n", elf_base);

            struct user_regs_struct regs{};
            regs_disasm_info(pid, &regs);

            // 开始轮询输入的命令
            while (true) {
                
                // 存储子进程当前寄存器的值
                // get_show_regs(pid, &regs);
                // num = get_rip_data(pid, regs.rip, rip_instruct);
                // execute_disasm(rip_instruct, num);
                
                printf("\033[32m\033[1mcgdb> \033[0m");
                getline(cin, cmd);

                //输入参数解析
                argparse();
                int argc = myargv.size();
                char** arguments = new char* [argc]; //转换参数类型

                for (int i = 0; i < argc; i++) {
                    arguments[i] = (char*) myargv[i].data();
                }

                // 退出操作
                if (strcmp(arguments[0], "stop") == 0 || strcmp(arguments[0], "q") == 0) {
                    // 杀死子进程，避免出现僵尸进程
                    ptrace(PTRACE_KILL, pid, nullptr, nullptr);
                    goto debug_stop;
                } else if (strcmp(arguments[0], "step") == 0 || strcmp(arguments[0], "si") == 0) {//单步调试
                    regs_disasm_info(pid, &regs);
                    // 发送 single step 给子进程
                    ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr);
                    // 等待子进程收到 sigtrap 信号
                    wait(&status);
                    // 执行到最后一条指令退出循环，同时父进程也会结束
                    if (WIFEXITED(status)) {
                        good_info("Process finished.");
                        break;
                    }
                } else if (strcmp(arguments[0], "continue") == 0 || strcmp(arguments[0], "c") == 0) {//继续执行
                    regs_disasm_info(pid, &regs);
                    // 继续执行，一直到子进程发出发出暂停信号
                    ptrace(PTRACE_CONT, pid, nullptr, nullptr);
                    // 等待子进程停止，并获取子进程状态值
                    wait(&status);

                    // 没有断点，一直执行到子进程结束
                    if (!break_point.break_point_mode) {
                        if (WIFEXITED(status)) {
                            good_info("Process finished.");
                            goto debug_stop;
                            // exit(0);
                        }
                    } 
                    else {
                        // 断点模式被激活，break_point_mode 字段被置为 true
                        // 等待并判断断点是否被命中
                        wait_break_point(pid, status, break_point);
                    }
                } else if (strcmp(arguments[0], "memory") == 0 || strcmp(arguments[0], "m") == 0) {//获取子进程制定区域的内存内容
                    ptrace(PTRACE_GETREGS, pid, nullptr, &regs);
                    struct Params 
                    {   // 默认地址采用 rip 指针的内容，偏移默认为0，默认读取40个字节
                        unsigned long long addr;
                        long offset;
                        int nbytes;
                    } params = {regs.rip, 0, 40};

                    if (argc == 1) {
                        show_memory(pid, regs.rip);//显示内存内容
                    } else {
                        for (int i = 1; i < argc; i++) {//检查是否有额外参数指定
                            if (strcmp(arguments[i], "-addr") == 0) {//指定内存的起始地址
                                params.addr = strtol(arguments[++i], nullptr, 16);
                                continue;//当前参数指定功能，下一个参数指定具体的值，两项获取之后直接跳一步检查别的参数
                            }
                            if (strcmp(arguments[i], "-off") == 0) {
                                params.offset = strtol(arguments[++i], nullptr, 10);
                                continue;
                            }
                            if (strcmp(arguments[i], "-nb") == 0) {
                                params.nbytes = strtol(arguments[++i], nullptr, 10);
                                continue;
                            }
                        }
                        show_memory(pid, params.addr, params.offset, params.nbytes);
                    }
                } else if (strcmp(arguments[0], "ic") == 0) {// 计算执行完毕所需指令数
                    long count = 0;
                    while (true) {
                        // 当前子进程还是暂停状态，父进程被阻塞
                        wait(&status);
                        if (WIFEXITED(status)) {
                            good_info("Process finished.");
                            printf("[+] Total instruction count is \033[32m\033[1m%ld\033[0m\n", 
                                count);
                            // 指令执行完子进程也结束运行
                            goto debug_stop;
                        }

                        // 单步执行下一条指令
                        ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr);

                        count++;
                    }
                } else if (strcmp(arguments[0], "break") == 0 || strcmp(arguments[0], "b") == 0) {
                    //打断点
                    if (argc == 2) {
                        for(int i = 0; i < bin->symbols.size(); i++) {
                            sym = &bin->symbols[i];
                            if(sym->fun_sym_type == "symtab") {
                                if (arguments[1] == sym->name){
                                    printf("[+] Break point at: \033[31m0x%lx\033[0m\n", 
                                        sym->addr);
                                    break_point.addr = sym->addr + elf_base; // .c_str
                                }
                            }
                        }
                        printf("[+] Break point addr: \033[31m0x%llx\033[0m\n", 
                            break_point.addr);
                        // 先把需要打断点的地址上指令取出备份
                        get_addr_data(pid, break_point.addr, break_point.backup, CODE_SIZE);
                        print_bytes("[+] Get trace instruction: ", break_point.backup, LONG_SIZE);
                        execute_disasm(break_point.backup, 8);
                        // 注入断点
                        break_point_inject(pid, break_point);
                    } else {
                        err_info("Please input the address of break point!");
                    }
                } else if (strcmp(arguments[0], "help") == 0 || strcmp(arguments[0], "h") == 0) {
                    // 显示帮助信息
                    show_help();
                } else if (strcmp(arguments[0], "vmmap") == 0) {
                    get_vmmap(pid);
                } else if (strcmp(arguments[0], "libc") == 0) {
                    get_base_address(pid);
                    printf("[+] Libc base: 0x%llx\n", libc_base);
                    printf("[+] Ld base: 0x%llx\n", ld_base);
                } else if (strcmp(arguments[0], "stack") == 0) {
                    printf("[+] Stack base: 0x%llx\n", stack_base);
                } else {
                    err_info("Invalid Argument!");
                }
                myargv.clear(); // 下一轮参数输入之前需要把当前存储的命令清除
            }
            // 等待子进程结束之后父进程再退出
            wait(&status);
        }
    }
    debug_stop: return;
} 
