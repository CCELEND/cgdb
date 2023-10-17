
#include "./dyn_debug/dyn_fun.h"
#include "./load_elf/loader_elf.h"
#include "./disasm/disasm.h"

vector<string> myargv;
string cmd;

int main(int argc, char *argv[]) 
{
    pid_t pid;
    Binary bin;
    Section *sec;
    Symbol *sym;
    char rip_instruct[64];
    string fname;
    unsigned long long base_addr;
    break_point break_point = {
        //默认不进入断点模式
        .break_point_mode = false 
    };
    int status, num;

    if(argc < 2) arg_error(argv[0]);

    fname.assign(argv[1]);
    printf("[*] Reading symbols from \033[34m\033[1m%s\033[0m...\n", fname.c_str());
    if(load_binary(fname, &bin, Binary::BIN_TYPE_AUTO) < 0) {
        err_exit("Program loading failed!");
    }

    while (true){
        printf("\033[32m\033[1mcgdb> \033[0m");
        getline(cin, cmd);

        if (cmd == "q"){
            goto cgdb_exit;
        } else if (cmd == "symbol" || cmd == "sym"){
            printf("[+] Symbol tables(\033[32m\033[1mFUNC\033[0m)\n");
            printf("    %-31s %18s   %s\n", "name", "address", "type");
            printf("======================================================================\n");
            for(int i = 0; i < bin.symbols.size(); i++) 
            {
                sym = &bin.symbols[i];
                if(sym->fun_sym_type == "symtab")
                {
                    printf("%-35s 0x%016jx   %s  %s\n", 
                        sym->name.c_str(), sym->addr, 
                        (sym->type & Symbol::SYM_TYPE_FUNC) ? "FUNC" : "", sym->fun_sym_type.c_str());
                }
            }
            printf("\033[34m\033[1mmodule internal symbol table:\033[0m\n");
            for(int i = 0; i < bin.symbols.size(); i++) {
                sym = &bin.symbols[i];
                if(sym->addr){
                    printf("%-35s 0x%016jx   %s  %s\n", 
                        sym->name.c_str(), sym->addr, 
                        (sym->type & Symbol::SYM_TYPE_FUNC) ? "FUNC" : "", sym->fun_sym_type.c_str());
                }
            }
        } else if (cmd == "dynsym" || cmd == "dyn"){
            printf("[+] Dynamic symbol(\033[32m\033[1mFUNC\033[0m)\n");
            printf("    %-31s %18s   %s\n", "name", "address", "type");
            printf("======================================================================\n");
            for(int i = 0; i < bin.symbols.size(); i++) 
            {
                sym = &bin.symbols[i];
                if(sym->fun_sym_type == "dynsym")
                {
                    printf("%-35s 0x%016jx   %s  %s\n", 
                        sym->name.c_str(), sym->addr, 
                        (sym->type & Symbol::SYM_TYPE_FUNC) ? "FUNC" : "", sym->fun_sym_type.c_str());
                }
            }
        } else if (cmd == "sections") {
            printf("[+] sections(\033[32m\033[1mcode and data\033[0m)\n");
            printf("%18s   %-8s %-20s %s\n", "vma", "size", "name", "type");
            printf("========================================================\n");
            for(int i = 0; i < bin.sections.size(); i++) 
            {
                sec = &bin.sections[i];
                printf("0x%016jx   %-8ju %-20s %s\n", 
                    sec->vma, sec->size, sec->name.c_str(), 
                    sec->type == Section::SEC_TYPE_CODE ? "CODE" : "DATA");
            }
        } else if (cmd == "got"){
            show_elf_got(fname);
        } else if (cmd == "r") {
            //fork 子进程
            switch (pid = fork()) {
                //fork 子进程失败
                case -1:
                    err_exit("Failed to create subprocess!");
                //处理子进程
                case 0:
                    if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0) {
                        err_exit("Ptrace error in subprocess!");
                    }
                    // .data 返回一个指向数组中第一个元素的指针，该指针在向量内部使用
                    if (execl(fname.data(), fname.data(), nullptr)) {
                        err_exit("Execvp error in subprocess!");
                    }
                    //子进程，没有成功执行
                    printf("\033[31m\033[1m[-] Invalid input command: %s\033[0m\n", fname.c_str());
                    exit(3);
                default:{
                    printf("[+] Tracked process pid: \033[32m%d\033[0m\n", pid);
                    sleep(1);

                    // 获取子进程的起始虚拟地址
                    get_base_address(pid, base_addr);

                    // 开始轮询输入的命令
                    while (true) {
                        struct user_regs_struct regs{};
                        // 存储子进程当前寄存器的值
                        show_regs(pid, &regs);

                        num = get_rip_data(pid, regs.rip, rip_instruct);
                        execute_disasm(rip_instruct, num);

                        printf("\033[32m\033[1mcgdb> \033[0m");
                        getline(cin, cmd);

                        //输入参数解析
                        argparse();
                        int argc = myargv.size();
                        char** arguments = new char* [argc]; //转换参数类型，以便能够喂到 exec 函数

                        for (int i = 0; i < argc; i++) {
                            arguments[i] = (char*) myargv[i].data();
                        }

                        // 退出操作
                        if (strcmp(arguments[0], "exit") == 0 || strcmp(arguments[0], "q") == 0) {
                            // 杀死子进程，避免出现僵尸进程
                            ptrace(PTRACE_KILL, pid, nullptr, nullptr);
                            goto cgdb_exit;
                        } else if (strcmp(arguments[0], "step") == 0 || strcmp(arguments[0], "si") == 0) {//单步调试
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
                            // 继续执行，一直到子进程发出发出暂停信号
                            ptrace(PTRACE_CONT, pid, nullptr, nullptr);
                            // 等待子进程停止，并获取子进程状态值
                            wait(&status);

                            //没有断点，一直执行到子进程结束
                            if (!break_point.break_point_mode) {
                                if (WIFEXITED(status)) {
                                    good_info("Process finished.");
                                    goto cgdb_exit;
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
                            {   //默认地址采用 rip 指针的内容，偏移默认为0，默认读取40个字节
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
                                    // 指令执行完子进程也结束运行了，父进程退出
                                    goto cgdb_exit;
                                    // exit(0);
                                }

                                // 单步执行下一条指令
                                ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr);

                                count++;
                            }
                        } else if (strcmp(arguments[0], "break") == 0 || strcmp(arguments[0], "b") == 0) {
                            //打断点
                            if (argc == 2) {
                                for(int i = 0; i < bin.symbols.size(); i++) {
                                    sym = &bin.symbols[i];
                                    if(sym->fun_sym_type == "symtab") {
                                        if (arguments[1] == sym->name){
                                            printf("[+] Break point at: \033[31m0x%lx\033[0m\n", 
                                                sym->addr);
                                            break_point.addr = sym->addr + base_addr; // .c_str
                                        }
                                    }
                                }
                                printf("[+] Break point addr: \033[31m0x%llx\033[0m\n", 
                                    break_point.addr);
                                // 先把需要打断点的地址上指令取出备份
                                get_data(pid, break_point.addr, break_point.backup, CODE_SIZE);
                                print_bytes("[+] Get trace instruction: ", break_point.backup, LONG_SIZE);
                                execute_disasm(break_point.backup, 8);
                                // 注入断点
                                break_point_inject(pid, break_point);
                            } else {
                                err_info("Please input the address of break point!");
                            }
                        } else if (strcmp(arguments[0], "help") == 0 || strcmp(arguments[0], "h") == 0) {
                            //显示帮助信息
                            show_help();
                        } else {
                            err_info("Invalid Argument!");
                        }
                        myargv.clear();// 下一轮参数输入之前需要把当前存储的命令清除
                    }
                    // 等待子进程结束之后父进程再退出
                    wait(&status);
                }
            }
        } 
    }
    cgdb_exit: return 0;
}