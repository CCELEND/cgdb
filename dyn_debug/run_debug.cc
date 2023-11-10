
#include "dyn_fun.h"

unsigned long long elf_base = 0;
unsigned long long elf_code_start = 0;
unsigned long long elf_code_end = 0;
unsigned long long elf_data_start = 0;
unsigned long long elf_data_end = 0;
unsigned long long elf_ini_start = 0;
unsigned long long elf_ini_end = 0;
unsigned long long elf_rodata_start = 0;
unsigned long long elf_rodata_end = 0;

unsigned long long heap_base = 0;
unsigned long long heap_end = 0;
unsigned long long stack_base = 0;
unsigned long long stack_end = 0;

unsigned long long libc_base = 0;
unsigned long long libc_code_start = 0;
unsigned long long libc_code_end = 0;
unsigned long long libc_data_start = 0;
unsigned long long libc_data_end = 0;

unsigned long long ld_base = 0;
unsigned long long ld_code_start = 0;
unsigned long long ld_code_end = 0;
unsigned long long ld_data_start = 0;
unsigned long long ld_data_end = 0;

unsigned long long vdso_code_start = 0;
unsigned long long vdso_code_end = 0;


unsigned long long disasm_addr = 0;
unsigned long long next_disasm_addr = 0;
bool disasm_addr_synchronous = true;

struct user_regs_struct regs{};
struct user_regs_struct last_regs{};

struct break_point break_point_list[8];
struct break_point ni_break_point;

// 键是 elf 函数名，值是开始地址
map<string, unsigned long long> elf_fun_start;
// 键是 elf 函数名，值是结束地址
map<string, unsigned long long> elf_fun_end;
// 键是 elf plt 函数名，值是结束地址
map<string, unsigned long long> elf_plt_fun_end;

struct fun_info_type regs_fun_info;
struct fun_info_type dis_fun_info;
struct fun_info_type flow_change_fun_info;

void run_dyn_debug(Binary* bin)
{
    pid_t pid;
    Symbol *sym;
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
            // .data 返回一个指向数组中第一个元素的指针，该指针在内部使用
            if (execl(fname.data(), fname.data(), nullptr)) {
                err_exit("Execl error in subprocess!");
            }
            // 子进程，没有成功执行
            printf("\033[31m\033[1m[-] Invalid input command: %s\033[0m\n", fname.c_str());
            exit(3);
        default:{
            printf("[+] Tracked process pid: \033[32m%d\033[0m\n", pid);
            sleep(1);
            // 获取子进程的虚拟地址
            get_vma_address(pid);
            printf("[+] Base addr: 0x%llx\n", elf_base);

            set_elf_rdata(bin);

            // 建立函数名和开始地址，结束地址的映射
            map_fun_start(pid, bin);
            map_fun_end(pid, bin);
            map_plt_fun_end(pid);

            get_regs(pid, &regs);
            show_regs_dis_stack_info(pid, &regs);
            copy_regs_to_last_regs(&last_regs, &regs);

            // 开始轮询输入的命令
            while (true) {

                printf("\033[32m\033[1mcgdb> \033[0m");
                getline(cin, cmd);

                debug_start:

                //输入参数解析
                argparse();
                int argc = myargv.size();
                char** arguments = new char* [argc]; // 转换参数类型

                for (int i = 0; i < argc; i++) {
                    arguments[i] = (char*) myargv[i].data();
                }

                // 退出操作
                if (strcmp(arguments[0], "q") == 0) {
                    // 杀死子进程，避免出现僵尸进程
                    ptrace(PTRACE_KILL, pid, nullptr, nullptr);
                    goto debug_stop;
                } else if (strcmp(arguments[0], "si") == 0) {//单步调试
                    
                    // 发送 single step 给子进程
                    ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr);
                    // 等待主进程收到 sigtrap 信号
                    wait(&status);

                    get_vma_address(pid);
                    get_regs(pid, &regs);
                    show_regs_dis_stack_info(pid, &regs);
                    copy_regs_to_last_regs(&last_regs, &regs);

                    // 执行到最后一条指令, 子进程正常结束, 退出循环
                    if (WIFEXITED(status)) {
                        printf("\033[32m\033[1m[+] Process: %d exited normally.\033[0m\n", pid);
                        break;
                    }
                } else if (strcmp(arguments[0], "ni") == 0) {
                    get_regs(pid, &regs);
                    set_ni_break_point(pid, regs.rip);

                    ptrace(PTRACE_CONT, pid, nullptr, nullptr);
                    wait(&status);

                    break_point_handler(pid, status, ni_break_point, false);
                }

                else if (strcmp(arguments[0], "c") == 0) {
                    printf("[*] Continuing...\n");

                    // 继续执行，一直到子进程发出发出暂停或者结束信号
                    ptrace(PTRACE_CONT, pid, nullptr, nullptr);
                    // 等待子进程停止或者结束，并获取子进程状态值
                    wait(&status);
                    int index = -1;

                    for (int i = 0; i < 8; i++) 
                    {
                        if (break_point_list[i].break_point_state) 
                        {
                            // if (libc_base == 0) get_vma_address(pid);

                            index = i;
                            break;
                        }
                    }
                    if (index != -1)
                        break_point_handler(pid, status, break_point_list[index], true);

                    // 没有断点, 子进程结束
                    if (WIFEXITED(status)) {
                        printf("\033[32m\033[1m[+] Process: %d exited normally.\033[0m\n", pid);
                        goto debug_stop;
                    }
                } else if (strcmp(arguments[0], "x") == 0){
                    if (argc == 3) 
                    {
                        int num = stoi(arguments[1]);
                        if (num < 0) {
                            err_info("Wrong number of reads!");
                        }
                        else {
                            unsigned long long address = strtoul(arguments[2], nullptr, 16);
                            show_addr_data(pid, num, address);
                        }
                    } else {
                        err_info("Please enter the address and read quantity!");
                    }
                } else if (strcmp(arguments[0], "ic") == 0) { // 计算执行完毕所需指令数
                    printf("[*] Calculating the number of instructions after this...\n");
                    long count = 0;
                    while (true) {

                        // 当前子进程还是暂停状态，父进程被阻塞
                        wait(&status);
                        if (WIFEXITED(status)) {
                            printf("[+] Process: \033[32m%d\033[0m exited normally.\n", pid);
                            printf("[+] Total instruction count: \033[32m%ld\033[0m\n", 
                                count);
                            goto debug_stop;
                        }

                        // 单步执行下一条指令
                        ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr);

                        count++;
                    }
                } else if (strcmp(arguments[0], "b") == 0) {
                    if (argc == 2) { // 打断点
                        set_break_point(pid, arguments[1], bin);
                    } else {
                        err_info("Please enter the break point address or function name!");
                    }
                } else if(strcmp(arguments[0], "d") == 0 && strcmp(arguments[1], "b") == 0){
                    if (argc == 3) {
                        int num = stoi(arguments[2]);
                        if (num >= 8 || num < 0) {
                            err_info("Error break point number!");
                        }
                        else {
                            break_point_delete(pid, num);
                        }
                    }
                    else {
                        err_info("Please enter the break point number to delete!");
                    }
                } else if (strcmp(arguments[0], "ib") == 0) {
                    printf("Num        Type            Address\n");
                    for (int i = 0; i < 8; i++) {
                        if (break_point_list[i].break_point_state) {
                            printf("%-11dbreak point     \033[31m0x%llx\033[0m\n",
                                i, break_point_list[i].addr
                            );
                        }
                    }
                } else if (strcmp(arguments[0], "fun") == 0){
                    if (argc == 2) { // 打断点
                        show_elf_fun_call(pid, arguments[1], bin);
                    } else {
                        err_info("Please enter the function name!");
                    }
                }

                else if (strcmp(arguments[0], "stack") == 0){
                    if (argc == 2) 
                    {
                        get_regs(pid, &regs);
                        int num = stoi(arguments[1]);
                        show_num_stack(pid, &regs, num);
                    } else {
                        err_info("Please Enter the correct quantity!");
                    }
                }

                else if (strcmp(arguments[0], "help") == 0 || strcmp(arguments[0], "h") == 0) {
                    // 显示帮助信息
                    show_help();
                } else if (strcmp(arguments[0], "vmmap") == 0) {
                    show_vmmap(pid);
                } else if (strcmp(arguments[0], "libc") == 0) {
                    printf("[+] libc base: 0x%llx\n", libc_base);
                    printf("[+] ld base:   0x%llx\n", ld_base);
                } else if (strcmp(arguments[0], "stackbase") == 0) {
                    printf("[+] stack: \033[33m0x%llx-0x%llx\033[0m\n", stack_base, stack_end);
                } else if (strcmp(arguments[0], "heapbase") == 0) {
                    printf("[+] heap: \033[34m0x%llx-0x%llx\033[0m\n",  heap_base,  heap_end);
                } else if (strcmp(arguments[0], "code") == 0) {
                    printf("[+] elf code:  \033[31m0x%llx-0x%llx\033[0m\n", elf_code_start,  elf_code_end);
                    printf("[+] libc code: \033[31m0x%llx-0x%llx\033[0m\n", libc_code_start, libc_code_end);
                    printf("[+] ld code:   \033[31m0x%llx-0x%llx\033[0m\n", ld_code_start,   ld_code_end);
                    printf("[+] vdso code: \033[31m0x%llx-0x%llx\033[0m\n", vdso_code_start, vdso_code_end);
                } else if (strcmp(arguments[0], "base") == 0) {
                    printf("[+] elf ini base: 0x%llx\n", elf_ini_start);
                    printf("[+] elf base:     0x%llx\n", elf_base);
                    printf("[+] libc base:    0x%llx\n", libc_base);
                    printf("[+] ld base:      0x%llx\n", ld_base);
                } else if (strcmp(arguments[0], "data") == 0) {
                    printf("[+] elf data:  \033[35m0x%llx-0x%llx\033[0m\n", elf_data_start,  elf_data_end);
                    printf("[+] libc data: \033[35m0x%llx-0x%llx\033[0m\n", libc_data_start, libc_data_end);
                    printf("[+] ld data:   \033[35m0x%llx-0x%llx\033[0m\n", ld_data_start,   ld_data_end);

                }
                else if (strcmp(arguments[0], "lplt") == 0) {
                    show_elf_plt_fun();
                } else if (strcmp(arguments[0], "plt") == 0) {
                    if (argc == 2) {
                        unsigned long long address = strtoul(arguments[1], nullptr, 16);
                        if ( addr_get_elf_plt_fun(address)== "" )
                            printf("\033[31m\033[1m[-] There is no such function!\033[0m\n");
                        else
                            cout << "<" << addr_get_elf_plt_fun(address) << "@plt>" << endl;
                    } else {
                        err_info("Please enter the function address!");
                    }
                }

                else if (strcmp(arguments[0], "test") == 0) {
                    // unsigned long long address = strtoul(arguments[1], nullptr, 16);

                    printf("-------------regs:\n");
                    show_fun_list(&regs_fun_info);
                    printf("--------------dis:\n");
                    show_fun_list(&dis_fun_info);
                    printf("--------------flow_change_fun:\n");
                    show_fun_list(&flow_change_fun_info);

                    // for (auto it : fun_start) {
                    //     printf("%-30s0x%llx\n", it.first.c_str(), it.second);
                    // }
                    // printf("\n");
                    // for (auto i : fun_end) {
                    //     printf("%-30s0x%llx\n", i.first.c_str(), i.second);
                    // }
                }

                else {
                    err_info("Command not found!");
                    printf("Enter 'h' to view supported commands.\n");
                }
                next_input: myargv.clear(); // 下一轮参数输入之前需要把当前存储的命令清除
            }
            // 等待子进程结束之后父进程再退出
            wait(&status);
        }
    }
    debug_stop: return;
} 
