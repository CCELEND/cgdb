
#include "dyn_fun.h"

u64 elf_base = 0;
u64 elf_ini_start = 0;
u64 elf_ini_end = 0;
u64 elf_rodata_start = 0;
u64 elf_rodata_end = 0;
u64 elf_code_start = 0;
u64 elf_code_end = 0;
u64 elf_data_start = 0;
u64 elf_data_end = 0;

u64 heap_base = 0;
u64 heap_end = 0;
u64 stack_base = 0;
u64 stack_end = 0;

u64 libc_base = 0;
u64 libc_code_start = 0;
u64 libc_code_end = 0;
u64 libc_data_start = 0;
u64 libc_data_end = 0;

u64 ld_base = 0;
u64 ld_code_start = 0;
u64 ld_code_end = 0;
u64 ld_data_start = 0;
u64 ld_data_end = 0;

u64 vdso_code_start = 0;
u64 vdso_code_end = 0;

u64 disasm_addr = 0;
u64 next_disasm_addr = 0;
bool disasm_addr_synchronous = true;

regs_struct regs{};
regs_struct last_regs{};
regs_struct fun_args_regs{};

break_point_type break_point_list[8];
break_point_type ni_break_point;

// 键是 elf 函数名，值是结束地址
map<string, u64> elf_fun_end;
// 键是 elf plt 函数名，值是结束地址
map<string, u64> elf_plt_fun_end;

fun_list_info_type regs_fun_info;
fun_list_info_type dis_fun_info;
fun_list_info_type flow_change_fun_info;

// 反汇编框架句柄
csh handle = 0;
// 动态分配储存机器码空间
char* disasm_code = NULL;

void 
run_dyn_debug(Binary* bin)
{
    pid_t pid;
    Symbol* sym;
    s32 status, num;

    // fork 子进程
    switch (pid = fork()) 
    {
        // fork 子进程失败
        case -1:
            err_info("Failed to create subprocess!");
            break;
        // 处理子进程
        case 0:
            if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0) 
            {
                err_info("Ptrace error in subprocess!");
                break;
            }
            // .data 返回一个指向数组中第一个元素的指针，该指针在内部使用
            if (execl(fname.data(), fname.data(), nullptr)) 
            {
                err_info("Execl error in subprocess!");
                break;
            }
            // 子进程，没有成功执行
            printf("\033[31m\033[1m[-] Invalid input command: %s\033[0m\n", fname.c_str());
            break;
        default:
        {
            // 初始化 Capstone
            printf("[*] Initialize Capstone...\n");
            if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) 
            {
                ptrace(PTRACE_KILL, pid, nullptr, nullptr);
                printf("\033[31m\033[1m[-] Failed to initialize Capstone!\033[0m\n");
                goto debug_stop;
            }

            disasm_code = (char*)calloc(1, 0x1000);
            memset(disasm_code, 0, 0x1000);

            printf("[+] Tracked process pid: \033[32m%d\033[0m\n", pid);
            sleep(1);
            // 获取子进程的虚拟地址
            get_vma_address(pid);
            printf("[+] elf base: 0x%llx\n", elf_base);

            set_elf_rdata(bin);
            // 建立函数名和结束地址的映射
            map_fun_end(pid);
            map_plt_fun_end(pid);

            get_regs(pid, &regs);
            show_regs_dis_stack_info(pid, &regs);
            copy_regs_to_last_regs(&last_regs, &regs);

            s32 all_sum;
            // 开始轮询输入的命令
            while (true) 
            {
                printf("\033[32m\033[1mcgdb> \033[0m");
                getline(cin, cmd);

                // 上、下、左、右这四个光标键对应的 ASCII 码值不是一个值而是三个，
                // 准确的说光标键的 ASCII 码值是一个组合
                all_sum = cmd[0] + cmd[1] + cmd[2];
                if (all_sum == KEYCODE_U) cmd = old_cmd;

                debug_start:
                //输入参数解析
                argparse();
                s32 argc = myargv.size();
                char** arguments = new char* [argc]; // 转换参数类型

                for (s32 i = 0; i < argc; i++)
                    arguments[i] = (char*) myargv[i].data();

                // 退出操作
                if (!strcmp(arguments[0], "q")) 
                {
                    // 杀死子进程，避免出现僵尸进程
                    ptrace(PTRACE_KILL, pid, nullptr, nullptr);
                    break;
                } 
                // 单步调试
                else if (!strcmp(arguments[0], "si")) 
                {
                    old_cmd = cmd;

                    // 发送 single step 给子进程
                    ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr);
                    // 等待主进程收到 sigtrap 信号
                    wait(&status);
                    // 执行到最后一条指令, 子进程正常结束, 退出循环
                    if (WIFEXITED(status)) 
                    {
                        printf("\033[32m\033[1m[+] Process: %d exited normally.\033[0m\n", pid);
                        break;
                    }

                    get_vma_address(pid);
                    get_regs(pid, &regs);
                    show_regs_dis_stack_info(pid, &regs);
                    copy_regs_to_last_regs(&last_regs, &regs);

                } 
                else if (!strcmp(arguments[0], "ni")) 
                {
                    old_cmd = cmd;
                    get_regs(pid, &regs);
                    set_ni_break_point(pid, regs.rip);

                    ptrace(PTRACE_CONT, pid, nullptr, nullptr);
                    wait(&status);

                    if (WIFEXITED(status)) 
                    {
                        printf("[+] Process: \033[32m%d\033[0m exited normally.\n", pid);
                        break;
                    }

                    break_point_handler(pid, status, ni_break_point, false);
                }
                else if (!strcmp(arguments[0], "c")) 
                {
                    printf("[*] Continuing...\n");

                    // 继续执行，一直到子进程发出发出暂停或者结束信号
                    ptrace(PTRACE_CONT, pid, nullptr, nullptr);

                    // 等待子进程停止或者结束，并获取子进程状态值
                    wait(&status);

                    if (WIFEXITED(status)) 
                    {
                        printf("[+] Process: \033[32m%d\033[0m exited normally.\n", pid);
                        break;
                    }

                    s32 index = -1;
                    for (s32 i = 0; i < 8; i++) 
                    {
                        if (break_point_list[i].break_point_state) 
                        {
                            index = i;
                            break;
                        }
                    }

                    if (index != -1)
                        break_point_handler(pid, status, break_point_list[index], true);

                } 
                // 计算执行完毕所需指令数
                else if (!strcmp(arguments[0], "ic")) 
                { 
                    printf("[*] Calculating the number of instructions after this...\n");
                    s64 count = 0;
                    while (true) 
                    {
                        // 当前子进程还是暂停状态，父进程被阻塞
                        wait(&status);

                        if (WIFEXITED(status)) 
                        {
                            printf("[+] Process: \033[32m%d\033[0m exited normally.\n", pid);
                            printf("[+] Total instruction count: \033[32m%lld\033[0m\n", 
                                count);
                            break;
                        }

                        // 单步执行下一条指令
                        ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr);
                        count++;
                    }
                }


                else if (!strcmp(arguments[0], "bf") || !strcmp(arguments[0], "b")) 
                {
                    if (argc == 2) 
                    {
                        u64 break_point_fun_addr, end_addr;
                        get_fun_addr(arguments[1], &break_point_fun_addr, &end_addr);

                        if (!break_point_fun_addr)
                            err_info("There is no such function!");
                        else  // 打断点
                            set_break_point(pid, break_point_fun_addr);
                    } 
                    else 
                        err_info("Please enter the break point function name!");
                } 
                else if (!strcmp(arguments[0], "ba")) 
                {
                    if (argc == 2) 
                    { 
                        u64 break_point_addr = strtoul(arguments[1], nullptr, 16);

                        if (!judg_addr_code(break_point_addr))
                            err_info("Illegal address!");
                        else // 打断点
                            set_break_point(pid, break_point_addr);
                    } 
                    else 
                        err_info("Please enter the break point address!");

                }             
                else if (!strcmp(arguments[0], "d") && !strcmp(arguments[1], "b")) 
                {
                    if (argc == 3) 
                    {
                        s32 num = stoi(arguments[2]);

                        if (num >= 8 || num < 0)
                            err_info("Error break point number!");
                        else
                            break_point_delete(pid, num);
                    }
                    else
                        err_info("Please enter the break point number to delete!");

                } 
                else if (!strcmp(arguments[0], "ib")) 
                {
                    break_point_info();
                }


                else if (!strcmp(arguments[0], "x")) 
                {
                    if (argc == 3) 
                    {
                        s32 num = stoi(arguments[1]);
                        if (num < 0) 
                            err_info("Wrong number of reads!");
                        else {
                            u64 address = strtoul(arguments[2], nullptr, 16);
                            show_addr_data(pid, num, address);
                        }
                    } 
                    else 
                        err_info("Please enter the address and read quantity!");
                } 
                else if (!strcmp(arguments[0], "stack")) 
                {
                    if (argc == 2) 
                    {
                        get_regs(pid, &regs);
                        s32 num = stoi(arguments[1]);
                        show_num_stack(pid, &regs, num);
                    }
                    else 
                        err_info("Please Enter the correct quantity!");
                }


                else if (!strcmp(arguments[0], "vmmap")) 
                {
                    show_vmmap(pid);
                } 
                else if (!strcmp(arguments[0], "base")) 
                {
                    show_base_addr();
                } 
                else if (!strcmp(arguments[0], "libc")) 
                {
                    show_glibc_addr();
                } 
                else if (!strcmp(arguments[0], "code")) 
                {
                    show_code_addr();
                } 
                else if (!strcmp(arguments[0], "data")) 
                {
                    show_data_addr();
                }
                else if (!strcmp(arguments[0], "stackbase")) 
                {
                    show_stack_addr();
                } 
                else if (!strcmp(arguments[0], "heapbase")) 
                {
                    show_heap_addr();
                }

                else if (!strcmp(arguments[0], "lfun")) 
                {
                    dyn_show_elf_fun();
                } 
                else if (!strcmp(arguments[0], "lplt")) 
                {
                    dyn_show_elf_plt_fun();
                } 
                else if (!strcmp(arguments[0], "plt")) 
                {
                    if (argc == 2) 
                    {
                        u64 address = strtoul(arguments[1], nullptr, 16);

                        if ( addr_get_elf_plt_fun(address)== "" )
                            printf("\033[31m\033[1m[-] There is no such function!\033[0m\n");
                        else
                            printf("%s\n", addr_get_elf_plt_fun(address).c_str());
                    } 
                    else 
                        err_info("Please enter the function address!");
                }
                else if (!strcmp(arguments[0], "fun")) 
                {
                    if (argc == 2)
                        show_elf_fun_call(pid, arguments[1]);
                    else 
                        err_info("Please enter the function name!");
                }
                else if (!strcmp(arguments[0], "tree")) 
                {
                    if (argc == 3)
                    {
                        s32 level = stoi(arguments[2]);
                        if (level > 5)
                        {
                            printf("[-] Too many levels\n");
                        }
                        else
                        {
                            if(!creat_root_node(arguments[1]))
                            {
                                printf("[*] Creating a forked function call tree...\n");
                                
                                creat_fun_tree(pid, level);
                                show_fun_tree();
                                free_fun_tree();
                            }
                            else
                                printf("[-] Failed to create node\n");
                        }

                    }
                    else
                    {
                        err_info("Please enter the function name!");
                    }
                }

                else if (!strcmp(arguments[0], "test")) 
                {
                    string fun_name;
                    u64 addr, fun_start_addr, fun_end_addr;

                    addr = strtoul(arguments[1], nullptr, 16);
                    fun_name = addr_get_glibc_fun_start_and_end(addr, 
                        &fun_start_addr, &fun_end_addr);

                    printf("%s\n", fun_name.c_str());
                    printf("0x%llx-0x%llx\n", fun_start_addr, fun_end_addr);
                }

                else if (!strcmp(arguments[0], "help") || !strcmp(arguments[0], "h")) 
                {
                    // 显示帮助信息
                    old_cmd = cmd;
                    show_help();
                } 
                else 
                {
                    err_info("Command not found!");
                    printf("Enter 'h' to view supported commands.\n");
                }
                next_input: myargv.clear(); // 下一轮参数输入之前需要把当前存储的命令清除
            }

            debug_stop: 
            // 等待子进程结束之后父进程再退出
            wait(&status);
            free(disasm_code);
            cs_close(&handle);
        }
    }
} 

// printf("-------------regs:\n");
// show_fun_list(&regs_fun_info);
// printf("--------------dis:\n");
// show_fun_list(&dis_fun_info);
// printf("--------------flow_change_fun:\n");
// show_fun_list(&flow_change_fun_info);

// for (auto it : fun_start) {
//     printf("%-30s0x%llx\n", it.first.c_str(), it.second);
// }
// printf("\n");
// for (auto i : fun_end) {
//     printf("%-30s0x%llx\n", i.first.c_str(), i.second);
// }

// printf("fun_args_regs.rdi: 0x%llx\n", fun_args_regs.rdi);
// printf("fun_args_regs.rsi: 0x%llx\n", fun_args_regs.rsi);
// printf("fun_args_regs.rdx: 0x%llx\n", fun_args_regs.rdx);
// printf("fun_args_regs.rcx: 0x%llx\n", fun_args_regs.rcx);
// printf("fun_args_regs.r8:  0x%llx\n", fun_args_regs.r8);
// printf("fun_args_regs.r9:  0x%llx\n", fun_args_regs.r9);

// printf("regs.rdi: 0x%llx\n", regs.rdi);
// printf("regs.rsi: 0x%llx\n", regs.rsi);
// printf("regs.rdx: 0x%llx\n", regs.rdx);
// printf("regs.rcx: 0x%llx\n", regs.rcx);
// printf("regs.r8:  0x%llx\n", regs.r8);
// printf("regs.r9:  0x%llx\n", regs.r9);