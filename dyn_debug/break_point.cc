
#include "dyn_fun.h"

void break_point_inject(pid_t pid, break_point& bp) 
{
    // int3 中断指令
    char code[CODE_SIZE] = { static_cast<char>(0xcc) };
    // 中断指令 int3 注入
    put_addr_data(pid, bp.addr, code, CODE_SIZE);    
    bp.break_point_state = true;     // 启用断点
}

void set_break_point(pid_t pid, char* bp_fun, Binary* bin) 
{
    Symbol *sym;
    unsigned long long break_point_addr;

    for(int i = 0; i < bin->symbols.size(); i++) {
        sym = &bin->symbols[i];
        if(sym->fun_sym_type == "symtab") {
            if (bp_fun == sym->name) {
                break_point_addr = sym->addr + elf_base;
                break;
            }
        }
    }
    if (!sym->addr){
        err_info("There is no such function!");
        return;
    }


    for (int i = 0; i < 8; i++) {
        if (break_point_list[i].addr == break_point_addr){
            err_info("Break point already exists!");
            return;
        }
    }
    for (int i = 0; i < 8; i++) {
        if (break_point_list[i].addr == 0)
        {
            break_point_list[i].addr = break_point_addr;
            printf("[+] Break point %d at \033[31m0x%lx\033[0m: \033[31m0x%llx\033[0m\n", 
                    i, sym->addr, break_point_list[i].addr);

            // 先把需要打断点的地址上指令取出备份
            get_addr_data(pid, break_point_list[i].addr, break_point_list[i].backup, CODE_SIZE);
            // print_bytes("[+] Get trace instruction: ", break_point_list[i].backup, CODE_SIZE);
            // execute_disasm(break_point_list[i].backup, CODE_SIZE);
            disasm(break_point_list[i].backup, break_point_list[i].addr, CODE_SIZE);
            // 注入断点
            break_point_inject(pid, break_point_list[i]);
            break;
        }
    }
}

void break_point_delete(pid_t pid, int num)
{
    put_addr_data(pid, break_point_list[num].addr, break_point_list[num].backup, CODE_SIZE);

    break_point_list[num].addr = 0;
    break_point_list[num].break_point_state = false;
}


int break_point_handler(pid_t pid, int status, break_point& bp) 
{
    struct user_regs_struct regs{};
    // 判断信号类型
    // exit 信号
    if (WIFEXITED(status)) err_exit("The child process has ended!");
    // 如果是 STOP 信号
    if (WIFSTOPPED(status)) 
    {
        // 如果触发了 SIGTRAP,说明碰到了断点
        if (WSTOPSIG(status) == SIGTRAP) 
        {                  
            ptrace(PTRACE_GETREGS, pid, nullptr, &regs);    // 读取寄存器的值，为回退做准备

            // 如果满足关系，说明断点命中
            if (bp.addr != (regs.rip - 1)) 
            {
                // 未命中
                printf("\033[31m\033[1m[-] Break point: 0x%llx failure!\033[0m\n", regs.rip);
                return -1;
            } 
            else 
            {
                printf("[+] Break point at: \033[31m0x%llx\033[0m\n", bp.addr);
                // 把 INT 3 patch 回本来正常的指令
                put_addr_data(pid, bp.addr, bp.backup, CODE_SIZE);
                // 执行流回退，重新执行正确的指令
                regs.rip = bp.addr;
                ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
                regs_disasm_info(pid, &regs);
                show_stack(pid, &regs);

                bp.addr = 0;
                bp.break_point_state = false; // 命中断点之后取消断点
                return 0;
            }
        }
    }
    return 0;
}

