
#include "dyn_fun.h"

// 断点注入
void break_point_inject(pid_t pid, break_point& bp) 
{
    // int3 中断指令
    char code[CODE_SIZE] = { static_cast<char>(0xcc) };
    // 中断指令 int3 注入
    put_addr_data(pid, bp.addr, code, CODE_SIZE);
    // 启用断点   
    bp.break_point_state = true;     
}

// 设置 ni 断点
void set_ni_break_point(pid_t pid, unsigned long long addr)
{
    char rip_instruct[32];
    unsigned long long next_addr;
    
    get_addr_data(pid, addr, rip_instruct, 32);
    next_addr = get_next_instruct_addr(rip_instruct, addr, 32);

    // 检查普通断点列表是否有这个地址的断点，有则取消
    for (int i = 0; i < 8; i++) 
    {
        if (break_point_list[i].addr == next_addr)
            break_point_delete(pid, i);
    }

    ni_break_point.addr = next_addr;
    // 需要打断点的地址上指令取出备份
    get_addr_data(pid, next_addr, ni_break_point.backup, CODE_SIZE);
    break_point_inject(pid, ni_break_point);

}

// 设置普通断点
// void set_break_point(pid_t pid, char* bp_fun)
void set_break_point(pid_t pid, unsigned long long break_point_addr)
{
    for (int i = 0; i < 8; i++) 
    {
        if (break_point_list[i].addr == break_point_addr)
        {
            err_info("Break point already exists!");
            return;
        }
    }

    int fun_offset;
    string fun_name = "", link_file = "";
    unsigned long long fun_start_addr, base_addr;
    for (int i = 0; i < 8; i++) 
    {
        if (!break_point_list[i].addr)
        {
            fun_name = get_fun(break_point_addr, &fun_start_addr);
            fun_offset = break_point_addr - fun_start_addr;
            link_file = get_addr_file_base(break_point_addr, &base_addr);
            printf("[+] Break point %d at (%s) offset \033[31m0x%llx\033[0m: \033[31m0x%llx\033[0m ", 
                    i, link_file.c_str(), break_point_addr-base_addr, break_point_addr);

            if (fun_offset)
                printf("<%s+%d>\n", fun_name.c_str(), fun_offset);
            else
                printf("<%s>\n", fun_name.c_str());

            break_point_list[i].addr = break_point_addr;
            // 需要打断点的地址上指令取出备份
            get_addr_data(pid, break_point_addr, break_point_list[i].backup, CODE_SIZE);
            // 输出2行断点地址的反汇编
            bp_disasm(pid, break_point_addr);
            // 注入断点
            break_point_inject(pid, break_point_list[i]);
            break;
        }
    }
}

// 删除断点
void break_point_delete(pid_t pid, int num)
{
    // 指令恢复
    put_addr_data(pid, break_point_list[num].addr, break_point_list[num].backup, CODE_SIZE);

    break_point_list[num].addr = 0;
    break_point_list[num].break_point_state = false;
}

// 断点处理
int break_point_handler(pid_t pid, int status, break_point& bp, bool showbp_flag) 
{
    struct user_regs_struct bp_regs{};
    // 判断信号类型
    // exit 信号
    if (WIFEXITED(status)) {
        err_info("The child process has ended!");
        return -1;
    }
    // 如果是 STOP 信号
    if (WIFSTOPPED(status)) 
    {
        // 如果触发了 SIGTRAP,说明碰到了断点
        if (WSTOPSIG(status) == SIGTRAP) 
        {                  
            ptrace(PTRACE_GETREGS, pid, nullptr, &bp_regs);    // 读取寄存器的值，为回退做准备

            // 如果满足关系，说明断点命中
            if (bp.addr != (bp_regs.rip - 1)) 
            {
                // 未命中
                printf("\033[31m\033[1m[-] Break point: 0x%llx failure!\033[0m\n", bp_regs.rip);
                return -1;
            } 
            else 
            {
                if (showbp_flag)
                    printf("[+] Break point at: \033[31m0x%llx\033[0m\n", bp.addr);

                // 把 INT 3 patch 回本来正常的指令
                put_addr_data(pid, bp.addr, bp.backup, CODE_SIZE);
                // 执行流回退，重新执行正确的指令
                bp_regs.rip = bp.addr;
                ptrace(PTRACE_SETREGS, pid, nullptr, &bp_regs);

                memcpy(&regs, &bp_regs, sizeof(struct user_regs_struct));
                get_vma_address(pid);
                show_regs_dis_stack_info(pid, &regs);
                copy_regs_to_last_regs(&last_regs, &regs);

                // 命中断点之后取消断点
                bp.addr = 0;
                bp.break_point_state = false;
                return 0;
            }
        }
    }
    return 0;
}

