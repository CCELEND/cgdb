
#include "dyn_fun.h"

void stack_point()
{

}

// 输出栈信息
void show_stack(pid_t pid, struct user_regs_struct* regs)
{
    printf("\033[34m─────────────────────────────────────[ STACK ]────────────────────────────────────\033[0m\n");
    ptrace(PTRACE_GETREGS, pid, nullptr, regs);

    unsigned long long stack = regs->rsp;
    unsigned long long addr;
    unsigned long long val;
    for (int i = 0; i < 8; i++)
    {
        if (stack == regs->rsp) {
            printf("%02d:%04x  rsp  ", i, i*8);
        } else if (stack == regs->rbp){
            printf("%02d:%04x  rbp  ", i, i*8);
        }
        else {
            printf("%02d:%04x       ", i, i*8);
        }

        flag_addr_printf(stack, false);
        addr = stack;
        while (true){
            // flag_addr_printf(addr, false);
            // val = get_addr_val(pid, stack);
            val = get_addr_val(pid, addr);
            addr = val;
            if (val < 0x550000000000 || val == 0xffffffffffffffff){
                printf(" ◂— ");
                flag_addr_printf(val, false);
                break;
            }
            else{
                printf(" —▸ ");
                flag_addr_printf(val, false);

            }
            // flag_addr_printf(val, false);
        }

        stack += 8;
        printf("\n");
    }
}

