
#include "dyn_fun.h"

// 输出栈信息
void show_stack(pid_t pid, struct user_regs_struct* regs)
{
    printf("\033[34m─────────────────────────────────────[ STACK ]────────────────────────────────────\033[0m\n");
    // ptrace(PTRACE_GETREGS, pid, nullptr, regs);

    unsigned long long stack = regs->rsp;
    
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

        show_addr_point(pid, stack, false);
        printf("\n");

        stack += 8;
    }
}

