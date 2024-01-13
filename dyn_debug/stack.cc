
#include "dyn_fun.h"

// 输出栈信息
void 
show_stack(pid_t pid, const regs_struct* regs)
{
    struct winsize size;
    u64 stack = regs->rsp;
    ioctl(STDIN_FILENO, TIOCGWINSZ, &size);
    s32 count = (size.ws_col-9) / 2;      // 要重复输出的次数

    show_str(count);
    printf("[ STACK ]");
    show_str(count);
    printf("\033[0m\n");

    for (s32 i = 0; i < 8; i++)
    {
        if (stack == regs->rsp) 
        {
            printf("%02d:%04x  rsp  ", i, i*8);
        } 
        else if (stack == regs->rbp)
        {
            printf("%02d:%04x  rbp  ", i, i*8);
        }
        else 
        {
            printf("%02d:%04x       ", i, i*8);
        }

        show_addr_point(pid, stack, false);
        printf("\n");

        stack += 8;
    }
}

void 
show_num_stack(pid_t pid, const regs_struct* regs, s32 num)
{
    if (num < 0 || num > 0x100)
    {
        err_info("Number of errors!");
        return;
    }

    u64 stack = regs->rsp;
    for (s32 i = 0; i < num; i++)
    {
        if (stack == regs->rsp) 
        {
            printf("%02d:%04x  rsp  ", i, i*8);
        } 
        else if (stack == regs->rbp)
        {
            printf("%02d:%04x  rbp  ", i, i*8);
        }
        else 
        {
            printf("%02d:%04x       ", i, i*8);
        }

        show_addr_point(pid, stack, false);
        printf("\n");

        stack += 8;
    }
}

