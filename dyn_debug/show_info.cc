
#include "dyn_fun.h"

void show_regs_dis_stack_info(pid_t pid, struct user_regs_struct* regs)
{
    show_regs(pid, regs);
    show_disasm(pid, regs->rip);
    show_stack(pid, regs);
}
