
#include "dyn_fun.h"


// 输出 fun arg
void show_fun_args(char* ops, 
    struct user_regs_struct* regs, struct user_regs_struct* last_regs)
{
    if (regs->rdi != last_regs->rdi || string(ops).find("rdi") != string::npos) {
        printf("        rdi: "); show_addr_point(pid, regs->rdi,   true); printf("\n");
    }
    else if (regs->rsi != last_regs->rsi) {
        printf("        rsi: "); show_addr_point(pid, regs->rsi,   true); printf("\n");
    }
    else if (regs->rdx != last_regs->rdx) {
        printf("        rdx: "); show_addr_point(pid, regs->rdx,   true); printf("\n");
    }
    else if (regs->rcx != last_regs->rcx) {
        printf("        rcx: "); show_addr_point(pid, regs->rcx,   true); printf("\n");
    }
    else if (regs->r8 != last_regs->r8) {
        printf("        r8: ");  show_addr_point(pid, regs->r8,   true);  printf("\n");
    }
    else if (regs->r9 != last_regs->r9) {
        printf("        r9: ");  show_addr_point(pid, regs->r9,   true);  printf("\n");
    }

}


