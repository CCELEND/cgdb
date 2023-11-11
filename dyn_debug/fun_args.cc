
#include "dyn_fun.h"

// 输出 fun arg
// void show_fun_args(pid_t pid, char* mnemonic, char* ops, 
//     struct user_regs_struct* regs, struct user_regs_struct* last_regs)
// {
//     if (regs->rdi != last_regs->rdi || string(ops).find("rdi") != string::npos && 
//         string(mnemonic).find("mov") != string::npos) 
//     {
//         printf("        rdi: "); show_addr_point(pid, regs->rdi,   true); printf("\n");
//     }
//     else if (regs->rsi != last_regs->rsi) {
//         printf("        rsi: "); show_addr_point(pid, regs->rsi,   true); printf("\n");
//     }
//     else if (regs->rdx != last_regs->rdx) {
//         printf("        rdx: "); show_addr_point(pid, regs->rdx,   true); printf("\n");
//     }
//     else if (regs->rcx != last_regs->rcx) {
//         printf("        rcx: "); show_addr_point(pid, regs->rcx,   true); printf("\n");
//     }
//     else if (regs->r8 != last_regs->r8) {
//         printf("        r8: ");  show_addr_point(pid, regs->r8,   true);  printf("\n");
//     }
//     else if (regs->r9 != last_regs->r9) {
//         printf("        r9: ");  show_addr_point(pid, regs->r9,   true);  printf("\n");
//     }
// }

void show_fun_args(pid_t pid,
    struct user_regs_struct* regs, struct user_regs_struct* fun_args_regs)
{
    if (regs->rdi != fun_args_regs->rdi ) 
    {
        printf("        rdi: "); show_addr_point(pid, regs->rdi,   true); printf("\n");
    }
    if (regs->rsi != fun_args_regs->rsi) {
        printf("        rsi: "); show_addr_point(pid, regs->rsi,   true); printf("\n");
    }
    if (regs->rdx != fun_args_regs->rdx) {
        printf("        rdx: "); show_addr_point(pid, regs->rdx,   true); printf("\n");
    }
    if (regs->rcx != fun_args_regs->rcx) {
        printf("        rcx: "); show_addr_point(pid, regs->rcx,   true); printf("\n");
    }
    if (regs->r8 != fun_args_regs->r8) {
        printf("        r8: ");  show_addr_point(pid, regs->r8,   true);  printf("\n");
    }
    if (regs->r9 != fun_args_regs->r9) {
        printf("        r9: ");  show_addr_point(pid, regs->r9,   true);  printf("\n");
    }
}

void set_fun_args_regs(struct user_regs_struct* regs, struct user_regs_struct* fun_args_regs)
{
    fun_args_regs->rdi = regs->rdi;
    fun_args_regs->rsi = regs->rsi;
    fun_args_regs->rdx = regs->rdx;
    fun_args_regs->rcx = regs->rcx;
    fun_args_regs->r8  = regs->r8 ;
    fun_args_regs->r9  = regs->r9 ;
}


