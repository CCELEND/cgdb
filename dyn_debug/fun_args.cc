
#include "dyn_fun.h"

// 输出函数参数
// 当前 regs 与函数参数  regs 的寄存器对比，如果有变化说明寄存器是函数参数
void 
show_fun_args(pid_t pid,
    const regs_struct* regs, const regs_struct* fun_args_regs)
{
    if (regs->rdi != fun_args_regs->rdi ){
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
    if (regs->r8  != fun_args_regs->r8 ) {
        printf("        r8: ");  show_addr_point(pid, regs->r8 ,   true); printf("\n");
    }
    if (regs->r9  != fun_args_regs->r9 ) {
        printf("        r9: ");  show_addr_point(pid, regs->r9 ,   true); printf("\n");
    }
}

// 设置函数参数 regs 结构体
void 
set_fun_args_regs(IN const regs_struct* regs, OUT regs_struct* fun_args_regs)
{
    fun_args_regs->rdi = regs->rdi;
    fun_args_regs->rsi = regs->rsi;
    fun_args_regs->rdx = regs->rdx;
    fun_args_regs->rcx = regs->rcx;
    fun_args_regs->r8  = regs->r8 ;
    fun_args_regs->r9  = regs->r9 ;
}


