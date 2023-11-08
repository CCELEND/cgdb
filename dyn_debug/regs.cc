
#include "dyn_fun.h"

// 获得 user_regs_struct
void get_regs(pid_t pid, struct user_regs_struct* regs)
{
    ptrace(PTRACE_GETREGS, pid, nullptr, regs);
}


// 输出寄存器信息
void show_regs(pid_t pid, struct user_regs_struct* regs)
{

    struct winsize size;
    ioctl(STDIN_FILENO, TIOCGWINSZ, &size);
    int count = (size.ws_col-13)/2;      // 要重复输出的次数
    show_str(count);
    printf("[ REGISTERS ]");
    show_str(count);
    printf("\033[0m\n");

    unsigned long long regs_val[17];
    regs_val[0]  = regs->rax; regs_val[1]  = regs->rbx; regs_val[2]  = regs->rcx; regs_val[3]  = regs->rdx;
    regs_val[4]  = regs->rdi; regs_val[5]  = regs->rsi; regs_val[6]  = regs->r8;  regs_val[7]  = regs->r9;
    regs_val[8]  = regs->r10; regs_val[9]  = regs->r11; regs_val[10] = regs->r12; regs_val[11] = regs->r13;
    regs_val[12] = regs->r14; regs_val[13] = regs->r15; regs_val[14] = regs->rbp; regs_val[15] = regs->rsp;
    regs_val[16] = regs->rip;
    
    printf("RAX      "); show_addr_point(pid, regs_val[0],  true); printf("\n");
    printf("RBX      "); show_addr_point(pid, regs_val[1],  true); printf("\n");
    printf("RCX      "); show_addr_point(pid, regs_val[2],  true); printf("\n");
    printf("RDX      "); show_addr_point(pid, regs_val[3],  true); printf("\n");
    printf("RDI      "); show_addr_point(pid, regs_val[4],  true); printf("\n");
    printf("RSI      "); show_addr_point(pid, regs_val[5],  true); printf("\n");
    printf("R8       "); show_addr_point(pid, regs_val[6],  true); printf("\n");
    printf("R9       "); show_addr_point(pid, regs_val[7],  true); printf("\n");
    printf("R10      "); show_addr_point(pid, regs_val[8],  true); printf("\n");
    printf("R11      "); show_addr_point(pid, regs_val[9],  true); printf("\n");
    printf("R12      "); show_addr_point(pid, regs_val[10], true); printf("\n");
    printf("R13      "); show_addr_point(pid, regs_val[11], true); printf("\n");
    printf("R14      "); show_addr_point(pid, regs_val[12], true); printf("\n");
    printf("R15      "); show_addr_point(pid, regs_val[13], true); printf("\n");
    printf("RBP      "); show_addr_point(pid, regs_val[14], true); printf("\n");
    printf("RSP      "); show_addr_point(pid, regs_val[15], true); printf("\n");
    printf("RIP      "); show_addr_point(pid, regs_val[16], true); printf("\n");

}

// 反汇编 rip 指令
void regs_disasm_info(pid_t pid, struct user_regs_struct* regs)
{
    if (libc_base == 0) get_vma_address(pid);

    show_regs(pid, regs);
    disasm1(pid, regs->rip);
}

