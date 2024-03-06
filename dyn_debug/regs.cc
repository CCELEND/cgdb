
#include "dyn_fun.h"

// 获得 user_regs_struct
void 
get_regs(pid_t pid, 
    IN pregs_struct regs)
{
    ptrace(PTRACE_GETREGS, pid, nullptr, regs);
}

// 输出寄存器信息
void 
show_regs(pid_t pid, 
    const pregs_struct regs)
{

    struct winsize size;
    ioctl(STDIN_FILENO, TIOCGWINSZ, &size);
    s32 count = (size.ws_col-13) / 2;      // 要重复输出的次数

    printf("LEGEND: "
    "\033[33mSTACK\033[0m | "
    "\033[34mHEAP\033[0m | "
    "\033[31mCODE\033[0m | "
    "\033[35mDATA\033[0m | RODATA\n");
    
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

    regs_val[0]  != last_regs.rax ? printf("\033[31m\033[1m*RAX\033[0m     ") : printf(" RAX     "); show_addr_point(pid, regs_val[0],   true); printf("\n");
    regs_val[1]  != last_regs.rbx ? printf("\033[31m\033[1m*RBX\033[0m     ") : printf(" RBX     "); show_addr_point(pid, regs_val[1],   true); printf("\n");
    regs_val[2]  != last_regs.rcx ? printf("\033[31m\033[1m*RCX\033[0m     ") : printf(" RCX     "); show_addr_point(pid, regs_val[2],   true); printf("\n");
    regs_val[3]  != last_regs.rdx ? printf("\033[31m\033[1m*RDX\033[0m     ") : printf(" RDX     "); show_addr_point(pid, regs_val[3],   true); printf("\n");
    regs_val[4]  != last_regs.rdi ? printf("\033[31m\033[1m*RDI\033[0m     ") : printf(" RDI     "); show_addr_point(pid, regs_val[4],   true); printf("\n");
    regs_val[5]  != last_regs.rsi ? printf("\033[31m\033[1m*RSI\033[0m     ") : printf(" RSI     "); show_addr_point(pid, regs_val[5],   true); printf("\n");
    regs_val[6]  != last_regs.r8  ? printf("\033[31m\033[1m*R8 \033[0m     ") : printf(" R8      "); show_addr_point(pid, regs_val[6],   true); printf("\n");
    regs_val[7]  != last_regs.r9  ? printf("\033[31m\033[1m*R9 \033[0m     ") : printf(" R9      "); show_addr_point(pid, regs_val[7],   true); printf("\n");
    regs_val[8]  != last_regs.r10 ? printf("\033[31m\033[1m*R10\033[0m     ") : printf(" R10     "); show_addr_point(pid, regs_val[8],   true); printf("\n");
    regs_val[9]  != last_regs.r11 ? printf("\033[31m\033[1m*R11\033[0m     ") : printf(" R11     "); show_addr_point(pid, regs_val[9],   true); printf("\n");
    regs_val[10] != last_regs.r12 ? printf("\033[31m\033[1m*R12\033[0m     ") : printf(" R12     "); show_addr_point(pid, regs_val[10],  true); printf("\n");
    regs_val[11] != last_regs.r13 ? printf("\033[31m\033[1m*R13\033[0m     ") : printf(" R13     "); show_addr_point(pid, regs_val[11],  true); printf("\n");
    regs_val[12] != last_regs.r14 ? printf("\033[31m\033[1m*R14\033[0m     ") : printf(" R14     "); show_addr_point(pid, regs_val[12],  true); printf("\n");
    regs_val[13] != last_regs.r15 ? printf("\033[31m\033[1m*R15\033[0m     ") : printf(" R15     "); show_addr_point(pid, regs_val[13],  true); printf("\n");
    regs_val[14] != last_regs.rbp ? printf("\033[31m\033[1m*RBP\033[0m     ") : printf(" RBP     "); show_addr_point(pid, regs_val[14],  true); printf("\n");
    regs_val[15] != last_regs.rsp ? printf("\033[31m\033[1m*RSP\033[0m     ") : printf(" RSP     "); show_addr_point(pid, regs_val[15],  true); printf("\n");
    regs_val[16] != last_regs.rip ? printf("\033[31m\033[1m*RIP\033[0m     ") : printf(" RIP     "); show_addr_point(pid, regs_val[16],  true); printf("\n");

}

void 
copy_regs_to_last_regs(OUT pregs_struct last_regs, IN const pregs_struct regs)
{
    memcpy(last_regs, regs, sizeof(struct user_regs_struct));
}

