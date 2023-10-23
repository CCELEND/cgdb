
#include "dyn_fun.h"

void get_regs(pid_t pid, struct user_regs_struct* regs)
{
    ptrace(PTRACE_GETREGS, pid, nullptr, regs);
}

// 输出寄存器信息
void show_regs(pid_t pid, struct user_regs_struct* regs)
{
    printf("\033[34m───────────────────────────────────[ REGISTERS ]──────────────────────────────────\033[0m\n");
    printf(
        "RAX      0x%llx\nRBX      0x%llx\nRCX      0x%llx\nRDX      0x%llx\nRDI      0x%llx\n"
        "RSI      0x%llx\nR8       0x%llx\nR9       0x%llx\nR10      0x%llx\nR11      0x%llx\n"
        "R12      0x%llx\nR13      0x%llx\nR14      0x%llx\nR15      0x%llx\n"
        ,
        regs->rax, regs->rbx, regs->rcx, regs->rdx, regs->rdi,
        regs->rsi, regs->r8, regs->r9, regs->r10, regs->r11,
        regs->r12, regs->r13, regs->r14, regs->r15
    );

    printf("RBP      ");
    flag_addr_printf(regs->rbp, true);
    printf("\n");

    printf("RSP      ");
    flag_addr_printf(regs->rsp, true);
    printf("\n");

    printf("RIP      ");
    flag_addr_printf(regs->rip, true);
    printf("\n");

    printf("\033[34m────────────────────────────────────[ DISASM ]────────────────────────────────────\033[0m\n");
}

// 获取 rip 指令, 返回指令长度
// int get_rip_codes(pid_t pid, unsigned long long addr, char* codes)
// {
//     char buf[128];
//     union u {
//         long val;
//         char chars[LONG_SIZE];
//     } word{};

//     for (int i = 0; i < 64; i += LONG_SIZE){
//         word.val = ptrace(PTRACE_PEEKDATA, pid, addr + i, nullptr);
//         if (word.val == -1) err_info("Trace error!");
//         memcpy(buf + i, word.chars, LONG_SIZE); // 将这8个字节拷贝进数组

//         for (int j = i; j < i+4; j++){
//             if (long((unsigned char)buf[j]) == 0xe8 || long((unsigned char)buf[j]) == 0xc3 || long((unsigned char)buf[j]) == 0xeb)  {
//                 memcpy(codes, buf, i+8);
//                 return (i+8);
//             }
//         }
//     }
//     return 0;
// }

// 反汇编 rip 指令
void regs_disasm_info(pid_t pid, struct user_regs_struct* regs)
{
    // 一条指令最长15字节, 最大11行 
    char rip_instruct[176];

    get_regs(pid, regs);
    show_regs(pid, regs);

    get_addr_data(pid, regs->rip, rip_instruct, 176);
    disasm(rip_instruct, regs->rip, 176, 11);

}

