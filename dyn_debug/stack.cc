
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

        // flag_addr_printf(stack, false);
        // addr = stack;
        // while (true)
        // {
        //     val = get_addr_val(pid, addr);
        //     if (val < 0x550000000000 || val > 0x7fffffffffff) {
        //         printf(" ◂— ");
        //         if (judg_addr_code(addr)) {
        //             get_addr_data(pid, addr, addr_instruct, 16);
        //             disasm_mne_op(addr_instruct, addr, 16, 1);
        //         }
        //         else {
        //             flag_addr_printf(val, false);
        //             if (val > 0x7fffffffffff)
        //                 val_to_string(val);
        //         }

        //         break;
        //     }
        //     else {
        //         printf(" —▸ ");
        //         flag_addr_printf(val, false);
        //     }

        //     addr = val;
        // }
        show_addr_point(pid, stack, false);
        printf("\n");

        stack += 8;
    }
}

