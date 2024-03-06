
#include "dyn_fun.h"

void 
show_regs_dis_stack_info(pid_t pid, 
    const pregs_struct regs)
{
    show_regs(pid, regs);
    show_disasm(pid, regs->rip);
    show_stack(pid, regs);
}

void
show_base_addr()
{
    printf("[+] elf base:     0x%llx\n", elf_base);
    printf("[+] libc base:    0x%llx\n", libc_base);
    printf("[+] ld base:      0x%llx\n", ld_base);
}

void
show_code_addr()
{
    printf("[+] elf code:  \033[31m0x%llx-0x%llx\033[0m\n", 
        elf_code_start,  elf_code_end);

    printf("[+] libc code: \033[31m0x%llx-0x%llx\033[0m\n", 
        libc_code_start, libc_code_end);

    printf("[+] ld code:   \033[31m0x%llx-0x%llx\033[0m\n", 
        ld_code_start,   ld_code_end);

    printf("[+] vdso code: \033[31m0x%llx-0x%llx\033[0m\n", 
        vdso_code_start, vdso_code_end);
}

void
show_data_addr()
{
    printf("[+] elf data:  \033[35m0x%llx-0x%llx\033[0m\n", 
        elf_data_start,  elf_data_end);

    printf("[+] libc data: \033[35m0x%llx-0x%llx\033[0m\n", 
        libc_data_start, libc_data_end);

    printf("[+] ld data:   \033[35m0x%llx-0x%llx\033[0m\n", 
        ld_data_start,   ld_data_end);
}

void
show_stack_addr()
{
    printf("[+] stack: \033[33m0x%llx-0x%llx\033[0m\n", 
        stack_base, stack_end);
}

void
show_heap_addr()
{
    printf("[+] heap: \033[34m0x%llx-0x%llx\033[0m\n", 
        heap_base,  heap_end);
}

void
show_glibc_addr()
{
    printf("[+] libc base: 0x%llx\n", 
        libc_base);
    
    printf("[+] ld base:   0x%llx\n", 
        ld_base);
}


