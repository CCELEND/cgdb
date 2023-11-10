
#include "dyn_fun.h"

// 输出 elf plt 函数的函数名和地址
void show_elf_plt_fun()
{
    printf("[+] Libc function \033[32mplt<@plt>\033[0m\n");
    printf("%-30saddress\n", "name");
    printf("============================================\n");
    for (auto it : elf_plt_fun) {
        printf("%-30s0x%llx\n", it.first.c_str(), it.second + elf_base);
    }
}

// 根据实际 elf plt 函数地址找函数名
string addr_get_elf_plt_fun(unsigned long long fun_addr)
{
    unsigned long long fun_plt_addr = fun_addr - elf_base;
    return get_map_key_value(elf_plt_fun, fun_plt_addr);
}


// 根据地址找所在 elf plt 函数偏移
int addr_get_elf_plt_fun_offset(unsigned long long addr)
{
    for (auto it : elf_plt_fun) 
    {
        if (addr >= it.second + elf_base && addr <= elf_plt_fun_end[it.first])
            return addr - it.second - elf_base;
    }

    return -1;
}

// 建立 elf plt 函数名和结束地址的映射
void map_plt_fun_end(pid_t pid)
{
    for (auto it : elf_plt_fun)
         elf_plt_fun_end[it.first] = it.second + elf_base + 0xb;
}


