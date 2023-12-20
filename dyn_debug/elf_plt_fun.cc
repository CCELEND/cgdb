
#include "dyn_fun.h"

// 输出 elf plt 函数的函数名和地址
void 
dyn_show_elf_plt_fun()
{
    printf("[+] PLT function \033[32mplt<@plt>\033[0m\n");
    printf("%-30saddress\n", "name");
    printf("============================================\n");
    
    for (auto it : elf_plt_fun_start)
    {
        printf("%-30s0x%llx\n", 
            it.first.c_str(), it.second + elf_base);
    }
}

// 根据实际 elf plt 函数地址找函数名
string 
addr_get_elf_plt_fun(u64 addr)
{
    for (auto it : elf_plt_fun_start) 
    {
        if (addr >= it.second + elf_base && 
            addr <= elf_plt_fun_end[it.first])
        {
            return it.first;
        }
    }

    return "";
}

// 通过 elf plt 函数名获得 elf plt 函数地址
u64 
get_elf_plt_fun_addr(const char* plt_fun_name)
{
    for (auto it : elf_plt_fun_start) 
    {
        if (string(plt_fun_name) == it.first)
        {
            return it.second + elf_base;
        }
    }

    return 0;
}


// 根据地址找所在 elf plt 函数偏移
s32 
addr_get_elf_plt_fun_offset(u64 addr)
{
    for (auto it : elf_plt_fun_start) 
    {
        if (addr >= it.second + elf_base && 
            addr <= elf_plt_fun_end[it.first])
        {
            return addr - it.second - elf_base;
        }
    }

    return -1;
}

// 建立 elf plt 函数名和结束地址的映射
void map_plt_fun_end(pid_t pid)
{
    for (auto it : elf_plt_fun_start)
    {
         elf_plt_fun_end[it.first] = it.second + elf_base + 0xb;
    }
}


