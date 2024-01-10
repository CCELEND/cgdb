
#include "dyn_fun.h"

// 输出 elf 函数的函数名和地址
void 
dyn_show_elf_fun()
{
    printf("[+] Intrinsic function\n");
    printf("%-30saddress\n", "name");
    printf("============================================\n");
    for (auto it : elf_fun_start)
    {
        printf("%-30s0x%llx\n", 
            it.first.c_str(), it.second + elf_base);
    }
}

// 通过 elf 函数名获得 elf 函数地址
u64 
get_elf_fun_addr(const char* fun_name)
{
    for (auto it : elf_fun_start) 
    {
        if (string(fun_name) == it.first)
        {
            return it.second + elf_base;
        }
    }

    return 0;
}

// 根据地址找所在 elf 函数名
string 
addr_get_elf_fun(u64 addr)
{
    for (auto it : elf_fun_start) 
    {
        if ( addr >= it.second + elf_base && 
             addr <= elf_fun_end[it.first] )
        {
            return it.first;
        }
    }

    return "";

}

// 根据地址找所在 elf 函数偏移
s32 
addr_get_elf_fun_offset(u64 addr)
{
    for (auto it : elf_fun_start) 
    {
        if ( addr >= it.second + elf_base && 
             addr <= elf_fun_end[it.first])
        {
            return addr - it.second - elf_base;
        }
    }

    return -1;

}

// 建立 elf 函数名和结束地址的映射
void 
map_fun_end(pid_t pid)
{
    for (auto it : elf_fun_start) 
        elf_fun_end[it.first] = get_fun_end(pid, it.second + elf_base);
}
