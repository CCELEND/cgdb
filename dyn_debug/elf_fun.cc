
#include "dyn_fun.h"

// 通过 elf 函数名获得 elf 函数地址
unsigned long long get_elf_fun_addr(char* fun_name, Binary* bin)
{
    Symbol *sym;

    for(int i = 0; i < bin->symbols.size(); i++) {
        sym = &bin->symbols[i];
        if(sym->fun_sym_type == "symtab") {
            if (fun_name == sym->name) {
                return sym->addr + elf_base;
            }
        }
    }

    return 0;
}

// 根据地址找所在 elf 函数名
string addr_get_elf_fun(unsigned long long addr)
{
    for (auto it : elf_fun_start) 
    {
        if (addr >= it.second && addr <= elf_fun_end[it.first])
            return it.first;
    }

    return "";

}

// 根据地址找所在 elf 函数偏移
int addr_get_elf_fun_offset(unsigned long long addr)
{
    for (auto it : elf_fun_start) 
    {
        if (addr >= it.second && addr <= elf_fun_end[it.first])
            return addr - it.second;
    }

    return -1;

}


// 建立 elf 函数名和开始地址的映射
void map_fun_start(pid_t pid, Binary* bin)
{
    Symbol *sym;
    for(int i = 0; i < bin->symbols.size(); i++) 
    {
        sym = &bin->symbols[i];
        if(sym->addr)
            elf_fun_start[sym->name] = sym->addr + elf_base;
    }

}

// 建立 elf 函数名和结束地址的映射
void map_fun_end(pid_t pid, Binary* bin)
{
    Symbol *sym;
    for(int i = 0; i < bin->symbols.size(); i++) 
    {
        sym = &bin->symbols[i];
        if(sym->addr)
            elf_fun_end[sym->name] = get_fun_end(pid, sym->addr + elf_base);
    }

}
