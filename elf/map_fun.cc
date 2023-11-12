
#include "loader_elf.h"

// 建立 elf 函数名和开始地址的映射
void map_fun_start(Binary* bin)
{
    Symbol* sym;
    for(int i = 0; i < bin->symbols.size(); i++) 
    {
        sym = &bin->symbols[i];
        if(sym->addr)
            elf_fun_start[sym->name] = sym->addr;
    }

}


// 根据函数名获得函数地址
unsigned long long get_fun_addr(char* funame)
{
    if (elf_fun_start.find(funame) != elf_fun_start.end()) {
        return elf_fun_start[funame];
    } 
    else {
        printf("\033[31m\033[1m[-] There is no such function!\033[0m\n");
        return 0;
    }

}


