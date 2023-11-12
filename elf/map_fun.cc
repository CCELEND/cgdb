
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



