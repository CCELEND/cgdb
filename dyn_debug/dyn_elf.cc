
#include "dyn_fun.h"

// 根据值找键
string get_map_key_value(map<string, unsigned long long>& myMap, 
    unsigned long long fun_plt_addr) 
{
    for (const auto& pair : myMap) 
    {
        if (pair.second == fun_plt_addr) {
            return pair.first;
        }
    }
    return "";
}

// 根据实际 plt 函数地址找函数名
string get_plt_fun(unsigned long long fun_addr)
{
    unsigned long long fun_plt_addr = fun_addr - elf_base;
    return get_map_key_value(fun_plt, fun_plt_addr);
}

// 输出全部二进制文件中 libc 函数的函数名和地址
void dyn_show_elf_lib_plt()
{
    printf("[+] Libc function \033[32mplt<@plt>\033[0m\n");
    printf("%-30saddress\n", "name");
    printf("============================================\n");
    for (auto it : fun_plt) {
        printf("%-30s0x%llx\n", it.first.c_str(), it.second + elf_base);
    }
}

// 通过函数名获得函数地址
unsigned long long get_fun_addr(char* fun_name, Binary* bin)
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

// 通过函数地址获得函数结束地址
unsigned long long get_fun_end_addr(pid_t pid, unsigned long long fun_addr)
{
    char buf[0x1000];
    union u {
        long val;
        char chars[LONG_SIZE];
    } word{};

    for (int i = 0; i < 0x1000; i += LONG_SIZE){
        word.val = ptrace(PTRACE_PEEKDATA, pid, fun_addr + i, nullptr);
        if (word.val == -1)
            err_info("Trace error!");
        memcpy(buf + i, word.chars, LONG_SIZE); // 将这8个字节拷贝进数组

        for (int j = i; j < i + 8; j++)
        {
            if ( long((unsigned char)buf[j]) == 0xf4 ||
                 long((unsigned char)buf[j]) == 0xc3 ||
                 long((unsigned char)buf[j]) == 0xe9 && long((unsigned char)buf[j-1]) == 0xfa
               )
            {
                return j + fun_addr;
            }
        }
    }

    return 0;
}

// 建立函数名和结束地址的映射
void map_fun_end(pid_t pid, Binary *bin)
{
    Symbol *sym;
    for(int i = 0; i < bin->symbols.size(); i++) 
    {
        sym = &bin->symbols[i];
        if(sym->addr)
            fun_end[sym->name] = get_fun_end_addr(pid, sym->addr + elf_base);
    }

}

// 建立函数名和开始地址的映射
void map_fun_start(pid_t pid, Binary *bin)
{
    Symbol *sym;
    for(int i = 0; i < bin->symbols.size(); i++) 
    {
        sym = &bin->symbols[i];
        if(sym->addr)
            fun_start[sym->name] = sym->addr + elf_base;
    }

}

// 根据地址找所在函数名
string addr_find_fun(unsigned long long addr)
{
    for (auto it : fun_start) 
    {
        if (addr >= it.second && addr <= fun_end[it.first])
            return it.first;
    }

    return "";

}

// 根据地址找所在函数偏移
int addr_find_fun_offset(unsigned long long addr)
{
    for (auto it : fun_start) 
    {
        if (addr >= it.second && addr <= fun_end[it.first])
            return addr-it.second;
    }

    return -1;

}