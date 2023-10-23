
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