
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

// 根据地址找所在 glibc 函数名 2.36
// 704d25fbbb72fa95d517b883131828c0883fe9.debug libc
// 2e105c0bb3ee8e8f5b917f8af764373d206659.debug ld
string get_libc_symbol_name(unsigned long long glib_addr) {
    unsigned long long glib_addr_offset;
    std::string command;

    if (glib_addr < ld_code_end && glib_addr > ld_code_start){
        glib_addr_offset = glib_addr - ld_base;
        command = std::string("objdump -d -j .text 2e105c0bb3ee8e8f5b917f8af764373d206659.debug | grep ");
    }
    else{
        glib_addr_offset = glib_addr - libc_base;
        command = std::string("objdump -d -j .text 704d25fbbb72fa95d517b883131828c0883fe9.debug | grep ");
    }

    // 使stringstream 将十六进制数转换为字符串
    std::stringstream ss;
    ss << std::hex << glib_addr_offset; // 使用十六进制输出
    std::string addr_hex_str = ss.str();
    // 去掉前缀"0x"
    if (addr_hex_str.size() >= 2 && addr_hex_str.substr(0, 2) == "0x") {
        addr_hex_str = addr_hex_str.substr(2);
    }

    command += addr_hex_str;
    FILE* fp = popen(command.c_str(), "r");
    if (!fp)
    {
        printf("\033[31m\033[1m[-] Popen failed!\033[0m\n");
        return "";
    }

    char* result = nullptr;
    size_t len = 0;
    ssize_t read;
    int lib_fun_str_start, lib_fun_str_end;
    std::string lib_fun_name = "";

    while ((read = getline(&result, &len, fp)) != -1) 
    {
        if (std::string(result).find("<") != std::string::npos) 
        {
            lib_fun_str_start = std::string(result).find("<");
            lib_fun_str_end = std::string(result).find(">");
            lib_fun_name = std::string(result).substr(lib_fun_str_start+1, lib_fun_str_end-lib_fun_str_start-1);
        }     
    }

    pclose(fp);   // 关闭管道
    free(result); // 释放动态分配的内存

    if(lib_fun_name != ""){
        return lib_fun_name;
    }

    return "";

}

string get_libc_plt_symbol_name(unsigned long long glib_addr) {
    unsigned long long glib_addr_offset;
    std::string command;

    if (glib_addr < ld_code_end && glib_addr > ld_code_start) 
    {
        glib_addr_offset = glib_addr - ld_base;
        command = std::string("objdump -d -j .plt.sec ld-linux-x86-64.so.2 | grep ");
    }
    else 
    {
        glib_addr_offset = glib_addr - libc_base;
        command = std::string("objdump -d -j .plt.sec libc.so.6 | grep ");
    }

    // 使stringstream 将十六进制数转换为字符串
    std::stringstream ss;
    ss << std::hex << glib_addr_offset; // 使用十六进制输出
    std::string addr_hex_str = ss.str();
    // 去掉前缀"0x"
    if (addr_hex_str.size() >= 2 && addr_hex_str.substr(0, 2) == "0x") {
        addr_hex_str = addr_hex_str.substr(2);
    }

    command += addr_hex_str;
    FILE* fp = popen(command.c_str(), "r");
    if (!fp)
    {
        printf("\033[31m\033[1m[-] Popen failed!\033[0m\n");
        return "";
    }

    char* result = nullptr;
    size_t len = 0;
    ssize_t read;
    int lib_fun_str_start, lib_fun_str_end;
    std::string lib_fun_name = "";

    while ((read = getline(&result, &len, fp)) != -1) 
    {
        if (std::string(result).find("<") != std::string::npos) 
        {
            lib_fun_str_start = std::string(result).find("<");
            lib_fun_str_end = std::string(result).find(">");
            lib_fun_name = std::string(result).substr(lib_fun_str_start+1, lib_fun_str_end-lib_fun_str_start-1);
        }     
    }

    pclose(fp);   // 关闭管道
    free(result); // 释放动态分配的内存

    if(lib_fun_name != ""){
        return lib_fun_name;
    }

    return "";

}

int addr_find_glibc_fun_offset(unsigned long long addr)
{
    if (addr >= glibc_fun_start && addr <= glibc_fun_end){
        return addr - glibc_fun_start;
    }
    return -1;

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
                 long((unsigned char)buf[j]) == 0xe9 && long((unsigned char)buf[j-1]) == 0xfa ||
                 long((unsigned char)buf[j]) == 0x0f && long((unsigned char)buf[j-1]) == 0x00
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
            return addr - it.second;
    }

    return -1;

}