
#include "dyn_fun.h"

// 根据值找键
string get_map_key_value(map<string, unsigned long long>& Map, unsigned long long plt_fun_addr) 
{
    for (const auto& pair : Map) 
    {
        if (pair.second == plt_fun_addr) {
            return pair.first;
        }
    }
    return "";
}

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

// 输出 elf 中 libc 函数的函数名和地址
void dyn_show_elf_lib_plt()
{
    printf("[+] Libc function \033[32mplt<@plt>\033[0m\n");
    printf("%-30saddress\n", "name");
    printf("============================================\n");
    for (auto it : elf_plt_fun) {
        printf("%-30s0x%llx\n", it.first.c_str(), it.second + elf_base);
    }
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

// 根据实际 elf plt 函数地址找函数名
string addr_get_elf_plt_fun(unsigned long long fun_addr)
{
    unsigned long long fun_plt_addr = fun_addr - elf_base;
    return get_map_key_value(elf_plt_fun, fun_plt_addr);
}


// 根据地址找所在 glibc 函数名 2.36
// 704d25fbbb72fa95d517b883131828c0883fe9.debug libc
// 2e105c0bb3ee8e8f5b917f8af764373d206659.debug ld
string addr_get_glibc_fun(unsigned long long glibc_fun_addr)
{
    if (glibc_fun_addr % 0x8 != 0)
        return "";

    unsigned long long glibc_fun_addr_offset;
    std::string command;
    std::string glibc_fun_name = "";
    bool is_libc, break_flag = false;

    if (glibc_fun_addr < ld_code_end && glibc_fun_addr > ld_code_start) {
        is_libc = false;
        glibc_fun_addr_offset = glibc_fun_addr - ld_base;
        command = std::string("objdump -d -j .text 2e105c0bb3ee8e8f5b917f8af764373d206659.debug | grep ");
    }
    else {
        is_libc = true;
        glibc_fun_addr_offset = glibc_fun_addr - libc_base;
        command = std::string("objdump -d -j .text 704d25fbbb72fa95d517b883131828c0883fe9.debug | grep ");
    }

    std::stringstream ss;
    FILE* fp;
    while (!break_flag)
    {
        ss.clear();
        ss.str("");

        std::string exe_command = command;
        // 使stringstream 将十六进制数转换为字符串
        
        ss << std::hex << glibc_fun_addr_offset; // 使用十六进制输出
        std::string addr_hex_str = ss.str();
        // 去掉前缀"0x"
        if (addr_hex_str.size() >= 2 && addr_hex_str.substr(0, 2) == "0x") {
            addr_hex_str = addr_hex_str.substr(2);
        }

        addr_hex_str = "0" + addr_hex_str;
        exe_command += addr_hex_str;
        fp = popen(exe_command.c_str(), "r");
        if (!fp)
        {
            printf("\033[31m\033[1m[-] Popen failed!\033[0m\n");
            break;
        }

        char* result = nullptr;
        size_t len = 0;
        ssize_t read;
        int lib_fun_str_start, lib_fun_str_end;
        
        while ((read = getline(&result, &len, fp)) != -1) 
        {
            if (std::string(result).find("<") != std::string::npos) 
            {
                lib_fun_str_start = std::string(result).find("<");
                lib_fun_str_end = std::string(result).find(">");
                glibc_fun_name = std::string(result).substr(lib_fun_str_start+1, lib_fun_str_end-lib_fun_str_start-1);
                // printf("%s\n", glibc_fun_name.c_str());
                break_flag = true;
                break;
            }     
        }
        // printf("0x%llx\n", glibc_fun_addr_offset);

        glibc_fun_addr_offset -= 0x8;
        pclose(fp);   // 关闭管道
        free(result); // 释放动态分配的内存
    }

    return glibc_fun_name;


}

// 根据地址找所在 glibc plt 函数名
string addr_get_glibc_plt_fun(unsigned long long glibc_plt_fun_addr) 
{
    unsigned long long glibc_plt_fun_addr_offset;
    std::string command;

    if (glibc_plt_fun_addr < ld_code_end && glibc_plt_fun_addr > ld_code_start) 
    {
        glibc_plt_fun_addr_offset = glibc_plt_fun_addr - ld_base;
        command = std::string("objdump -d -j .plt.sec ld-linux-x86-64.so.2 | grep ");
    }
    else 
    {
        glibc_plt_fun_addr_offset = glibc_plt_fun_addr - libc_base;
        command = std::string("objdump -d -j .plt.sec libc.so.6 | grep ");
    }

    // stringstream 将十六进制数转换为字符串
    std::stringstream ss;
    ss << std::hex << glibc_plt_fun_addr_offset; // 使用十六进制输出
    std::string addr_hex_str = ss.str();
    // 去掉前缀"0x"
    if (addr_hex_str.size() >= 2 && addr_hex_str.substr(0, 2) == "0x") {
        addr_hex_str = addr_hex_str.substr(2);
        addr_hex_str = "0" + addr_hex_str;
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
    int lib_plt_fun_str_start, lib_plt_fun_str_end;
    std::string lib_plt_fun_name = "";

    while ((read = getline(&result, &len, fp)) != -1) 
    {
        if (std::string(result).find("<") != std::string::npos) 
        {
            lib_plt_fun_str_start = std::string(result).find("<");
            lib_plt_fun_str_end = std::string(result).find(">");
            lib_plt_fun_name = std::string(result).substr(lib_plt_fun_str_start+1, 
                lib_plt_fun_str_end - lib_plt_fun_str_start-1);
        }     
    }

    pclose(fp);   // 关闭管道
    free(result); // 释放动态分配的内存

    if(lib_plt_fun_name != ""){
        return lib_plt_fun_name;
    }

    return "";

}

string addr_get_fun(unsigned long long addr)
{
    for (int i = 0; i < 5; i++)
    {
        if(addr >= dis_fun_info.dis_fun_list[i].fun_start_addr && 
            addr <= dis_fun_info.dis_fun_list[i].fun_end_addr )
            return dis_fun_info.dis_fun_list[i].fun_name;
    }

    return "";
}


// 通过 elf 函数地址获得函数结束地址
unsigned long long get_fun_end(pid_t pid, unsigned long long fun_addr)
{
    char buf[0x1000];
    union u 
    {
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
            // 函数结束的标志的指令码
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

// 通过 glibc 函数地址获得函数结束地址
unsigned long long get_glibc_fun_end(unsigned long long glibc_fun_addr)
{
    unsigned long long glibc_fun_addr_offset;
    unsigned long long glibc_fun_end_addr = 0;
    std::string command;
    bool is_libc, break_flag = false;

    if (glibc_fun_addr < ld_code_end && glibc_fun_addr > ld_code_start) {
        is_libc = false;
        glibc_fun_addr_offset = glibc_fun_addr - ld_base;
        command = std::string("objdump -d -j .text 2e105c0bb3ee8e8f5b917f8af764373d206659.debug | grep ");
    }
    else {
        is_libc = true;
        glibc_fun_addr_offset = glibc_fun_addr - libc_base;
        command = std::string("objdump -d -j .text 704d25fbbb72fa95d517b883131828c0883fe9.debug | grep ");
    }

    std::stringstream ss;
    FILE* fp;
    while (!break_flag)
    {
        ss.clear();
        ss.str("");
        glibc_fun_addr_offset += 0x8;
        std::string exe_command = command;
        // 使stringstream 将十六进制数转换为字符串
        
        ss << std::hex << glibc_fun_addr_offset; // 使用十六进制输出
        std::string addr_hex_str = ss.str();
        // 去掉前缀"0x"
        if (addr_hex_str.size() >= 2 && addr_hex_str.substr(0, 2) == "0x") {
            addr_hex_str = addr_hex_str.substr(2);
        }

        addr_hex_str = "0" + addr_hex_str;
        exe_command += addr_hex_str;
        fp = popen(exe_command.c_str(), "r");
        if (!fp)
        {
            printf("\033[31m\033[1m[-] Popen failed!\033[0m\n");
            break;
        }

        char* result = nullptr;
        size_t len = 0;
        ssize_t read;
        while ((read = getline(&result, &len, fp)) != -1) 
        {
            if (std::string(result).find("<") != std::string::npos) 
            {
                glibc_fun_end_addr = strtoul(result, nullptr, 16) - 1;
                break_flag = true;
                break;
            }   
        }
        pclose(fp);   // 关闭管道
        free(result); // 释放动态分配的内存
    }

    if (is_libc)
        return glibc_fun_end_addr + libc_base;
    else
        return glibc_fun_end_addr + ld_base;
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

// 根据地址找所在 glibc 函数偏移
int addr_get_glibc_fun_offset(unsigned long long addr)
{

    for (int i = 0; i < 5; i++)
    {
        if (addr >= dis_fun_info.dis_fun_list[i].fun_start_addr && 
            addr <= dis_fun_info.dis_fun_list[i].fun_end_addr)
            return addr - dis_fun_info.dis_fun_list[i].fun_start_addr;

    }

    return -1;
}

// 根据地址找所在 glibc plt 函数偏移
// int addr_get_glibc_plt_fun_offset(unsigned long long addr)
// {
//     if (addr >= glibc_fun_start && addr <= glibc_fun_end)
//         return addr - glibc_fun_start;

//     return -1;
// }


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

// 建立 elf plt 函数名和结束地址的映射
void map_plt_fun_end(pid_t pid)
{
    for (auto it : elf_plt_fun)
        elf_plt_fun_end[it.first] = get_fun_end(pid, it.second + elf_base);
}

void clear_dis_fun_list()
{
    for (int i = 0; i < 5; i++)
    {
        dis_fun_info.dis_fun_list[i].fun_start_addr = 0;
        dis_fun_info.dis_fun_list[i].fun_end_addr = 0;
        dis_fun_info.dis_fun_list[i].fun_name = "";
    }
    dis_fun_info.dis_fun_num = 0;
}

void set_dis_fun_list(unsigned long long fun_addr)
{
    for (int i = 0; i < 5; i++) 
    {
        // 地址在列表某个函数范围内就直接退出
        if (fun_addr >= dis_fun_info.dis_fun_list[i].fun_start_addr && 
            fun_addr <= dis_fun_info.dis_fun_list[i].fun_end_addr )
            break;

        if ( dis_fun_info.dis_fun_list[i].fun_start_addr == 0 ) 
        {
            // glibc
            if (fun_addr > 0x7f0000000000)
            {
                dis_fun_info.dis_fun_list[i].fun_start_addr = fun_addr;
                dis_fun_info.dis_fun_list[i].fun_end_addr = get_glibc_fun_end(fun_addr);
                dis_fun_info.dis_fun_list[i].fun_name = addr_get_glibc_fun(fun_addr);
                dis_fun_info.dis_fun_num++;
                break;

            }

            // elf
            else
            {
                string fun_name;
                fun_name = addr_get_elf_fun(fun_addr);
                if (fun_name != "") {
                    dis_fun_info.dis_fun_list[i].fun_start_addr = elf_fun_start[fun_name];
                    dis_fun_info.dis_fun_list[i].fun_end_addr = elf_fun_end[fun_name];
                    dis_fun_info.dis_fun_list[i].fun_name = fun_name;
                    dis_fun_info.dis_fun_num++;
                    break;
                }
                else {
                    fun_name = addr_get_elf_plt_fun(fun_addr);
                    if (fun_name != "") {
                        dis_fun_info.dis_fun_list[i].fun_start_addr = elf_plt_fun[fun_name] + elf_base;
                        dis_fun_info.dis_fun_list[i].fun_end_addr = elf_plt_fun_end[fun_name];
                        fun_name += "@plt";
                        dis_fun_info.dis_fun_list[i].fun_name = fun_name;
                        dis_fun_info.dis_fun_num++;
                        break;
                    }
                }

            }
        }

    }
}

// test
void show_dis_fun_list()
{
    for (int i = 0; i < 5; i++ )
    {
        if (dis_fun_info.dis_fun_list[i].fun_start_addr == 0)
            break;
        printf("idx: %d\n", i);
        printf("fun start: 0x%llx\n", dis_fun_info.dis_fun_list[i].fun_start_addr);
        printf("fun end:   0x%llx\n", dis_fun_info.dis_fun_list[i].fun_end_addr);
        printf("fun name:  %s\n", dis_fun_info.dis_fun_list[i].fun_name.c_str());
    }

    printf("num: %d\n", dis_fun_info.dis_fun_num);
}