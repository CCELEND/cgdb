
#include "dyn_fun.h"


// 根据地址找所在 elf init, fini 段符号名
string 
addr_get_elf_init(u64 elf_init_addr) 
{
    u64 elf_init_addr_offset;
    std::string command;

    elf_init_addr_offset = elf_init_addr - elf_base;
    command = std::string("objdump -d -j .init_array ") + fname + std::string(" | grep ");

    // stringstream 将十六进制数转换为字符串
    std::stringstream ss;
    ss << std::hex << elf_init_addr_offset; // 使用十六进制输出
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
    int elf_init_str_start, elf_init_str_end;
    std::string elf_init_name = "";

    while ((read = getline(&result, &len, fp)) != -1) 
    {
        if (std::string(result).find("<") != std::string::npos) 
        {
            elf_init_str_start = std::string(result).find("<");
            elf_init_str_end = std::string(result).find(">");
            
            elf_init_name = std::string(result).substr(elf_init_str_start+1, 
                elf_init_str_end - elf_init_str_start-1);
        }     
    }

    pclose(fp);   // 关闭管道
    free(result); // 释放动态分配的内存

    if(elf_init_name != "")
    {
        return elf_init_name;
    }

    return "";

}


string 
addr_get_elf_fini(u64 elf_fini_addr) 
{
    u64 elf_fini_addr_offset;
    std::string command;

    elf_fini_addr_offset = elf_fini_addr - elf_base;
    command = std::string("objdump -d -j .fini_array ") + fname + std::string(" | grep ");

    // stringstream 将十六进制数转换为字符串
    std::stringstream ss;
    ss << std::hex << elf_fini_addr_offset; // 使用十六进制输出
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
    int elf_fini_str_start, elf_fini_str_end;
    std::string elf_fini_name = "";

    while ((read = getline(&result, &len, fp)) != -1) 
    {
        if (std::string(result).find("<") != std::string::npos) 
        {
            elf_fini_str_start = std::string(result).find("<");
            elf_fini_str_end = std::string(result).find(">");
            elf_fini_name = std::string(result).substr(elf_fini_str_start+1, 
                elf_fini_str_end - elf_fini_str_start-1);
        }     
    }

    pclose(fp);   // 关闭管道
    free(result); // 释放动态分配的内存

    if(elf_fini_name != "")
    {
        return elf_fini_name;
    }

    return "";

}

