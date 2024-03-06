
#include "dyn_fun.h"


// 根据地址找所在 elf init, fini 段符号名
string 
addr_get_elf_init(u64 elf_init_addr) 
{
    u64 elf_init_addr_offset;
    string command;

    elf_init_addr_offset = elf_init_addr - elf_base;
    command = string("objdump -d -j .init_array ") + fname + string(" | grep ");

    // stringstream 将十六进制数转换为字符串
    stringstream ss;
    ss << hex << elf_init_addr_offset; // 使用十六进制输出
    string addr_hex_str = ss.str();
    // 去掉前缀"0x"
    if (addr_hex_str.size() >= 2 && addr_hex_str.substr(0, 2) == "0x") 
    {
        addr_hex_str = addr_hex_str.substr(2);
        addr_hex_str = "0" + addr_hex_str;
    }

    command += addr_hex_str;
    FILE* fp = popen(command.c_str(), "r");
    if (!fp)
    {
        err_info("Popen failed!");
        return "";
    }

    pchar result = new char[100];
    memset(result, 0, 100);
    size_t len = 0;
    ssize_t read;
    int elf_init_str_start, elf_init_str_end;
    string elf_init_name = "";

    while ((read = getline(&result, &len, fp)) != -1) 
    {
        if (string(result).find("<") != string::npos) 
        {
            elf_init_str_start = string(result).find("<");
            elf_init_str_end = string(result).find(">");
            
            elf_init_name = string(result).substr(elf_init_str_start+1, 
                elf_init_str_end - elf_init_str_start-1);
        }     
    }

    pclose(fp);   // 关闭管道
    if (result) 
    {
        delete[] result;
    }

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
    string command;

    elf_fini_addr_offset = elf_fini_addr - elf_base;
    command = string("objdump -d -j .fini_array ") + fname + string(" | grep ");

    // stringstream 将十六进制数转换为字符串
    stringstream ss;
    ss << hex << elf_fini_addr_offset; // 使用十六进制输出
    string addr_hex_str = ss.str();
    // 去掉前缀"0x"
    if (addr_hex_str.size() >= 2 && addr_hex_str.substr(0, 2) == "0x") 
    {
        addr_hex_str = addr_hex_str.substr(2);
        addr_hex_str = "0" + addr_hex_str;
    }

    command += addr_hex_str;
    FILE* fp = popen(command.c_str(), "r");
    if (!fp)
    {
        err_info("Popen failed!");
        return "";
    }

    pchar result = new char[100];
    memset(result, 0, 100);
    size_t len = 0;
    ssize_t read;

    int elf_fini_str_start, elf_fini_str_end;
    string elf_fini_name = "";

    while ((read = getline(&result, &len, fp)) != -1) 
    {
        if (string(result).find("<") != string::npos) 
        {
            elf_fini_str_start = string(result).find("<");
            elf_fini_str_end = string(result).find(">");

            elf_fini_name = string(result).substr(elf_fini_str_start+1, 
                    elf_fini_str_end - elf_fini_str_start-1);
        }     
    }

    pclose(fp);   // 关闭管道
    if (result) 
    {
        delete[] result;
    }

    if(elf_fini_name != "")
    {
        return elf_fini_name;
    }

    return "";

}

