
#include "dyn_fun.h"

// 根据地址找所在 glibc data 段符号名
string addr_get_glibc_data(u64 glibc_data_addr) 
{
    u64 glibc_data_addr_offset;
    string command;

    if (glibc_data_addr > ld_data_start && glibc_data_addr < ld_data_end) 
    {
        glibc_data_addr_offset = glibc_data_addr - ld_base;
        // command = string("objdump -d -j .data ld-linux-x86-64.so.2 | grep ");
        command = string("objdump -d -j .data 2e105c0bb3ee8e8f5b917f8af764373d206659.debug | grep ");
    }
    else 
    {
        glibc_data_addr_offset = glibc_data_addr - libc_base;
        // command = string("objdump -d -j .data libc.so.6 | grep ");
        command = string("objdump -d -j .data 704d25fbbb72fa95d517b883131828c0883fe9.debug | grep ");
        
    }

    // stringstream 将十六进制数转换为字符串
    stringstream ss;
    ss << hex << glibc_data_addr_offset; // 使用十六进制输出
    string addr_hex_str = ss.str();
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
    s32 lib_data_str_start, lib_data_str_end;
    string lib_data_name = "";

    while ((read = getline(&result, &len, fp)) != -1) 
    {
        if (string(result).find("<") != string::npos) 
        {
            lib_data_str_start = string(result).find("<");
            // lib_data_str_end = string(result).find("@");
            lib_data_str_end = string(result).find(">");
            lib_data_name = string(result).substr(lib_data_str_start+1, 
                lib_data_str_end - lib_data_str_start-1);
        }     
    }

    pclose(fp);   // 关闭管道
    free(result); // 释放动态分配的内存

    if(lib_data_name != "")
    {
        return lib_data_name;
    }

    return "";

}


