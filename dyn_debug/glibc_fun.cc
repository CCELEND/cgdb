
#include "dyn_fun.h"

// 根据地址找所在 glibc 函数名 2.36
// 704d25fbbb72fa95d517b883131828c0883fe9.debug libc
// 2e105c0bb3ee8e8f5b917f8af764373d206659.debug ld
string addr_get_glibc_fun(u64 glibc_fun_addr, 
    u64* glibc_fun_start)
{
    if (glibc_fun_addr % 0x8 != 0)
        glibc_fun_addr = glibc_fun_addr &~ 0xf;

    u64 glibc_fun_addr_offset;
    string command;
    string glibc_fun_name = "";
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

    stringstream ss;
    FILE* fp;
    while (!break_flag)
    {
        ss.clear();
        ss.str("");

        string exe_command = command;
        // 使stringstream 将十六进制数转换为字符串
        
        ss << hex << glibc_fun_addr_offset; // 使用十六进制输出
        string addr_hex_str = ss.str();
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
        s32 lib_fun_str_start, lib_fun_str_end;
        
        while ((read = getline(&result, &len, fp)) != -1) 
        {
            if (string(result).find("<") != string::npos) 
            {
                lib_fun_str_start = string(result).find("<");
                lib_fun_str_end = string(result).find(">");
                glibc_fun_name = string(result).substr(lib_fun_str_start+1, 
                    lib_fun_str_end-lib_fun_str_start-1);
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

    if (is_libc)
        *glibc_fun_start = glibc_fun_addr_offset + libc_base + 0x8;
    else
        *glibc_fun_start = glibc_fun_addr_offset + ld_base + 0x8;

    return glibc_fun_name;


}

// 通过 glibc 函数地址获得函数结束地址
u64 get_glibc_fun_end(u64 glibc_fun_addr, 
    string fun_name)
{
    if (glibc_fun_addr % 0x8 != 0)
        glibc_fun_addr = glibc_fun_addr &~ 0xf;

    u64 glibc_fun_addr_offset;
    u64 glibc_fun_end_addr = 0;
    string command;
    string glibc_fun_name = "";
    bool is_libc, break_flag = false;

    if (glibc_fun_addr < ld_code_end && glibc_fun_addr > ld_code_start) {
        is_libc = false;
        glibc_fun_addr_offset = glibc_fun_addr - ld_base;
        command = string("objdump -d -j .text 2e105c0bb3ee8e8f5b917f8af764373d206659.debug | grep ");
    }
    else {
        is_libc = true;
        glibc_fun_addr_offset = glibc_fun_addr - libc_base;
        command = string("objdump -d -j .text 704d25fbbb72fa95d517b883131828c0883fe9.debug | grep ");
    }

    stringstream ss;
    FILE* fp;
    while (!break_flag)
    {
        ss.clear();
        ss.str("");
        glibc_fun_addr_offset += 0x8;
        string exe_command = command;
        // 使stringstream 将十六进制数转换为字符串
        
        ss << hex << glibc_fun_addr_offset; // 使用十六进制输出
        string addr_hex_str = ss.str();
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
        s32 lib_fun_str_start, lib_fun_str_end;
        while ((read = getline(&result, &len, fp)) != -1) 
        {
            if (string(result).find("<") != string::npos) 
            {

                lib_fun_str_start = string(result).find("<");
                lib_fun_str_end = string(result).find(">");
                glibc_fun_name = string(result).substr(lib_fun_str_start+1, 
                    lib_fun_str_end-lib_fun_str_start-1);

                if (glibc_fun_name != fun_name)
                {
                    glibc_fun_end_addr = strtoul(result, nullptr, 16) - 1;
                    break_flag = true;
                    break;                  
                }


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

