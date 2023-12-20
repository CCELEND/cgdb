
#include "dyn_fun.h"

// 通过 glibc 函数名获得函数开始地址
u64 
get_glibc_fun_addr(const char* fun_name)
{
    bool is_libc = false;
    u64 glibc_fun_addr = 0;
    string glibc_fun_name, command, exe_command;
    char* result = new char[100];

    if (string(fun_name).find("libc.") != string::npos)
    {
        is_libc = true;
        command = string(
            "objdump -d -j .text 704d25fbbb72fa95d517b883131828c0883fe9.debug | grep \\<");
        glibc_fun_name = string(fun_name).substr(5);
    }
    else
    {
        command = string(
            "objdump -d -j .text 2e105c0bb3ee8e8f5b917f8af764373d206659.debug | grep \\<");
        glibc_fun_name = string(fun_name).substr(3);
    }

    FILE* fp;
    exe_command = command + glibc_fun_name + "\\>";
    fp = popen(exe_command.c_str(), "r");
    if (!fp)
    {
        printf("\033[31m\033[1m[-] Popen failed!\033[0m\n");
        if (result) delete[] result;
        return 0;
    }

    memset(result, 0, 100);

    size_t len = 0;
    ssize_t read;
    while ((read = getline(&result, &len, fp)) != -1) 
    {
        if (string(result).find("<") != string::npos) 
        {
            glibc_fun_addr = strtoul(result, nullptr, 16);
            break;
        }     
    }

    pclose(fp);   // 关闭管道
    if (result) 
        delete[] result;

    if (!glibc_fun_addr) 
        return 0;

    if (is_libc)
        glibc_fun_addr += libc_base;
    else
        glibc_fun_addr += ld_base;
    return glibc_fun_addr;
}


// 通过 glibc 地址获得函数名, 函数开始地址, 函数结束地址
tuple<string, u64, u64>
addr_get_glibc_fun_start_and_end(u64 glibc_addr)
{
    tuple<string, u64, u64> ret_val;

    u64 glibc_fun_addr_offset, glibc_fun_start_addr, glibc_fun_end_addr;
    string command = "", glibc_fun_name = "";
    s32 sub_num = 0x1;
    bool is_libc, break_flag = false;

    // ld
    if (glibc_addr > ld_code_start && glibc_addr < ld_code_end) 
    {
        is_libc = false;
        glibc_fun_addr_offset = glibc_addr - ld_base;
        command = string(
            "objdump -d -j .text 2e105c0bb3ee8e8f5b917f8af764373d206659.debug | grep ");
    }
    // libc
    else 
    {
        is_libc = true;
        glibc_fun_addr_offset = glibc_addr - libc_base;
        command = string(
            "objdump -d -j .text 704d25fbbb72fa95d517b883131828c0883fe9.debug | grep ");
    }

    stringstream ss;
    FILE* fp;
    char* result = new char[100];
    
    while (!break_flag)
    {
        ss.clear();
        ss.str("");

        string exe_command = command;
        // 使stringstream 将十六进制数转换为字符串
        ss << hex << glibc_fun_addr_offset; // 使用十六进制输出
        string addr_hex_str = ss.str();
        // 去掉前缀"0x"
        if (addr_hex_str.size() >= 2 && addr_hex_str.substr(0, 2) == "0x") 
            addr_hex_str = addr_hex_str.substr(2);

        addr_hex_str = "0" + addr_hex_str;
        exe_command += addr_hex_str;
        exe_command += " -A 3";

        fp = popen(exe_command.c_str(), "r");
        if (!fp)
        {
            printf("\033[31m\033[1m[-] Popen failed!\033[0m\n");
            ret_val = make_tuple("", 0, 0);
            if (result) delete[] result;
            return ret_val;
        }

        memset(result, 0, 100);
        
        size_t len = 0;
        ssize_t read;
        s32 lib_fun_str_start, lib_fun_str_end;
        
        while ((read = getline(&result, &len, fp)) != -1) 
        {
            if (string(result).find("<") != string::npos) 
            {
                if (glibc_fun_name == "")
                {
                    lib_fun_str_start = string(result).find("<");
                    lib_fun_str_end = string(result).find(">");
                    glibc_fun_name = string(result).substr(lib_fun_str_start+1, 
                        lib_fun_str_end-lib_fun_str_start-1);
                    glibc_fun_start_addr = glibc_fun_addr_offset;
                }
                else
                {
                    glibc_fun_end_addr = strtoul(result, nullptr, 16) - 1;
                    break_flag = true;
                    break;
                }
            }
        }

        pclose(fp);   
        glibc_fun_addr_offset -= sub_num;
        // printf("0x%llx\n", glibc_fun_addr_offset);
    }

    // 释放动态分配的内存
    if (result) delete[] result;

    if (is_libc)
    {
        glibc_fun_start_addr += libc_base;
        glibc_fun_end_addr += libc_base;
        ret_val = make_tuple("libc." + glibc_fun_name, 
            glibc_fun_start_addr, glibc_fun_end_addr);
    }
    else
    {
        glibc_fun_start_addr += ld_base;
        glibc_fun_end_addr += ld_base;
        ret_val = make_tuple("ld." + glibc_fun_name, 
            glibc_fun_start_addr, glibc_fun_end_addr);
    }

    return ret_val;

}