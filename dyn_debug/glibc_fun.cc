
#include "dyn_fun.h"

// 根据地址找所在 glibc 函数名 2.36
// 704d25fbbb72fa95d517b883131828c0883fe9.debug libc
// 2e105c0bb3ee8e8f5b917f8af764373d206659.debug ld
string addr_get_glibc_fun(u64 glibc_fun_addr, u64* glibc_fun_start)
{
    if (glibc_fun_addr % 0x8 != 0)
        glibc_fun_addr = glibc_fun_addr &~ 0xf;

    u64 glibc_fun_addr_offset;
    string command;
    string glibc_fun_name = "";
    bool is_libc, break_flag = false;

    if (glibc_fun_addr < ld_code_end && glibc_fun_addr > ld_code_start) 
    {
        is_libc = false;
        glibc_fun_addr_offset = glibc_fun_addr - ld_base;
        command = string("objdump -d -j .text 2e105c0bb3ee8e8f5b917f8af764373d206659.debug | grep ");
    }
    else 
    {
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
        // 释放动态分配的内存
        if (result)
            free(result);
    }

    if (is_libc){
        *glibc_fun_start = glibc_fun_addr_offset + libc_base + 0x8;
        // glibc_fun_name = "libc." + glibc_fun_name;
    }
    else{
        *glibc_fun_start = glibc_fun_addr_offset + ld_base + 0x8;
        // glibc_fun_name = "ld." + glibc_fun_name;
    }

    return glibc_fun_name;

}

// 通过 glibc 函数名获得函数开始地址
u64 get_glibc_fun_addr(char* fun_name)
{
    bool finded = false, is_libc = false;
    FILE* fp;
    u64 glibc_fun_addr;
    string command, exe_command;
    char* result;

    // printf("%s\n", fun_name);

    for (int i = 0; i < 2 && !finded; i++)
    {
        if (i == 1){
            command = string("objdump -d -j .text 2e105c0bb3ee8e8f5b917f8af764373d206659.debug | grep \\<");
        }
        else{
            is_libc = true;
            command = string("objdump -d -j .text 704d25fbbb72fa95d517b883131828c0883fe9.debug | grep \\<");
        }

        exe_command = command + string(fun_name) + "\\>";
        fp = popen(exe_command.c_str(), "r");
        if (!fp)
        {
            printf("\033[31m\033[1m[-] Popen failed!\033[0m\n");
            break;
        }

        // char* result = nullptr;
        // result = nullptr;
        result = new char[100];

        size_t len = 0;
        ssize_t read;
        while ((read = getline(&result, &len, fp)) != -1) 
        {
            if (string(result).find("<") != string::npos) 
            {
                glibc_fun_addr = strtoul(result, nullptr, 16);
                finded = true;
                break;
            }     
        }

        pclose(fp);   // 关闭管道
        if (result){
            // free(result);
            delete[] result;
        }

    }

    if (is_libc)
        glibc_fun_addr = glibc_fun_addr + libc_base;
    else
        glibc_fun_addr = glibc_fun_addr + ld_base;

    if (!finded)
        return 0;

    return glibc_fun_addr;
}

// 通过 glibc 函数地址获得函数结束地址
u64 get_glibc_fun_end(u64 glibc_fun_addr, string fun_name)
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
    char* result;
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

        // char* result = nullptr;
        result = new char[100];
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
        if (result)
            // free(result);
            delete[] result;
    }

    if (is_libc)
        return glibc_fun_end_addr + libc_base;
    else
        return glibc_fun_end_addr + ld_base;
}


// 通过 glibc 地址获得函数开始地址, 函数结束地址
string addr_get_glibc_fun_start_and_end(u64 glibc_addr, u64* glibc_fun_start, u64* glibc_fun_end)
{
    u64 glibc_fun_addr_offset, glibc_fun_start_addr, glibc_fun_end_addr;
    string command = "", glibc_fun_name = "";
    s32 sub_num;
    bool is_libc, break_flag = false;

    if (glibc_addr > ld_code_start && glibc_addr < ld_code_end) 
    {
        is_libc = false;
        glibc_fun_addr_offset = glibc_addr - ld_base;
        command = string("objdump -d -j .text 2e105c0bb3ee8e8f5b917f8af764373d206659.debug | grep ");
    }
    else 
    {
        is_libc = true;
        glibc_fun_addr_offset = glibc_addr - libc_base;
        command = string("objdump -d -j .text 704d25fbbb72fa95d517b883131828c0883fe9.debug | grep ");
    }

    // if (glibc_fun_addr_offset % 8 == 0)
    //     sub_num = 0x8;
    // else
        sub_num = 0x1;

    stringstream ss;
    FILE* fp;
    char* result;
    
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
            *glibc_fun_start = 0;
            *glibc_fun_end = 0;
            return "";
        }

        // char* result = nullptr;

        result = new char[100];
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

        pclose(fp);   // 关闭管道
        // 释放动态分配的内存
        if (result) {
            delete[] result;
        }
            // free(result);

        glibc_fun_addr_offset -= sub_num;

        // printf("0x%llx\n", glibc_fun_addr_offset);
    }

    if (is_libc)
    {
        *glibc_fun_start = glibc_fun_start_addr + libc_base;
        *glibc_fun_end = glibc_fun_end_addr + libc_base;
    }
    else
    {
        *glibc_fun_start = glibc_fun_start_addr + ld_base;
        *glibc_fun_end = glibc_fun_end_addr + ld_base;
    }
    return glibc_fun_name;

}