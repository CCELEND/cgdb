
#include "dyn_fun.h"

// 根据地址找所在 glibc plt 函数名
string 
addr_get_glibc_plt_fun(u64 glibc_plt_fun_addr) 
{
    u64 glibc_plt_fun_addr_offset;
    string exe_cmd, command, command2;
    string lib_plt_fun_name = "";
    bool finded = false;

    if (glibc_plt_fun_addr < ld_code_end && 
        glibc_plt_fun_addr > ld_code_start) 
    {
        glibc_plt_fun_addr_offset = glibc_plt_fun_addr - ld_base;
        command = string(
            "objdump -d -j .plt.sec ld-linux-x86-64.so.2 | fgrep ");
        command2 = command;
    }
    else 
    {
        glibc_plt_fun_addr_offset = glibc_plt_fun_addr - libc_base;
        command = string(
            "objdump -d -j .plt.sec libc.so.6 | fgrep ");
        command2 = string(
            "objdump -d -j .plt.got libc.so.6 | fgrep ");
    }

    // stringstream 将十六进制数转换为字符串
    stringstream ss;
    ss << hex << glibc_plt_fun_addr_offset; // 使用十六进制输出
    string addr_hex_str = ss.str();

    // 去掉前缀"0x"
    if (addr_hex_str.size() >= 2 && 
        addr_hex_str.substr(0, 2) == "0x") 
    {
        addr_hex_str = addr_hex_str.substr(2);
        addr_hex_str = "0" + addr_hex_str;
    }

    command += addr_hex_str;
    command2 += addr_hex_str;

    char* result = new char[100];

    for (int i = 0; i < 2 && !finded; i++)
    {
        if (i == 0) 
            exe_cmd = command;
        else 
            exe_cmd = command2;

        FILE* fp = popen(exe_cmd.c_str(), "r");
        if (!fp)
        {
            err_info("Popen failed!");
            break;
        }

        memset(result, 0, 100);

        size_t len = 0;
        ssize_t read;
        s32 lib_plt_fun_str_start, lib_plt_fun_str_end;

        while ((read = getline(&result, &len, fp)) != -1) 
        {
            if (string(result).find("<") != string::npos) 
            {
                lib_plt_fun_str_start = string(result).find("<");
                lib_plt_fun_str_end = string(result).find(">");

                lib_plt_fun_name = string(result).substr(lib_plt_fun_str_start+1, 
                    lib_plt_fun_str_end - lib_plt_fun_str_start-1);
                finded = true;
            }     
        }

        pclose(fp);
    }

    if (result) 
    {
        delete[] result;
    }

    if(lib_plt_fun_name != "")
    {
        return lib_plt_fun_name;
    }

    return "";

}

// 通过 glibc plt 函数名获得函数开始地址
u64 
get_glibc_plt_fun_addr(const char* fun_name)
{
    bool finded = false, is_libc = false;
    FILE* fp;
    u64 glibc_plt_fun_addr;
    string command, exe_command;

    char* result = new char[100];

    for (int i = 0; i < 2 && !finded; i++)
    {
        if (i == 0)
        {
            // command = string(
            //     "objdump -d -j .plt.sec ld-linux-x86-64.so.2 | fgrep ");
            command = string(
                "objdump -d -j .plt.sec ld-linux-x86-64.so.2 | grep \\<");
        }
        else
        {
            is_libc = true;
            // command = string(
            //     "objdump -d -j .plt.sec libc.so.6 | fgrep ");
            command = string(
                "objdump -d -j .plt.sec libc.so.6 | grep \\<");
        }

        exe_command = command + string(fun_name);
        fp = popen(exe_command.c_str(), "r");
        if (!fp)
        {
            printf("\033[31m\033[1m[-] Popen failed!\033[0m\n");
            break;
        }

        memset(result, 0, 100);
        size_t len = 0;
        ssize_t read;

        while ((read = getline(&result, &len, fp)) != -1) 
        {
            if (string(result).find("<") != string::npos) 
            {
                glibc_plt_fun_addr = strtoul(result, nullptr, 16);
                finded = true;
                break;
            }     
        }

        pclose(fp);   // 关闭管道
    }

    if (result) 
    {
        delete[] result;
    }

    if (is_libc)
    {
        glibc_plt_fun_addr = glibc_plt_fun_addr + libc_base;
    }
    else
    {
        glibc_plt_fun_addr = glibc_plt_fun_addr + ld_base;
    }

    if (!finded) 
    {
        return 0;
    }

    return glibc_plt_fun_addr;
}