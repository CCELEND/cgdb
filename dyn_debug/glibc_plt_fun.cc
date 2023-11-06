
#include "dyn_fun.h"


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

    if(lib_plt_fun_name != "")
    {
        return lib_plt_fun_name;
    }

    return "";

}


