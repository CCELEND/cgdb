
#include "loader_elf.h"

// 建立函数名和 plt 地址的映射
void map_plt_fun_start()
{
    string command = string("objdump -d -j .plt.sec -M intel ") + fname;
    FILE* fp = popen(command.c_str(), "r");
    if (!fp)
    {
        printf("\033[31m\033[1m[-] Popen failed!\033[0m\n");
        return;
    }

    char* result = nullptr;
    size_t len = 0;
    ssize_t read;
    u64 plt_fun_addr;
    s32 fun_str_start, fun_str_end;
    string fun_name;

    while ((read = getline(&result, &len, fp)) != -1) 
    {
        if (string(result).find("@plt") != string::npos) 
        {
            fun_str_start = string(result).find("<");
            fun_str_end = string(result).find(">");
            fun_name = string(result).substr(fun_str_start+1, fun_str_end-fun_str_start-1);
            plt_fun_addr = strtoul(result, nullptr, 16);
            elf_plt_fun_start[fun_name] = plt_fun_addr;
        }     
    }

    pclose(fp);   // 关闭管道
    free(result); // 释放动态分配的内存
}


