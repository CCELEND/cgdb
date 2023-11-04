
#include "loader_elf.h"

// 建立函数名和 plt 地址的映射
void map_fun_plt(std::string fname)
{
    std::string command = std::string("objdump -d -j .plt.sec -M intel ") + fname;
    FILE* fp = popen(command.c_str(), "r");
    if (!fp)
    {
        printf("\033[31m\033[1m[-] Popen failed!\033[0m\n");
        return;
    }

    char* result = nullptr;
    size_t len = 0;
    ssize_t read;
    unsigned long long fun_plt_addr;
    int fun_str_start, fun_str_end;
    std::string fun_name;

    while ((read = getline(&result, &len, fp)) != -1) 
    {
        if (std::string(result).find("@plt") != std::string::npos) 
        {
            fun_str_start = std::string(result).find("<");
            fun_str_end = std::string(result).find("@");
            fun_name = std::string(result).substr(fun_str_start+1, fun_str_end-fun_str_start-1);
            fun_plt_addr = strtoul(result, nullptr, 16);
            elf_plt_fun[fun_name] = fun_plt_addr;
        }     
    }

    pclose(fp);   // 关闭管道
    free(result); // 释放动态分配的内存
}

// 根据函数名获得 plt 地址
unsigned long long get_plt_fun_addr(char* funame)
{
    if (elf_plt_fun.find(funame) != elf_plt_fun.end()) {
        return elf_plt_fun[funame];
    } 
    else {
        printf("\033[31m\033[1m[-] There is no such function!\033[0m\n");
        return 0;
    }

}


