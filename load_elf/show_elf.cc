#include "loader_elf.h"

void 
show_elf_got(std::string fname)
{
    std::string command = std::string("objdump -R ") + fname;
    // 执行命令并将标准输出连接到文件流中
    FILE* fp = popen(command.c_str(), "r");
    if (!fp)
    {
        printf("\033[31m\033[1m[-] Popen failed!\033[0m\n");
        return;
    }

    char *result = nullptr;
    size_t len = 0;
    ssize_t read;

    while ((read = getline(&result, &len, fp)) != -1) {
        // 处理每一行输出
        std::cout << result;
    }

    pclose(fp);   // 关闭管道
    free(result); // 释放动态分配的内存
}

// void 
// show_elf_plt(std::string fname)
// {
//     std::string command = std::string("objdump -R ") + fname;
//     // 执行命令并将标准输出连接到文件流中
//     FILE* fp = popen(command.c_str(), "r");
//     if (!fp)
//     {
//         printf("\033[31m\033[1m[-] Popen failed!\033[0m\n");
//         return;
//     }

//     char *result = nullptr;
//     size_t len = 0;
//     ssize_t read;

//     while ((read = getline(&result, &len, fp)) != -1) {
//         // 处理每一行输出
//         std::cout << result;
//     }

//     pclose(fp);   // 关闭管道
//     free(result); // 释放动态分配的内存
// }
