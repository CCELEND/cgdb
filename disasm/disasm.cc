#include "disasm.h"

// execute_disasm("f30f1efa554889e5");

void execute_disasm(char* byte_codes, int num)
{

    char buf[129];
    for(int i = 0; i < num; ++i){
        sprintf(buf+i*2, "%02x", (unsigned char) byte_codes[i]);
    }

    string byte_codes_str = buf;
    string command = string("cstool -u x64 ") + "'" + byte_codes_str + "'";

    // printf("[+] Dump of assembler code:\n");
    // 执行命令并将标准输出连接到文件流中
    FILE* fp = popen(command.c_str(), "r");
    if (!fp)
    {
        printf("\033[31m\033[1m[-] Popen failed!\033[0m\n");
        return;
    }

    // char result[512];
    // // 读取文件流中的数据
    // fread(result, 1, sizeof(result), fp);
    // // 关闭文件流
    // pclose(fp);
    // printf("\033[31m%s\033[0m\n", result);
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