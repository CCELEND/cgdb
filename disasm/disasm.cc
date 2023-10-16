
#include "disasm.h"

void execute_disasm(char* byte_codes)
{
    char buf[17];
    for(int i = 0; i < 8; ++i){
        sprintf(buf+i*2, "%02x", (unsigned char) byte_codes[i]);
    }
    printf("[+] Dump of assembler code:\n");

    string byte_codes_str = buf;
    string command = string("cstool -u x64 ") + "'" + byte_codes_str + "'";

    // 执行命令并将标准输出连接到文件流中
    FILE* fp = popen(command.c_str(), "r");
    if (!fp)
    {
        printf("\033[31m\033[1m[-] Popen failed!\033[0m\n");
        return;
    }

    char result[256];
    // 读取文件流中的数据
    fread(result, 1, sizeof(result), fp);

    pclose(fp); // 关闭文件流
    printf("%s", result);
}

// int main()
// {
//     execute_disasm("f30f1efa554889e5");
//     return 0;
// }

