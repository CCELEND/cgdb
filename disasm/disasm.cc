#include "disasm.h"

void execute_disasm(char* byte_codes, int num)
{
    char buf[129];
    for(int i = 0; i < num; ++i){
        sprintf(buf+i*2, "%02x", (unsigned char) byte_codes[i]);
    }

    string byte_codes_str = buf;
    string command = string("cstool -u x64 ") + "'" + byte_codes_str + "'";

    // 执行命令并将标准输出连接到文件流中
    FILE* fp = popen(command.c_str(), "r");
    if (!fp)
    {
        printf("\033[31m\033[1m[-] Popen failed!\033[0m\n");
        return;
    }

    char* result = nullptr;
    size_t len = 0;
    ssize_t read;

    while ((read = getline(&result, &len, fp)) != -1) {
        // 处理每一行输出
        std::cout << result;
    }

    // ►  
    // 关闭管道
    pclose(fp);
    // 释放动态分配的内存
    free(result);
}

void disasm(char* byte_codes, int num)
{
    csh handle;     // 声明一个 csh 类型的句柄变量。这个句柄将在 Capstone 的每个 API 中使用
    cs_insn *insn;  // 声明 insn，一个 cs_insn 类型的指针变量，指向一个包含所有反汇编指令的内存
    size_t count;

    // 使用函数 cs_open() 初始化 Capstone。 此 API 有3个参数：硬件架构、硬件模式和指向句柄的指针
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return;
    
    // cs_disasm() 的第2和第3个参数是要反汇编的二进制代码及其长度。 第4个参数是第一条指令的地址0x0
    // 如果想反汇编所有的代码，直到没有更多的代码，或者它遇到一个 broken instruction，使用0作为第5个参数
    // 在最后第5个参数 insn 中返回动态分配的内存，可用于在接下来的步骤中提取所有反汇编指令
    // 返回值：成功反汇编的指令数
    count = cs_disasm(handle, (uint8_t*)byte_codes, num, 0x0, 0, &insn);
    if (count > 0) {
        size_t j;
        for (j = 0; j < count; j++) {
            // 汇编代码的 address 地址，mnemonic 是操作码，op_str 是操作数
            printf("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
                    insn[j].op_str);
        }
        // 释放由 cs_disasm 分配的动态内存
        cs_free(insn, count);
    } else
        printf("ERROR: Failed to disassemble given code!\n");
    // 关闭句柄
    cs_close(&handle);
}