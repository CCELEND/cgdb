#include "disasm.h"

// void execute_disasm(char* byte_codes, int num)
// {
//     char buf[129];
//     for(int i = 0; i < num; ++i){
//         sprintf(buf+i*2, "%02x", (unsigned char) byte_codes[i]);
//     }

//     string byte_codes_str = buf;
//     string command = string("cstool -u x64 ") + "'" + byte_codes_str + "'";

//     // 执行命令并将标准输出连接到文件流中
//     FILE* fp = popen(command.c_str(), "r");
//     if (!fp) {
//         printf("\033[31m\033[1m[-] Popen failed!\033[0m\n");
//         return;
//     }

//     char* result = nullptr;
//     size_t len = 0;
//     ssize_t read;

//     while ((read = getline(&result, &len, fp)) != -1) {
//         // 处理每一行输出
//         std::cout << result;
//     }

//     // ►  
//     // 关闭管道
//     pclose(fp);
//     // 释放动态分配的内存
//     free(result);
// }



// ->11 disasm
void disasm(char* byte_codes, unsigned long long addr, int num)
{
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        printf("\033[31m\033[1m[-] Failed to initialize Capstone!\033[0m\n");
        return;
    }    

    count = cs_disasm(handle, (uint8_t*)byte_codes, num, addr, 0, &insn);
    if (count > 0) {
        size_t j;
        for (j = 0; j < count; j++) 
        {
            char code[32];
            for(int i = 0; i < insn[j].size; ++i){
                sprintf(code + i*2, "%02x", (unsigned char) insn[j].bytes[i]);
            }

            // address 汇编代码的地址, code 指令码, mnemonic 操作码, op_str 操作数
            if (!j){
                printf("\033[32m\033[1m ► 0x%lx\033[0m"
                    "\033[34m\033[1m\t%-20s\033[0m"
                    "\033[33m%-8s\033[0m"
                    "\033[36m\033[1m%s\033[0m\n", 
                    insn[j].address, code, insn[j].mnemonic,
                    insn[j].op_str);
            }
            else{
                printf("   0x%lx"
                    "\033[34m\t%-20s\033[0m"
                    "\033[33m\033[2m%-8s\033[0m"
                    "\033[36m%s\033[0m\n", 
                    insn[j].address, code, insn[j].mnemonic,
                    insn[j].op_str);
            }   
        }

        cs_free(insn, count);
    } 
    else printf("\033[31m\033[1m[-] Failed to disassemble given code!\n");

    cs_close(&handle);
}

// puts@plt