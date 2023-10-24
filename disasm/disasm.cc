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



// ->11 disasm num 指令长度
void disasm(char* byte_codes, unsigned long long addr, int num, int line)
{
    csh handle;
    cs_insn *insn;
    size_t count;
    unsigned long long plt_addr;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        printf("\033[31m\033[1m[-] Failed to initialize Capstone!\033[0m\n");
        return;
    }    

    count = cs_disasm(handle, (uint8_t*)byte_codes, num, addr, 0, &insn);
    if (count > 0) {
        size_t j;
        for (j = 0; j < line; j++) 
        {
            char code[32];
            for(int i = 0; i < insn[j].size; ++i){
                sprintf(code + i*2, "%02x", (unsigned char) insn[j].bytes[i]);
            }

            // address 汇编代码的地址, code 指令码, mnemonic 操作码, op_str 操作数
            if (!j){
                printf("\033[32m\033[1m ► 0x%lx\033[0m\t"
                    "\033[34m\033[1m%-20s\033[0m"
                    "\033[33m\033[1m%-16s\033[0m"
                    "\033[36m\033[1m%s\033[0m\n", 
                    insn[j].address, code, insn[j].mnemonic,
                    insn[j].op_str);
            }
            else{
                printf("   0x%lx\t"
                    "\033[34m%-20s\033[0m", 
                    insn[j].address, code);

                if ( strcmp(insn[j].mnemonic, "call") == 0 || 
                     strcmp(insn[j].mnemonic, "ret") == 0 || 
                     strcmp(insn[j].mnemonic, "jmp") == 0 )
                {
                    printf( "\033[33m%-16s\033[0m"
                            "\033[36m%s\033[0m ",
                        insn[j].mnemonic, insn[j].op_str);

                    if (strcmp(insn[j].mnemonic, "call") == 0 || strcmp(insn[j].mnemonic, "jmp") == 0)
                    {
                        plt_addr = strtoul(insn[j].op_str, nullptr, 16);
                        cout << "<\033[31m" << get_plt_fun(plt_addr) << "@plt\033[0m>" << endl;   
                    }
                    else
                        printf("\n");

                }
                else {
                    printf( "\033[33m\033[2m%-16s\033[0m"
                            "\033[36m\033[2m%s\033[0m\n",
                        insn[j].mnemonic, insn[j].op_str);
                }
            }   
        }
        cs_free(insn, count);
    }
    else printf("\033[31m\033[1m[-] Failed to disassemble given code!\n");

    cs_close(&handle);
}

//汇编 mnemonic 操作码, op_str 操作数
void disasm_mne_op(char* byte_codes, unsigned long long addr, int num, int line)
{
    csh handle;
    cs_insn *insn;
    size_t count;
    unsigned long long plt_addr;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        printf("\033[31m\033[1m[-] Failed to initialize Capstone!\033[0m\n");
        return;
    }    

    count = cs_disasm(handle, (uint8_t*)byte_codes, num, addr, 0, &insn);
    if (count > 0) {
        size_t j;
        for (j = 0; j < line; j++) 
        {
            // mnemonic 操作码, op_str 操作数
            printf(
                "\033[33m%s\033[0m "
                "\033[36m%s\033[0m ", 
                insn[j].mnemonic,insn[j].op_str);

            if ( strcmp(insn[j].mnemonic, "call") == 0 ||  
                 strcmp(insn[j].mnemonic, "jmp") == 0 )
            {
                plt_addr = strtoul(insn[j].op_str, nullptr, 16);
                cout << "<\033[31m" << get_plt_fun(plt_addr) << "@plt\033[0m>";
            }
        }
        cs_free(insn, count);
    }
    else printf("\033[31m\033[1m[-] Failed to disassemble given code!\n");

    cs_close(&handle);
}

// void disasm(char* byte_codes, unsigned long long addr, int num, int line)
// {
//     csh handle;
//     cs_insn *insn;
//     size_t count;
//     unsigned long long plt_addr;

//     if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
//         printf("\033[31m\033[1m[-] Failed to initialize Capstone!\033[0m\n");
//         return;
//     }    

//     count = cs_disasm(handle, (uint8_t*)byte_codes, num, addr, 0, &insn);
//     if (count > 0) {
//         size_t j;
//         for (j = 0; j < line; j++) 
//         {
//             char code[32];
//             for(int i = 0; i < insn[j].size; ++i){
//                 sprintf(code + i*2, "%02x", (unsigned char) insn[j].bytes[i]);
//             }

//             // address 汇编代码的地址, code 指令码, mnemonic 操作码, op_str 操作数
//             if (!j){
//                 printf("\033[32m\033[1m ► 0x%lx\033[0m\t"
//                     "\033[34m\033[1m%-20s\033[0m"
//                     "\033[33m\033[1m%-16s\033[0m"
//                     "\033[36m\033[1m%s\033[0m\n", 
//                     insn[j].address, code, insn[j].mnemonic,
//                     insn[j].op_str);
//             }
//             else{
//                 if ( strcmp(insn[j].mnemonic, "call") == 0 || 
//                      strcmp(insn[j].mnemonic, "ret") == 0 || 
//                      strcmp(insn[j].mnemonic, "jmp") == 0 )
//                 {
//                      // printf("   0x%lx\t"
//                      //    "\033[34m%-20s\033[0m"
//                      //    "\033[33m%-16s\033[0m"
//                      //    "\033[36m\033[2m%s\033[0m\n", 
//                      //    insn[j].address, code, insn[j].mnemonic,
//                      //    insn[j].op_str);
//                      printf("   0x%lx\t"
//                         "\033[34m%-20s\033[0m"
//                         "\033[33m%-16s\033[0m", 
//                         insn[j].address, code, insn[j].mnemonic);
//                      if (strcmp(insn[j].mnemonic, "call") == 0) {
//                         plt_addr = strtoul(insn[j].op_str, nullptr, 16);
//                         printf("\033[36m\033[2m%s\033[0m ",insn[j].op_str);
//                         cout << "<\033[31m" << get_plt_fun(plt_addr) << "@plt\033[0m>" << endl;
//                      }
//                      else
//                         printf("\033[36m\033[2m%s\033[0m\n",insn[j].op_str);

//                 }
//                 else {
//                     printf("   0x%lx\t"
//                         "\033[34m%-20s\033[0m"
//                         "\033[33m\033[2m%-16s\033[0m"
//                         "\033[36m\033[2m%s\033[0m\n", 
//                         insn[j].address, code, insn[j].mnemonic,
//                         insn[j].op_str);
//                 }
//             }   
//         }

//         cs_free(insn, count);
//     }
//     else printf("\033[31m\033[1m[-] Failed to disassemble given code!\n");

//     cs_close(&handle);
// }
