#include "disasm.h"

// 输出指令行数 line, num 指令长度
void disasm(char* byte_codes, 
    unsigned long long addr, int num, int line)
{
    csh handle;
    cs_insn *insn;
    size_t count;
    unsigned long long plt_addr;
    string fun_name;
    int offset;

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

            fun_name = addr_get_elf_fun(insn[j].address);
            offset = addr_get_elf_fun_offset(insn[j].address);

            // address 汇编代码的地址, code 指令码, mnemonic 操作码, op_str 操作数
            if (!j){

                printf("\033[32m\033[1m ► 0x%lx\033[0m ", insn[j].address);

                if(fun_name != "") {
                    printf("\033[32m\033[1m<%s+%d>\t", fun_name.c_str(), offset);
                }

                printf( "\033[34m\033[1m%-20s\033[0m"
                        "\033[33m\033[1m%-16s\033[0m"
                        "\033[36m\033[1m%s\033[0m\n", 
                        code, insn[j].mnemonic,
                        insn[j].op_str);

                if (strcmp(insn[j].mnemonic, "ret") == 0 && fun_name == "main"){
                    break;
                }
            }
            else{

                printf("   0x%lx ", insn[j].address);

                if(fun_name != "") {
                    printf("<%s+%d>\t", fun_name.c_str(), offset);
                }

                printf("\033[34m%-20s\033[0m", code);

                if ( strcmp(insn[j].mnemonic, "call") == 0 || 
                     strcmp(insn[j].mnemonic, "ret")  == 0 || 
                     strcmp(insn[j].mnemonic, "jmp")  == 0 )
                {
                    printf( "\033[33m%-16s\033[0m"
                            "\033[36m%s\033[0m ",
                        insn[j].mnemonic, insn[j].op_str);

                    if (strcmp(insn[j].mnemonic, "call") == 0 || 
                        strcmp(insn[j].mnemonic, "jmp")  == 0 )
                    {
                        plt_addr = strtoul(insn[j].op_str, nullptr, 16);
                        if (plt_addr < 0x7f0000000000)
                            cout << "<\033[31m" << addr_get_elf_plt_fun(plt_addr) << "@plt\033[0m>"; 
                    }

                    if (strcmp(insn[j].mnemonic, "ret") == 0 && fun_name == "main") {
                        printf("\n");
                        break;
                    }
 
                    printf("\n\n");

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

// 输出跳转指令流操作数的函数符号和偏移
void flow_change_op(char* ops)
{
    unsigned long long flow_change_addr;
    string flow_change_fun_name = "";
    int offset;
    flow_change_addr = strtoul(ops, nullptr, 16);
    if (!flow_change_addr)
        return;

    set_fun_list(&flow_change_fun_info, flow_change_addr);
    flow_change_fun_name = addr_get_fun(&flow_change_fun_info, flow_change_addr);
    offset = addr_get_fun_offset(&flow_change_fun_info, flow_change_addr);
    if (!offset)
        cout << "<\033[31m" << flow_change_fun_name << "\033[0m>";
    else
        printf("<\033[31m%s+%d\033[0m>", flow_change_fun_name.c_str(), offset);
}

void show_disasm(pid_t pid, unsigned long long rip_val)
{
    csh handle;
    cs_insn *insn;
    size_t count;
    int fun_offset;

    struct winsize size;
    ioctl(STDIN_FILENO, TIOCGWINSZ, &size);
    int str_count = (size.ws_col-10)/2;      // 要重复输出的次数
    show_str(str_count);
    printf("[ DISASM ]");
    show_str(str_count);
    printf("\033[0m\n");

    char addr_instruct[176];
    // 反汇编开始地址与 rip 同步
    if (disasm_addr_synchronous || next_disasm_addr && next_disasm_addr != rip_val) {
        disasm_addr = rip_val;
    }

    get_addr_data(pid, disasm_addr, addr_instruct, 176);
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        printf("\033[31m\033[1m[-] Failed to initialize Capstone!\033[0m\n");
        return;
    }
    count = cs_disasm(handle, (uint8_t*)addr_instruct, 176, disasm_addr, 0, &insn);
    if (count > 0) {
        size_t j;
        int num;
        int line = 0;
        num = dis_fun_info.fun_num;

        for (int i = 0; i < 11 && i < count-1; i++ )
            line++;
        // printf("%d\n", line);

        if( !(insn[0].address >= dis_fun_info.fun_list[0].fun_start_addr &&
            insn[0].address <= dis_fun_info.fun_list[0].fun_end_addr
            &&
            insn[line-1].address >= dis_fun_info.fun_list[num-1].fun_start_addr &&
            insn[line-1].address <= dis_fun_info.fun_list[num-1].fun_end_addr)
          )
        {
            // printf("---0x%lx\n", insn[line-1].address);
            clear_fun_list(&dis_fun_info); // 清空函数列表
            for(int i = 0; i < 11 && i < count-1; i++)
                set_fun_list(&dis_fun_info, insn[i].address);
        }

        for (j = 0; j < 11 && j < count-1; j++)
        {
            char code[32];
            string dis_fun_name = "";
            
            for(int i = 0; i < insn[j].size; ++i)
                sprintf(code + i*2, "%02x", (unsigned char) insn[j].bytes[i]);

            dis_fun_name = addr_get_fun(&dis_fun_info, insn[j].address);
            // 根据地址得到函数偏移
            fun_offset = addr_get_fun_offset(&dis_fun_info, insn[j].address);

            // address 汇编代码的地址, code 指令码, mnemonic 操作码, op_str 操作数
            if (insn[j].address == rip_val)
            {
                next_disasm_addr = insn[j + 1].address;

                printf("\033[32m\033[1m ► 0x%lx\033[0m ", insn[j].address);

                if(dis_fun_name != "")
                    printf("\033[32m\033[1m<%s+%04d>   ", dis_fun_name.c_str(), fun_offset);

                printf("\033[34m\033[1m%-20s\033[0m" "\033[33m\033[1m%-16s\033[0m" 
                    "\033[36m\033[1m%s\033[0m ", 
                        code, insn[j].mnemonic, insn[j].op_str);

                if (strcmp(insn[j].mnemonic, "call") == 0 || 
                    strcmp(insn[j].mnemonic, "jmp" ) == 0 ||
                    strcmp(insn[j].mnemonic, "ret" ) == 0 ||
                    strcmp(insn[j].mnemonic, "je"  ) == 0 || 
                    strcmp(insn[j].mnemonic, "ja" )  == 0 )
                {
                    flow_change_op(insn[j].op_str);
                    printf("\n");
                }

                printf("\n");

            }
            else{

                printf("   0x%lx ", insn[j].address);

                if(dis_fun_name != "")
                    printf("<%s+%04d>   ", dis_fun_name.c_str(), fun_offset);

                printf("\033[34m%-20s\033[0m", code);

                if ( strcmp(insn[j].mnemonic, "call") == 0 || 
                     strcmp(insn[j].mnemonic, "ret" ) == 0 || 
                     strcmp(insn[j].mnemonic, "jmp" ) == 0 || 
                     strcmp(insn[j].mnemonic, "je"  ) == 0 || 
                     strcmp(insn[j].mnemonic, "ja" ) == 0 )
                {
                    printf( "\033[33m%-16s\033[0m"
                            "\033[36m%s\033[0m ",
                        insn[j].mnemonic, insn[j].op_str);

                    if (strcmp(insn[j].mnemonic, "call") == 0 || 
                        strcmp(insn[j].mnemonic, "jmp" ) == 0 || 
                        strcmp(insn[j].mnemonic, "je"  ) == 0 || 
                        strcmp(insn[j].mnemonic, "ja" ) == 0 )
                    {

                        flow_change_op(insn[j].op_str);
                    }

                    printf("\n\n");
                }
                else {
                    printf("\033[33m\033[2m%-16s\033[0m" "\033[36m\033[2m%s\033[0m\n",
                        insn[j].mnemonic, insn[j].op_str);
                }
            }

            if (insn[5].address == rip_val)
                disasm_addr = insn[1].address;
        }
        disasm_addr_synchronous = false;
        cs_free(insn, count);
    }
    else printf("\033[31m\033[1m[-] Failed to disassemble given code!\n");

    cs_close(&handle);
}

//输出 line 行反汇编, 只输出 mnemonic 操作码, op_str 操作数
void disasm_mne_op(char* byte_codes, 
    unsigned long long addr, int num, int line)
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
            printf(
                "\033[33m\033[1m%s\033[0m "
                "\033[36m\033[1m%s\033[0m ", 
                insn[j].mnemonic, insn[j].op_str
            );
            if ( strcmp(insn[j].mnemonic, "call") == 0 ||  
                 strcmp(insn[j].mnemonic, "jmp" ) == 0 )
            {
                flow_change_op(insn[j].op_str);
            }
        }
        cs_free(insn, count);
    }
    else printf("\033[31m\033[1m[-] Failed to disassemble given code!\n");

    cs_close(&handle);
}

// 获得下一条指令地址
unsigned long long get_next_instruct_addr(char* byte_codes, 
    unsigned long long addr, int num)
{
    csh handle;
    cs_insn *insn;
    size_t count;
    unsigned long long next_addr;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        printf("\033[31m\033[1m[-] Failed to initialize Capstone!\033[0m\n");
        return 0;
    }

    count = cs_disasm(handle, (uint8_t*)byte_codes, num, addr, 0, &insn);
    if (count > 0) {
        next_addr = insn[1].address;
        cs_free(insn, count);        
    }
    else {
        printf("\033[31m\033[1m[-] Failed to disassemble given code!\n");
        cs_close(&handle);
        return 0;
    }

    cs_close(&handle);

    return next_addr;
}

// if (flow_change_addr > 0x7f0000000000) {
//     flow_change_fun_name = addr_get_glibc_plt_fun(flow_change_addr);
//     if (flow_change_fun_name != "")
//         cout << "<\033[31m" << flow_change_fun_name << "\033[0m>";
//     else {
//         flow_change_fun_name = addr_get_glibc_fun(flow_change_addr);
//         if (flow_change_fun_name != "")
//             cout << "<\033[31m" << flow_change_fun_name << "\033[0m>";
//         else
//             cout << "";
//     }
// }
// else
// {
//     flow_change_fun_name = addr_get_elf_fun(flow_change_addr);
//     if (flow_change_fun_name != "")
//         cout << "<\033[31m" << flow_change_fun_name << "\033[0m>";
//     else {
//         flow_change_fun_name = addr_get_elf_plt_fun(flow_change_addr);
//         if (flow_change_fun_name != "")
//             cout << "<\033[31m" << flow_change_fun_name << "@plt\033[0m>";
//         else
//             cout << "";
//     }
// }