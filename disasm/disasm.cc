#include "disasm.h"

// 输出指令行数 line, num 指令长度
void disasm(char* byte_codes, unsigned long long addr, int num, int line)
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

            fun_name = addr_find_fun(insn[j].address);
            offset = addr_find_fun_offset(insn[j].address);

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
                     strcmp(insn[j].mnemonic, "ret") == 0  || 
                     strcmp(insn[j].mnemonic, "jmp") == 0 )
                {
                    printf( "\033[33m%-16s\033[0m"
                            "\033[36m%s\033[0m ",
                        insn[j].mnemonic, insn[j].op_str);

                    if (strcmp(insn[j].mnemonic, "call") == 0 || 
                        strcmp(insn[j].mnemonic, "jmp") == 0)
                    {
                        plt_addr = strtoul(insn[j].op_str, nullptr, 16);
                        if (plt_addr < 0x7f0000000000)
                            cout << "<\033[31m" << get_plt_fun(plt_addr) << "@plt\033[0m>"; 
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

void disasm1(pid_t pid, unsigned long long rip_val)
{
    csh handle;
    cs_insn *insn;
    size_t count;
    // string fun_name = "";
    int fun_offset;

    char addr_instruct[176];
    // 反汇编开始地址与 rip 同步
    if (disasm_addr_synchronous || next_disasm_addr && next_disasm_addr != rip_val) {
        disasm_addr = rip_val;
        dis_fun_name = get_libc_symbol_name(rip_val);
        if (dis_fun_name != "")
            glibc_fun_start = rip_val;
        glibc_fun_end = get_fun_end_addr(pid, rip_val);
    }

    get_addr_data(pid, disasm_addr, addr_instruct, 176);

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        printf("\033[31m\033[1m[-] Failed to initialize Capstone!\033[0m\n");
        return;
    }    

    count = cs_disasm(handle, (uint8_t*)addr_instruct, 176, disasm_addr, 0, &insn);
    if (count > 0) {
        size_t j;
        for (j = 0; j < 11; j++)
        {
            char code[32];
            for(int i = 0; i < insn[j].size; ++i){
                sprintf(code + i*2, "%02x", (unsigned char) insn[j].bytes[i]);
            }
            // 根据地址得到函数名和偏移
            if (dis_fun_name == ""){
                dis_fun_name = addr_find_fun(insn[j].address);
            }

            fun_offset = addr_find_fun_offset(insn[j].address);
            if (fun_offset == -1)
                fun_offset = addr_find_glibc_fun_offset(insn[j].address);


            // address 汇编代码的地址, code 指令码, mnemonic 操作码, op_str 操作数

            if (insn[j].address == rip_val){
                next_disasm_addr = insn[j + 1].address;

                printf("\033[32m\033[1m ► 0x%lx\033[0m ", insn[j].address);

                if(dis_fun_name != "") {
                    printf("\033[32m\033[1m<%s+%d>\t", dis_fun_name.c_str(), fun_offset);
                }

                printf( "\033[34m\033[1m%-20s\033[0m"
                        "\033[33m\033[1m%-16s\033[0m"
                        "\033[36m\033[1m%s\033[0m\n", 
                        code, insn[j].mnemonic,
                        insn[j].op_str);

                if (strcmp(insn[j].mnemonic, "ret") == 0 && dis_fun_name == "main"){
                    break;
                }
            }
            else{

                printf("   0x%lx ", insn[j].address);

                if(dis_fun_name != "") {
                    printf("<%s+%d>\t", dis_fun_name.c_str(), fun_offset);
                }

                printf("\033[34m%-20s\033[0m", code);

                if ( strcmp(insn[j].mnemonic, "call") == 0 || 
                     strcmp(insn[j].mnemonic, "ret") == 0  || 
                     strcmp(insn[j].mnemonic, "jmp") == 0 )
                {
                    printf( "\033[33m%-16s\033[0m"
                            "\033[36m%s\033[0m ",
                        insn[j].mnemonic, insn[j].op_str);

                    if (strcmp(insn[j].mnemonic, "call") == 0 || 
                        strcmp(insn[j].mnemonic, "jmp") == 0)
                    {
                        unsigned long long flow_change_addr;
                        string flow_change_fun_name;
                        flow_change_addr = strtoul(insn[j].op_str, nullptr, 16);

                        flow_change_fun_name = addr_find_fun(flow_change_addr);
                        if (flow_change_fun_name != "")
                            cout << "<\033[31m" << flow_change_fun_name << "\033[0m>";
                        else {
                            flow_change_fun_name = get_plt_fun(flow_change_addr);
                            if (flow_change_fun_name != "")
                                cout << "<\033[31m" << flow_change_fun_name << "@plt\033[0m>";
                            else {
                                flow_change_fun_name = get_libc_symbol_name(flow_change_addr);
                                if (flow_change_fun_name == "")
                                    flow_change_fun_name = get_libc_plt_symbol_name(flow_change_addr);
                                cout << "<\033[31m" << flow_change_fun_name << "\033[0m>";
                            }
                        }
 
                    }

                    if (strcmp(insn[j].mnemonic, "ret") == 0 && dis_fun_name == "main") {
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

            if (insn[5].address == rip_val) {
                disasm_addr = insn[1].address;
            }
        }
        disasm_addr_synchronous = false;
        cs_free(insn, count);
    }
    else printf("\033[31m\033[1m[-] Failed to disassemble given code!\n");

    cs_close(&handle);
}

//输出 line 行反汇编, 只输出 mnemonic 操作码, op_str 操作数
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
            printf(
                "\033[33m\033[1m%s\033[0m "
                "\033[36m\033[1m%s\033[0m ", 
                insn[j].mnemonic, insn[j].op_str
            );

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

// 获得下一条指令地址
unsigned long long get_next_instruct_addr(char* byte_codes, unsigned long long addr, int num)
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

