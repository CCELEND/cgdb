#include "disasm.h"

// 判断操作码是否是跳转指令
bool 
judg_jump(char* mnemonic)
{
    if (
        !strcmp(mnemonic, "call") || !strcmp(mnemonic, "jmp") ||
        !strcmp(mnemonic, "je"  ) ||
        !strcmp(mnemonic, "jne" ) || !strcmp(mnemonic, "jz" ) ||
        !strcmp(mnemonic, "ja"  ) || !strcmp(mnemonic, "jae") ||
        !strcmp(mnemonic, "jb"  ) || !strcmp(mnemonic, "jbe") ||
        !strcmp(mnemonic, "jg"  ) || !strcmp(mnemonic, "jge") ||
        !strcmp(mnemonic, "jl"  ) || !strcmp(mnemonic, "jle") ||
        !strcmp(mnemonic, "bnd jmp" ) //|| !strcmp(mnemonic, "ret" )
       )
        return true;
    else
        return false;
}

// addr:汇编代码的地址, fun_name:函数名, offset:偏移, 
// 指令码:codes, 操作码:mnemonic, 操作数:ops 
// 高亮显示
void 
dis_highlight_show(u64 addr, string fun_name, s32 offset, 
    char* codes, char* mnemonic, char* ops)
{
    tuple<string, u64, u64> ret_val;
    string jump_fun_name = "";
    u64 jump_addr, jump_fun_start_addr;
    s32 jump_fun_offset;

    printf("\033[32m\033[1m ► 0x%llx\033[0m ", addr);
    if(fun_name != "")
    {
        printf("\033[32m\033[1m<%s+%04d>   ", fun_name.c_str(), offset);
    }
    printf("\033[34m\033[1m%-20s\033[0m", codes);
    printf("\033[33m\033[1m%-16s\033[0m", mnemonic);
    printf("\033[36m\033[1m%s\033[0m ", ops);
    if (judg_jump(mnemonic))
    {
        jump_addr = strtoul(ops, nullptr, 16);

        ret_val = get_fun_start_end(jump_addr);
        jump_fun_name = get<0>(ret_val);
        jump_fun_start_addr = get<1>(ret_val);

        jump_fun_offset = jump_addr - jump_fun_start_addr;

        if (jump_fun_offset)
            printf("\033[32m\033[1m<%s+%d>", jump_fun_name.c_str(), jump_fun_offset);
        else
            printf("\033[32m\033[1m<%s>", jump_fun_name.c_str());
    }
}
void 
dis_show(u64 addr, string fun_name, s32 offset, 
    char* codes, char* mnemonic, char* ops)
{
    tuple<string, u64, u64> ret_val;
    string jump_fun_name = "";
    u64 jump_addr, jump_fun_start_addr;
    s32 jump_fun_offset;

    printf("   0x%llx ", addr);
    if(fun_name != ""){
        printf("<%s+%04d>   ", fun_name.c_str(), offset);
    }
    printf("\033[34m%-20s\033[0m", codes);
    printf("\033[33m%-16s\033[0m", mnemonic);
    printf("\033[36m%s\033[0m ", ops);
    if (judg_jump(mnemonic))
    {
        jump_addr = strtoul(ops, nullptr, 16);

        ret_val = get_fun_start_end(jump_addr);
        jump_fun_name = get<0>(ret_val);
        jump_fun_start_addr = get<1>(ret_val);

        jump_fun_offset = jump_addr - jump_fun_start_addr;

        if (jump_fun_offset)
            printf("<%s+%d>", jump_fun_name.c_str(), jump_fun_offset);
        else
            printf("<%s>", jump_fun_name.c_str());
    }
}

// 只输出两行
void 
bp_disasm(pid_t pid, u64 addr)
{
    cs_insn* insn;
    size_t count;

    memset(disasm_code, 0, 32);
    get_addr_data(pid, addr, disasm_code, 32);

    count = cs_disasm(handle, (uint8_t*)disasm_code, 32, addr, 0, &insn);
    if (count > 0) 
    {
        size_t j;
        s32 fun_offset;
        tuple<string, u64, u64> ret_val;
        string dis_fun_name = "";
        u64 fun_start_addr;

        for (j = 0; j < 2 && j < count-1; j++)
        {
            char code[32];
            
            ret_val = get_fun_start_end(insn[j].address);
            dis_fun_name = get<0>(ret_val);
            fun_start_addr = get<1>(ret_val);

            fun_offset = insn[j].address - fun_start_addr;
            
            for(s32 i = 0; i < insn[j].size; ++i)
                sprintf(code + i*2, "%02x", (unsigned char) insn[j].bytes[i]);

            // addr 汇编代码的地址, code 指令码, mnemonic 操作码, op_str 操作数
            if (insn[j].address == addr)
            {
                dis_highlight_show(insn[j].address, dis_fun_name, fun_offset, 
                    code, insn[j].mnemonic, insn[j].op_str);
            }
            else
            {
                dis_show(insn[j].address, dis_fun_name, fun_offset, 
                    code, insn[j].mnemonic, insn[j].op_str);
            }
            printf("\n");
        }
        cs_free(insn, count);
    }
    else 
        printf("\033[31m\033[1m[-] Failed to disassemble given code!\n");

}


// 显示调用函数符号和信息
void 
call_disasm(char* byte_codes, 
    u64 addr, s32 num, string call_fun_name)
{
    cs_insn *insn;
    size_t count;
    u64 fun_addr;
    string fun_name;
    s32 offset;

    count = cs_disasm(handle, (uint8_t*)byte_codes, num, addr, 0, &insn);
    if (count > 0) 
    {
        size_t j;
        for (j = 0; j < count; j++) 
        {
            char code[32];
            string dis_fun_name = "";
            
            // for(s32 i = 0; i < insn[j].size; ++i)
            //     sprintf(code + i*2, "%02x", (unsigned char) insn[j].bytes[i]);

            // printf("\033[34m\033[1m%-20s\033[0m" "\033[33m\033[1m%-16s\033[0m" 
            //         "\033[36m\033[1m%s\033[0m\n", 
            //             code, insn[j].mnemonic, insn[j].op_str);

            if ( !strcmp(insn[j].mnemonic, "call") || 
                 !strcmp(insn[j].mnemonic, "jmp") )
            {
                fun_addr = strtoul(insn[j].op_str, nullptr, 16);

                fun_name = addr_get_elf_fun(fun_addr);
                if (fun_name == "")
                {
                    fun_name = addr_get_elf_plt_fun(fun_addr);
                    offset = addr_get_elf_plt_fun_offset(fun_addr);
                }
                else
                {
                    offset = addr_get_elf_fun_offset(fun_addr);
                }
                printf("  -> 0x%lx(\033[31m%s\033[0m+0x%llx) call \033[31m%15s\033[0m: ", 
                    insn[j].address, call_fun_name.c_str(), insn[j].address-addr,
                    fun_name.c_str());
                printf("0x%llx\n", fun_addr);
            } 
        }
        cs_free(insn, count);
    }
    else printf("\033[31m\033[1m[-] Failed to disassemble given code!\n");

}

// 输出跳转指令流操作数的函数符号和偏移
void 
flow_change_op(char* ops)
{
    u64 flow_change_addr;
    string flow_change_fun_name = "";
    s32 offset;

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

void 
show_disasm(pid_t pid, u64 rip_val)
{
    cs_insn* insn;
    size_t count;
    s32 fun_offset;

    struct winsize size;
    ioctl(STDIN_FILENO, TIOCGWINSZ, &size);
    s32 str_count = (size.ws_col-10)/2;      // 要重复输出的次数
    show_str(str_count);
    printf("[ DISASM ]");
    show_str(str_count);
    printf("\033[0m\n");

    // 反汇编开始地址与 rip 同步
    if (disasm_addr_synchronous || next_disasm_addr && next_disasm_addr != rip_val) 
    {
        disasm_addr = rip_val;
    }

    memset(disasm_code, 0, 176);
    get_addr_data(pid, disasm_addr, disasm_code, 176);

    count = cs_disasm(handle, (uint8_t*)disasm_code, 176, disasm_addr, 0, &insn);
    if (count > 0) 
    {
        size_t j;
        s32 num;
        s32 line = 0;
        num = dis_fun_info.fun_num;

        for (s32 i = 0; i < 11 && i < count-1; i++ )
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
            for(s32 i = 0; i < 11 && i < count-1; i++)
                set_fun_list(&dis_fun_info, insn[i].address);
        }

        for (j = 0; j < 11 && j < count-1; j++)
        {
            char code[32];
            string dis_fun_name = "";
            
            for(s32 i = 0; i < insn[j].size; ++i)
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

                if (!strcmp(insn[j].mnemonic, "endbr64"))
                {
                    set_fun_args_regs(&regs, &fun_args_regs);
                }

                if (judg_jump(insn[j].mnemonic))
                {
                    flow_change_op(insn[j].op_str);
                    printf("\n");
                    show_fun_args(pid, &regs, &fun_args_regs);
                }

                if (!strcmp(insn[j-1].mnemonic, "call"))
                    set_fun_args_regs(&regs, &fun_args_regs);

                printf("\n");

            }
            else
            {

                printf("   0x%lx ", insn[j].address);

                if(dis_fun_name != "")
                    printf("<%s+%04d>   ", dis_fun_name.c_str(), fun_offset);

                printf("\033[34m%-20s\033[0m", code);

                if (judg_jump(insn[j].mnemonic))
                {
                    printf( "\033[33m%-16s\033[0m"
                            "\033[36m%s\033[0m ",
                        insn[j].mnemonic, insn[j].op_str);

                    // 输出跳转指令流操作数的函数符号和偏移
                    flow_change_op(insn[j].op_str);

                    printf("\n\n");
                }
                else 
                {
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
    else 
        printf("\033[31m\033[1m[-] Failed to disassemble given code!\n");

}

//输出 line 行反汇编, 只输出 mnemonic 操作码, op_str 操作数
void 
disasm_mne_op(char* byte_codes, 
    u64 addr, s32 num, s32 line)
{
    cs_insn *insn;
    size_t count;
    u64 plt_addr;

    count = cs_disasm(handle, (uint8_t*)byte_codes, num, addr, 0, &insn);
    if (count > 0) 
    {
        size_t j;
        for (j = 0; j < line; j++) 
        {
            printf(
                "\033[33m\033[1m%s\033[0m "
                "\033[36m\033[1m%s\033[0m ", 
                insn[j].mnemonic, insn[j].op_str
            );
            if ( !strcmp(insn[j].mnemonic, "call") ||  
                 !strcmp(insn[j].mnemonic, "jmp" ) )
            {
                flow_change_op(insn[j].op_str);
            }
        }
        cs_free(insn, count);
    }
    else 
        printf("\033[31m\033[1m[-] Failed to disassemble given code!\n");

}

// 获得下一条指令地址
u64 
get_next_instruct_addr(pid_t pid, u64 addr)
{
    cs_insn* insn;
    size_t count;
    u64 next_addr;

    memset(disasm_code, 0, 32);
    get_addr_data(pid, addr, disasm_code, 32);

    count = cs_disasm(handle, (uint8_t*)disasm_code, 32, addr, 0, &insn);
    if (count > 0) 
    {
        next_addr = insn[1].address;
        cs_free(insn, count);        
    }
    else 
    {
        printf("\033[31m\033[1m[-] Failed to disassemble given code!\n");
        return 0;
    }

    return next_addr;
}