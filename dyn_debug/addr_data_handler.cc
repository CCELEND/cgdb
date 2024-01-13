
#include "dyn_fun.h"

// 获取该地址8字节的值
s64 
get_addr_val(pid_t pid, u64 addr)
{
    u64 val;
    val = ptrace(PTRACE_PEEKDATA, pid, addr, nullptr);
    if (val == -1)
    {
        perror("Read failure");
        return -1;
    }

    return val;
}

// 往指定地址写入8字节值
s64
put_addr_val(pid_t pid, 
    u64 addr, s64 val)
{
    if (ptrace(PTRACE_POKEDATA, pid, addr, val) == -1) 
    {
        perror("Write failed");
        return -1;
    }

    return 0;
}

// 从子进程指定地址读取 len 字节长度数据到 str, len 需要8字节对齐
void 
get_data_from_addr(pid_t pid, 
    u64 addr, char* str, s32 len)
{
    char* laddr = str;
    u64 data_addr = addr;
    s32 j = len >> 3;

    union u 
    {
        long val;
        char chars[LONG_SIZE];
    } word{};

    for (s32 i = 0; i < j; i++)
    {
        data_addr = addr + i * LONG_SIZE;

        word.val = get_addr_val(pid, data_addr);
        if (word.val == -1)
        {
            return;
        }

        memcpy(laddr, word.chars, LONG_SIZE);//将这8个字节拷贝进 laddr 数组
        laddr += LONG_SIZE;
    }
    str[len] = '\0';

}

// 从 str 插入 len 字节长度数据到子进程指定地址
void 
put_data_to_addr(pid_t pid, 
    u64 addr, char* str, s32 len) 
{
    char* laddr = str;
    u64 data_addr = addr;
    s32 j = len >> 3;
    union u 
    {
        long val;
        char chars[LONG_SIZE];
    } word{};

    for (s32 i = 0; i < j; i++)
    {
        memcpy(word.chars, laddr, LONG_SIZE);
        data_addr = addr + i * LONG_SIZE;

        if (put_addr_val(pid, data_addr, word.val) == -1)
        {
            return;
        }

        laddr += LONG_SIZE;
    }
}

// 按照字节打印数据
void 
print_bytes(const char* codes, s32 len) 
{
    for (s32 i = 0; i < len; ++i) 
    {
        printf("%02x", (unsigned char) codes[i]);

        if ((i + 1) % 8 == 0) 
        {
            printf("\n");
        }
    }
}

void
elf_code_fun_printf(u64 addr)
{
    string fun_name;
    s32 offset;

    set_fun_list(&regs_fun_info, addr);
    fun_name = addr_get_fun(&regs_fun_info, addr);
    offset = addr_get_fun_offset(&regs_fun_info, addr);

    if (!offset) 
    {
        printf("\033[31m0x%llx (elf.%s)\033[0m", 
            addr, fun_name.c_str());
    }
    else 
    {
        printf("\033[31m0x%llx (elf.%s+%d)\033[0m", 
            addr, fun_name.c_str(), offset);  
    }
}
void
elf_ini_printf(u64 addr)
{
    string ini_name = addr_get_elf_fini(addr);

    if (ini_name != "") 
    {
        printf("0x%llx (elf.%s)\033[0m", 
            addr, ini_name.c_str());
    }
    else 
    {
        ini_name = addr_get_elf_init(addr);
        printf("0x%llx (elf.%s)\033[0m", 
            addr, ini_name.c_str());
    }
}
void
elf_heap_printf(u64 addr)
{
    if (addr == heap_base) 
    {
        printf("\033[34m0x%llx (heap)\033[0m", 
            addr);
    }
    else 
    {
        printf("\033[34m0x%llx (heap+0x%llx)\033[0m", 
            addr, addr-heap_base);
    }
}
void
glibc_code_fun_printf(u64 addr)
{
    string fun_name;
    s32 offset;

    set_fun_list(&regs_fun_info, addr);
    fun_name = addr_get_fun(&regs_fun_info, addr);
    offset = addr_get_fun_offset(&regs_fun_info, addr);

    if (!offset) 
    {
        printf("\033[31m0x%llx (%s)\033[0m", 
            addr, fun_name.c_str());
    }
    else 
    {
        printf("\033[31m0x%llx (%s+%d)\033[0m", 
            addr, fun_name.c_str(), offset);
    }
}
void
glibc_data_printf(u64 addr)
{
    string data_name;

    data_name = addr_get_glibc_data(addr);
    printf("\033[35m0x%llx (%s)\033[0m", 
        addr, data_name.c_str());
}
void 
stack_printf(u64 addr)
{
    if (addr > regs.rsp) 
    {
        printf("\033[33m0x%llx (stack+0x%llx)\033[0m", 
            addr, addr-regs.rsp);
    }
    else if(addr < regs.rsp) 
    {
        printf("\033[33m0x%llx (stack-0x%llx)\033[0m", 
            addr, regs.rsp-addr);
    }
    else 
    {
        printf("\033[33m0x%llx (stack)\033[0m", 
            addr); 
    }
}


// 输出带颜色的地址以标记所属地址范围 
// addr_flag 为真会显示地址所属文件
void 
flag_addr_printf(u64 addr, bool addr_flag)
{
    if (!addr) 
    {
        printf("0x%llx", addr);
        return;
    }

    string fun_name, data_name, ini_name;
    s32 offset;

    if (addr_flag)  // true
    {
        if (addr > elf_code_start && addr < elf_code_end) 
        {
            elf_code_fun_printf(addr);
        } 
        else if (addr > libc_code_start && addr < libc_code_end) 
        {
            glibc_code_fun_printf(addr);
        } 
        else if (addr > stack_base && addr < stack_end) 
        {
            stack_printf(addr);
        } 
        else if (addr >= heap_base && addr <= heap_end) 
        {
            elf_heap_printf(addr);
        } 
        else if (!ld_base || addr > ld_code_start && addr < ld_code_end) 
        {
            glibc_code_fun_printf(addr);
        } 
        else if ( addr > ld_data_start   && addr < ld_data_end || 
                  addr > libc_data_start && addr < libc_data_end ) 
        {
            glibc_data_printf(addr);
        } 
        else if (addr > elf_ini_start && addr < elf_ini_end) 
        {
            elf_ini_printf(addr);
        } 
        else if (addr > elf_rodata_start && addr < elf_rodata_end) 
        {
            printf("0x%llx (elf[rodata])", addr);
        }
        else
        {
            printf("0x%llx", addr);
        }
    }
    else
    {
        if (judg_addr_code(addr)) 
        {
            printf("\033[31m0x%llx\033[0m", addr);
        }
        else if (addr > stack_base && addr < stack_end) 
        {
            printf("\033[33m0x%llx\033[0m", addr);
        }
        else if (addr >= heap_base && addr <= heap_end) 
        {
            printf("\033[34m0x%llx\033[0m", addr);
        }
        else 
        {
            printf("0x%llx", addr);
        }
    }
}

// 输出指定地址的数据，输出 num 组，每组8字节
void 
show_addr_data(pid_t pid, 
    s32 num, u64 addr)
{
    union u 
    {
        long val;
        char chars[LONG_SIZE];
    } word{};
    char laddr[8];

    for (s32 i = 0; i < num; i++) 
    {
        if( i % 2 == 0 )
        {
            flag_addr_printf(addr + i * LONG_SIZE, false);
            printf(": ");
        }

        word.val = get_addr_val(pid, addr + i * LONG_SIZE);
        if (word.val == -1) 
        {
            return;
        }

        memcpy(laddr, word.chars, LONG_SIZE);

        printf("0x");
        for (s32 j = 7; j > -1; --j)
        {
            printf("%02x", (unsigned char)laddr[j]);
            if (j == 0) {
                printf("     ");
            }
        }

        if ( ( i + 1 ) % 2 == 0 || ( i + 1 ) == num ) 
        {
            printf("\n");
        }
    }

}

void
end_output(pid_t pid, 
    u64 addr, u64 val)
{
    char addr_instruct[17];

    printf(" ◂— ");
    
    if (judg_addr_code(addr)) 
    {
        get_data_from_addr(pid, addr, addr_instruct, 16);
        disasm_mne_op(addr_instruct, addr, 16, 1);
    }
    else 
    {
        flag_addr_printf(val, false);
        if ( val > 0x7fffffffffff && 
             val != 0xffffffffffffffff ) 
        {
            val_to_string(val);
        }
    }
}

// 输出地址的多重指针
void 
show_addr_point(pid_t pid, 
    u64 address, bool addr_flag)
{
    u64 addr;
    u64 val;
    flag_addr_printf(address, addr_flag);

    if ( address < 0x550000000000 || 
         address > 0x7fffffffffff ) 
    {
        return;
    }

    addr = address;
    while (true)
    {
        val = get_addr_val(pid, addr);

        if (val < 0x550000000000 || 
            val > 0x7fffffffffff || 
            val == addr ) 
        {
            end_output(pid, addr, val);
            break;
        }
        else 
        {
            printf(" —▸ ");
            flag_addr_printf(val, true);
        }

        addr = val;
    }
}

// 字节流转换字符串
void 
val_to_string(u64 val)
{
    union u 
    {
        u64 val;
        char chars[LONG_SIZE];
    } word{};
    word.val = val;

    printf(" '");
    for(s32 i = 0; i < CODE_SIZE; ++i)
    {
        if ( long((unsigned char)word.chars[i]) == 0x00 ) 
        {
            break;
        }

        if ( long((unsigned char)word.chars[i]) >= 0x21 &&
             long((unsigned char)word.chars[i]) <= 0x7e ) {
            printf("%c", word.chars[i]);
        }
    }
    printf("'");
}

// 判断地址是否可执行
bool 
judg_addr_code(u64 addr)
{
    if (addr > elf_code_start && addr < elf_code_end) 
        return true;

    else if (addr > libc_code_start && addr < libc_code_end) 
        return true;

    else if (addr > ld_code_start && addr < ld_code_end) 
        return true;

    else if (addr > vdso_code_start && addr < vdso_code_end) 
        return true;
    
    else
        return false;
}

bool 
judg_fun_legitimacy(const char* fun_name)
{
    string str = string(fun_name);

    if (isdigit(str[0]))
    {
        return false;
    }

    for (char c : str) 
    {
        if (!(isdigit(c) || isalpha(c) || c == '_' || c == '.'))
        {
            return false;
        }
    }

    return true;

}

// 通过地址获取文件名和加载基址
tuple<string, u64>
get_addr_file_base(u64 addr)
{
    tuple<string, u64> ret_val;

    if (addr > elf_code_start && addr < elf_code_end) 
    {
        ret_val = make_tuple("elf", elf_base);
        return ret_val;
    } 
    else if (addr > libc_code_start && addr < libc_code_end) 
    {
        ret_val = make_tuple("libc", libc_base);
        return ret_val;
    } 
    else if (addr > ld_code_start && addr < ld_code_end) 
    {
        ret_val = make_tuple("ld", ld_base);
        return ret_val;
    }

    ret_val = make_tuple("", 0);
    return ret_val;
}

// qword ptr [rip + 0x2f25]
// 从字符串获取十六进制值
u64 
get_hex_in_string(const char* str)
{
    u64 hex_val;
    s32 hex_str_start, hex_str_end;
    string hex_str;

    if (string(str).find("0x") != string::npos)
    {
        hex_str_start = string(str).find("0x");
        hex_str_end = string(str).find("]");

        hex_str = string(str).substr(hex_str_start+2, 
                    hex_str_end-hex_str_start-2);
        hex_val = strtoul(hex_str.c_str(), nullptr, 16);

        return hex_val;
    }
    
    return 0;
}