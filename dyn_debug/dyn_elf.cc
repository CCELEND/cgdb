
#include "dyn_fun.h"

// 从函数信息结构体获取对应地址的信息
string 
addr_get_fun(const fun_list_info_type* fun_info, u64 addr)
{
    for (s32 i = 0; i < 0x10; i++)
    {
        if( addr >= fun_info->fun_list[i].fun_start_addr && 
            addr <= fun_info->fun_list[i].fun_end_addr )
        {
            return fun_info->fun_list[i].fun_name;
        }
    }

    return "";
}

// 通过地址找函数名, 函数开始地址, 结束地址
tuple<string, u64, u64>
get_fun_start_end(u64 addr)
{
    string fun_name;
    tuple<string, u64, u64> fun_info;

    if (addr > 0x7f0000000000)
    {
        fun_name = addr_get_glibc_plt_fun(addr);
        if (fun_name != "") 
        {
            fun_info = make_tuple(fun_name, addr, addr + 0xb);
            return fun_info;
        }
        else
        {
            fun_info = addr_get_glibc_fun_start_and_end(addr);
            return fun_info;
        }
    }

    // elf
    else
    {
        fun_name = addr_get_elf_fun(addr);
        if (fun_name != "") 
        {
            fun_info = make_tuple(
                fun_name, 
                elf_fun_start[fun_name] + elf_base, 
                elf_fun_end[fun_name]);

            return fun_info;
        }
        else 
        {
            fun_name = addr_get_elf_plt_fun(addr);
            fun_info = make_tuple(
                fun_name,
                elf_plt_fun_start[fun_name] + elf_base,
                elf_plt_fun_end[fun_name]);

            return fun_info;
        }

    }

}


// 通过函数名找函数开始地址, 结束地址
tuple<s32, u64, u64>
get_fun_addr(const char* fun_name)
{
    u64 addr;
    tuple<s32, u64, u64> fun_addr_info;

    // elf
    addr = get_elf_fun_addr(fun_name);
    if (addr)
    {
        fun_addr_info = make_tuple(0, addr, elf_fun_end[string(fun_name)]);
        return fun_addr_info;
    }
    addr = get_elf_plt_fun_addr(fun_name);
    if (addr)
    {
        fun_addr_info = make_tuple(0, addr, elf_plt_fun_end[string(fun_name)]);
        return fun_addr_info;
    }

    // glibc
    addr = get_glibc_fun_addr(fun_name);
    if (addr)
    {
        tuple<string, u64, u64> fun_info;
        u64 fun_start_addr, fun_end_addr;

        fun_info = addr_get_glibc_fun_start_and_end(addr);
        fun_start_addr = get<1>(fun_info);
        fun_end_addr = get<2>(fun_info);

        fun_addr_info = make_tuple(0, fun_start_addr, fun_end_addr);
        return fun_addr_info;
    }
    addr = get_glibc_plt_fun_addr(fun_name);
    if (addr)
    {
        fun_addr_info = make_tuple(0, addr, addr + 0xb);
        return fun_addr_info;
    }

    fun_addr_info = make_tuple(-1, 0, 0);
    return fun_addr_info;
}

// 通过函数地址获得函数结束地址
u64 
get_fun_end(pid_t pid, u64 fun_addr)
{
    // char buf[0x1000];
    char* buf = new char[0x1000];
    memset(buf, 0, 0x1000);
    union u 
    {
        long val;
        char chars[LONG_SIZE];
    } word{};

    for (s32 i = 0; i < 0x1000; i += LONG_SIZE)
    {
        word.val = get_addr_val(pid, fun_addr + i);
        if (word.val == -1) 
        {
            delete[] buf;
            return 0;
        }

        memcpy(buf + i, word.chars, LONG_SIZE); // 将这8个字节拷贝进数组

        for (s32 j = i; j < i + 8; j++)
        {
            // 函数结束的标志的指令码
            if ( long((unsigned char)buf[j]) == 0xf4 ||
                 long((unsigned char)buf[j]) == 0xc3 ||
                 long((unsigned char)buf[j]) == 0xe9 && long((unsigned char)buf[j-1]) == 0xfa ||
                 long((unsigned char)buf[j]) == 0x0f && long((unsigned char)buf[j-1]) == 0x00 )
            {
                delete[] buf;
                return j + fun_addr;
            }
        }
    }

    delete[] buf;
    return 0;
}
