
#include "dyn_fun.h"

// 从函数信息结构体获取对应地址的信息
string addr_get_fun(fun_list_info_type* fun_info, u64 addr)
{
    for (s32 i = 0; i < 0x10; i++)
    {
        if(addr >= fun_info->fun_list[i].fun_start_addr && 
           addr <= fun_info->fun_list[i].fun_end_addr)
            return fun_info->fun_list[i].fun_name;
    }

    return "";
}

// 通过地址找函数名
string get_fun(u64 addr, u64* fun_start_addr)
{
    string fun_name;
    if (addr > 0x7f0000000000)
    {
        fun_name = addr_get_glibc_plt_fun(addr);
        if (fun_name != "") 
        {
            *fun_start_addr = addr;
            return fun_name;
        }
        else
        {
            fun_name = addr_get_glibc_fun(addr, fun_start_addr);
            return fun_name;
        }
    }

    // elf
    else
    {
        fun_name = addr_get_elf_fun(addr);
        if (fun_name != "") 
        {
            *fun_start_addr = elf_fun_start[fun_name] + elf_base;
            return fun_name;
        }
        else 
        {
            fun_name = addr_get_elf_plt_fun(addr);
            *fun_start_addr = elf_plt_fun_start[fun_name] + elf_base;
            return fun_name;
        }

    }

}

// 通过函数名找开始地址, 结束地址
u64 get_fun_addr(char* fun_name, u64* fun_end_addr)
{
    u64 fun_start_addr;

    fun_start_addr = get_elf_fun_addr(fun_name);
    if (fun_start_addr)
    {
        *fun_end_addr = elf_fun_end[string(fun_name)];
        return fun_start_addr;
    }
    fun_start_addr = get_elf_plt_fun_addr(fun_name);
    if (fun_start_addr)
    {
        *fun_end_addr = elf_plt_fun_end[string(fun_name)];
        return fun_start_addr;
    }

    fun_start_addr = get_glibc_fun_addr(fun_name);
    if (fun_start_addr)
    {
        // printf("0x%llx\n",fun_start_addr);
        *fun_end_addr = get_glibc_fun_end(fun_start_addr, string(fun_name));
        return fun_start_addr;
    }
    fun_start_addr = get_glibc_plt_fun_addr(fun_name);
    if (fun_start_addr)
    {
        *fun_end_addr = fun_start_addr + 0xb;
        return fun_start_addr;
    }

    *fun_end_addr = 0;
    return 0;

}

// 通过函数地址获得函数结束地址
u64 get_fun_end(pid_t pid, u64 fun_addr)
{
    char buf[0x1000];
    union u 
    {
        long val;
        char chars[LONG_SIZE];
    } word{};

    for (s32 i = 0; i < 0x1000; i += LONG_SIZE){
        word.val = ptrace(PTRACE_PEEKDATA, pid, fun_addr + i, nullptr);
        if (word.val == -1)
            err_info("Trace error!");
        memcpy(buf + i, word.chars, LONG_SIZE); // 将这8个字节拷贝进数组

        for (s32 j = i; j < i + 8; j++)
        {
            // 函数结束的标志的指令码
            if ( long((unsigned char)buf[j]) == 0xf4 ||
                 long((unsigned char)buf[j]) == 0xc3 ||
                 long((unsigned char)buf[j]) == 0xe9 && long((unsigned char)buf[j-1]) == 0xfa ||
                 long((unsigned char)buf[j]) == 0x0f && long((unsigned char)buf[j-1]) == 0x00 )
            {
                return j + fun_addr;
            }
        }
    }

    return 0;
}


