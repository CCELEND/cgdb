
#include "dyn_fun.h"

// 清理函数列表
void 
clear_fun_list(fun_list_info_type* fun_list_info)
{
    for (s32 i = 0; i < fun_list_info->fun_num; i++)
    {
        if ( !fun_list_info->fun_list[i].fun_start_addr ) 
        {
            break;
        }

        fun_list_info->fun_list[i].fun_start_addr = 0;
        fun_list_info->fun_list[i].fun_end_addr = 0;
        fun_list_info->fun_list[i].fun_name = "";
    }
    fun_list_info->fun_num = 0;
}

static s32
set_glibc_fun_list(fun_list_info_type* fun_list_info, 
    s32 i, u64 glibc_fun_addr)
{
    string fun_name;

    fun_name = addr_get_glibc_plt_fun(glibc_fun_addr);
    if (fun_name != "") 
    {
        fun_list_info->fun_list[i].fun_start_addr = 
            glibc_fun_addr;

        fun_list_info->fun_list[i].fun_end_addr = 
            glibc_fun_addr + 0xb;

        fun_list_info->fun_list[i].fun_name = 
            fun_name;

        fun_list_info->fun_num++;

        return 0;
    }

    tuple<string, u64, u64> fun_list_info_temp;
    u64 glibc_fun_start, glibc_fun_end;

    fun_list_info_temp = addr_get_glibc_fun_start_and_end(glibc_fun_addr);
    fun_name = get<0>(fun_list_info_temp);
    glibc_fun_start = get<1>(fun_list_info_temp);
    glibc_fun_end = get<2>(fun_list_info_temp);

    fun_list_info->fun_list[i].fun_name = 
        fun_name;

    fun_list_info->fun_list[i].fun_start_addr = 
        glibc_fun_start;

    fun_list_info->fun_list[i].fun_end_addr = 
        glibc_fun_end;

    fun_list_info->fun_num++;

    return 0;
}

static s32
set_elf_fun_list(fun_list_info_type* fun_list_info, 
    s32 i, u64 elf_fun_addr)
{
    string fun_name;

    fun_name = addr_get_elf_fun(elf_fun_addr);
    if (fun_name != "") 
    {
        fun_list_info->fun_list[i].fun_start_addr = 
            elf_fun_start[fun_name] + elf_base;

        fun_list_info->fun_list[i].fun_end_addr = 
            elf_fun_end[fun_name];

        fun_list_info->fun_list[i].fun_name = 
            fun_name;

        fun_list_info->fun_num++;

        return 0;
    }

    fun_name = addr_get_elf_plt_fun(elf_fun_addr);

    fun_list_info->fun_list[i].fun_start_addr = 
        elf_plt_fun_start[fun_name] + elf_base;

    fun_list_info->fun_list[i].fun_end_addr = 
        elf_plt_fun_end[fun_name];

    fun_list_info->fun_list[i].fun_name = 
        fun_name;

    fun_list_info->fun_num++;

    return 0;
}

// 设置函数列表
void 
set_fun_list(fun_list_info_type* fun_list_info, u64 fun_addr)
{
    for (s32 i = 0; i < 0x10; i++) 
    {
        // 地址在列表某个函数范围内就直接退出
        if (fun_addr >= fun_list_info->fun_list[i].fun_start_addr && 
            fun_addr <= fun_list_info->fun_list[i].fun_end_addr )
        {
            break;
        }

        if ( fun_list_info->fun_list[i].fun_start_addr == 0 ) 
        {
            // glibc
            if (fun_addr > 0x7f0000000000)
            {
                if (!set_glibc_fun_list(fun_list_info, i, fun_addr))
                {
                    break;
                }
            }

            // elf
            if (!set_elf_fun_list(fun_list_info, i, fun_addr))
            {
                break;
            }
        }
    }
}

// 显示函数列表
void 
show_fun_list(const fun_list_info_type* fun_list_info)
{
    for (s32 i = 0; i < 0x10; i++)
    {
        if (fun_list_info->fun_list[i].fun_start_addr == 0) 
        {
            break;
        }

        printf("idx: %d\n", i);

        printf("fun start: 0x%llx\n", 
            fun_list_info->fun_list[i].fun_start_addr);

        printf("fun end:   0x%llx\n", 
            fun_list_info->fun_list[i].fun_end_addr);

        printf("fun name:  %s\n",     
            fun_list_info->fun_list[i].fun_name.c_str());
    }

    printf("num: %d\n", fun_list_info->fun_num);
}

// 通过地址获得对应函数地址偏移
s32 
addr_get_fun_offset(const fun_list_info_type* fun_list_info, u64 addr)
{

    for (s32 i = 0; i < 0x10; i++)
    {
        if ( addr >= fun_list_info->fun_list[i].fun_start_addr && 
             addr <= fun_list_info->fun_list[i].fun_end_addr )
        {
            return addr - fun_list_info->fun_list[i].fun_start_addr;
        }
    }

    return -1;
}