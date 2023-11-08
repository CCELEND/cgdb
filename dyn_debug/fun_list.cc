
#include "dyn_fun.h"

void clear_fun_list(struct fun_info_type* fun_info)
{
    for (int i = 0; i < fun_info->fun_num; i++)
    {
        if (fun_info->fun_list[i].fun_start_addr == 0)
            break;
        fun_info->fun_list[i].fun_start_addr = 0;
        fun_info->fun_list[i].fun_end_addr = 0;
        fun_info->fun_list[i].fun_name = "";
    }
    fun_info->fun_num = 0;
}

void set_fun_list(struct fun_info_type* fun_info, unsigned long long fun_addr)
{
    for (int i = 0; i < 0x10; i++) 
    {
        // 地址在列表某个函数范围内就直接退出
        if (fun_addr >= fun_info->fun_list[i].fun_start_addr && 
            fun_addr <= fun_info->fun_list[i].fun_end_addr )
            break;

        if ( fun_info->fun_list[i].fun_start_addr == 0 ) 
        {
            string fun_name;
            // glibc
            if (fun_addr > 0x7f0000000000)
            {
                fun_name = addr_get_glibc_plt_fun(fun_addr);
                if (fun_name != "") 
                {
                    fun_info->fun_list[i].fun_start_addr = fun_addr;
                    fun_info->fun_list[i].fun_end_addr = fun_addr + 0xb;
                    fun_info->fun_list[i].fun_name = fun_name;
                    fun_info->fun_num++;
                    break;
                }
                else
                {
                    fun_name = addr_get_glibc_fun(fun_addr);
                    fun_info.fun_list[i]->fun_start_addr = fun_addr;
                    fun_info.fun_list[i]->fun_name = fun_name;
                    fun_info.fun_list[i]->fun_end_addr = get_glibc_fun_end(fun_addr, fun_name);
                    fun_info->fun_num++;
                    break;
                }
            }

            // elf
            else
            {
                fun_name = addr_get_elf_fun(fun_addr);
                if (fun_name != "") 
                {
                    fun_info.fun_list[i]->fun_start_addr = elf_fun_start[fun_name];
                    fun_info.fun_list[i]->fun_end_addr = elf_fun_end[fun_name];
                    fun_info.fun_list[i]->fun_name = fun_name;
                    fun_info.fun_num++;
                    break;
                }
                else 
                {
                    fun_name = addr_get_elf_plt_fun(fun_addr);
                    fun_info->fun_list[i].fun_start_addr = elf_plt_fun[fun_name] + elf_base;
                    fun_info->fun_list[i].fun_end_addr = elf_plt_fun_end[fun_name];
                    fun_name += "@plt";
                    fun_info->fun_list[i].fun_name = fun_name;
                    fun_info->fun_num++;
                    break;

                }

            }
        }

    }
}

// test
void show_fun_list(struct fun_info_type* fun_info)
{
    for (int i = 0; i < 0x10; i++ )
    {
        if (fun_info->fun_list[i].fun_start_addr == 0) break;

        printf("idx: %d\n", i);
        printf("fun start: 0x%llx\n", fun_info->fun_list[i].fun_start_addr);
        printf("fun end:   0x%llx\n", fun_info->fun_list[i].fun_end_addr);
        printf("fun name:  %s\n",     fun_info->fun_list[i].fun_name.c_str());
    }

    printf("num: %d\n", fun_info->fun_num);
}

int addr_get_fun_offset(struct fun_info_type* fun_info, unsigned long long addr)
{

    for (int i = 0; i < 0x10; i++)
    {
        if ( addr >= fun_info->fun_list[i].fun_start_addr && 
             addr <= fun_info->fun_list[i].fun_end_addr )
            return addr - fun_info->fun_list[i].fun_start_addr;

    }

    return -1;
}