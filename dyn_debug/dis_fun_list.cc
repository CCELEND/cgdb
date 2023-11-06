
#include "dyn_fun.h"

void clear_dis_fun_list()
{
    for (int i = 0; i < 5; i++)
    {
        if (dis_fun_info.fun_list[i].fun_start_addr == 0) break;

        dis_fun_info.fun_list[i].fun_start_addr = 0;
        dis_fun_info.fun_list[i].fun_end_addr = 0;
        dis_fun_info.fun_list[i].fun_name = "";
    }
    dis_fun_info.fun_num = 0;
}

void set_dis_fun_list(unsigned long long fun_addr)
{
    for (int i = 0; i < 5; i++) 
    {
        // 地址在列表某个函数范围内就直接退出
        if (fun_addr >= dis_fun_info.fun_list[i].fun_start_addr && 
            fun_addr <= dis_fun_info.fun_list[i].fun_end_addr )
            break;

        if ( dis_fun_info.fun_list[i].fun_start_addr == 0 ) 
        {
            string fun_name;
            // glibc
            if (fun_addr > 0x7f0000000000)
            {
                fun_name = addr_get_glibc_plt_fun(fun_addr);
                if (fun_name != "") 
                {
                    dis_fun_info.fun_list[i].fun_start_addr = fun_addr;
                    dis_fun_info.fun_list[i].fun_end_addr = fun_addr + 0xb;
                    dis_fun_info.fun_list[i].fun_name = fun_name;
                    dis_fun_info.fun_num++;
                    break;
                }
                else
                {
                    dis_fun_info.fun_list[i].fun_start_addr = fun_addr;
                    dis_fun_info.fun_list[i].fun_end_addr = get_glibc_fun_end(fun_addr);
                    dis_fun_info.fun_list[i].fun_name = addr_get_glibc_fun(fun_addr);
                    dis_fun_info.fun_num++;
                    break;
                }
            }

            // elf
            else
            {
                fun_name = addr_get_elf_fun(fun_addr);
                if (fun_name != "") 
                {
                    // dis_fun_info.fun_list[i].fun_start_addr = elf_fun_start[fun_name];
                    dis_fun_info.fun_list[i].fun_start_addr = fun_addr;
                    dis_fun_info.fun_list[i].fun_end_addr = elf_fun_end[fun_name];
                    dis_fun_info.fun_list[i].fun_name = fun_name;
                    dis_fun_info.fun_num++;
                    break;
                }
                else 
                {
                    fun_name = addr_get_elf_plt_fun(fun_addr);
                    fun_name += "@plt";
                    // dis_fun_info.fun_list[i].fun_start_addr = elf_plt_fun[fun_name] + elf_base;
                    dis_fun_info.fun_list[i].fun_start_addr = fun_addr;
                    // dis_fun_info.fun_list[i].fun_end_addr = elf_plt_fun_end[fun_name];
                    dis_fun_info.fun_list[i].fun_end_addr = fun_addr + 0xb;
                    dis_fun_info.fun_list[i].fun_name = fun_name;
                    dis_fun_info.fun_num++;
                    break;

                }

            }
        }

    }
}

// test
void show_dis_fun_list()
{
    for (int i = 0; i < 5; i++ )
    {
        if (dis_fun_info.fun_list[i].fun_start_addr == 0)
            break;
        printf("idx: %d\n", i);
        printf("fun start: 0x%llx\n", dis_fun_info.fun_list[i].fun_start_addr);
        printf("fun end:   0x%llx\n", dis_fun_info.fun_list[i].fun_end_addr);
        printf("fun name:  %s\n",     dis_fun_info.fun_list[i].fun_name.c_str());
    }

    printf("num: %d\n", dis_fun_info.fun_num);
}

int addr_get_dis_fun_offset(unsigned long long addr)
{

    for (int i = 0; i < 5; i++)
    {
        if ( addr >= dis_fun_info.fun_list[i].fun_start_addr && 
             addr <= dis_fun_info.fun_list[i].fun_end_addr )
            return addr - dis_fun_info.fun_list[i].fun_start_addr;

    }

    return -1;
}