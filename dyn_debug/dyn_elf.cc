
#include "dyn_fun.h"

// 根据值找键
string get_map_key_value(map<string, unsigned long long>& Map, unsigned long long plt_fun_addr) 
{
    for (const auto& pair : Map) 
    {
        if (pair.second == plt_fun_addr) {
            return pair.first;
        }
    }
    return "";
}

string addr_get_fun(unsigned long long addr)
{
    for (int i = 0; i < 5; i++)
    {
        if(addr >= dis_fun_info.fun_list[i].fun_start_addr && 
            addr <= dis_fun_info.fun_list[i].fun_end_addr )
            return dis_fun_info.fun_list[i].fun_name;
    }

    return "";
}

// 通过函数地址获得函数结束地址
unsigned long long get_fun_end(pid_t pid, unsigned long long fun_addr)
{
    char buf[0x1000];
    union u 
    {
        long val;
        char chars[LONG_SIZE];
    } word{};

    for (int i = 0; i < 0x1000; i += LONG_SIZE){
        word.val = ptrace(PTRACE_PEEKDATA, pid, fun_addr + i, nullptr);
        if (word.val == -1)
            err_info("Trace error!");
        memcpy(buf + i, word.chars, LONG_SIZE); // 将这8个字节拷贝进数组

        for (int j = i; j < i + 8; j++)
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


