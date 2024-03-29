
#include "dyn_fun.h"

// 解析输入参数
void 
argparse() 
{
    string param;
    // 用到空格进行分割，为了防止最后一个参数分割不到加一个空格
    for (char i : cmd + " ") 
    {
        if (i != ' ') 
        {
            param += i;
        } 
        else 
        {
            myargv.push_back(param);
            param = "";
            continue;
        }
    }
}

void 
show_help() 
{
    printf(" \033[34mq\033[0m: Stop process.\n");
    printf(" \033[34msi\033[0m: Single step.\n");
    printf(" \033[34mni\033[0m: Single step over.\n");
    printf(" \033[34mc\033[0m: Run until the process stops.\n");
    printf(" \033[34mic\033[0m: Calculate the number of instructions after this.\n");

    printf(" \033[34mx [num] [addr]\033[0m: Display the content of the address.\n"
           "     for example: \"x 16 0x7ffe5ae0c4a0\" Output 16 sets of memory and values from this address.\n");
    printf(" \033[34mstack [num]\033[0m: Display a certain number of stack(rsp) values and pointers.\n");
    
    printf(" \033[34mib\033[0m: Display break point information.\n");
    printf(" \033[34mbf [fun name] or b [fun name]\033[0m: Insert function break point.\n");
    printf(" \033[34mba [addr]\033[0m: Insert address break point.\n");
    printf(" \033[34md b [idx]\033[0m: Based on break point index, remove break point.\n");

    printf(" \033[34mvmmap\033[0m: Display the virtual address space of the program.\n");
    printf(" \033[34mbase\033[0m: Display the base address of elf, libc and ld.\n");
    printf(" \033[34mlibc\033[0m: Display the base address of libc and ld.\n");
    printf(" \033[34mcode\033[0m: Display the range of executable segments.\n");
    printf(" \033[34mdata\033[0m: Display the range of data segments.\n");
    printf(" \033[34mstackbase\033[0m: Display the start and end addresses of the stack.\n");
    printf(" \033[34mheapbase\033[0m: Display the start and end addresses of the heap.\n");

    printf(" \033[34mfun [fun name]\033[0m: Display the calling function of the this function.\n");
    printf(" \033[34mlfun\033[0m: Display internal function name and address.\n");
    printf(" \033[34mlplt\033[0m: Display PLT function name and address.\n");
    printf(" \033[34mplt [addr]\033[0m: Find the corresponding PLT function based on the address.\n");
    printf(" \033[34mtree [fun name] [level]\033[0m: Output [level] level function call tree.\n"
           "     (Maximum level is 5)\n");

    printf(" \033[34mKEYCODE_U\033[0m: Enter the up key on the keyboard to execute the previous command.\n");
    printf(" [*] Note that when entering the function name, if it is a glibc function, please enter the prefix('libc.' or 'ld.')\n"
           "     for example: libc._IO_puts\n");

}