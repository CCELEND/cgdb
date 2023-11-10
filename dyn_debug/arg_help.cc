
#include "dyn_fun.h"

// 解析输入参数
void argparse() {
    string param;
    for (char i:cmd + " ") {// 用到空格进行分割，为了防止最后一个参数分割不到加一个空格
        if (i != ' ') {
            param += i;
        } else {
            myargv.push_back(param);
            param = "";
            continue;
        }
    }
}

void show_help() {
    printf(" q: Stop process.\n");
    printf(" si: Single step.\n");
    printf(" ni: Single step over.\n");
    printf(" c: Run until the process stops.\n");
    printf(" ic: Calculate the number of instructions after this.\n");

    printf(" x [num] [addr]: Display the content of the address.\n"
           "     for example: \"x 16 0x7ffe5ae0c4a0\" Output 16 sets of memory and values from this address.\n");
    printf(" stack [num]: Display a certain number of stack(rsp) values and pointers\n")
    
    printf(" ib: Display break point information.\n");
    printf(" b [fun name]: Insert function break point.\n");
    printf(" d b [idx]: Based on break point index, remove break point.\n");

    printf(" vmmap: Display the virtual address space of the program.\n");
    printf(" base: Display the base addresses of elf, libc and ld.\n");
    printf(" libc: Display the base addresses of libc and ld.\n");
    printf(" code: Display the range of executable segments.\n");
    printf(" data: Display the range of data segments.\n");
    printf(" stackbase: Display the start and end addresses of the stack.\n");
    printf(" heapbase: Display the start and end addresses of the heap.\n");

    printf(" fun [fun name]: Display the calling function of the this function\n");
    printf(" lplt: Display the PLT address of the libc function.\n");
    printf(" plt [addr]: Find the corresponding PLT function based on the address.\n");
}