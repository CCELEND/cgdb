
#include "dyn_fun.h"

// 解析输入参数
void argparse() {
    string param;
    for (char i:cmd + " ") {//因为要用到空格进行分割，为了防止最后一个参数分割不到加一个空格
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
    printf("Type \"exit\" to exit debugger.\n");
    printf("Type \"step\" or \"si\" to single step.\n");
    printf("Type \"continue\" or \"c\" to continue until tracee stop.\n");
    printf("Type \"memory\" or \"m\" to show memory content.\n"
           "\tYou can use \"-addr\" or \"-off\" or \"-nb\" as argument.\n"
           "\tuse \"-addr\" to specify hexadecimal start address of the memory\n"
           "\t\tfor example: Type \"m -addr ff\" to specify the start address 0xff\n"
           "\t\t(default start address is RIP)\n"
           "\tuse \"-off\" to specify the decimal offset from the start address\n"
           "\t\t(default offset is 0)\n"
           "\tuse \"-nb\" to specify the decimal number of bytes to be displayed\n"
           "\t\t(default number is 40)\n");
    printf("Type \"ic\" to count total instructions.\n");
    printf("Type \"break\" or \"b\" to insert break point.\n"
           "\tfor example: Type \"b 555555555131\" to specify the break point address 0x555555555131\n");
}