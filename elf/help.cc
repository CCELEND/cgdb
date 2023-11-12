
#include "loader_elf.h"

void show_elf_help() 
{
    printf(" \033[34msym\033[0m: Show function symbols.\n");
    printf(" \033[34mdyn\033[0m: Show dynamic symbols.\n");
    printf(" \033[34msections\033[0m: Display sections of code and data types for elf.\n");
    printf(" \033[34mgot\033[0m: Display got.\n");
    printf(" \033[34mplt\033[0m: Display PLT function name, disassembly, and address.\n");
    printf(" \033[34mlplt\033[0m: Display PLT function name and address.\n");
    printf(" \033[34mlfun\033[0m: Display internal function name and address.\n");
    printf(" \033[34mr\033[0m: Run dynamic debugging.\n");
    printf(" \033[34mq\033[0m: Exit program.\n");
}