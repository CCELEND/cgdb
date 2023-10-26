
#include "loader_elf.h"

void show_elf_help() {
    printf("sym: Show function symbols.\n");
    printf("dyn: Show dynamic symbols.\n");
    printf("sections: Display sections of code and data types for elf.\n");
    printf("got: Display got.\n");
    printf("plt: Display PLT content.\n");
    printf("lplt: Display the PLT address of the libc function..\n");
    printf("r: Run dynamic debugging.\n");
}