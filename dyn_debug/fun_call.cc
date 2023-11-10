
#include "dyn_fun.h"

void show_elf_fun_call(pid_t pid, char* elf_fun_name, Binary* bin)
{
    char fun_code[0x1000];
    unsigned long long fun_start_addr, fun_end_addr, fun_size;
    string fun_name;

    fun_start_addr = get_elf_fun_addr(elf_fun_name, bin);
    if (!fun_start_addr){
        err_info("There is no such function!");
        return;
    }
    fun_name = string(elf_fun_name);
    fun_end_addr = elf_fun_end[fun_name];

    fun_size = fun_end_addr - fun_start_addr;
    // 8字节对齐
    fun_size = fun_size + LONG_SIZE - fun_size % LONG_SIZE;

    get_addr_data(pid, fun_start_addr, fun_code, fun_size);
    printf("0x%llx-0x%llx\n", fun_start_addr, fun_end_addr);
    printf("\033[31m%s\033[0m():\n", fun_name.c_str());
    call_disasm(fun_code, fun_start_addr, fun_size, fun_name);

}

