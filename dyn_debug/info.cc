
#include "dyn_fun.h"

void 
arg_error(const char* cgdb){
    printf("[-] Usage: %s <binary>\n", cgdb);
    exit(EXIT_FAILURE);
}

void 
err_exit(const char* msg)
{
    printf("\033[31m\033[1m[-] %s\033[0m\n", msg);
    exit(EXIT_FAILURE);
}

void 
err_info(const char* msg)
{
    printf("\033[31m\033[1m[-] %s\033[0m\n", msg);
}

void 
note_info(const char* msg)
{
    printf("\033[34m\033[1m[*] %s\033[0m\n", msg);
}

void 
good_info(const char* msg)
{
    printf("\033[32m\033[1m[+] %s\033[0m\n", msg);
}

void 
show_str(s32 count)
{
    for (s32 i = 0; i < count; i++)
        printf("\033[34m─");
}

