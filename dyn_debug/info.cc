
#include "dyn_fun.h"

void arg_error(const char* fname){
    printf("\033[31m\033[1m[-] Usage: %s <binary>\033[0m\n", fname);
    exit(EXIT_FAILURE);
}

void err_exit(const char* msg)
{
    printf("\033[31m\033[1m[-] %s\033[0m\n", msg);
    exit(EXIT_FAILURE);
}

void err_info(const char* msg)
{
    printf("\033[31m\033[1m[-] %s\033[0m\n", msg);
}

void note_info(const char* msg)
{
    printf("\033[34m\033[1m[*] %s\033[0m\n", msg);
}

void good_info(const char* msg)
{
    printf("\033[32m\033[1m[+] %s\033[0m\n", msg);
}

void show_str(int count)
{
    for (int i = 0; i < count; i++)
        printf("\033[34m─");
}

