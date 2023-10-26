
#include "./dyn_debug/dyn_fun.h"
#include "./elf/loader_elf.h"
#include "./disasm/disasm.h"

// 定义全局变量
vector<string> myargv;
string cmd;
// 键是函数名，值是地址
map<string, unsigned long long> fun_plt;

int main(int argc, char *argv[]) 
{
    Binary bin;
    Section *sec;
    Symbol *sym;
    pid_t pid;
    string fname;

    if(argc < 2) arg_error(argv[0]);

    fname.assign(argv[1]);
    printf("[*] Reading symbols from \033[34m\033[1m%s\033[0m...\n", fname.c_str());
    if(load_binary(fname, &bin, Binary::BIN_TYPE_AUTO) < 0) {
        err_exit("Program loading failed!");
    }

    map_fun_plt(fname);

    while (true) {
        printf("\033[34m\033[1mcgdb> \033[0m");
        getline(cin, cmd);

        if (cmd == "q") {
            goto cgdb_exit;
        } else if (cmd == "sym") {
            show_elf_symbol(&bin);
        } else if (cmd == "dyn") {
            show_elf_dynsym(&bin);
        } else if (cmd == "sections") {
            show_elf_sections_code_data(&bin);
        } else if (cmd == "got") {
            show_elf_got(fname);
        } else if (cmd == "plt") {
            show_elf_plt(fname);
        } else if (cmd == "lplt") {
            show_elf_lib_plt();
        } else if (cmd == "r") {
            run_dyn_debug(fname, &bin);
        } else if (cmd == "help" || cmd == "h") {
            show_elf_help();
        }
        else {
            err_info("Command not found!");
            printf("Enter 'h' to view supported commands.\n");
        }
    }
    cgdb_exit: return 0;
}