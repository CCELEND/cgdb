#include "loader_elf.h"

// 显示 got
void show_elf_got()
{
    std::string command = std::string("objdump -R ") + fname;
    // 执行命令并将标准输出连接到文件流中
    FILE* fp = popen(command.c_str(), "r");
    if (!fp)
    {
        printf("\033[31m\033[1m[-] Popen failed!\033[0m\n");
        return;
    }

    char *result = nullptr;
    size_t len = 0;
    ssize_t read;

    while ((read = getline(&result, &len, fp)) != -1) {
        if (strcmp(result, "\n") != 0 && std::string(result).find("elf64-x86-64") == std::string::npos)
            std::cout << result;
    }

    pclose(fp);   // 关闭管道
    free(result); // 释放动态分配的内存
}

// 显示 libc plt
void show_elf_plt()
{
    std::string command = std::string("objdump -d -j .plt.sec -M intel ") + fname;
    // 执行命令并将标准输出连接到文件流中
    FILE* fp = popen(command.c_str(), "r");
    if (!fp)
    {
        printf("\033[31m\033[1m[-] Popen failed!\033[0m\n");
        return;
    }

    char *result = nullptr;
    size_t len = 0;
    ssize_t read;

    while ((read = getline(&result, &len, fp)) != -1) {
        // 处理每一行输出
        if (strcmp(result, "\n") != 0 && std::string(result).find("elf64-x86-64") == std::string::npos
            && std::string(result).find("Disassembly") == std::string::npos){
            std::cout << result;
        }
    }

    pclose(fp);   // 关闭管道
    free(result); // 释放动态分配的内存
}

// 显示 libc plt
void show_elf_lib_plt()
{
    printf("[+] Libc function \033[32m<@plt>\033[0m\n");
    printf("%-30saddress\n", "name");
    printf("=====================================\n");
    for (auto it : elf_plt_fun) {
        printf("%-30s0x%llx\n", it.first.c_str(), it.second);
    }
}

// 显示符号表
void show_elf_symbol(Binary* bin)
{
    Symbol *sym;

    printf("[+] Symbol tables (\033[32mFUNC\033[0m)\n");
    printf("    %-31s %18s   %s\n", "name", "address", "type");
    printf("======================================================================\n");

    for(int i = 0; i < bin->symbols.size(); i++) 
    {
        sym = &bin->symbols[i];
        if(sym->fun_sym_type == "symtab")
        {
            printf("%-35s 0x%016jx   %s  %s\n", 
                sym->name.c_str(), sym->addr, 
                (sym->type & Symbol::SYM_TYPE_FUNC) ? "FUNC" : "", sym->fun_sym_type.c_str());
        }
    }

    printf("\033[34mmodule internal symbol table:\033[0m\n");
    for(int i = 0; i < bin->symbols.size(); i++) {
        sym = &bin->symbols[i];
        if(sym->addr){
            printf("%-35s 0x%016jx   %s  %s\n", 
                sym->name.c_str(), sym->addr, 
                (sym->type & Symbol::SYM_TYPE_FUNC) ? "FUNC" : "", sym->fun_sym_type.c_str());
        }
    }
}

// 显示动态符号表
void show_elf_dynsym(Binary* bin)
{
    Symbol *sym;

    printf("[+] Dynamic symbol (\033[32mFUNC\033[0m)\n");
    printf("    %-31s %18s   %s\n", "name", "address", "type");
    printf("======================================================================\n");

    for(int i = 0; i < bin->symbols.size(); i++) 
    {
        sym = &bin->symbols[i];
        if(sym->fun_sym_type == "dynsym")
        {
            printf("%-35s 0x%016jx   %s  %s\n", 
                sym->name.c_str(), sym->addr, 
                (sym->type & Symbol::SYM_TYPE_FUNC) ? "FUNC" : "", sym->fun_sym_type.c_str());
        }
    }
}

// 显示代码和数据段
void show_elf_sections_code_data(Binary* bin)
{
    Section *sec;

    printf("[+] sections (\033[31mcode\033[0m | \033[35mdata\033[0m)\n");
    printf("%18s   %-8s %-20s %s\n", "vma", "size", "name", "type");
    printf("========================================================\n");
    for(int i = 0; i < bin->sections.size(); i++) 
    {
        sec = &bin->sections[i];
        printf("0x%016jx   %-8ju %-20s %s\n", 
            sec->vma, sec->size, sec->name.c_str(), 
            sec->type == Section::SEC_TYPE_CODE ? "CODE" : "DATA");
    }
}
