
#include "dyn_fun.h"

// 得到虚拟内存地址
void get_vma_address(pid_t pid)
{
    if (libc_base) return;

    string maps_path = "/proc/" + to_string(pid) + "/maps";
    ifstream inf(maps_path.data());//建立输入流
    if (!inf) {
        err_info("Read failed!");
        return;
    }

    string line;
    getline(inf, line);
    // 默认读到 - 字符为止，16进制
    elf_base = strtoul(line.data(), nullptr, 16);
    while(getline(inf, line))
    {
        if (line.find("-7f") == string::npos && line.find("r-xp") != string::npos && !elf_code_start) {
            elf_code_start = strtoul(line.data(), nullptr, 16);
            elf_code_end = strtoul(line.data()+13, nullptr, 16);
        } 

        else if (line.find("libc") != string::npos && !libc_base) {
            libc_base = strtoul(line.data(), nullptr, 16);
        } else if (line.find("libc") != string::npos && line.find("r-xp") != string::npos && !libc_code_start) {
            libc_code_start = strtoul(line.data(), nullptr, 16);
            libc_code_end = strtoul(line.data()+13, nullptr, 16);
        } else if (line.find("libc") != string::npos && line.find("rw-p") != string::npos && !libc_data_start){
            libc_data_start = strtoul(line.data(), nullptr, 16);
            libc_data_end = strtoul(line.data()+13, nullptr, 16);

        } else if (line.find("ld-linux") != string::npos && !ld_base) {
            ld_base = strtoul(line.data(), nullptr, 16);
        } else if (line.find("ld-linux") != string::npos && line.find("r-xp") != string::npos && !ld_code_start) {
            ld_code_start = strtoul(line.data(), nullptr, 16);
            ld_code_end = strtoul(line.data()+13, nullptr, 16);
        } else if (line.find("ld-linux") != string::npos && line.find("rw-p") != string::npos && !ld_data_start) {
            ld_data_start = strtoul(line.data(), nullptr, 16);
            ld_data_end = strtoul(line.data()+13, nullptr, 16);

        }
        else if (line.find("[stack]") != string::npos && !stack_base) {
            stack_base = strtoul(line.data(), nullptr, 16);
            stack_end = strtoul(line.data()+13, nullptr, 16);

        } else if (line.find("[heap]") != string::npos && !heap_base) {
            heap_base = strtoul(line.data(), nullptr, 16);
            heap_end = strtoul(line.data()+13, nullptr, 16);
            
        } else if (line.find("[vdso]") != string::npos && line.find("r-xp") != string::npos && !vdso_code_start) {
            vdso_code_start = strtoul(line.data(), nullptr, 16);
            vdso_code_end = strtoul(line.data()+13, nullptr, 16);
        }

    }

    inf.close();

}
 
// 显示虚拟内存地址空间
void show_vmmap(pid_t pid) 
{
    string maps_path = "/proc/" + to_string(pid) + "/maps";
    ifstream inf(maps_path.data());//建立输入流
    if (!inf) {
        err_info("Read failed!");
        return;
    }

    printf("LEGEND: "
        "\033[33mSTACK\033[0m | "
        "\033[34mHEAP\033[0m | "
        "\033[31mCODE\033[0m | "
        "\033[35mDATA\033[0m\n");
    printf("%12s%13s%5s%9s%6s%8s%24s\n",
        "Start", "End", "Perm", "Offset", "Dev", "Inode", "File"
    );

    string line;
    while(getline(inf, line))
    {
        if (line.find("-xp") != string::npos) {
            printf("\033[31m%s\033[0m\n", line.c_str());
        } else if (line.find("rw-p") != string::npos) {
            if (line.find("[stack]") != string::npos){
                printf("\033[33m%s\033[0m\n", line.c_str());
            } else if (line.find("[heap]") != string::npos){
                printf("\033[34m%s\033[0m\n", line.c_str());
            } else {
                printf("\033[35m%s\033[0m\n", line.c_str());
            }
        } else {
            printf("%s\n", line.c_str());
        }
    }

    inf.close();
}
