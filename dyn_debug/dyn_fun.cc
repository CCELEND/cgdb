
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

/* *
 * 从子进程指定地址读取数据
 * pid: 子进程pid号
 * addr: 地址
 * str: 用来存储读取的字节
 * len: 读取字节长度
 * */
void get_addr_data(pid_t pid, unsigned long long addr, char* str, int len) {
    char* laddr = str;
    int i = 0, j = len / LONG_SIZE;//计算一共需要读取多少个字
    union u {
        long val;
        char chars[LONG_SIZE];
    } word{};
    while (i < j) {//每次读取1个字，8个字节，每次地址加8(LONG_SIZE)
        word.val = ptrace(PTRACE_PEEKDATA, pid, addr + i * LONG_SIZE, nullptr);
        if (word.val == -1)
            err_info("Trace error!");
        memcpy(laddr, word.chars, LONG_SIZE);//将这8个字节拷贝进数组
        ++i;
        laddr += LONG_SIZE;
    }
    j = len % LONG_SIZE;//不足一个字的虚读一个字
    if (j != 0) {
        word.val = ptrace(PTRACE_PEEKDATA, pid, addr + i * LONG_SIZE, nullptr);
        if (word.val == -1)
            err_info("Trace error!");
    }
    str[len] = '\0';
}

/* *
 * 从子进程指定地址插入数据
 * pid: 子进程pid号
 * addr: 地址
 * str: 用来插入的字节
 * len: 插入字节数
 * */
void put_addr_data(pid_t pid, unsigned long long addr, char* str, int len) {
    char* laddr = str;
    int i = 0, j = len / LONG_SIZE;
    union u {
        long val;
        char chars[LONG_SIZE];
    } word{};
    while (i < j) {
        memcpy(word.chars, laddr, LONG_SIZE);
        if (ptrace(PTRACE_POKEDATA, pid, addr + i * LONG_SIZE, word.val) == -1)
            err_info("Trace error!");
        ++i;
        laddr += LONG_SIZE;
    }
    j = len % LONG_SIZE;
    if (j != 0) {
        word.val = 0;
        memcpy(word.chars, laddr, j);
        if (ptrace(PTRACE_POKEDATA, pid, addr + i * LONG_SIZE, word.val) == -1)
            err_info("Trace error!");
    }
}

/* *
 * 按字节打印数据
 * tip: 可以附带 字符串输出
 * codes: 需要打印的字节
 * len: 需要打印的字节数
 * */
void print_bytes(const char* tip, char* codes, int len) 
{
    int i;

    printf("%s", tip);
    for (i = 0; i < len; ++i) 
    {
        printf("%02x", (unsigned char) codes[i]);
        if ((i + 1) % 8 == 0)
            printf("\n");
    }
}

/* *
 * 显示任意内存内容
 * pid: 子进程pid
 * addr: 指定内存基地址
 * offset: 指定相对于基地址的偏移地址
 * nbytes: 需要显示的字节数
 * */
void show_memory(pid_t pid, unsigned long long addr, long offset, int nbytes) {
    printf("current base address is : 0x%llx\n"//显示任意内存内容
           "offset is : %ld\n", addr, offset);
    auto* memory_content = new char[nbytes];
    get_addr_data(pid, addr + offset, memory_content, nbytes);//从指定的地址按照指定的偏移量读取指定的字节数
    printf("The %d bytes after start address: 0x%llx :\n", nbytes, addr + offset);
    print_bytes("", memory_content, nbytes);
}

void flag_addr_printf(unsigned long long addr, bool addr_flag)
{
    if (addr == 0)
    {
        printf("0x%llx", addr);
        return;
    }

    if (addr_flag)
    {
        if (addr > elf_code_start && addr < elf_code_end) {
            printf("\033[31m0x%llx\033[0m (elf)", addr);
        } else if (addr > libc_code_start && addr < libc_code_end) {
            printf("\033[31m0x%llx\033[0m (libc)", addr);
        } else if (addr > stack_base) {
            printf("\033[33m0x%llx\033[0m (stack)", addr);
        } else {
            printf("\033[31m0x%llx\033[0m (ld-linux)", addr);
        }
    }
    else
    {
        if (addr > elf_code_start && addr < elf_code_end) {
            printf("\033[31m0x%llx\033[0m", addr);
        } else if (addr > libc_code_start && addr < libc_code_end) {
            printf("\033[31m0x%llx\033[0m", addr);
        } else if (addr > ld_code_start && addr < ld_code_end){
            printf("\033[31m0x%llx\033[0m", addr);
        } else if (addr > stack_base) {
            printf("\033[33m0x%llx\033[0m", addr);
        }
    }
}

void read_addr_data(pid_t pid, char* num , char* addr)
{
    int r_num = stoi(num);
    if (r_num < 0){
        err_info("Wrong number of reads!");
        return;
    }
    unsigned long long address = strtoul(addr, nullptr, 16);

    union u {
        long val;
        char chars[LONG_SIZE];
    } word{};
    char laddr[8];

    for (int i = 0; i < r_num; i++) {
        if( i % 2 == 0){
            flag_addr_printf(address + i * LONG_SIZE, false);
            printf(": ");
        }
        printf("0x");

        word.val = ptrace(PTRACE_PEEKDATA, pid, address + i * LONG_SIZE, nullptr);
        if (word.val == -1)
            err_info("Trace error!");
        memcpy(laddr, word.chars, LONG_SIZE);

        for (int j = 7; j > -1; --j)
        {
            printf("%02x", (unsigned char) laddr[j]);
            if (j == 0)
                printf("      ");
        }

        if (( i + 1 ) % 2 == 0){
            printf("\n");
        }

    }
}

/* *
 * 获取子进程再虚拟地址空间的起始地址
 * pid: 子进程 pid
 * base_addr: 用来存储起始地址
 * */
void get_base_address(pid_t pid) {
    /* *
     * 每个进程的内存分布文件放在/proc/进程pid/maps文件夹里
     * 通过获取pid来读取对应的maps文件
     * */
    if (libc_base) return;

    string maps_path = "/proc/" + to_string(pid) + "/maps";
    ifstream inf(maps_path.data());//建立输入流
    if (!inf) {
        err_info("Read failed!");
        return;
    }
    string line;
    getline(inf, line);//读第一行，根据文件的特点，起始地址之后是"-"字符
    elf_base = strtoul(line.data(), nullptr, 16);//默认读到"-"字符为止，16进制

    while(getline(inf, line))
    {
        if (line.find("libc") != string::npos && !libc_base) {
            libc_base = strtoul(line.data(), nullptr, 16);

        } else if (line.find("ld-linux") != string::npos && !ld_base) {
            ld_base = strtoul(line.data(), nullptr, 16);

        } else if (line.find("[stack]") != string::npos && !stack_base) {
            stack_base = strtoul(line.data(), nullptr, 16);
            stack_end = strtoul(line.data()+13, nullptr, 16);

        }
    }

    inf.close();
}

void get_code_address(pid_t pid) {
    /* *
     * 每个进程的内存分布文件放在/proc/进程pid/maps文件夹里
     * 通过获取pid来读取对应的maps文件
     * */

    if (libc_code_start) return;

    string maps_path = "/proc/" + to_string(pid) + "/maps";
    ifstream inf(maps_path.data());//建立输入流
    if (!inf) {
        err_info("Read failed!");
        return;
    }

    string line;
    while(getline(inf, line))
    {
        if (line.find("-7f") == string::npos && line.find("r-xp") != string::npos && !elf_code_start) {
            elf_code_start = strtoul(line.data(), nullptr, 16);
            elf_code_end = strtoul(line.data()+13, nullptr, 16);

        } else if (line.find("libc") != string::npos && line.find("r-xp") != string::npos && !libc_code_start) {
            libc_code_start = strtoul(line.data(), nullptr, 16);
            libc_code_end = strtoul(line.data()+13, nullptr, 16);

        } else if (line.find("ld-linux") != string::npos && line.find("r-xp") != string::npos && !ld_code_start) {
            ld_code_start = strtoul(line.data(), nullptr, 16);
            ld_code_end = strtoul(line.data()+13, nullptr, 16);
        }
    }

    inf.close();
}

void get_vmmap(pid_t pid){
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