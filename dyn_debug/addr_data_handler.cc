
#include "dyn_fun.h"

unsigned long long get_addr_val(pid_t pid, unsigned long long addr)
{
    unsigned long long  val;
    val = ptrace(PTRACE_PEEKDATA, pid, addr, nullptr);
    return val;
}

// 从子进程指定地址读取 len 字节长度数据到 str
void get_addr_data(pid_t pid, unsigned long long addr, char* str, int len) 
{
    char* laddr = str;
    int i = 0, j = len / LONG_SIZE; // 计算一共需要读取多少个字
    union u {
        long val;
        char chars[LONG_SIZE];
    } word{};

    while (i < j) { // 每次读取1个字，8个字节，每次地址加8(LONG_SIZE)
        word.val = ptrace(PTRACE_PEEKDATA, pid, addr + i * LONG_SIZE, nullptr);
        if (word.val == -1) err_info("Trace error!");
        memcpy(laddr, word.chars, LONG_SIZE);//将这8个字节拷贝进数组
        ++i;
        laddr += LONG_SIZE;
    }
    j = len % LONG_SIZE;// 不足一个字的虚读一个字
    if (j != 0) {
        word.val = ptrace(PTRACE_PEEKDATA, pid, addr + i * LONG_SIZE, nullptr);
        if (word.val == -1) err_info("Trace error!");
    }
    str[len] = '\0';
}

// 从 str 插入 len 字节长度数据到子进程指定地址
void put_addr_data(pid_t pid, unsigned long long addr, char* str, int len) 
{
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

// 按照字节打印数据，可附带提示信息
void print_bytes(const char* tip, char* codes, int len) 
{
    int i;

    printf("%s", tip);
    for (i = 0; i < len; ++i) 
    {
        printf("%02x", (unsigned char) codes[i]);
        if ((i + 1) % 8 == 0) printf("\n");
    }
}

// 输出带颜色的地址以标记所属地址范围 addr_flag 为真会显示地址所属文件
void flag_addr_printf(unsigned long long addr, bool addr_flag)
{
    if (addr == 0) {
        printf("0x%llx", addr);
        return;
    }

    if (addr_flag)  // true
    {
        if (addr > elf_code_start && addr < elf_code_end) {
            printf("\033[31m0x%llx\033[0m (elf)", addr);
        } else if (addr > libc_code_start && addr < libc_code_end) {
            printf("\033[31m0x%llx\033[0m (libc)", addr);
        } else if (addr > stack_base) {
            printf("\033[33m0x%llx\033[0m (stack)", addr);
        } else if (!ld_base || addr > ld_code_start && addr < ld_code_end){
            printf("\033[31m0x%llx\033[0m (ld-linux)", addr);
        }
        else {
            printf("0x%llx", addr);
        }
    }
    else
    {
        if (judg_addr_code(addr)){
            printf("\033[31m0x%llx\033[0m", addr);
        } else if (addr > stack_base && addr < stack_end) {
            printf("\033[33m0x%llx\033[0m", addr);
        }
        else {
            printf("0x%llx", addr);
        }
    }
}

// 输出指定地址的数据，输出 num 组，每组8字节
void show_addr_data(pid_t pid, int num , unsigned long long addr)
{
    union u {
        long val;
        char chars[LONG_SIZE];
    } word{};
    char laddr[8];

    for (int i = 0; i < num; i++) {
        if( i % 2 == 0){
            flag_addr_printf(addr + i * LONG_SIZE, false);
            printf(": ");
        }
        printf("0x");

        word.val = ptrace(PTRACE_PEEKDATA, pid, addr + i * LONG_SIZE, nullptr);
        if (word.val == -1) err_info("Trace error!");
        memcpy(laddr, word.chars, LONG_SIZE);

        for (int j = 7; j > -1; --j)
        {
            printf("%02x", (unsigned char) laddr[j]);
            if (j == 0) printf("     ");
        }

        if (( i + 1 ) % 2 == 0 || (i + 1 ) == num) printf("\n");

    }
    // printf("\n");
}

void val_to_string(unsigned long long val)
{
    union u {
        unsigned long long val;
        char chars[LONG_SIZE];
    } word{};

    word.val = val;
    printf(" '%s'", word.chars);
}

bool judg_addr_code(unsigned long long addr)
{
    if (addr > elf_code_start && addr < elf_code_end) {
        return true;
    } else if (addr > libc_code_start && addr < libc_code_end) {
        return true;
    } else if (addr > ld_code_start && addr < ld_code_end) {
        return true;
    } else if (addr > vdso_code_start && addr < vdso_code_end) {
        return true;
    } 
    else
        return false;

}