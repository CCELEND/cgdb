
#include "dyn_fun.h"

void arg_error(const char* fname){
    printf("\033[31m\033[1m[-] Usage: %s <binary>\033[0m\n", fname);
    exit(EXIT_FAILURE);
}

void err_exit(const char *msg)
{
    printf("\033[31m\033[1m[-] %s\033[0m\n", msg);
    exit(EXIT_FAILURE);
}

void err_info(const char *msg)
{
    printf("\033[31m\033[1m[-] %s\033[0m\n", msg);
}

void note_info(const char *msg)
{
    printf("\033[34m\033[1m[*] %s\033[0m\n", msg);
}

void good_info(const char *msg)
{
    printf("\033[32m\033[1m[+] %s\033[0m\n", msg);
}

//解析输入参数
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

// 输出寄存器
void show_regs(pid_t child, struct user_regs_struct* regs)
{
    printf("\033[34m──────────────[ REGISTERS ]──────────────\033[0m\n");
    ptrace(PTRACE_GETREGS, child, nullptr, regs);
	printf(
		"RAX      0x%llx\nRBX      0x%llx\nRCX      0x%llx\nRDX      0x%llx\nRDI      0x%llx\n"
		"RSI      0x%llx\nR8       0x%llx\nR9       0x%llx\nR10      0x%llx\nR11      0x%llx\n"
		"R12      0x%llx\nR13      0x%llx\nR14      0x%llx\nR15      0x%llx\nEFLAGS   0x%llx\n"
		"RBP      0x%llx\nRSP      \033[33m0x%llx\033[0m\nRIP      \033[31m0x%llx\033[0m\n",
		regs->rax, regs->rbx, regs->rcx, regs->rdx, regs->rdi,
		regs->rsi, regs->r8, regs->r9, regs->r10, regs->r11,
		regs->r12, regs->r13, regs->r14, regs->r15, regs->eflags,
		regs->rbp, regs->rsp, regs->rip
    );
    printf("\033[34m────────────────────────────────────[ DISASM ]────────────────────────────────────\033[0m\n");
}

int get_rip_data(pid_t child, unsigned long long addr, char* codes)
{
    char buf[128];
    union u {
        long val;
        char chars[LONG_SIZE];
    } word{};

    printf("%llx\n", addr);

    for (int i = 0; i < 64; i += LONG_SIZE){
        word.val = ptrace(PTRACE_PEEKDATA, child, addr + i, nullptr);
        if (word.val == -1)
            err_info("Trace error!");
        memcpy(buf + i, word.chars, LONG_SIZE); //将这8个字节拷贝进数组
        for (int j = i; j < i+4; j++){
            printf("%02x ", (unsigned char)buf[j]);
            if (long((unsigned char)buf[j]) == 0xe8 || long((unsigned char)buf[j]) == 0xc3 || long((unsigned char)buf[j]) == 0xeb)  {
                memcpy(codes, buf, i+8);
                return (i+8);
            }
        }
    }
    return 0;
}

/* *
 * 从子进程指定地址读取数据
 * child: 子进程pid号
 * addr: 地址
 * str: 用来存储读取的字节
 * len: 读取字节长度
 * */
void get_data(pid_t child, unsigned long long addr, char* str, int len) {
    char* laddr = str;
    int i = 0, j = len / LONG_SIZE;//计算一共需要读取多少个字
    union u {
        long val;
        char chars[LONG_SIZE];
    } word{};
    while (i < j) {//每次读取1个字，8个字节，每次地址加8(LONG_SIZE)
        word.val = ptrace(PTRACE_PEEKDATA, child, addr + i * LONG_SIZE, nullptr);
        if (word.val == -1)
            err_info("Trace error!");
        memcpy(laddr, word.chars, LONG_SIZE);//将这8个字节拷贝进数组
        ++i;
        laddr += LONG_SIZE;
    }
    j = len % LONG_SIZE;//不足一个字的虚读一个字
    if (j != 0) {
        word.val = ptrace(PTRACE_PEEKDATA, child, addr + i * LONG_SIZE, nullptr);
        if (word.val == -1)
            err_info("Trace error!");
    }
    str[len] = '\0';
}

/* *
 * 从子进程指定地址插入数据
 * child: 子进程pid号
 * addr: 地址
 * str: 用来插入的字节
 * len: 插入字节数
 * */
void put_data(pid_t child, unsigned long long addr, char* str, int len) {
    char* laddr = str;//与getdata类似
    int i = 0, j = len / LONG_SIZE;
    union u {
        long val;
        char chars[LONG_SIZE];
    } word{};
    while (i < j) {
        memcpy(word.chars, laddr, LONG_SIZE);
        if (ptrace(PTRACE_POKEDATA, child, addr + i * LONG_SIZE, word.val) == -1)
            err_info("Trace error!");
        ++i;
        laddr += LONG_SIZE;
    }
    j = len % LONG_SIZE;
    if (j != 0) {
        word.val = 0;
        memcpy(word.chars, laddr, j);
        if (ptrace(PTRACE_POKEDATA, child, addr + i * LONG_SIZE, word.val) == -1)
            err_info("Trace error!");
    }
}

/* *
 * 按字节打印数据
 * tip: 可以附带 字符串输出
 * codes: 需要打印的字节
 * len: 需要打印的字节数
 * */
void print_bytes(const char* tip, char* codes, int len) {

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
    get_data(pid, addr + offset, memory_content, nbytes);//从指定的地址按照指定的偏移量读取指定的字节数
    printf("The %d bytes after start address: 0x%llx :\n", nbytes, addr + offset);
    print_bytes("", memory_content, nbytes);
}

/* *
 * 注入断点
 * pid: 子进程pid
 * bp: 断点结构体
 * 
 */
void break_point_inject(pid_t pid, break_point& bp) {
    char code[LONG_SIZE] = { static_cast<char>(0xcc) };//int3中断指令

    // print_bytes("[+] Set break point instruction: ", code, LONG_SIZE);
    put_data(pid, bp.addr, code, CODE_SIZE);    //将中断指令int3注入
    bp.break_point_mode = true;     //将断点模式标识变量置为true
}

/* *
 * 等待断点，判断是否命中
 * pid: 子进程pid
 * status: 由外部传入，获取当前trace停止的状态码
 * bp: 断点结构体
 * */
int wait_break_point(pid_t pid, int status, break_point& bp) {
    struct user_regs_struct regs{};
    /* 捕获信号之后判断信号类型	*/
    if (WIFEXITED(status)) {
        /* 如果是EXit信号 */
        err_exit("Subprocess EXITED!");
        // printf("\n\n");
        // exit(0);
    }
    if (WIFSTOPPED(status)) {
        /* 如果是STOP信号 */
        if (WSTOPSIG(status) == SIGTRAP) {                //如果是触发了SIGTRAP,说明碰到了断点
            ptrace(PTRACE_GETREGS, pid, 0, &regs);    //读取此时用户态寄存器的值，准备为回退做准备
            /* 将此时的指针与我的addr做对比，如果满足关系，说明断点命中 */
            if (bp.addr != (regs.rip - 1)) {
                /*未命中*/
                printf("Miss, fail to hit, RIP: 0x%llx\n", regs.rip);
                return -1;
            } else {
                /*如果命中*/
                printf("Hit break point at: \033[31m0x%llx\033[0m\n", bp.addr);
                /*把INT 3 patch 回本来正常的指令*/
                put_data(pid, bp.addr, bp.backup, CODE_SIZE);
                ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
                /*执行流回退，重新执行正确的指令*/
                regs.rip = bp.addr;//addr与rip不相等，恢复时以addr为准
                ptrace(PTRACE_SETREGS, pid, 0, &regs);
                bp.break_point_mode = false;//命中断点之后取消断点状态
                return 1;
            }
        }
    }
    return 0;
}

/* *
 * 获取子进程再虚拟地址空间的起始地址
 * pid: 子进程pid
 * base_addr: 用来存储起始地址
 * */
void get_base_address(pid_t pid, unsigned long long& base_addr) {
    /* *
     * 每个进程的内存分布文件放在/proc/进程pid/maps文件夹里
     * 通过获取pid来读取对应的maps文件
     * */
    string maps_path = "/proc/" + to_string(pid) + "/maps";
    ifstream inf(maps_path.data());//建立输入流
    if (!inf) {
        err_info("Read failed!");
        return;
    }
    string line;
    getline(inf, line);//读第一行，根据文件的特点，起始地址之后是"-"字符
    base_addr = strtol(line.data(), nullptr, 16);//默认读到"-"字符为止，16进制
    printf("[+] Base addr: 0x%llx\n", base_addr);
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
    printf("Type \"reg\" or \"r\" to show registers.\n");
    printf("Type \"step\" or \"s\" to single step.\n");
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
    printf("Type \"break\" or \"b\" to insert break_point.\n"
           "\tfor example: Type \"b 555555555131\" to specify the break_point address 0x555555555131\n");
}