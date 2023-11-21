
#include "dyn_fun.h"

// │   │       ├── cmdline └──

// root node
fun_tree_node_t* root_node = NULL;

fun_tree_node_t* creat_node(u64 addr)
{
    string fun_name;
    u64 fun_start_addr, fun_end_addr;

    fun_tree_node_t* node = NULL;

    // printf("111\n");
    fun_name = get_fun(addr, &fun_start_addr);
    // printf("222\n");
    get_fun_addr((char*)fun_name.c_str(), &fun_start_addr, &fun_end_addr); // 3434

    node = new fun_tree_node_t;
    printf("666\n");
    if (!node) {
        printf("[-] Failed to create node!\n");
        return NULL;
    }
    memset(node, 0, sizeof(struct fun_tree_node));

    node->next = NULL;
    node->sub_fun = NULL;
    node->sub_fun_num = 0;
    node->fun_info.fun_name = fun_name;
    node->fun_info.fun_start_addr = fun_start_addr;
    node->fun_info.fun_end_addr = fun_end_addr;

    return node;
}

void insert_sub_link(u64 sub_fun_addr, fun_tree_node_t* parent_node)
{
    if ( sub_fun_addr >= parent_node->fun_info.fun_start_addr && 
         sub_fun_addr <= parent_node->fun_info.fun_end_addr )
        return;

    fun_tree_node_t *temp = NULL, *sub_node = NULL;

    if (!parent_node->sub_fun)
    {
        sub_node = creat_node(sub_fun_addr);
        printf("head: %s---\n", sub_node->fun_info.fun_name.c_str());
        // printf("%p\n", sub_node);
        parent_node->sub_fun = sub_node;
        parent_node->sub_fun_num++;
        return;
    }

    for(temp = parent_node->sub_fun; temp; temp = temp->next)
    {

        if ( sub_fun_addr >= temp->fun_info.fun_start_addr && 
             sub_fun_addr <= temp->fun_info.fun_end_addr )
        {
            break;
        }

        if (!temp->next)
        {
            sub_node = creat_node(sub_fun_addr);
            printf("%s-------\n", sub_node->fun_info.fun_name.c_str());
            // printf("%p\n", sub_node);
            temp->next = sub_node;
            parent_node->sub_fun_num++;
            break;
        }
    }
}

void parent_disasm(pid_t pid, char* byte_codes, u64 parent_fun_addr, s32 parent_fun_size,
    fun_tree_node_t* parent_node)
{
    // csh handle = 0;
    cs_insn* insn = NULL;
    size_t count;

    // if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) 
    // {
    //     printf("\033[31m\033[1m[-] Failed to initialize Capstone!\033[0m\n");
    //     return;
    // }

    // printf("888\n");
    count = cs_disasm(handle, (uint8_t*)byte_codes, parent_fun_size, parent_fun_addr, 0, &insn);
    // printf("999\n");

    if (count > 0) {
        size_t j;
        for (j = 0; j < count; j++) 
        {
            if (judg_jump(insn[j].mnemonic))
            {
                u64 sub_fun_addr = 0;
                printf("%s, %s\n",insn[j].mnemonic, insn[j].op_str);

                // u64 fun_start_addr;
                if (!strcmp(insn[j].mnemonic, "bnd jmp"))
                {
                    u64 got_addr;
                    got_addr = insn[j].address + get_hex_in_string(insn[j].op_str) + 7;
                    sub_fun_addr = get_addr_val(pid, got_addr);
                    printf("0x%llx\n", sub_fun_addr);
                }
                else
                {
                    sub_fun_addr = strtoul(insn[j].op_str, nullptr, 16);
                    if (!sub_fun_addr)
                        continue;
                }
                insert_sub_link(sub_fun_addr, parent_node);
            }
        }

        cs_free(insn, count);
    }
    else printf("\033[31m\033[1m[-] Failed to disassemble given code!\033[0m\n");

    // cs_close(&handle);
}

// 建立根节点
s32 creat_root_node(char* root_fun_name)
{
    u64 r_fun_start_addr, r_fun_end_addr;
    string r_fun_name;

    get_fun_addr(root_fun_name, &r_fun_start_addr, &r_fun_end_addr);
    if (!r_fun_start_addr)
    {
        err_info("There is no such function!");
        return -1;
    }

    // printf("0x%llx-0x%llx\n", fun_start_addr, fun_end_addr);
    r_fun_name = string(root_fun_name);

    root_node = new fun_tree_node_t;
    if (!root_node) return -1;
    memset(root_node, 0, sizeof(struct fun_tree_node));

    root_node->next = NULL;
    root_node->sub_fun = NULL;
    root_node->sub_fun_num = 0;
    root_node->fun_info.fun_name = r_fun_name;
    root_node->fun_info.fun_start_addr = r_fun_start_addr;
    root_node->fun_info.fun_end_addr = r_fun_end_addr;

    return 0;
}

// 根据父节点数据建立子函数链表
s32 creat_sub_link(pid_t pid, fun_tree_node_t* parent_node)
{
    u64 p_fun_start_addr, p_fun_end_addr, p_fun_size;
    string p_fun_name;
    char* p_fun_code = NULL;

    p_fun_name = parent_node->fun_info.fun_name;
    p_fun_start_addr = parent_node->fun_info.fun_start_addr;
    p_fun_end_addr = parent_node->fun_info.fun_end_addr;

    p_fun_size = p_fun_end_addr - p_fun_start_addr;
    p_fun_size = p_fun_size + LONG_SIZE - p_fun_size % LONG_SIZE; // 8字节对齐

    p_fun_code = new char[p_fun_size];
    memset(p_fun_code, 0, p_fun_size);

    get_addr_data(pid, p_fun_start_addr, p_fun_code, p_fun_size);
    parent_disasm(pid, p_fun_code, p_fun_start_addr, p_fun_size, parent_node);

    // printf("%p\n", parent_node);

    delete[] p_fun_code;
    p_fun_code = NULL;

    return 0;
}


void free_fun_tree()
{
    vector<fun_tree_node_t*> sib_link_next_node;
    fun_tree_node_t *temp = NULL, *parent_node = root_node;

    printf("free-----------------\n");

    while(parent_node)
    {
        printf("%s\n", parent_node->fun_info.fun_name.c_str());
        // 当前节点兄节点压栈
        sib_link_next_node.push_back(parent_node->next);
        temp = parent_node;
        // printf("%p\n", temp);

        // 当前节点有子
        if (parent_node->sub_fun)
        {
            parent_node = parent_node->sub_fun;
        }
        // 当前节点无子
        else
        {
            printf("free no sub: %ld\n", sib_link_next_node.size());
            // 弹出空值
            while (!sib_link_next_node.back())
            {
                sib_link_next_node.pop_back();
            }
            // printf("freeno: %ld\n", sib_link_next_node.size());

            if (!sib_link_next_node.size())
            {
                printf("free3\n");
                // memset(temp, 0, sizeof(struct fun_tree_node));
                delete temp;
                break;
            }

            parent_node = sib_link_next_node.back();
            sib_link_next_node.pop_back();
        }

        // printf("%p\n", temp);
        // memset(temp, 0, sizeof(struct fun_tree_node));
        delete temp;
    }
}

void show_fun_tree(s32 level)
{
    vector<fun_tree_node_t*> sib_link_next_node;
    fun_tree_node_t* temp_node = root_node;
    int depth = 0;

    sib_link_next_node.push_back(temp_node->next);
    // 输出根节点
    printf("%s\n", temp_node->fun_info.fun_name.c_str());
    if (temp_node->sub_fun)
    {
        temp_node = temp_node->sub_fun;
        // 层级加1
        ++depth;
    }
    else return;

    while(temp_node)
    {

        // 当前节点兄弟节点压栈
        sib_link_next_node.push_back(temp_node->next);

        // 输出当前节点
        // for (int i = 0; i < depth-2; i++) printf("│   ");
        for (int i = 0; i < depth-1; i++) printf("│   ");

        // for (int i = 0; i < depth-1; i++) printf("    ");
        // temp_node->fun_info.fun_start_addr
        if (temp_node->next)
            printf("├── %s\n", temp_node->fun_info.fun_name.c_str());
            // printf("├── %s 0x%llx\n", temp_node->fun_info.fun_name.c_str(), 
            //     temp_node->fun_info.fun_start_addr);
        else
            printf("└── %s\n", temp_node->fun_info.fun_name.c_str());
            // printf("└── %s 0x%llx\n", temp_node->fun_info.fun_name.c_str(), 
            //     temp_node->fun_info.fun_start_addr);

        // 当前节点有子
        if (temp_node->sub_fun)
        {
            temp_node = temp_node->sub_fun;
            ++depth;
        }
        // 当前节点无子
        else
        {
            // 弹出空值
            while (!sib_link_next_node.back())
            {
                sib_link_next_node.pop_back();
                --depth;
            }

            if (!sib_link_next_node.size()) break;

            temp_node = sib_link_next_node.back();
            sib_link_next_node.pop_back();
        }


    }
}

// level 2
void creat_fun_tree(pid_t pid, s32 level)
{
    vector<fun_tree_node_t*> sib_link_next_node;
    fun_tree_node_t* parent_node = root_node;
    int current_depth = 0;

    // printf("%ld\n", sizeof(struct fun_tree_node));

    while(parent_node)
    {
        printf("%s\n", parent_node->fun_info.fun_name.c_str());
        // 当前节点兄节点压栈
        sib_link_next_node.push_back(parent_node->next);

        if (current_depth < level)
            creat_sub_link(pid, parent_node);
        else
            break;

        // 当前节点有子
        if (parent_node->sub_fun && current_depth+1 < level)
        {
            parent_node = parent_node->sub_fun;
            ++current_depth;
        }
        // 当前节点无子, 或者到达层数限制
        else
        {
            // 当前节点无兄
            while (!sib_link_next_node.back() && current_depth != 0)
            {
                sib_link_next_node.pop_back();
                --current_depth;
            }
            parent_node = sib_link_next_node.back();
            sib_link_next_node.pop_back();
        }
    }

}

// sib_link_next_node.push_back(parent_node->next);
// = sib_link_next_node.back();
// sib_link_next_node.pop_back();
