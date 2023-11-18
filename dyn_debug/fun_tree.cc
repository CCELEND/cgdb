
#include "dyn_fun.h"

// │   │       ├── cmdline └──

fun_tree_node_t* level_node = NULL;
fun_tree_node_t* root_node = NULL;
fun_tree_node_t* parent_node = NULL;
fun_tree_node_t* sub_node = NULL;
char* fun_code = NULL;

// void set_sub_node_link(string sub_fun_name)
// {
//     fun_tree_node_t* temp = NULL;
//     sub_node = (fun_tree_node_t*)calloc(1, sizeof(struct fun_tree_node));

//     sub_node->fun_info.fun_name = sub_fun_name;
//     sub_node->next = NULL;

//     if (!parent_node->sub_fun && parent_node->fun_info.fun_name != sub_node->fun_info.fun_name)
//     {
//         parent_node->sub_fun = sub_node;
//         parent_node->sub_fun_num++;
//         return;
//     }

//     for(temp = parent_node->sub_fun; temp; temp = temp->next)
//     {

//         if ( temp->fun_info.fun_name == sub_node->fun_info.fun_name )
//         {
//             free(sub_node);
//             sub_node = NULL;
//             break;
//         }

//         if (!temp->next)
//         {
//             temp->next = sub_node;
//             parent_node->sub_fun_num++;
//             break;
//         }
//     }
// }

fun_tree_node_t* creat_fun_tree_node(u64 addr)
{
    u64 fun_start_addr, fun_end_addr;
    string fun_name;

    fun_tree_node_t* node = NULL;

    fun_name = get_fun(addr, &fun_start_addr);
    get_fun_addr((char*)fun_name.c_str(), &fun_start_addr, &fun_end_addr);

    node = (fun_tree_node_t*)calloc(1, sizeof(struct fun_tree_node));
    node->next = NULL;
    node->sub_fun = NULL;
    node->sub_fun_num = 0;
    node->fun_info.fun_name = fun_name;
    node->fun_info.fun_start_addr = fun_start_addr;
    node->fun_info.fun_end_addr = fun_end_addr;

    return node;
}

void set_sub_node_link(u64 sub_fun_addr)
{
    if ( sub_fun_addr >= parent_node->fun_info.fun_start_addr && 
         sub_fun_addr <= parent_node->fun_info.fun_end_addr )
        return;

    fun_tree_node_t* temp = NULL;

    if (!parent_node->sub_fun)
    {
        sub_node = creat_fun_tree_node(sub_fun_addr);
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
            sub_node = creat_fun_tree_node(sub_fun_addr);
            temp->next = sub_node;
            parent_node->sub_fun_num++;
            break;
        }
    }
}

void tree_disasm(pid_t pid, char* byte_codes, u64 parent_fun_addr, s32 num, string parent_fun_name)
{
    csh handle;
    cs_insn* insn;
    size_t count;
    u64 sub_fun_addr;
    string sub_fun_name;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        printf("\033[31m\033[1m[-] Failed to initialize Capstone!\033[0m\n");
        return;
    }    

    count = cs_disasm(handle, (uint8_t*)byte_codes, num, parent_fun_addr, 0, &insn);
    if (count > 0) {
        size_t j;
        for (j = 0; j < count; j++) 
        {
            if (judg_jump(insn[j].mnemonic))
            {
                printf("%s, %s\n",insn[j].mnemonic, insn[j].op_str);

                u64 fun_start_addr;
                if (!strcmp(insn[j].mnemonic, "bnd jmp"))
                {
                    u64 got_addr;
                    got_addr = insn[j].address + get_hex_in_string(insn[j].op_str) + 7;
                    sub_fun_addr = get_addr_val(pid, got_addr);
                }
                else
                {
                    sub_fun_addr = strtoul(insn[j].op_str, nullptr, 16);
                    if (!sub_fun_addr)
                        continue;
                }

                set_sub_node_link(sub_fun_addr);
            } 
        }
        cs_free(insn, count);
    }
    else printf("\033[31m\033[1m[-] Failed to disassemble given code!\n");

    cs_close(&handle);
}

// 建立根节点
s32 set_root_node(char* root_fun_name)
{
    u64 fun_start_addr, fun_end_addr, fun_size;
    string fun_name;

    get_fun_addr(root_fun_name, &fun_start_addr, &fun_end_addr);
    if (!fun_start_addr)
    {
        err_info("There is no such function!");
        return -1;
    }

    fun_name = string(root_fun_name);
    // printf("0x%llx-0x%llx\n", fun_start_addr, fun_end_addr);
    fun_size = fun_end_addr - fun_start_addr;
    // 8字节对齐
    fun_size = fun_size + LONG_SIZE - fun_size % LONG_SIZE;
    fun_code = (char*)calloc(1, fun_size);

    root_node = (fun_tree_node_t*)calloc(1, sizeof(struct fun_tree_node));
    root_node->next = NULL;
    root_node->sub_fun = NULL;
    root_node->sub_fun_num = 0;
    root_node->fun_info.fun_name = fun_name;
    root_node->fun_info.fun_start_addr = fun_start_addr;
    root_node->fun_info.fun_end_addr = fun_end_addr;

    level_node = root_node;

    return 0;

}

// 根据父节点数据建立子函数链表
s32 set_parent_sub_node(pid_t pid)
{
    u64 fun_start_addr, fun_end_addr, fun_size;
    string fun_name;

    fun_name = parent_node->fun_info.fun_name;
    fun_start_addr = parent_node->fun_info.fun_start_addr;
    fun_end_addr = parent_node->fun_info.fun_end_addr;

    fun_size = fun_end_addr - fun_start_addr;
    // 8字节对齐
    fun_size = fun_size + LONG_SIZE - fun_size % LONG_SIZE;
    fun_code = (char*)calloc(1, fun_size);

    get_addr_data(pid, fun_start_addr, fun_code, fun_size);
    tree_disasm(pid, fun_code, fun_start_addr, fun_size, fun_name);

    free(fun_code);
    fun_code = NULL;

    return 0;

}


void free_fun_tree()
{
    // level_node = root_node;

    // fun_tree_node_t* head = level_node->sub_fun;
    // while(head != NULL)
    // {
    //     fun_tree_node_t* temp = head;
    //     head = head->next;
    //     free(temp);
    // }

    // free(root_node);
    // root_node = NULL;

    for (level_node = root_node->sub_fun; level_node; level_node = level_node->sub_fun)
    {
        fun_tree_node_t* head = level_node->sub_fun;
        while(head != NULL)
        {
            fun_tree_node_t* temp = head;
            head = head->next;
            free(temp);
        }
    }
}

// s32
void show_fun_tree()
{
    printf("sub fun num: %d\n", root_node->sub_fun_num);
    printf("   \033[31m%s\033[0m\n", root_node->fun_info.fun_name.c_str());

    for (level_node = root_node; level_node; level_node = level_node->sub_fun)
    {
        for(parent_node = level_node->sub_fun; parent_node; parent_node = parent_node->next)
        {
            if (!parent_node->next)
                printf("   └── \033[31m%s\033[0m\n", parent_node->fun_info.fun_name.c_str()
                    );
            else
                printf("   ├── \033[31m%s\033[0m\n", parent_node->fun_info.fun_name.c_str()
                    );
        }
    }

}

void creat_fun_tree(pid_t pid, s32 level)
{
    vector<fun_tree_node_t*> sub_link_head_next_p;

    for (int i = 0; i < level; i++)
    {
        for(parent_node = level_node; parent_node; parent_node = parent_node->next)
        {
            set_parent_sub_node(pid);
        }
        level_node = level_node->sub_fun;
    }

}

// sub_link_head_next_p.push_back(parent_node->next);
// = sub_link_head_next_p.back();
// sub_link_head_next_p.pop_back();


