
#include "dyn_fun.h"

// │   ├──  └──

// root node
pfun_tree_node_t root_node = NULL;

pfun_tree_node_t 
creat_node(u64 addr)
{
    string fun_name;
    u64 fun_start_addr, fun_end_addr;
    tuple<string, u64, u64> fun_info_temp;
    pfun_tree_node_t node = NULL;
    
    fun_info_temp = get_fun_start_end(addr);
    fun_name = get<0>(fun_info_temp);
    fun_start_addr = get<1>(fun_info_temp);
    fun_end_addr = get<2>(fun_info_temp);

    // try{}
    node = new fun_tree_node_t;
    if (!node) 
    {
        printf("[-] Failed to create node!\n");
        return NULL;
    }
    memset(node, 0, sizeof(fun_tree_node_t));

    node->fun_info.fun_start_addr = fun_start_addr;
    node->fun_info.fun_end_addr = fun_end_addr;
    node->fun_info.fun_name = fun_name;

    node->next = NULL;
    node->sub_fun = NULL;
    node->sub_fun_num = 0;

    return node;
}

void 
insert_sub_link(const u64 sub_fun_addr, 
    OUT pfun_tree_node_t parent_node)
{
    if ( sub_fun_addr >= parent_node->fun_info.fun_start_addr && 
         sub_fun_addr <= parent_node->fun_info.fun_end_addr )
    {
        return;
    }

    pfun_tree_node_t temp = NULL;
    pfun_tree_node_t sub_node = NULL;

    if (!parent_node->sub_fun)
    {
        sub_node = creat_node(sub_fun_addr);
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
            temp->next = sub_node;
            parent_node->sub_fun_num++;
            break;
        }
    }
}

void
parent_disasm(pid_t pid,
    const u64 parent_fun_addr, const s32 parent_fun_size,
    OUT pfun_tree_node_t parent_node)
{
    cs_insn* insn = NULL;
    size_t count;

    count = cs_disasm(handle, (uint8_t*)disasm_code, 
        parent_fun_size, parent_fun_addr, 0, &insn);
    if (count > 0) 
    {
        size_t j;
        for (j = 0; j < count; j++) 
        {
            if (judg_jump(insn[j].mnemonic))
            {
                u64 sub_fun_addr = 0;
                // printf("%s, %s\n",insn[j].mnemonic, insn[j].op_str);

                if (!strcmp(insn[j].mnemonic, "bnd jmp"))
                {
                    u64 got_addr;

                    got_addr = insn[j].address + get_hex_in_string(insn[j].op_str) + 7;
                    sub_fun_addr = get_8_data_from_addr(pid, got_addr);
                }
                else
                {
                    if (string(insn[j].op_str).find("rip") != string::npos)
                    {
                        u64 got_addr, addr;

                        addr = get_hex_in_string(insn[j].op_str);
                        got_addr = insn[j].address + addr + 6;
                        sub_fun_addr = get_8_data_from_addr(pid, got_addr);
                        // printf("0x%llx\n", sub_fun_addr);
                    }
                    else
                    {
                        sub_fun_addr = strtoul(insn[j].op_str, nullptr, 16);
                    }

                    if (!sub_fun_addr) 
                    {
                        continue;
                    }
                }

                insert_sub_link(sub_fun_addr, parent_node);
            }
        }

        cs_free(insn, count);
    }
    else 
        err_info("Failed to disassemble given code!");
}

// 建立根节点
s32 
creat_root_node(const pchar root_fun_name)
{
    tuple<s32, u64, u64> fun_info_temp;
    string r_fun_name;
    u64 r_fun_start_addr, r_fun_end_addr;

    fun_info_temp = get_fun_addr(root_fun_name);
    r_fun_start_addr = get<1>(fun_info_temp);
    r_fun_end_addr = get<2>(fun_info_temp);

    if (!r_fun_start_addr)
    {
        err_info("There is no such function!");
        return -1;
    }

    // printf("0x%llx-0x%llx\n", fun_start_addr, fun_end_addr);
    r_fun_name = string(root_fun_name);

    root_node = new fun_tree_node_t;
    if (!root_node) return -1;

    memset(root_node, 0, sizeof(fun_tree_node_t));

    root_node->next = NULL;
    root_node->sub_fun = NULL;
    root_node->sub_fun_num = 0;
    root_node->fun_info.fun_name = r_fun_name;
    root_node->fun_info.fun_start_addr = r_fun_start_addr;
    root_node->fun_info.fun_end_addr = r_fun_end_addr;

    return 0;
}

// 根据父节点数据建立子函数链表
s32 
creat_sub_link(pid_t pid, 
    pfun_tree_node_t parent_node)
{
    u64 p_fun_start_addr, p_fun_end_addr, p_fun_size;
    string p_fun_name;

    p_fun_name = parent_node->fun_info.fun_name;
    p_fun_start_addr = parent_node->fun_info.fun_start_addr;
    p_fun_end_addr = parent_node->fun_info.fun_end_addr;

    p_fun_size = p_fun_end_addr - p_fun_start_addr;
    p_fun_size = p_fun_size + LONG_SIZE - p_fun_size % LONG_SIZE; // 8字节对齐

    if (p_fun_size > 0x1000)
    {
        disasm_code = (pchar)realloc(disasm_code, p_fun_size);
    }
    memset(disasm_code, 0, p_fun_size);

    get_data_from_addr(pid, p_fun_start_addr, disasm_code, p_fun_size);

    parent_disasm(pid, p_fun_start_addr, p_fun_size, parent_node);

    return 0;
}


void 
free_fun_tree()
{
    vector<pfun_tree_node_t> sib_link_next_node;
    pfun_tree_node_t temp = NULL;
    pfun_tree_node_t parent_node = root_node;

    while(parent_node)
    {
        // 当前节点兄节点压栈
        sib_link_next_node.push_back(parent_node->next);
        temp = parent_node;

        // 当前节点有子
        if (parent_node->sub_fun)
        {
            parent_node = parent_node->sub_fun;
        }
        // 当前节点无子
        else
        {
            // 弹出空值
            while (!sib_link_next_node.back())
            {
                sib_link_next_node.pop_back();
            }

            if (!sib_link_next_node.size())
            {
                memset(temp, 0, sizeof(fun_tree_node_t));
                delete temp;
                break;
            }

            parent_node = sib_link_next_node.back();
            sib_link_next_node.pop_back();
        }

        memset(temp, 0, sizeof(fun_tree_node_t));
        delete temp;
    }
}

void 
show_fun_tree()
{
    vector<pfun_tree_node_t> sib_link_next_node;
    pfun_tree_node_t temp_node = root_node;
    s32 depth = 0;

    sib_link_next_node.push_back(temp_node->next);
    // 输出根节点
    printf(" %s\n", 
        temp_node->fun_info.fun_name.c_str());

    if (temp_node->sub_fun)
    {
        temp_node = temp_node->sub_fun;
        ++depth; // 层级加1
    }
    else 
    {
        return;
    }

    while(temp_node)
    {
        // 当前节点兄弟节点压栈
        sib_link_next_node.push_back(temp_node->next);
        // 输出当前节点
        for (s32 i = 1; i < depth; i++)
        {
            if (sib_link_next_node[i])
            {
                printf(" │   ");
            }
            else
            {
                printf("     ");
            }
        }

        if (temp_node->next)
        {
            printf(" ├─── %s\n", 
                temp_node->fun_info.fun_name.c_str());
        }
        else
        {
            printf(" └─── %s\n", 
                temp_node->fun_info.fun_name.c_str());
        }

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

            if (!sib_link_next_node.size())
            {
                break;
            }

            temp_node = sib_link_next_node.back();
            sib_link_next_node.pop_back();
        }
    }
}


void 
creat_fun_tree(pid_t pid, s32 level)
{
    vector<pfun_tree_node_t> sib_link_next_node;
    pfun_tree_node_t parent_node = root_node;
    int current_depth = 0;

    while(parent_node)
    {
        // printf("%s\n", parent_node->fun_info.fun_name.c_str());
        // 当前节点兄节点压栈
        sib_link_next_node.push_back(parent_node->next);

        if (current_depth < level)
        {
            creat_sub_link(pid, parent_node);
        }
        else
        {
            break;
        }

        // 当前节点有子
        if ( parent_node->sub_fun && 
             current_depth+1 < level )
        {
            parent_node = parent_node->sub_fun;
            ++current_depth;
        }
        // 当前节点无子, 或者到达层数限制
        else
        {
            // 当前节点无兄
            while ( !sib_link_next_node.back() && 
                    current_depth != 0 )
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