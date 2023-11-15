
#include "dyn_fun.h"

// │   │       ├── cmdline └──

fun_tree_info_t* parent_node;
fun_tree_info_t* sub_node;
// char* fun_code;

void set_sub_node_link(string sub_fun_name)
{
    fun_tree_info_t* temp = NULL;
    sub_node = (fun_tree_info_t*)malloc(sizeof(struct fun_tree_info));
    memset(sub_node, 0, sizeof(struct fun_tree_info));

    sub_node->fun_name = sub_fun_name;
    sub_node->next = NULL;

    if (!parent_node->sub_fun)
    {
        parent_node->sub_fun = sub_node;
        parent_node->sub_fun_num++;
        return;
    }

    for(temp = parent_node->sub_fun; temp; temp = temp->next)
    {

        if (temp->fun_name == sub_node->fun_name)
        {
            free(sub_node);
            sub_node = NULL;
            break;
        }
        if (!temp->next){
            temp->next = sub_node;
            parent_node->sub_fun_num++;
            break;
        }
    }
}

void tree_disasm(char* byte_codes, u64 parent_fun_addr, s32 num, string parent_fun_name)
{
    csh handle;
    cs_insn *insn;
    size_t count;
    u64 sub_fun_addr;
    string sub_fun_name;
    // s32 offset;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        printf("\033[31m\033[1m[-] Failed to initialize Capstone!\033[0m\n");
        return;
    }    

    count = cs_disasm(handle, (uint8_t*)byte_codes, num, parent_fun_addr, 0, &insn);
    if (count > 0) {
        size_t j;
        for (j = 0; j < count; j++) 
        {            
            if ( !strcmp(insn[j].mnemonic, "call") || 
                 !strcmp(insn[j].mnemonic, "jmp") )
            {
                sub_fun_addr = strtoul(insn[j].op_str, nullptr, 16);

                sub_fun_name = addr_get_elf_fun(sub_fun_addr);
                if (sub_fun_name == "")
                {
                    sub_fun_name = addr_get_elf_plt_fun(sub_fun_addr);
                    sub_fun_name += "@plt";
                }

                set_sub_node_link(sub_fun_name);
            } 
        }
        cs_free(insn, count);
    }
    else printf("\033[31m\033[1m[-] Failed to disassemble given code!\n");

    cs_close(&handle);
}


s32 set_parent_node(pid_t pid, char* parent_fun_name)
{
    char fun_code[0x1000];
    // if (!fun_code)
    //     fun_code = (char*)malloc(0x1000);

    u64 fun_start_addr, fun_end_addr, fun_size;
    string fun_name;

    fun_start_addr = get_elf_fun_addr(parent_fun_name);
    if (!fun_start_addr){
        err_info("There is no such function!");
        return -1;
    }
    fun_name = string(parent_fun_name);
    fun_end_addr = elf_fun_end[fun_name];

    fun_size = fun_end_addr - fun_start_addr;
    // 8字节对齐
    fun_size = fun_size + LONG_SIZE - fun_size % LONG_SIZE;

    // memset(fun_code, 0, fun_size+0x10);
    parent_node = (fun_tree_info_t*)malloc(sizeof(struct fun_tree_info));
    memset(parent_node, 0, sizeof(struct fun_tree_info));

    parent_node->next = NULL;
    parent_node->sub_fun = NULL;
    parent_node->sub_fun_num = 0;
    parent_node->fun_name = fun_name;

    get_addr_data(pid, fun_start_addr, fun_code, fun_size);
    tree_disasm(fun_code, fun_start_addr, fun_size, fun_name);

    return 0;

}



void show_fun_tree()
{
    fun_tree_info_t* temp = NULL;
    for(temp = parent_node->sub_fun; temp; temp = temp->next)
    {
        printf("%s\n", temp->fun_name.c_str());
    }
}

void free_fun_tree()
{
    fun_tree_info_t* head = parent_node->sub_fun;
    while(head != NULL)
    {
        fun_tree_info_t* temp = head;
        head = head->next;
        free(temp);
    }
    free(parent_node);
    parent_node = NULL;
}
