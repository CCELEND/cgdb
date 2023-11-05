#include "dyn_fun.h"

// string regs_addr_get_fun(unsigned long long addr, int* offset)
// {

//     string fun_name = "";

//     if (addr > 0x7f0000000000) {
//         fun_name = addr_get_glibc_plt_fun(addr);
//         if (fun_name != ""){
//             return fun_name;
//         }
//         else {
//             fun_name = addr_get_glibc_fun(addr);
//             if (fun_name != ""){
//                 *offset = addr_get_glibc_fun_offset(addr);
//                 return fun_name;
//             }
//             else
//                 return "";
//         }
//     }
//     else
//     {
//         fun_name = addr_get_elf_fun(addr);
//         if (fun_name != ""){
//             *offset = addr_get_elf_fun_offset(addr);
//             return fun_name;
//         }
//         else {
//             fun_name = addr_get_elf_plt_fun(addr);
//             if (fun_name != ""){
//                 *offset = addr_get_elf_plt_fun_offset(addr);
//                 return fun_name;
//             }
//             else
//                 return "";

//         }

//     }
// }