
#include "dyn_fun.h"

void 
set_elf_rdata(Binary* bin)
{
    Section* sec;

    for(s32 i = 0; i < bin->sections.size(); i++) 
    {
        sec = &bin->sections[i];

        if (sec->name == ".rodata")
        {
            elf_rodata_start = sec->vma + elf_base;
            elf_rodata_end = elf_rodata_start + sec->size;
        }

        if (sec->name == ".init_array")
        {
            elf_ini_start = sec->vma + elf_base;
        }
        
        if (sec->name == ".fini_array")
        {
            elf_ini_end = sec->vma + elf_base + sec->size;
        }
    }
}

