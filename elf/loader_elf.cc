
#include "loader_elf.h"

// 打开二进制文件
static bfd*
open_bfd(std::string &fname)
{
  static int bfd_inited = 0;

  bfd *bfd_h;

  if(!bfd_inited) {
    // 初始化 libbfd 的内部状态
    bfd_init();
    bfd_inited = 1;
  }

  bfd_h = bfd_openr(fname.c_str(), NULL);
  if(!bfd_h) {
    fprintf(stderr, "failed to open binary '%s' (%s)\n",
            fname.c_str(), bfd_errmsg(bfd_get_error()));
    return NULL;
  }

  // 检查二进制文件的格式, 加载器将其设置为 bfd_object, 用来验证打开的文件确实是一个对象
  // 可执行文件、可重定位对象，或者共享库
  if(!bfd_check_format(bfd_h, bfd_object)) {
    fprintf(stderr, "file '%s' does not look like an executable (%s)\n",
            fname.c_str(), bfd_errmsg(bfd_get_error()));
    return NULL;
  }

  /* Some versions of bfd_check_format pessimistically set a wrong_format
   * error before detecting the format, and then neglect to unset it once
   * the format has been detected. We unset it manually to prevent problems. */
  bfd_set_error(bfd_error_no_error);

  if(bfd_get_flavour(bfd_h) == bfd_target_unknown_flavour) {
    fprintf(stderr, "unrecognized format for binary '%s' (%s)\n",
            fname.c_str(), bfd_errmsg(bfd_get_error()));
    return NULL;
  }

  return bfd_h;
}

// 加载静态符号表
static int
load_symbols_bfd(bfd *bfd_h, Binary *bin)
{
  int ret;
  long n, nsyms, i;
  asymbol **bfd_symtab; // 指向符号的指针数组
  Symbol *sym;

  bfd_symtab = NULL;

  // 返回需要存储符号信息的空间大小
  n = bfd_get_symtab_upper_bound(bfd_h);
  if(n < 0) {
    fprintf(stderr, "failed to read symtab (%s)\n",
            bfd_errmsg(bfd_get_error()));
    goto fail;
  } 
  else if(n) {
    // 分配存储符号信息的空间
    bfd_symtab = (asymbol**)malloc(n);
    if(!bfd_symtab) {
      fprintf(stderr, "out of memory\n");
      goto fail;
    }
    // 填充符号表到 bfd_symtab
    nsyms = bfd_canonicalize_symtab(bfd_h, bfd_symtab);
    if(nsyms < 0) {
      fprintf(stderr, "failed to read symtab (%s)\n",
              bfd_errmsg(bfd_get_error()));
      goto fail;
    }
    // 遍历所有符号
    for(i = 0; i < nsyms; i++) {
      // 检查其是否设置了 BSF_FUNCTION 标志，是否是一个函数符号
      if(bfd_symtab[i]->flags & BSF_FUNCTION) {
        bin->symbols.push_back(Symbol());
        sym = &bin->symbols.back();
        sym->type = Symbol::SYM_TYPE_FUNC;
        sym->name = std::string(bfd_symtab[i]->name);
        // 得到函数符号的起始地址
        sym->fun_sym_type = std::string("symtab"); //
        sym->addr = bfd_asymbol_value(bfd_symtab[i]);
      }
    }
  }

  // 为零，代表没有符号表
  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  if(bfd_symtab) free(bfd_symtab);

  return ret;
}

// 加载动态符号表
static int
load_dynsym_bfd(bfd *bfd_h, Binary *bin)
{
  int ret;
  long n, nsyms, i;
  asymbol **bfd_dynsym;
  Symbol *sym;

  bfd_dynsym = NULL;

  // 返回为符号指针保留的字节数
  n = bfd_get_dynamic_symtab_upper_bound(bfd_h);
  if(n < 0) {
    fprintf(stderr, "failed to read dynamic symtab (%s)\n",
            bfd_errmsg(bfd_get_error()));
    goto fail;
  } 
  else if(n) {
    bfd_dynsym = (asymbol**)malloc(n);
    if(!bfd_dynsym) {
      fprintf(stderr, "out of memory\n");
      goto fail;
    }
    // 填充符号表到 bfd_dynsym
    nsyms = bfd_canonicalize_dynamic_symtab(bfd_h, bfd_dynsym);
    if(nsyms < 0) {
      fprintf(stderr, "failed to read dynamic symtab (%s)\n",
              bfd_errmsg(bfd_get_error()));
      goto fail;
    }
    for(i = 0; i < nsyms; i++) {
      if(bfd_dynsym[i]->flags & BSF_FUNCTION) {
        bin->symbols.push_back(Symbol());
        sym = &bin->symbols.back();
        sym->type = Symbol::SYM_TYPE_FUNC;
        sym->name = std::string(bfd_dynsym[i]->name);
        sym->fun_sym_type = std::string("dynsym");  //
        sym->addr = bfd_asymbol_value(bfd_dynsym[i]);
      }
    }
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  if(bfd_dynsym) free(bfd_dynsym);

  return ret;
}

// 加载节信息
static int
load_sections_bfd(bfd *bfd_h, Binary *bin)
{
  int bfd_flags;
  uint64_t vma, size;
  const char *secname;
  // libbfd 通过 asection 链表表示所有的节，加载器会用 asection* 来遍历该链表
  asection* bfd_sec;
  Section *sec;
  Section::SectionType sectype;

  // 遍历所有节
  // 由 libbfd 的节的链表头指向 bfd_h->sections
  for(bfd_sec = bfd_h->sections; bfd_sec; bfd_sec = bfd_sec->next) {
    // 获取节的标志
    bfd_flags = bfd_get_section_flags(bfd_h, bfd_sec);

    // 只加载代码和数据段
    sectype = Section::SEC_TYPE_NONE;
    if(bfd_flags & SEC_CODE) {
      sectype = Section::SEC_TYPE_CODE;
    } else if(bfd_flags & SEC_DATA) {
      sectype = Section::SEC_TYPE_DATA;
    } else {
      continue;
    }

    // 节的虚拟地址, 大小, 名称
    // vma     = bfd_section_vma(bfd_h, bfd_sec);
    // size    = bfd_section_size(bfd_h, bfd_sec);
    // secname = bfd_section_name(bfd_h, bfd_sec);
    vma     = bfd_section_vma(bfd_sec);
    size    = bfd_section_size(bfd_sec);
    secname = bfd_section_name(bfd_sec);
    if(!secname) secname = "<unnamed>";

    // 此加载器在 Binary 中保留了一个 Section, 并复制读到的所有字段
    bin->sections.push_back(Section());
    sec = &bin->sections.back();

    sec->binary = bin;
    sec->name   = std::string(secname);
    sec->type   = sectype;
    sec->vma    = vma;
    sec->size   = size;
    sec->bytes  = (uint8_t*)malloc(size);
    if(!sec->bytes) {
      fprintf(stderr, "out of memory\n");
      return -1;
    }
    // 将 libbfd 的节对象的所有字节复制到 Section 中
    if(!bfd_get_section_contents(bfd_h, bfd_sec, sec->bytes, 0, size)) {
      fprintf(stderr, "failed to read section '%s' (%s)\n",
              secname, bfd_errmsg(bfd_get_error()));
      return -1;
    }
  }

  return 0;
}


static int
load_binary_bfd(std::string &fname, Binary *bin, Binary::BinaryType type)
{
  int ret;
  bfd *bfd_h;
  const bfd_arch_info_type *bfd_info;

  bfd_h = NULL;

  bfd_h = open_bfd(fname);
  if(!bfd_h) {
    goto fail;
  }

  bin->filename = std::string(fname);
  // 获取二进制文件的入口点地址
  // 返回 bfd 对象的 start_address 字段的值，起始地址是 bfd_vma
  bin->entry    = bfd_get_start_address(bfd_h);

  // 设置相应的 Binary 类型, ELF 或者 PE
  bin->type_str = std::string(bfd_h->xvec->name);
  switch(bfd_h->xvec->flavour) {
    case bfd_target_elf_flavour:
      bin->type = Binary::BIN_TYPE_ELF;
      break;
    case bfd_target_coff_flavour:
      bin->type = Binary::BIN_TYPE_PE;
      break;
    case bfd_target_unknown_flavour:
    default:
      fprintf(stderr, "unsupported binary type (%s)\n", bfd_h->xvec->name);
      goto fail;
  }

  // 返回指向 bfd_arch_info_type 数据结构的指针
  bfd_info = bfd_get_arch_info(bfd_h);
  // 提供了有关二进制体系结构的信息，以及方便的、可打印的字符串描述该体系结构
  bin->arch_str = std::string(bfd_info->printable_name);
  switch(bfd_info->mach) {
    case bfd_mach_i386_i386:
      bin->arch = Binary::ARCH_X86; 
      bin->bits = 32;
      break;
    case bfd_mach_x86_64:
      bin->arch = Binary::ARCH_X86;
      bin->bits = 64;
      break;
    default:
      fprintf(stderr, "unsupported architecture (%s)\n", bfd_info->printable_name);
      goto fail;
  }

  /* Symbol handling is best-effort only (they may not even be present) */
  // 加载符号
  load_symbols_bfd(bfd_h, bin);
  // 动态符号
  load_dynsym_bfd(bfd_h, bin);

  // 加载二进制节
  if(load_sections_bfd(bfd_h, bin) < 0) goto fail;

  // 信息已经复制到 Binary 对象, 接下来关闭 bfd

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  if(bfd_h) bfd_close(bfd_h);

  return ret;
}

// 是解析由文件名指定的二进制文件，并将其加载到指定的 Binary 对象中
int
load_binary(std::string &fname, Binary *bin, Binary::BinaryType type)
{
  return load_binary_bfd(fname, bin, type);
}

// 释放 Binary 动态分配的所有组件
void
unload_binary(Binary *bin)
{
  size_t i;
  Section *sec;

  for(i = 0; i < bin->sections.size(); i++) {
    sec = &bin->sections[i];
    if(sec->bytes) {
      free(sec->bytes);
    }
  }
}
