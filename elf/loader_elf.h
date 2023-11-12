#ifndef LOADER_ELF_H
#define LOADER_ELF_H

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <iostream>
#include <unistd.h>
#include <string>
#include <vector>
#include <bfd.h>
#include <map>

// 新版本的宏有问题, 需要修改
#define bfd_get_section_flags(bfd, ptr) ((void) bfd, (ptr)->flags)

// 键为函数名，值为地址
extern std::map<std::string, unsigned long long> elf_fun_start;
extern std::map<std::string, unsigned long long> elf_plt_fun_start;

extern std::string fname;

class Binary;
class Section;
class Symbol;

// 符号类
class Symbol {
public:
  enum SymbolType {
    SYM_TYPE_UKN  = 0,
    SYM_TYPE_FUNC = 1
  };

  Symbol() : type(SYM_TYPE_UKN), name(), addr(0) {}

  SymbolType  type;         // 枚举体, 符号类型
  std::string name;         // 符号名字
  std::string fun_sym_type; // 函数符号类型
  uint64_t    addr;         // 符号起始地址
};

// 保存节的基本信息
class Section {
public:
  enum SectionType {
    SEC_TYPE_NONE = 0,
    SEC_TYPE_CODE = 1,
    SEC_TYPE_DATA = 2
  };

  Section() : binary(NULL), type(SEC_TYPE_NONE), vma(0), size(0), bytes(NULL) {}

  bool contains (uint64_t addr) { return (addr >= vma) && (addr-vma < size); }

  Binary       *binary;
  std::string   name;
  SectionType   type;
  uint64_t      vma;
  uint64_t      size;
  uint8_t      *bytes;
};

// 二进制程序的基本信息
class Binary {
public:
  enum BinaryType {
    BIN_TYPE_AUTO = 0,
    BIN_TYPE_ELF  = 1,
    BIN_TYPE_PE   = 2
  };
  enum BinaryArch {
    ARCH_NONE = 0,
    ARCH_X86  = 1
  };

  Binary() : type(BIN_TYPE_AUTO), arch(ARCH_NONE), bits(0), entry(0) {}

  Section *get_text_section() { for(auto &s : sections) if(s.name == ".text") return &s; return NULL; }

  std::string          filename;
  BinaryType           type;
  std::string          type_str;
  BinaryArch           arch;
  std::string          arch_str;
  unsigned             bits;
  uint64_t             entry;
  std::vector<Section> sections;
  std::vector<Symbol>  symbols;
};

int  load_binary   (std::string &fname, Binary* bin, Binary::BinaryType type);
void unload_binary (Binary* bin);

void show_elf_symbol(Binary* bin);
void show_elf_dynsym(Binary* bin);
void show_elf_sections_code_data(Binary* bin);
void show_elf_got   ();
void show_elf_plt   ();
void show_elf_plt_fun();
void show_elf_fun();

void map_fun_start(Binary* bin);
void map_plt_fun_start();

unsigned long long get_plt_fun_addr(char* funame);

void show_elf_help();

#endif /* LOADER_H */

