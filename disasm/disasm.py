
#coding=utf-8
from capstone import *

code_hex = ""
# code_hex 是字符串，转换为字节对象
CODE = bytes.fromhex(code_hex)
print("Disassembly:")
md = Cs(CS_ARCH_X86, CS_MODE_64)
for i in md.disasm(CODE, 0x0):
    print("0x%x:\t%-20s%-8s%s" %(i.address, (i.bytes).hex(), i.mnemonic, i.op_str))