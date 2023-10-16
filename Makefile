CXX=g++
OBJ=cgdb

.PHONY: all clean

all: $(OBJ)

loader_elf.o: ./load_elf/loader_elf.cc
	$(CXX) -std=c++11 -c ./load_elf/loader_elf.cc

dyn_fun.o: ./dyn_debug/dyn_fun.cc
	$(CXX) -std=c++11 -c ./dyn_debug/dyn_fun.cc

disasm.o: ./disasm/disasm.cc
	$(CXX) -std=c++11 -c ./disasm/disasm.cc

cgdb: loader_elf.o dyn_fun.o disasm.o cgdb.cc
	$(CXX) -std=c++11 -o cgdb cgdb.cc loader_elf.o dyn_fun.o disasm.o -lbfd

clean:
	rm -f $(OBJ) *.o

