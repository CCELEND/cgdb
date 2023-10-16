CXX=g++
OBJ=cgdb

.PHONY: all clean

all: loader_elf.o dyn_fun.o disasm.o $(OBJ)
# all: $(OBJ)

loader_elf.o: ./load_elf/loader_elf.cc
	$(CXX) -std=c++11 -c $^ -o build/$@

dyn_fun.o: ./dyn_debug/dyn_fun.cc
	$(CXX) -std=c++11 -c $^ -o build/$@

disasm.o: ./disasm/disasm.cc
	$(CXX) -std=c++11 -c $^ -o build/$@

fun_obj := $(wildcard ./build/*.o)

cgdb: $(fun_obj)
	$(CXX) -std=c++11 -o ./build/$@ cgdb.cc $(fun_obj) -lbfd


clean:
	rm -f ./build/$(OBJ) ./build/*.o

