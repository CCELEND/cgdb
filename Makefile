CXX=g++
OBJ=cgdb

.PHONY: all clean

all: $(OBJ)

loader_elf.o: ./load_elf/loader_elf.cc
	$(CXX) -std=c++11 -c $^ -o $@

show_elf.o: ./load_elf/show_elf.cc
	$(CXX) -std=c++11 -c $^ -o $@

dyn_fun.o: ./dyn_debug/dyn_fun.cc
	$(CXX) -std=c++11 -c $^ -o $@

disasm.o: ./disasm/disasm.cc
	$(CXX) -std=c++11 -c $^ -o $@

cgdb: loader_elf.o show_elf.o dyn_fun.o disasm.o
	$(CXX) -std=c++11 -o build/$@ cgdb.cc $^ -lbfd

clean:
	rm -f build/$(OBJ) ./*.o
