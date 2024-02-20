CXX=g++
OBJ=cgdb

BUILDDIR:=build

elf_sources:=$(wildcard elf/*.cc)
elf_objects:=$(addprefix $(BUILDDIR)/, $(patsubst %.cc, %.o, $(elf_sources)))

debug_sources:=$(wildcard dyn_debug/*.cc)
debug_objects:=$(addprefix $(BUILDDIR)/, $(patsubst %.cc, %.o, $(debug_sources)))

disasm_sources:=$(wildcard disasm/*.cc)
disasm_objects:=$(addprefix $(BUILDDIR)/, $(patsubst %.cc, %.o, $(disasm_sources)))

.PHONY: all clean

all: $(OBJ)

$(BUILDDIR)/%.o: %.cc
	$(CXX) -std=c++17 -c $^ -o $@

$(OBJ): $(elf_objects) $(debug_objects) $(disasm_objects)
	$(CXX) -std=c++17 -o build/$@ cgdb.cc $^ -lbfd -lcapstone

clean:
	rm -f $(BUILDDIR)/$(OBJ) `find -name "*.o"`
