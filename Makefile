CXX=g++
OBJ=cgdb

BUILDDIR:=build
sources:=$(wildcard elf/*.cc)
objects:=$(addprefix $(BUILDDIR)/, $(patsubst %.cc, %.o, $(sources)))

sources2:=$(wildcard dyn_debug/*.cc)
objects2:=$(addprefix $(BUILDDIR)/, $(patsubst %.cc, %.o, $(sources2)))

.PHONY: all clean

all: $(OBJ)

$(BUILDDIR)/%.o: %.cc
	$(CXX) -std=c++11 -c $^ -o $@

$(BUILDDIR)/disasm.o: disasm/disasm.cc
	$(CXX) -std=c++11 -c $^ -o $@

$(OBJ): $(objects) $(objects2) $(BUILDDIR)/disasm.o
	$(CXX) -std=c++11 -o build/$@ cgdb.cc $^ -lbfd -lcapstone

clean:
	rm -f $(BUILDDIR)/$(OBJ) `find -name "*.o"`
