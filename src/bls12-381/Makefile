CC = g++
CFLAGS = -std=c++11 -w -O3

# Name of the library
LIB_NAME = bls

# Assuming src is a defined variable or replace with an actual path
LIB_SOURCES = $(wildcard src/*.cpp)

# Object files for the library
LIB_OBJECTS = $(patsubst %.cpp,%.o,$(LIB_SOURCES))

# Header files for the library
INCLUDE_HEADERS = include 

# Source files for the test program
TEST_SOURCES = test/unittests.cpp

# Object files for the test program
TEST_OBJECTS = $(patsubst %.cpp,%.o,$(TEST_SOURCES))

# Source files for the test program
BENCH_SOURCES = bench/eth_bench.cpp

# Object files for the bench program
BENCH_OBJECTS = $(patsubst %.cpp,%.o,$(BENCH_SOURCES))

all: lib$(LIB_NAME).a unittest eth_bench

lib$(LIB_NAME).a: $(LIB_OBJECTS)
	ar rcs $@ $^

%.o: %.cpp 
	$(CC) -c $(CFLAGS) $< -o $@ -I$(INCLUDE_HEADERS) 

unittest: $(TEST_OBJECTS) lib$(LIB_NAME).a
	$(CC) $(CFLAGS) $^ -o test/$@ -L. -l$(LIB_NAME) -I$(INCLUDE_HEADERS)

eth_bench: $(BENCH_OBJECTS) lib$(LIB_NAME).a
	$(CC) $(CFLAGS) $^ -o bench/$@ -L. -l$(LIB_NAME) -I$(INCLUDE_HEADERS)

clean:
	rm -f $(LIB_OBJECTS) $(TEST_OBJECTS) $(BENCH_OBJECTS) lib$(LIB_NAME).a test/unittest bench/eth_bench
