CC=gcc
CFLAGS=-I/usr/local/include/CUnit -lcunit
# Source files without the main.c file
SOURCE_FROM_SRC=../src/config_parser.c ../src/filters.c ../src/iprange.c
TEST_C_FILES=$(filter-out rtu_slave_sim.c,$(wildcard *.c))
SOURCE=$(TEST_C_FILES) $(SOURCE_FROM_SRC)
LDLIBS=-L/usr/local/lib -lcunit -lmodbus -lmosquitto

all: test

test: test.c $(SOURCE)
	$(CC) -o test $(SOURCE) $(CFLAGS) $(LDLIBS)

run: test
	./test

clean:
	rm -f test

.PHONY: all clean run
