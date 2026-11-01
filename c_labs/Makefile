CC = clang
CFLAGS = -Wall -Wextra -pedantic -Werror -std=c11 -Iinclude
SRC = src/buffer_overflow.c src/format_string.c src/integer_overflow.c
TEST_SRC = tests/test_c_labs.c
BIN = test_runner

.PHONY: all clean test

all: $(BIN)

$(BIN): $(SRC) $(TEST_SRC)
	$(CC) $(CFLAGS) -o $(BIN) $(SRC) $(TEST_SRC)

test: $(BIN)
	./$(BIN)

clean:
	rm -f $(BIN) *.o
