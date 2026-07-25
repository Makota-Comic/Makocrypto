CC ?= gcc
CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -O3 -Iinclude -Isrc
LDFLAGS :=

BUILD_DIR := build
LIB_DIR := $(BUILD_DIR)/lib
OBJ_DIR := $(BUILD_DIR)/obj
BIN_DIR := $(BUILD_DIR)/bin

LIB_SOURCES := src/cipher.c src/keyschedule.c src/mode_cbc.c src/random.c src/kdf.c
LIB_OBJECTS := $(patsubst src/%.c,$(OBJ_DIR)/%.o,$(LIB_SOURCES))
STATIC_LIB := $(LIB_DIR)/libmakocrypto.a

CLI_BIN := $(BIN_DIR)/makocrypto

TEST_SOURCES := $(wildcard tests/*.c)
TEST_BINARIES := $(patsubst tests/%.c,$(BIN_DIR)/%,$(TEST_SOURCES))

TOOL_SOURCES := $(wildcard tools/*.c)
TOOL_BINARIES := $(patsubst tools/%.c,$(BIN_DIR)/%,$(TOOL_SOURCES))

.PHONY: all release debug test tools clean install uninstall format help

all: $(STATIC_LIB) $(CLI_BIN)

release: CFLAGS += -DNDEBUG
release: clean all

debug: CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -g -O0 -fsanitize=address,undefined -Iinclude -Isrc
debug: LDFLAGS += -fsanitize=address,undefined
debug: clean all

$(OBJ_DIR)/%.o: src/%.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(STATIC_LIB): $(LIB_OBJECTS)
	@mkdir -p $(LIB_DIR)
	ar rcs $@ $^

$(CLI_BIN): src/main.c $(STATIC_LIB)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $< -L$(LIB_DIR) -lmakocrypto $(LDFLAGS) -o $@

$(BIN_DIR)/%: tests/%.c $(STATIC_LIB)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $< -L$(LIB_DIR) -lmakocrypto -lm $(LDFLAGS) -o $@

$(BIN_DIR)/%: tools/%.c $(STATIC_LIB)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $< -L$(LIB_DIR) -lmakocrypto -lm $(LDFLAGS) -o $@

test: $(TEST_BINARIES)
	@for t in $(TEST_BINARIES); do \
		echo "== Running $$t =="; \
		./$$t || exit 1; \
	done

tools: $(TOOL_BINARIES)

clean:
	rm -rf $(BUILD_DIR)

install: release
	install -d $(DESTDIR)/usr/local/bin
	install -d $(DESTDIR)/usr/local/lib
	install -d $(DESTDIR)/usr/local/include/makocrypto
	install -m 755 $(CLI_BIN) $(DESTDIR)/usr/local/bin/makocrypto
	install -m 644 $(STATIC_LIB) $(DESTDIR)/usr/local/lib/libmakocrypto.a
	install -m 644 include/makocrypto/makocrypto.h $(DESTDIR)/usr/local/include/makocrypto/

uninstall:
	rm -f $(DESTDIR)/usr/local/bin/makocrypto
	rm -f $(DESTDIR)/usr/local/lib/libmakocrypto.a
	rm -f $(DESTDIR)/usr/local/include/makocrypto/makocrypto.h

format:
	clang-format -i src/*.c src/*.h include/makocrypto/*.h tests/*.c tools/*.c

help:
	@echo "Makocrypto build targets:"
	@echo "  make            Build static library and CLI (debug flags off)"
	@echo "  make release    Optimized build (-O2)"
	@echo "  make debug      Build with AddressSanitizer/UBSan for development"
	@echo "  make test       Build and run the test suite"
	@echo "  make tools      Build analysis tools (avalanche, NIST export, benchmark)"
	@echo "  make install    Install binary, library, and headers system-wide"
	@echo "  make clean      Remove all build artifacts"
