CC ?= gcc
CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -O3 -Iinclude -Isrc
LDFLAGS :=

BUILD_DIR := build
LIB_DIR := $(BUILD_DIR)/lib
OBJ_DIR := $(BUILD_DIR)/obj
BIN_DIR := $(BUILD_DIR)/bin

# Object files only depend on their .c file and header dependencies as far
# as `make` timestamps are concerned -- they carry no memory of *which*
# CFLAGS produced them. Switching between plain/debug/release builds
# without an intervening `make clean` therefore used to link tools/tests
# against a stale library built with different flags (e.g. tools compiled
# without -fsanitize= linked against a libmakocrypto.a still full of
# ASan/UBSan-instrumented objects from a prior `make debug`), which fails
# at link time with undefined __asan_*/__ubsan_* references, or worse,
# would silently mix flag sets if the symbols happened to resolve.
#
# `make` decides which targets are stale by scanning file mtimes once,
# before running any recipe -- so a recipe that deletes .o files partway
# through a build does not change a rebuild decision `make` already made
# earlier in that same run for a target higher up the dependency graph
# (e.g. the .a archive can still be judged "up to date" even after this
# invalidation deletes the .o files it is made of). A prerequisite, order
# only or not, cannot fix this: by the time any recipe runs, the graph is
# already decided.
#
# The fix instead runs *before* `make` builds that graph at all: FLAGS_SENTINEL
# records the last-used flags in a plain file. sync-flags (below) compares
# it against the live flags and, on a mismatch, deletes the object cache,
# then every target that actually triggers a build (all/debug/release/
# test/tools) depends on sync-flags and re-invokes `make` as a separate
# sub-process for the real work -- so that sub-process starts its own
# mtime scan only after the stale objects are already gone.
FLAGS_SENTINEL := $(OBJ_DIR)/.cflags-used
CURRENT_FLAGS := $(CC)|$(CFLAGS)|$(LDFLAGS)
MAKEOVERRIDES_FWD := CC='$(CC)' CFLAGS='$(CFLAGS)' LDFLAGS='$(LDFLAGS)'

LIB_SOURCES := src/cipher.c src/keyschedule.c src/mode_cbc.c src/mode_gcm.c src/random.c src/kdf.c
LIB_OBJECTS := $(patsubst src/%.c,$(OBJ_DIR)/%.o,$(LIB_SOURCES))
STATIC_LIB := $(LIB_DIR)/libmakocrypto.a

CLI_BIN := $(BIN_DIR)/makocrypto

TEST_SOURCES := $(wildcard tests/*.c)
TEST_BINARIES := $(patsubst tests/%.c,$(BIN_DIR)/%,$(TEST_SOURCES))

TOOL_SOURCES := $(wildcard tools/*.c)
TOOL_BINARIES := $(patsubst tools/%.c,$(BIN_DIR)/%,$(TOOL_SOURCES))

.PHONY: all release debug test tools clean install uninstall format help
.PHONY: sync-flags all-real test-real tools-real

# sync-flags runs as plain recipe code in *this* make process, strictly
# before the recursive $(MAKE) call below starts a new process and a new
# mtime scan. If the recorded flags don't match the live ones, it deletes
# every object file up front so the recursive invocation's dependency
# graph is built from a cache that's already consistent -- there is no
# point at which a stale .o and the "current" flags can coexist.
sync-flags:
	@mkdir -p $(OBJ_DIR)
	@if [ ! -f $(FLAGS_SENTINEL) ] || [ "$$(cat $(FLAGS_SENTINEL))" != '$(CURRENT_FLAGS)' ]; then \
		echo "Build flags changed since last build (or no prior build found) -- clearing object cache."; \
		rm -f $(LIB_OBJECTS); \
		echo '$(CURRENT_FLAGS)' > $(FLAGS_SENTINEL); \
	fi

all: sync-flags
	@$(MAKE) --no-print-directory all-real $(MAKEOVERRIDES_FWD)

release: CFLAGS += -DNDEBUG
release: clean all

debug: CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -g -O0 -fsanitize=address,undefined -Iinclude -Isrc
debug: LDFLAGS += -fsanitize=address,undefined
debug: clean all

all-real: $(STATIC_LIB) $(CLI_BIN)

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

test: sync-flags
	@$(MAKE) --no-print-directory test-real $(MAKEOVERRIDES_FWD)

test-real: $(TEST_BINARIES)
	@for t in $(TEST_BINARIES); do \
		echo "== Running $$t =="; \
		./$$t || exit 1; \
	done

tools: sync-flags
	@$(MAKE) --no-print-directory tools-real $(MAKEOVERRIDES_FWD)

tools-real: $(TOOL_BINARIES)

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