# Marrow - Portable Distributed Kernel
# C89/C90 compliant build using tcc or gcc

# Detect compiler
CC := $(shell command -v tcc 2>/dev/null)
ifeq ($(CC),)
    CC = gcc
endif

CFLAGS = -std=c89 -Wall -Wpedantic -g -D_POSIX_C_SOURCE=200112L
LDFLAGS =

# Detect Nix environment
ifneq ($(NIX_LDFLAGS),)
    CC = gcc
    # Convert -rpath to -Wl,-rpath, format for GCC, and filter out empty entries
    LDFLAGS += $(shell echo '$(NIX_LDFLAGS)' | perl -pe 's/-rpath\s+(\S+)/-Wl,-rpath,$1/g' | tr -s ' ' | sed 's/ -Wl,-rpath, //g')
    CFLAGS += $(NIX_CFLAGS_COMPILE)
    $(info Building in Nix environment - using GCC)
endif

# Detect OpenSSL via pkg-config (works in Nix and non-Nix environments)
OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS   := $(shell pkg-config --libs   openssl 2>/dev/null)
ifneq ($(OPENSSL_LIBS),)
    CFLAGS  += -DUSE_OPENSSL $(OPENSSL_CFLAGS)
    LDFLAGS += $(OPENSSL_LIBS)
    $(info OpenSSL found via pkg-config - authentication enabled)
else
    $(info OpenSSL not found - authentication disabled)
endif

# Detect ALSA via pkg-config (for audio device)
ALSA_CFLAGS := $(shell pkg-config --cflags alsa 2>/dev/null)
ALSA_LIBS   := $(shell pkg-config --libs   alsa 2>/dev/null)
ifneq ($(ALSA_LIBS),)
    CFLAGS  += -DUSE_ALSA $(ALSA_CFLAGS)
    LDFLAGS += $(ALSA_LIBS)
    $(info ALSA found via pkg-config - audio device enabled)
else
    $(info Warning: ALSA not found - audio device disabled)
endif

# Directories
SRC_DIR = lib
INCLUDE_DIR = include
BUILD_DIR = build
BIN_DIR = bin

# Source files
MARROW_9P_SRCS = $(SRC_DIR)/9p/protocol.c $(SRC_DIR)/9p/ops.c $(SRC_DIR)/9p/tree.c
MARROW_GRAPHICS_SRCS = $(SRC_DIR)/graphics/memdraw.c $(SRC_DIR)/graphics/memimage.c \
                       $(SRC_DIR)/graphics/pixconv.c
MARROW_AUTH_SRCS = $(SRC_DIR)/auth/ed448.c $(SRC_DIR)/auth/dp9ik.c \
                   $(SRC_DIR)/auth/p9any.c \
                   $(SRC_DIR)/auth/session.c $(SRC_DIR)/auth/factotum.c \
                   $(SRC_DIR)/auth/keys.c $(SRC_DIR)/auth/secstore.c \
                   $(SRC_DIR)/auth/p9sk1.c
MARROW_REGISTRY_SRCS = $(SRC_DIR)/registry/cpu.c $(SRC_DIR)/registry/rcpu.c \
                       $(SRC_DIR)/registry/namespace.c $(SRC_DIR)/registry/service.c \
                       $(SRC_DIR)/registry/discovery.c $(SRC_DIR)/registry/mount.c
MARROW_SYS_SRCS = sys/console.c sys/fd.c sys/proc.c sys/env.c sys/svc.c \
                  sys/devdraw.c sys/devscreen.c sys/devmouse.c sys/devkbd.c sys/devaudio.c \
                  sys/devtime.c
MARROW_PLATFORM_SRCS = $(SRC_DIR)/platform/socket.c

# Runtime support (PEB, context switching, syscalls)
MARROW_RUNTIME_SRCS = $(SRC_DIR)/runtime/peb.c $(SRC_DIR)/runtime/context.c \
                       $(SRC_DIR)/runtime/syscall.c $(SRC_DIR)/runtime/p9compat.c

# Loader (Plan 9 executable loading)
MARROW_LOADER_SRCS = $(SRC_DIR)/loader/p9exec.c

# Assembly stubs (platform-specific)
MARROW_ASM_SRCS = $(SRC_DIR)/asm/amd64_ctx.S $(SRC_DIR)/asm/amd64_syscall.S

MARROW_SERVER_SRCS = $(SRC_DIR)/server/core.c $(SRC_DIR)/server/init.c $(SRC_DIR)/server/server.c

MARROW_SRCS = $(MARROW_9P_SRCS) $(MARROW_GRAPHICS_SRCS) $(MARROW_AUTH_SRCS) $(MARROW_REGISTRY_SRCS) \
              $(MARROW_SYS_SRCS) $(MARROW_PLATFORM_SRCS) \
              $(MARROW_RUNTIME_SRCS) $(MARROW_LOADER_SRCS)

# Object files
MARROW_OBJS = $(MARROW_9P_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o) \
              $(MARROW_GRAPHICS_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o) \
              $(MARROW_AUTH_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o) \
              $(MARROW_REGISTRY_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o) \
              $(MARROW_SYS_SRCS:sys/%.c=$(BUILD_DIR)/sys/%.o) \
              $(MARROW_PLATFORM_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o) \
              $(MARROW_RUNTIME_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o) \
              $(MARROW_LOADER_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o) \
              $(MARROW_ASM_SRCS:$(SRC_DIR)/%.S=$(BUILD_DIR)/%.o)

MARROW_SERVER_OBJS = $(MARROW_SERVER_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

# Targets
LIB_TARGET = $(BUILD_DIR)/libmarrow.a
SERVER_TARGET = $(BIN_DIR)/marrow
EMBED_LIB_TARGET = $(BUILD_DIR)/libmarrow_embed.a

# Default target
.PHONY: all
all: $(SERVER_TARGET) $(EMBED_LIB_TARGET)

.PHONY: embed-example
embed-example: $(EMBED_EXAMPLE_TARGET)

# Create directories
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)/9p
	mkdir -p $(BUILD_DIR)/graphics
	mkdir -p $(BUILD_DIR)/auth
	mkdir -p $(BUILD_DIR)/registry
	mkdir -p $(BUILD_DIR)/platform
	mkdir -p $(BUILD_DIR)/server
	mkdir -p $(BUILD_DIR)/sys
	mkdir -p $(BUILD_DIR)/runtime
	mkdir -p $(BUILD_DIR)/loader
	mkdir -p $(BUILD_DIR)/asm

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Library
$(LIB_TARGET): $(MARROW_OBJS) | $(BUILD_DIR)
	ar rcs $@ $^

# Server binary
$(SERVER_TARGET): cmd/marrow/main.c $(LIB_TARGET) | $(BIN_DIR)
	gcc -std=c89 -Wall -Wpedantic -g $(CFLAGS) -DINCLUDE_CPU_SERVER -DINCLUDE_NAMESPACE \
		-I$(INCLUDE_DIR) -I$(SRC_DIR) $< -L$(BUILD_DIR) -lmarrow -o $@ $(LDFLAGS)

# Embedding library
$(EMBED_LIB_TARGET): $(MARROW_SERVER_OBJS) $(LIB_TARGET) | $(BUILD_DIR)
	ar rcs $@ $^

# Embedding example
EMBED_EXAMPLE_TARGET = $(BIN_DIR)/embed_example
$(EMBED_EXAMPLE_TARGET): examples/embed/main.c $(EMBED_LIB_TARGET) $(LIB_TARGET) | $(BIN_DIR)
	gcc -std=c89 -Wall -Wpedantic -g $(CFLAGS) -I$(INCLUDE_DIR) -I$(SRC_DIR) \
		$< -L$(BUILD_DIR) -lmarrow_embed -lmarrow -o $@ $(LDFLAGS)

# Compile object files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -I$(SRC_DIR) -c $< -o $@

$(BUILD_DIR)/sys/%.o: sys/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -I$(SRC_DIR) -c $< -o $@

# Special case for devaudio.c - use C99 since ALSA headers require it
$(BUILD_DIR)/sys/devaudio.o: sys/devaudio.c | $(BUILD_DIR)
	$(CC) -std=c99 -Wall -Wpedantic -g -D_POSIX_C_SOURCE=200112L \
		$(filter-out -std=c89,$(CFLAGS)) -I$(INCLUDE_DIR) -I$(SRC_DIR) -c $< -o $@

# Assembly files (amd64)
$(BUILD_DIR)/asm/%.o: $(SRC_DIR)/asm/%.S | $(BUILD_DIR)
	as --64 $< -o $@

# Test programs
TEST_DIR = tests
TEST_BIN_DIR = $(BUILD_DIR)/tests

.PHONY: tests
tests: $(TEST_BIN_DIR)/test_peb $(TEST_BIN_DIR)/test_loader

$(TEST_BIN_DIR):
	mkdir -p $(TEST_BIN_DIR)

$(TEST_BIN_DIR)/test_peb: $(TEST_DIR)/test_peb.c $(LIB_TARGET) | $(TEST_BIN_DIR)
	gcc -std=c89 -Wall -Wpedantic -g $(CFLAGS) -I$(INCLUDE_DIR) -I$(SRC_DIR) \
		$< -L$(BUILD_DIR) -lmarrow -o $@

$(TEST_BIN_DIR)/test_loader: $(TEST_DIR)/test_loader.c $(LIB_TARGET) | $(TEST_BIN_DIR)
	gcc -std=c89 -Wall -Wpedantic -g $(CFLAGS) -I$(INCLUDE_DIR) -I$(SRC_DIR) \
		$< -L$(BUILD_DIR) -lmarrow -o $@

.PHONY: test-peb
test-peb: $(TEST_BIN_DIR)/test_peb
	$(TEST_BIN_DIR)/test_peb

.PHONY: test-loader
test-loader: $(TEST_BIN_DIR)/test_loader
	$(TEST_BIN_DIR)/test_loader

# Clean
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)

# Run server
.PHONY: run
run: $(SERVER_TARGET)
	./$(SERVER_TARGET) --port 17010

# Run embedding example
.PHONY: run-embed
run-embed: $(EMBED_EXAMPLE_TARGET)
	./$(EMBED_EXAMPLE_TARGET)
