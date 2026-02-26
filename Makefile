# Marrow - Portable Distributed Kernel
# C89/C90 compliant build using tcc or gcc

# Detect compiler
CC := $(shell command -v tcc 2>/dev/null)
ifeq ($(CC),)
    CC = gcc
endif

CFLAGS = -std=c89 -Wall -Wpedantic -g
LDFLAGS =

# Detect Nix environment
ifneq ($(NIX_LDFLAGS),)
    CC = gcc
    LDFLAGS += $(shell echo '$(NIX_LDFLAGS)' | perl -pe 's/-rpath (\S+)/-Wl,-rpath,$1/g')
    CFLAGS += $(NIX_CFLAGS_COMPILE)
    CFLAGS += -DUSE_OPENSSL
    LDFLAGS += -lcrypto
    $(info Building in Nix environment - using GCC)
endif

# Directories
SRC_DIR = lib
INCLUDE_DIR = include
BUILD_DIR = build
BIN_DIR = bin

# Source files
MARROW_9P_SRCS = $(SRC_DIR)/9p/protocol.c $(SRC_DIR)/9p/ops.c $(SRC_DIR)/9p/tree.c \
                 $(SRC_DIR)/9p/drawconn_stub.c
MARROW_AUTH_SRCS = $(SRC_DIR)/auth/dp9ik.c $(SRC_DIR)/auth/p9any.c \
                   $(SRC_DIR)/auth/session.c $(SRC_DIR)/auth/factotum.c \
                   $(SRC_DIR)/auth/keys.c $(SRC_DIR)/auth/secstore.c \
                   $(SRC_DIR)/auth/p9sk1.c
MARROW_REGISTRY_SRCS = $(SRC_DIR)/registry/cpu.c $(SRC_DIR)/registry/rcpu.c \
                       $(SRC_DIR)/registry/namespace.c
MARROW_SYS_SRCS = sys/console.c sys/fd.c sys/proc.c sys/env.c
MARROW_PLATFORM_SRCS = $(SRC_DIR)/platform/socket.c

MARROW_SRCS = $(MARROW_9P_SRCS) $(MARROW_AUTH_SRCS) $(MARROW_REGISTRY_SRCS) \
              $(MARROW_SYS_SRCS) $(MARROW_PLATFORM_SRCS)

# Object files
MARROW_OBJS = $(MARROW_9P_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o) \
              $(MARROW_AUTH_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o) \
              $(MARROW_REGISTRY_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o) \
              $(MARROW_SYS_SRCS:sys/%.c=$(BUILD_DIR)/sys/%.o) \
              $(MARROW_PLATFORM_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

# Targets
LIB_TARGET = $(BUILD_DIR)/libmarrow.a
SERVER_TARGET = $(BIN_DIR)/marrow

# Default target
.PHONY: all
all: $(SERVER_TARGET)

# Create directories
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)/9p
	mkdir -p $(BUILD_DIR)/auth
	mkdir -p $(BUILD_DIR)/registry
	mkdir -p $(BUILD_DIR)/platform
	mkdir -p $(BUILD_DIR)/sys

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Library
$(LIB_TARGET): $(MARROW_OBJS) | $(BUILD_DIR)
	ar rcs $@ $^

# Server binary
$(SERVER_TARGET): cmd/marrow/main.c $(LIB_TARGET) | $(BIN_DIR)
	gcc -std=c89 -Wall -Wpedantic -g $(CFLAGS) -DINCLUDE_CPU_SERVER -DINCLUDE_NAMESPACE \
		-I$(INCLUDE_DIR) -I$(SRC_DIR) $< -L$(BUILD_DIR) -lmarrow -o $@ $(LDFLAGS)

# Compile object files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -I$(SRC_DIR) -c $< -o $@

$(BUILD_DIR)/sys/%.o: sys/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -I$(SRC_DIR) -c $< -o $@

# Clean
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)

# Run server
.PHONY: run
run: $(SERVER_TARGET)
	./$(SERVER_TARGET) --port 17010
