# Marrow - Portable Distributed Kernel
# Plan 9 mk build file

<../mkfile.common

# Object file extension
O=.o

# Directories
SRC=lib
INCLUDE=include
BUILD=build
BIN=bin

# Library target
LIB=$BUILD/libmarrow.a
SERVER=$BIN/marrow

# Source files by module
MARROW_9P=9p/protocol 9p/ops 9p/tree
MARROW_GRAPHICS=graphics/memdraw graphics/memimage graphics/pixconv
MARROW_AUTH=auth/ed448 auth/dp9ik auth/p9any auth/session auth/factotum auth/keys auth/secstore auth/p9sk1
MARROW_REGISTRY=registry/cpu registry/rcpu registry/namespace registry/service registry/discovery registry/mount
MARROW_SYS=sys/console sys/fd sys/proc sys/env sys/svc sys/devdraw sys/devscreen sys/devmouse sys/devkbd sys/devaudio sys/devtime
MARROW_PLATFORM=platform/socket
MARROW_RUNTIME=runtime/peb runtime/context runtime/syscall runtime/p9compat
MARROW_LOADER=loader/p9exec
MARROW_ASM=asm/amd64_ctx asm/amd64_syscall

# Server sources
MARROW_SERVER=server/core server/init server/server

# All objects
OFILES=${MARROW_9P:%=$BUILD/%.$O} ${MARROW_GRAPHICS:%=$BUILD/%.$O} \
	${MARROW_AUTH:%=$BUILD/%.$O} ${MARROW_REGISTRY:%=$BUILD/%.$O} \
	${MARROW_SYS:%=$BUILD/%.$O} ${MARROW_PLATFORM:%=$BUILD/%.$O} \
	${MARROW_RUNTIME:%=$BUILD/%.$O} ${MARROW_LOADER:%=$BUILD/%.$O} \
	${MARROW_ASM:%=$BUILD/%.$O}

SERVER_OFILES=${MARROW_SERVER:%=$BUILD/%.$O}

# Default target
all:V: $LIB $SERVER

# Create directories
setup:V:
	mkdir -p $BUILD/9p $BUILD/graphics $BUILD/auth $BUILD/registry
	mkdir -p $BUILD/platform $BUILD/server $BUILD/sys
	mkdir -p $BUILD/runtime $BUILD/loader $BUILD/asm
	mkdir -p $BIN

# Library
$LIB: $OFILES
	ar rvc $target $OFILES

# Server binary
$SERVER: cmd/marrow/main.c $LIB
	$LD -Wall -g -DINCLUDE_CPU_SERVER -DINCLUDE_NAMESPACE \
		-I$INCLUDE -I$SRC cmd/marrow/main.c -L$BUILD -lmarrow -o $target $LDFLAGS

# Compile rules
$BUILD/9p/%.$O: $SRC/9p/%.c
	$CC $CFLAGS -I$INCLUDE -I$SRC -c $stem.c -o $target

$BUILD/graphics/%.$O: $SRC/graphics/%.c
	$CC $CFLAGS -I$INCLUDE -I$SRC -c $stem.c -o $target

$BUILD/auth/%.$O: $SRC/auth/%.c
	$CC $CFLAGS -I$INCLUDE -I$SRC -c $stem.c -o $target

$BUILD/registry/%.$O: $SRC/registry/%.c
	$CC $CFLAGS -I$INCLUDE -I$SRC -c $stem.c -o $target

$BUILD/platform/%.$O: $SRC/platform/%.c
	$CC $CFLAGS -I$INCLUDE -I$SRC -c $stem.c -o $target

$BUILD/runtime/%.$O: $SRC/runtime/%.c
	$CC $CFLAGS -I$INCLUDE -I$SRC -c $stem.c -o $target

$BUILD/loader/%.$O: $SRC/loader/%.c
	$CC $CFLAGS -I$INCLUDE -I$SRC -c $stem.c -o $target

$BUILD/asm/%.$O: $SRC/asm/%.S
	as --64 $stem.c -o $target

$BUILD/sys/%.$O: sys/%.c
	$CC $CFLAGS -I$INCLUDE -I$SRC -c $stem.c -o $target

$BUILD/server/%.$O: $SRC/server/%.c
	$CC $CFLAGS -I$INCLUDE -I$SRC -c $stem.c -o $target

# Clean
clean:V:
	rm -rf $BUILD $BIN

# Run server
run:V: $SERVER
	./$SERVER --port 17010
