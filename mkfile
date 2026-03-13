# Mu - Portable Microkernel
# Plan 9 mk build file - Plan 9 Compilers Only

<../mkfile.common

# Plan 9 architecture (must be set for $O to work)
OBJTYPE=amd64

# Plan 9 toolchain settings
LDFLAGS+=-lpthread  # Plan 9 build on Linux still needs pthread
ASFLAGS=
MARROW_ASM_EXT=S  # Use .S files (GCC/as compatible)
CFLAGS+=-DUSE_PLAN9_AUDIO  # Enable Plan 9 audio support

# Directories
SRC=lib
INCLUDE=include
BUILD=build
BIN=bin

# Library target
LIB=$BUILD/libmu.a
SERVER=$BIN/mu

# lib9 integration - sys toolchain builds lib9
LIB9=../sys/src/lib/9
LIB9_INCLUDE=../sys/include
LIB9_LIB=$ROOT/amd64/lib/lib9.a

# Source files by module (paths relative to $SRC)
MARROW_9P=9p/handlers 9p/ops 9p/tree 9p/fid_state
MARROW_GRAPHICS=graphics/memdraw graphics/memimage graphics/pixconv
MARROW_AUTH=auth/ed448 auth/sha2 auth/dp9ik auth/session auth/factotum auth/keys auth/p9sk1 auth/p9any_stub
# Temporarily disabled: auth/p9any auth/secstore (plan9port header conflicts)
MARROW_REGISTRY=registry/cpu registry/rcpu registry/namespace registry/service registry/discovery registry/mount
MARROW_SYS=sys/console sys/fd sys/proc sys/env sys/svc sys/devdraw sys/devscreen sys/devmouse sys/devkbd sys/devaudio sys/devtime sys/devrendezvous sys/devdisplay
MARROW_PLATFORM=platform/socket
MARROW_RUNTIME=runtime/peb runtime/context runtime/syscall runtime/p9compat
MARROW_LOADER=loader/p9exec
MARROW_ASM=amd64_ctx amd64_syscall

# Server sources
MARROW_SERVER=server/core server/init server/server

# All objects
OFILES=${MARROW_9P:%=$BUILD/%.$O} ${MARROW_GRAPHICS:%=$BUILD/%.$O} \
	${MARROW_AUTH:%=$BUILD/%.$O} ${MARROW_REGISTRY:%=$BUILD/%.$O} \
	${MARROW_SYS:%=$BUILD/%.$O} ${MARROW_PLATFORM:%=$BUILD/%.$O} \
	${MARROW_RUNTIME:%=$BUILD/%.$O} ${MARROW_LOADER:%=$BUILD/%.$O} \
	${MARROW_ASM:%=$BUILD/asm/%.$O}

SERVER_OFILES=${MARROW_SERVER:%=$BUILD/%.$O}

# Default target
all:V: setup $LIB $SERVER

# Create directories
setup:V:
	mkdir -p $BUILD/9p $BUILD/graphics $BUILD/auth $BUILD/registry
	mkdir -p $BUILD/platform $BUILD/server $BUILD/sys
	mkdir -p $BUILD/runtime $BUILD/loader $BUILD/asm
	mkdir -p $BIN

# Library
$LIB: $OFILES $LIB9_LIB
	ar rvc $target $OFILES

# Server binary
$SERVER: cmd/mu/main.c $LIB $LIB9_LIB
	$LD $CFLAGS -DINCLUDE_CPU_SERVER -DINCLUDE_NAMESPACE \
		-I$INCLUDE -I$SRC -I$LIB9_INCLUDE cmd/mu/main.c -L$BUILD -L$LIB9 -lmu -l9 -o $target $LDFLAGS

# Compile rules
$BUILD/9p/%.$O: $SRC/9p/%.c
	$CC $CFLAGS -I$INCLUDE -I$SRC -I$LIB9_INCLUDE -c $prereq -o $target

$BUILD/graphics/%.$O: $SRC/graphics/%.c
	$CC $CFLAGS -I$INCLUDE -I$SRC -I$LIB9_INCLUDE -c $prereq -o $target

$BUILD/auth/%.$O: $SRC/auth/%.c
	$CC $CFLAGS -I$INCLUDE -I$SRC -I$LIB9_INCLUDE -c $prereq -o $target

$BUILD/registry/%.$O: $SRC/registry/%.c
	$CC $CFLAGS -I$INCLUDE -I$SRC -I$LIB9_INCLUDE -c $prereq -o $target

$BUILD/platform/%.$O: $SRC/platform/%.c
	$CC $CFLAGS -I$INCLUDE -I$SRC -I$LIB9_INCLUDE -c $prereq -o $target

$BUILD/runtime/%.$O: $SRC/runtime/%.c
	$CC $CFLAGS -I$INCLUDE -I$SRC -I$LIB9_INCLUDE -c $prereq -o $target

$BUILD/loader/%.$O: $SRC/loader/%.c
	$CC $CFLAGS -I$INCLUDE -I$SRC -I$LIB9_INCLUDE -c $prereq -o $target

# Assembly compilation - .S format (GCC/as compatible, using 9c)
$BUILD/asm/%.$O: $SRC/asm/%.S
	$CC -c $CFLAGS $prereq -o $target

$BUILD/sys/%.$O: sys/%.c
	$CC $CFLAGS -I$INCLUDE -I$SRC -I$LIB9_INCLUDE -c $prereq -o $target

$BUILD/server/%.$O: $SRC/server/%.c
	$CC $CFLAGS -I$INCLUDE -I$SRC -I$LIB9_INCLUDE -c $prereq -o $target

# Tests
TESTS=test_link test_loader test_loader_debug test_loader_funcs test_loader_simple \
	test_minimal test_peb test_segment test_simple test_symbol test_symbol_debug

TEST_BINS=${TESTS:%=$BUILD/tests/%}

$BUILD/tests/%: tests/%.c $LIB
	mkdir -p $BUILD/tests
	$CC $CFLAGS -I$INCLUDE -I$SRC tests/$stem.c -L$BUILD -lmu -o $target $LDFLAGS -lm

test:V: $LIB ${TEST_BINS}
	sh tests/run_tests.sh ${TEST_BINS}

# Clean
clean:V:
	rm -rf $BUILD $BIN

# Run server
run:V: $SERVER
	./$SERVER --port 17010
