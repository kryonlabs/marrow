{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    # Build tool + Plan 9 compiler toolchain (mk, 9c, 9l, 9ar, ...)
    plan9port

    # Graphics & Display
    SDL2
    SDL2.dev

    # Authentication
    openssl
    openssl.dev

    # Audio
    alsa-lib
    alsa-lib.dev

    # Math library
    glibc.dev

    # Network testing
    netcat
  ];

  shellHook = ''
    export PLAN9="${pkgs.plan9port}/plan9"
    export PATH="$PLAN9/bin:${pkgs.plan9port}/bin:$PATH"

    # SDL2 and ALSA flags for mk
    export SDL2_CFLAGS="${pkgs.SDL2.dev}/include"
    export SDL2_LDFLAGS="-L${pkgs.SDL2}/lib -lSDL2"
    export ALSA_LDFLAGS="-L${pkgs.alsa-lib}/lib -lasound"

    # Combine flags for mk
    export EXTRA_CFLAGS="-I$SDL2_CFLAGS"
    export EXTRA_LDFLAGS="$SDL2_LDFLAGS $ALSA_LDFLAGS -lcrypto"

    echo "--- Marrow Dev Environment ---"
    echo "Build tool : mk (Plan 9 make)"
    echo "Compiler   : 9c (Plan 9 C compiler)"
    echo "Linker     : 9l (Plan 9 linker)"
    echo "Auth       : OpenSSL loaded"
    echo ""
    echo "Commands:"
    echo "  mk           # build everything"
    echo "  mk clean     # clean"
    echo "  9c -c foo.c  # compile single file with 9c"
    echo "--------------------------------"
    echo ""
    echo "Run server: ./bin/marrow --port 17010"
    echo "Test 9P:    9p -a 'tcp!127.0.0.1!17010' ls /"
  '';
}
