{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    # The Compiler
    tinycc
    gcc  # Alternative compiler for better warnings

    # Build Tools
    gnumake
    pkg-config

    # OpenSSL for authentication (dp9ik, p9any, etc.)
    openssl
    openssl.dev

    # Math library
    glibc.dev

    # Testing Tools (provides 9mount, 9p, etc.)
    plan9port

    # Network testing
    netcat
  ];

  shellHook = ''
    # Add plan9port to PATH (both bin and plan9/bin)
    export PLAN9="${pkgs.plan9port}/plan9"
    export PATH="$PLAN9/bin:${pkgs.plan9port}/bin:$PATH"

    echo "--- Marrow Dev Environment ---"
    echo "Compiler: tcc (C89/C90)"
    echo "Authentication: OpenSSL loaded"
    echo "Testing tools: plan9port loaded"
    echo "--------------------------------"
    echo ""
    echo "Build: make"
    echo "Run: ./bin/marrow --port 17010"
    echo "Test 9P: 9p -a 'tcp!127.0.0.1!17010' ls /"
    echo "Note: Use -a flag for direct TCP connection"
    echo "      Binaries have RPATH set and work outside nix-shell"
  '';
}
