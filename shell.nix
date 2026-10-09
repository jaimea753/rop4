{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  name = "rop4-dev-env";

  buildInputs = with pkgs; [
    go
    capstone          # libcapstone v5 (C library + headers) for the CGo disasm wrapper
    pkg-config
  ];

  # cgo uses `#cgo pkg-config: capstone`. On nixpkgs, pkg-config reports
  # -I.../include/capstone, so `#include <capstone.h>` works but the portable
  # `#include <capstone/capstone.h>` does not. Add the parent include dir so
  # both spellings resolve (and the code stays portable to standard distros).
  CGO_CFLAGS = "-I${pkgs.capstone}/include";

  shellHook = ''
    export CGO_ENABLED=1
    export GOFLAGS=-mod=mod
  '';
}
