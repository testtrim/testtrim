{
  description = "cargo based nix development";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system: let
      overlays = [ (import rust-overlay) ];
      pkgs = import nixpkgs {
        inherit system overlays;
      };
    in {
      devShells.default =
        pkgs.mkShell rec {
          nativeBuildInputs = [ pkgs.pkg-config ];

          buildInputs =  with pkgs; [
          ];

          packages = with pkgs; [
            (rust-bin.selectLatestNightlyWith( toolchain: toolchain.default.override {
              extensions = [
                "rust-src"
                "rust-analyzer"
                "llvm-tools-preview" # for llvm-profdata & llvm-cov
              ];
            }))

            # LLVM rust demangler
            rustfilt

            # allows access to llvm-profdata
            # $ cargo profdata -- merge -sparse default.profraw -o default.profdata
            # and llvm-cov...
            # $ cargo cov -- show -Xdemangler=rustfilt target/debug/rust-coverage-thingy -instr-profile=default.profdata -show-line-counts-or-regions -show-instantiations
            cargo-binutils
          ];

          LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath buildInputs;          

          shellHook = ''
            export RUSTFLAGS="-C instrument-coverage"
            export LLVM_PROFILE_FILE="default.profraw"
          '';
        };
    });
}
