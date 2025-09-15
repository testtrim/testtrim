# SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
#
# SPDX-License-Identifier: GPL-3.0-or-later

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
      my-rust-dev = pkgs.rust-bin.stable.latest.default.override {
        extensions = [
          "rust-src"
          "rust-analyzer"
          "llvm-tools-preview" # for llvm-profdata & llvm-cov # FIXME: maybe not needed anymore; pretty dated from early development days
        ];
      };
      my-rust-build = pkgs.rust-bin.stable.latest.default.override {
        # my-rust-build is to be used for packaging builds -- it should have the same capabilities as my-rust-dev but
        # without any development tools.  In particular, "rust-src" must not be included as an extension as that will
        # bloat the runtime dependencies -- https://github.com/oxalica/rust-overlay/issues/199 -- since it will cause all
        # compiled binaries to have embedded references to the source files, requiring the entire dev environment for
        # any package output.
        extensions = [];
      };
      rustPlatform = pkgs.makeRustPlatform {
        cargo = my-rust-build; # .stable.latest.minimal;
        rustc = my-rust-build; # .stable.latest.minimal;
      };
      myBuildInputs = with pkgs; [
        openssl
        sqlite
      ];
      myNativeBuildInputs = with pkgs; [
        pkg-config
        openssl.dev
      ];
    in {
      devShells.default =
        pkgs.mkShell rec {
          nativeBuildInputs = [ pkgs.pkg-config ];

          buildInputs =  with pkgs; [
          ];

          packages = with pkgs;
            myBuildInputs ++
            myNativeBuildInputs ++
            [
              cargo-binutils # allows access to llvm-profdata # FIXME: maybe not needed anymore; pretty dated from early development days
              cargo-expand # useful for understanding macros, run `cargo expand --lib > tmp.rs` to view intermediate output
              cargo-nextest
              dasel # needed for rust-check.yaml
              diesel-cli
              git-cliff # needed for release.yaml workflow
              jq # needed for release.yaml workflow
              my-rust-dev
              reuse
              # rustfilt # LLVM rust demangler -- not available in nixpkgs anymore 2025-01-26 -- https://github.com/NixOS/nixpkgs/pull/377036
              sqlx-cli
              strace

              # Can locally run the Forgejo action for quicker dev cycles:
              # act --container-daemon-socket unix:///run/podman/podman.sock -W ./.forgejo/workflows -P docker=node:20-bullseye
              act

              # FIXME: integration tests rely on having development tools available for each system that they operate
              # under -- ideally they would load such a thing from the target repo.  But this isn't a critical issue to
              # resolve because when testtrim is being used normally, it would be someone else's responsibility to get dev
              # tools in place that are relevant to the project.
              dotnet-sdk_8  # for dotnet-coverage-specimen
              go_1_25 # for go-coverage-specimen
              nodejs_22 # for javascript-coverage-specimen
            ];

          LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath buildInputs;

          shellHook = ''
            export RUST_BACKTRACE=1
          '';
        };

      packages = let
        testtrimVersion = (builtins.fromTOML (builtins.readFile ./testtrim-cli/Cargo.toml)).package.version;
        appPackage = rustPlatform.buildRustPackage {
          name = "testtrim";

          srcs = [
            ./.sqlx
            ./db
            ./testtrim-cli
            ./testtrim-syscall-test-app
            ./Cargo.lock
            ./Cargo.toml
          ];
          unpackPhase = ''
            runHook preUnpack

            for _src in $srcs; do
              cp -r "$_src" $(stripHash "$_src")
            done

            runHook postUnpack
          '';

          cargoLock = {
            lockFile = ./Cargo.lock;
          };

          buildInputs = myBuildInputs;
          nativeBuildInputs = myNativeBuildInputs;

          # We'll do tests outside of the build in the CI.
          doCheck = false;

          buildPhase = ''
            runHook preBuild

            export CARGO_HOME=$TMPDIR # prevents any output to /homeless-shelter with cargo cache DBs
            cargo build --release

            runHook postBuild
          '';
          installPhase = ''
            runHook preInstall

            mkdir -p $out/bin
            cp target/release/testtrim $out/bin/

            runHook postInstall
          '';
        };
      in
      {
        # nix build --print-build-logs .#testtrim
        testtrim = appPackage;

        # nix build --print-build-logs .#docker && podman load -i result -q && podman run -it --rm -p 127.0.0.1:8080:8080 codeberg.org/testtrim/server:0.2.1
        docker = pkgs.dockerTools.buildLayeredImage {
          name = "codeberg.org/testtrim/server";
          tag = testtrimVersion;

          contents = [
            appPackage
            pkgs.coreutils # typically useful for diagnosing problems in the container
            # pkgs.cacert # may be needed?; not sure, depends on what rust TLS clients are in-use and what their CA strategy is...?
          ];

          config = {
            Cmd = [
              "${appPackage}/bin/testtrim"
              "run-server"
              # Default bind is localhost; but for port forwards to work correctly containers are expected to listen on
              # 0.0.0.0.
              "--bind-socket=0.0.0.0:8080"
              # Bump output up to DEBUG level -- the actix-web logger middleware only logs internal error details at
              # the DEBUG level.  This seems weird to me, but arguably could make sense -- some errors are not
              # internal server errors that you would treat as such.
              "-vv"
            ];
            Env = [];
            ExposedPorts = {
              "8080/tcp" = {};
            };
          };
        };
      };

    });
}
