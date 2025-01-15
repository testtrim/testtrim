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
      my-rust-bin = (pkgs.rust-bin.selectLatestNightlyWith( toolchain: toolchain.default.override {
        extensions = [
          "rust-src"
          "rust-analyzer"
          "llvm-tools-preview" # for llvm-profdata & llvm-cov # FIXME: maybe not needed anymore; pretty dated from early development days
        ];
      }));
      rustPlatform = pkgs.makeRustPlatform {
        cargo = my-rust-bin; # .stable.latest.minimal;
        rustc = my-rust-bin; # .stable.latest.minimal;
      };
      # aya-rs has hard-coded commands built into it to run "cargo +nightly ..." as part of its build scripts (eg.
      # https://github.com/aya-rs/aya/blob/f34d355d7d70f8f9ef0f0a01a4338e50cf0080b4/aya-build/src/lib.rs#L62).  However,
      # "+nightly" isn't truly an argument supported by cargo; instead it is added by rustup's cargo wrapper to allow
      # choosing a toolchain for the current command.  But we're not using rustup, causing all the aya-rs builds to fail.
      # So, as a workaround, we replace our cargo command with a script that strips the "+nightly" out.
      cargoWrapper = pkgs.stdenv.mkDerivation {
        name = "testtrim-cargo-wrapper";
        # No source needed as we're creating the script directly
        dontUnpack = true;
        buildPhase = ''
          mkdir -p $out/bin
          cat > $out/bin/cargo << 'EOF'
          #!/usr/bin/env bash
          args=()
          for arg in "$@"; do
              if [[ ! $arg == +* ]]; then
                  args+=("$arg")
              fi
          done
          exec ${my-rust-bin}/bin/cargo "''${args[@]}"
          EOF
          chmod +x $out/bin/cargo
        '';
        # Skip unneeded phases
        dontInstall = true;
      };
      myBuildInputs = with pkgs; [
        openssl
        sqlite
      ];
      myNativeBuildInputs = with pkgs; [
        pkg-config
        openssl.dev
        cargoWrapper
        bpf-linker
      ];
    in {
      devShells.default =
        pkgs.mkShell rec {
          nativeBuildInputs = [ pkgs.pkg-config ];

          buildInputs =  with pkgs; [
          ];

          packages = with pkgs;
            [ my-rust-bin ] ++
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
              my-rust-bin
              reuse
              rustfilt # LLVM rust demangler
              sqlx-cli
              strace

              # FIXME: eBPF and aya tools -- not sure what we'll actually need yet.
              # bpftrace
              # bpf-linker
              # cargo-generate
              # bpftools

              # Can locally run the Forgejo action for quicker dev cycles:
              # act --container-daemon-socket unix:///run/podman/podman.sock -W ./.forgejo/workflows -P docker=node:20-bullseye
              act

              # FIXME: integration tests rely on having development tools available for each system that they operate
              # under -- ideally they would load such a thing from the target repo.  But this isn't a critical issue to
              # resolve because when testtrim is being used normally, it would be someone else's responsibility to get dev
              # tools in place that are relevant to the project.
              dotnet-sdk_8  # for dotnet-coverage-specimen
              go_1_23 # for go-coverage-specimen
            ];

          LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath buildInputs;

          shellHook = ''
            export RUST_BACKTRACE=1
            export PATH=${cargoWrapper}/bin:$PATH
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
            ./testtrim-ebpf-common
            ./testtrim-ebpf-program
            ./testtrim-ebpf-tracing
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

          # FIXME: not sure what dependencies are leftover here that might be affecting the binary output -- for
          # example, "cargo" -- that shouldn't be present after build...
          buildInputs = myBuildInputs;
          nativeBuildInputs = myNativeBuildInputs;

          # We'll do tests outside of the build in the CI.
          doCheck = false;

          # FIXME: it might be nicer to have the `cargo sql prepare` occur in this build script.  That'd nicer than
          # having to run it, `git add .sqlx`, but not keep them.  But it would require starting Postgres here and running
          # the SQL migrations, which is pretty awkward in a build script.
          buildPhase = ''
            runHook preBuild

            # Normally buildRustPackage has a hook that sets up .cargo/config.toml and, amoung other things, sets a
            # ""rustflags" = [ "-C", "target-feature=-crt-static" ]".  This interfers with the bpf-linker which doesn't
            # support having `-crt-static` as an input, and causes: note: Error: error: unexpected argument '-c' found
            # So... we remove it.
            sed -i '/"rustflags"/d' .cargo/config.toml

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
              "-vvv"
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
