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
            [ my-rust-bin ] ++
            myBuildInputs ++
            myNativeBuildInputs ++
            [
              cargo-binutils # allows access to llvm-profdata # FIXME: maybe not needed anymore; pretty dated from early development days
              cargo-nextest
              diesel-cli
              git-cliff # needed for release.yaml workflow
              jq # needed for release.yaml workflow
              my-rust-bin
              reuse
              rustfilt # LLVM rust demangler
              sqlx-cli
              strace
              cargo-expand

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
          '';
        };

      packages = let
        # FIXME: work version into the build, I guess, so that the binary can identify itself?
        testtrimVersion = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).package.version;
        # Before building app, sqlx queries must be "prepared":
        #   cargo sqlx prepare
        # and because the nix flake system will only see files that are added to git, then...
        #   git add .sqlx
        # but it shouldn't be commited in that state.
        appPackage = rustPlatform.buildRustPackage {
          name = "testtrim";

          srcs = [
            ./.sqlx
            ./db
            ./src
            ./tests
            ./build.rs
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
            find .
            find .sqlx
            cargo build --release
          '';
          installPhase = ''
            mkdir -p $out/usr/bin
            cp target/release/testtrim $out/usr/bin/
          '';
        };
      in
      {
        # nix build --print-build-logs .#app
        app = appPackage;

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
              "${appPackage}/usr/bin/testtrim"
              "run-server"
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
