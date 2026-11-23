# Both halves of git-e2ee, built from this workspace:
#   client: `git-e2ee` and `git-remote-e2ee` (git finds both on PATH)
#   relay:  `git-e2ee-relay`
{
  lib,
  rustPlatform,
  protobuf,
  cmake,
  perl,
}:

let
  src = lib.cleanSourceWith {
    src = lib.cleanSource ../.;
    filter =
      path: type:
      let
        name = baseNameOf path;
      in
      !(name == "target" || name == "result" || lib.hasPrefix "result-" name);
  };

  build =
    {
      pname,
      crate,
      description,
    }:
    rustPlatform.buildRustPackage {
      inherit pname src;
      version = "0.1.0";

      cargoLock = {
        lockFile = ../Cargo.lock;
        # libsignal and its ratchet are git dependencies, pinned by commit in
        # Cargo.lock: fetched by that commit, no extra hashes to maintain.
        allowBuiltinFetchGit = true;
      };

      cargoBuildFlags = [ "-p" crate ];

      # libsignal's build scripts compile protobufs; aws-lc (TLS) and the
      # bundled SQLite are C.
      nativeBuildInputs = [
        protobuf
        cmake
        perl
      ];
      env.PROTOC = "${protobuf}/bin/protoc";
      # The C libraries are the versions Cargo.lock pins, built from the
      # crates' bundled sources (what the test suite runs against): aws-lc for
      # TLS, whose nixpkgs copy is a version these bindings (aws-lc-sys 0.47)
      # don't accept, and SQLite. nixpkgs' setup hook asks for system copies
      # in a configure hook, so this undoes it just before the build.
      preBuild = ''
        export AWS_LC_SYS_USE_SYSTEM=0
        unset LIBSQLITE3_SYS_USE_PKG_CONFIG
      '';

      # The end-to-end tests drive real git against relays on local ports;
      # run them with `cargo test` in a dev shell instead.
      doCheck = false;

      meta = {
        inherit description;
        homepage = "https://github.com/z44a/git-e2ee";
        mainProgram = pname;
        license = lib.licenses.agpl3Only;
        platforms = lib.platforms.linux;
      };
    };
in
{
  client = build {
    pname = "git-e2ee";
    crate = "e2ee-helper";
    description = "End-to-end encrypted, deniable git remotes (git-e2ee and git-remote-e2ee)";
  };

  relay = build {
    pname = "git-e2ee-relay";
    crate = "e2ee-relay";
    description = "Untrusted relay for git-e2ee remotes";
  };
}
