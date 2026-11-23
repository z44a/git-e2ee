{
  description = "git-e2ee: end-to-end encrypted, deniable git remotes";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAll (
        pkgs:
        let
          p = pkgs.callPackage ./nix/package.nix { };
        in
        {
          git-e2ee = p.client;
          git-e2ee-relay = p.relay;
          default = p.client;
        }
      );

      overlays.default =
        final: _prev:
        let
          p = final.callPackage ./nix/package.nix { };
        in
        {
          git-e2ee = p.client;
          git-e2ee-relay = p.relay;
        };

      nixosModules.git-e2ee-relay = import ./nix/relay-module.nix self;
      nixosModules.default = self.nixosModules.git-e2ee-relay;

      # Every flag the NixOS module can pass exists in the relay it runs.
      checks = forAll (
        pkgs:
        let
          relay = self.packages.${pkgs.stdenv.hostPlatform.system}.git-e2ee-relay;
          flags =
            map (o: o.flag) (builtins.attrValues (import ./nix/relay-flags.nix pkgs.lib))
            ++ [
              "--db"
              "--listen"
              "--public-url"
              "--tls-cert"
              "--tls-key"
              "--plaintext-behind-proxy"
              "--trust-forwarded-for"
              "--allow-classical-tls"
              "--invite-only"
              "--contact"
              "--policy"
            ];
        in
        {
          relay-module-flags = pkgs.runCommand "git-e2ee-relay-module-flags" { } ''
            help=$(${relay}/bin/git-e2ee-relay --help)
            for f in ${pkgs.lib.escapeShellArgs flags}; do
              grep -qE -- "(^| )$f( |$)" <<<"$help" || { echo "the module passes $f, which git-e2ee-relay doesn't know"; exit 1; }
            done
            touch $out
          '';
        }
      );

      devShells = forAll (pkgs: {
        default = import ./shell.nix { inherit pkgs; };
      });
    };
}
