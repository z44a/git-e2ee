# NixOS module: services.git-e2ee-relay
self:
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.git-e2ee-relay;
  tls = cfg.tlsCert != null;
  # One typed option per tunable relay flag (see relay-flags.nix).
  tunables = import ./relay-flags.nix lib;
  policyFile = if cfg.policy != null then pkgs.writeText "git-e2ee-relay-policy.txt" cfg.policy else cfg.policyFile;
in
{
  options.services.git-e2ee-relay = {
    enable = lib.mkEnableOption "the git-e2ee relay";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.git-e2ee-relay;
      defaultText = lib.literalExpression "git-e2ee.packages.\${system}.git-e2ee-relay";
      description = "The relay package.";
    };

    publicUrl = lib.mkOption {
      type = lib.types.strMatching "https?://.+";
      example = "https://relay.example";
      description = "The URL clients use for this relay (device signatures are bound to it).";
    };

    listen = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1:8470";
      description = ''
        Address to listen on. Behind a reverse proxy, keep the loopback default
        (the proxy must offer the X25519MLKEM768 TLS group; clients require it).
        With built-in TLS (`tlsCert`), e.g. `0.0.0.0:443`.
      '';
    };

    # Strings, not Nix paths: a path literal (`/var/lib/acme/...` without
    # quotes) would copy the private key into the world-readable store.
    tlsCert = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "/var/lib/acme/relay.example/fullchain.pem";
      description = "Absolute path (a string) to the PEM certificate chain for built-in TLS. Null: plaintext behind a reverse proxy.";
    };

    tlsKey = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "/var/lib/acme/relay.example/key.pem";
      description = "Absolute path (a string) to the PEM private key for built-in TLS. Read at startup; never copied to the store.";
    };

    behindProxy = lib.mkOption {
      type = lib.types.bool;
      default = cfg.tlsCert == null;
      defaultText = lib.literalExpression "tlsCert == null";
      description = ''
        A reverse proxy on this machine terminates TLS: serve plaintext and
        rate-limit by its X-Forwarded-For header (`--plaintext-behind-proxy
        --trust-forwarded-for`). Needs a loopback `listen`, and can't be
        combined with built-in TLS (a proxy can't add headers inside TLS).
      '';
    };

    allowClassicalTls = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Built-in TLS: also accept classical-only key exchange. By default only
        the hybrid post-quantum X25519MLKEM768 is accepted (and clients require it).
      '';
    };

    inviteOnly = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Only users holding a registration token may register (users who already
        registered a device keep working). Issue one with
        `sudo -u git-e2ee-relay git-e2ee-relay --db /var/lib/git-e2ee-relay/relay.sqlite invite`
        (add `--uses N` for one token several people can use).
      '';
    };

    contact = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "abuse@example.com";
      description = "Contact address shown in the default policy (`git e2ee init-user` shows it).";
    };

    policy = lib.mkOption {
      type = lib.types.nullOr lib.types.lines;
      default = null;
      description = ''
        This relay's policy, shown to users when they run `git e2ee init-user`
        (it goes into the Nix store: it's public anyway). Null: `policyFile`,
        or the default (a repeat-infringer policy plus `contact`).
      '';
    };

    policyFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = "A file with the policy, instead of `policy`.";
    };

    extraFlags = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Flags this module has no option for (from a newer relay), passed as given.";
    };
  }
  // lib.mapAttrs (
    _: o:
    lib.mkOption {
      type = lib.types.nullOr o.type;
      default = null;
      description = "${o.description} Null: the relay's default (${toString o.default}).";
    }
  ) tunables;

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = (cfg.tlsCert == null) == (cfg.tlsKey == null);
        message = "services.git-e2ee-relay: set both tlsCert and tlsKey, or neither.";
      }
      {
        assertion = lib.all (p: p == null || (lib.hasPrefix "/" p && !lib.hasPrefix builtins.storeDir p)) [
          cfg.tlsCert
          cfg.tlsKey
        ];
        message = "services.git-e2ee-relay: tlsCert and tlsKey must be absolute paths outside the Nix store (quote them).";
      }
      {
        assertion = !(tls && cfg.behindProxy);
        message = "services.git-e2ee-relay: behindProxy can't be combined with built-in TLS (a proxy can't add headers inside TLS).";
      }
      {
        assertion = !(cfg.allowClassicalTls && !tls);
        message = "services.git-e2ee-relay: allowClassicalTls only applies to built-in TLS (tlsCert); behind a proxy, the proxy decides.";
      }
      {
        assertion = cfg.policy == null || cfg.policyFile == null;
        message = "services.git-e2ee-relay: set policy or policyFile, not both.";
      }
    ];

    users.users.git-e2ee-relay = {
      isSystemUser = true;
      group = "git-e2ee-relay";
      home = "/var/lib/git-e2ee-relay";
    };
    users.groups.git-e2ee-relay = { };

    # The relay keeps relay.sqlite and relay.sqlite.slots/ here.
    systemd.services.git-e2ee-relay = {
      description = "git-e2ee relay";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      serviceConfig = {
        User = "git-e2ee-relay";
        Group = "git-e2ee-relay";
        StateDirectory = "git-e2ee-relay";
        StateDirectoryMode = "0700";
        ExecStart = lib.escapeShellArgs (
          [
            (lib.getExe' cfg.package "git-e2ee-relay")
            "--db"
            "/var/lib/git-e2ee-relay/relay.sqlite"
            "--listen"
            cfg.listen
            "--public-url"
            cfg.publicUrl
          ]
          ++ lib.optionals tls [
            "--tls-cert"
            "%d/cert"
            "--tls-key"
            "%d/key"
          ]
          ++ lib.optionals cfg.behindProxy [
            "--plaintext-behind-proxy"
            "--trust-forwarded-for"
          ]
          ++ lib.optional cfg.allowClassicalTls "--allow-classical-tls"
          ++ lib.optional cfg.inviteOnly "--invite-only"
          ++ lib.optionals (cfg.contact != null) [
            "--contact"
            cfg.contact
          ]
          ++ lib.optionals (policyFile != null) [
            "--policy"
            "${policyFile}"
          ]
          ++ lib.concatLists (
            lib.mapAttrsToList (
              name: o:
              lib.optionals (cfg.${name} != null) [
                o.flag
                (toString cfg.${name})
              ]
            ) tunables
          )
          ++ cfg.extraFlags
        );
        # Certificates are handed over as credentials, so the key file can
        # stay readable by root only.
        LoadCredential = lib.optionals tls [
          "cert:${cfg.tlsCert}"
          "key:${cfg.tlsKey}"
        ];
        AmbientCapabilities = lib.optional tls "CAP_NET_BIND_SERVICE";
        CapabilityBoundingSet = lib.optional tls "CAP_NET_BIND_SERVICE";
        Restart = "on-failure";
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
          "AF_UNIX"
        ];
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";
      };
    };
  };
}
