use std::path::PathBuf;

use clap::Parser;

/// Untrusted relay for git-remote-e2ee.
#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    cmd: Option<Admin>,
    /// Address to listen on.
    #[arg(long, default_value = "127.0.0.1:8470")]
    listen: String,
    /// SQLite database path.
    #[arg(long, default_value = "e2ee-relay.sqlite")]
    db: PathBuf,
    /// Days to keep unacknowledged blobs and mail.
    #[arg(long, default_value_t = 14)]
    ttl_days: u64,
    /// Maximum size of one blob (an encrypted pack chunk; clients send 15.5
    /// MiB chunks, at most 31 MiB), in MiB. At most 63.
    #[arg(long, default_value_t = 32)]
    max_blob_mib: usize,
    /// Maximum stored blob bytes across all repos, in MiB.
    #[arg(long, default_value_t = 65536)]
    max_total_blob_mib: u64,
    /// Maximum queued messages per device mailbox.
    #[arg(long, default_value_t = 20_000)]
    max_mailbox_messages: u64,
    /// One-time prekeys handed out per device per hour (drain protection).
    #[arg(long, default_value_t = 20)]
    max_one_time_handouts_per_hour: u64,
    /// Maximum new repos per hour, relay-wide (repo creation is anonymous).
    #[arg(long, default_value_t = 1000)]
    max_new_repos_per_hour: u64,
    /// Sustained requests per second per client IP (0 = unlimited).
    #[arg(long, default_value_t = 100.0)]
    rate_per_sec: f64,
    /// Burst size for the per-IP rate limit.
    #[arg(long, default_value_t = 1000.0)]
    rate_burst: f64,
    /// PEM certificate chain for built-in TLS 1.3.
    #[arg(long, requires = "tls_key")]
    tls_cert: Option<PathBuf>,
    /// PEM private key for built-in TLS.
    #[arg(long, requires = "tls_cert")]
    tls_key: Option<PathBuf>,
    /// Also accept classical-only TLS key exchange (default: X25519MLKEM768 only).
    #[arg(long)]
    allow_classical_tls: bool,
    /// Serve plaintext on a non-loopback address because a TLS proxy terminates in front.
    #[arg(long)]
    plaintext_behind_proxy: bool,
    /// Rate-limit by the last X-Forwarded-For hop (set when behind a reverse proxy).
    #[arg(long)]
    trust_forwarded_for: bool,
    /// The URL clients use for this relay, e.g. https://relay.example. Device
    /// signatures are bound to it. Required unless serving plaintext loopback.
    #[arg(long)]
    public_url: Option<String>,
    /// A text file with this relay's policy, shown to users when they run
    /// `git e2ee register`. Default: a repeat-infringer policy plus --contact.
    #[arg(long)]
    policy: Option<PathBuf>,
    /// Contact address for the default policy (reports, questions).
    #[arg(long)]
    contact: Option<String>,
    /// Only users holding a registration token (`git-e2ee-relay invite`) may register.
    #[arg(long)]
    invite_only: bool,
    /// Anonymous access tokens each device may obtain per day.
    #[arg(long, default_value_t = 5000)]
    access_tokens_per_day: u64,
    /// Messages per device per day from senders without its delivery token.
    #[arg(long, default_value_t = 20)]
    request_lane_per_day: u64,
    /// Total waiting mail across all mailboxes, in GiB.
    #[arg(long, default_value_t = 16)]
    max_mail_gib: u64,
    /// Total number of pseudonymous (per-repo) mailboxes.
    #[arg(long, default_value_t = 1_000_000)]
    max_mailboxes: u64,
    /// Concurrent connections, in total and from one IP address.
    #[arg(long, default_value_t = 1024)]
    max_connections: usize,
    #[arg(long, default_value_t = 32)]
    max_connections_per_ip: usize,
    /// Most disk the mail and blob storage files may take, in GiB (they
    /// never shrink; keep it above the mail and blob quotas, with room).
    #[arg(long, default_value_t = 128)]
    max_storage_gib: u64,
    /// New users (identities) and new devices per address (IPv6: /64) per
    /// hour, and in total. They cost no access tokens, so on an open relay
    /// these are what bound them.
    #[arg(long, default_value_t = 10)]
    new_users_per_ip_hour: u64,
    #[arg(long, default_value_t = 30)]
    new_devices_per_ip_hour: u64,
    #[arg(long, default_value_t = 1_000_000)]
    max_users: u64,
    #[arg(long, default_value_t = 2_000_000)]
    max_devices: u64,
}

/// Operator commands, run against the same --db (the relay may be running).
#[derive(clap::Subcommand)]
enum Admin {
    /// Print a registration token for one new user (`--uses N`: up to N).
    Invite {
        /// Hours until the token expires.
        #[arg(long, default_value_t = 24)]
        hours: u64,
        /// How many different new users may register with it (each one's
        /// first registration takes one use).
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..))]
        uses: u32,
    },
    /// Ban a user (hex user id): drop their registrations and void all access tokens.
    Ban { user: String },
    /// Lift a ban (on invite-only relays they need a new token).
    Unban { user: String },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    // A blob lives in one storage slot (at most 64 MiB with its header).
    if args.max_blob_mib > 63 {
        anyhow::bail!("--max-blob-mib can be at most 63");
    }
    let limits = e2ee_relay::Limits {
        max_blob_bytes: args.max_blob_mib << 20,
        max_total_blob_bytes: args.max_total_blob_mib << 20,
        max_mailbox_messages: args.max_mailbox_messages,
        max_new_logs_per_hour: args.max_new_repos_per_hour,
        max_one_time_handouts_per_hour: args.max_one_time_handouts_per_hour,
        rate_per_sec: args.rate_per_sec,
        rate_burst: args.rate_burst,
        trust_forwarded_for: args.trust_forwarded_for,
        invite_only: args.invite_only,
        access_tokens_per_day: args.access_tokens_per_day,
        request_lane_per_day: args.request_lane_per_day,
        max_total_mail_bytes: args.max_mail_gib << 30,
        max_pmailboxes: args.max_mailboxes,
        max_connections: args.max_connections,
        max_connections_per_ip: args.max_connections_per_ip,
        max_storage_bytes: args.max_storage_gib << 30,
        new_identities_per_ip_hour: args.new_users_per_ip_hour,
        new_devices_per_ip_hour: args.new_devices_per_ip_hour,
        max_users: args.max_users,
        max_devices: args.max_devices,
        ..Default::default()
    };
    // Spent access tokens are remembered for at least half the TTL, and a
    // token stays valid for two days: below 4 days one could be spent twice.
    if args.ttl_days < 4 {
        anyhow::bail!("--ttl-days must be at least 4");
    }
    let relay = e2ee_relay::Relay::open(&args.db, std::time::Duration::from_secs(args.ttl_days * 24 * 3600), limits)?;
    match &args.cmd {
        Some(Admin::Invite { hours, uses }) => {
            let uses = *uses;
            println!("{}", relay.issue_invite(std::time::Duration::from_secs(hours * 3600), uses)?);
            eprintln!(
                "valid for {} for the next {hours} hour(s)",
                if uses == 1 { "one new user".to_string() } else { format!("up to {uses} different new users") }
            );
            return Ok(());
        }
        Some(Admin::Ban { user }) => {
            relay.ban(user)?;
            println!("banned {user}");
            return Ok(());
        }
        Some(Admin::Unban { user }) => {
            relay.unban(user)?;
            println!("unbanned {user}");
            return Ok(());
        }
        None => {}
    }
    match (&args.policy, &args.contact) {
        (Some(path), _) => relay.set_policy(std::fs::read_to_string(path)?)?,
        (None, Some(c)) => relay.set_policy(e2ee_relay::default_policy(Some(c)))?,
        (None, None) => tracing::warn!(
            "no --contact or --policy given: the policy shown to users has no contact address"
        ),
    }
    if args.trust_forwarded_for && args.tls_cert.is_some() {
        anyhow::bail!(
            "--trust-forwarded-for doesn't work with --tls-cert: TLS ends at the relay, so a proxy in front of \
             it can't add X-Forwarded-For, and every client would look like the proxy (sharing one rate \
             limit). Either let the proxy terminate TLS (--plaintext-behind-proxy), or expose the relay directly"
        );
    }
    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    let addr = listener.local_addr()?;
    // X-Forwarded-For is only trustworthy from a proxy on this machine.
    if args.trust_forwarded_for && !addr.ip().is_loopback() {
        anyhow::bail!(
            "--trust-forwarded-for needs a loopback --listen address (the reverse proxy in front of the relay); \
             exposed directly, clients could spoof their IP and dodge rate limits"
        );
    }
    match &args.public_url {
        Some(u) => relay.set_public_url(u)?,
        None if args.tls_cert.is_some() || !addr.ip().is_loopback() => anyhow::bail!(
            "--public-url is required (the URL clients use, e.g. https://relay.example): \
             device signatures are bound to it"
        ),
        None => {}
    }
    match (&args.tls_cert, &args.tls_key) {
        (Some(cert), Some(key)) => {
            tracing::info!("git-e2ee-relay listening on https://{addr}");
            let tls = e2ee_relay::TlsConfig {
                cert_pem: std::fs::read(cert)?,
                key_pem: std::fs::read(key)?,
                allow_classical: args.allow_classical_tls,
            };
            e2ee_relay::serve_tls(listener, relay, 0, tls).await
        }
        _ => {
            if !addr.ip().is_loopback() && !args.plaintext_behind_proxy {
                anyhow::bail!(
                    "refusing to serve plaintext on {addr}: pass --tls-cert/--tls-key, or \
                     --plaintext-behind-proxy if a TLS proxy terminates in front of the relay"
                );
            }
            tracing::info!("git-e2ee-relay listening on http://{addr} (plaintext)");
            e2ee_relay::serve(listener, relay, 0).await
        }
    }
}
