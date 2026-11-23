//! Management CLI for git-remote-e2ee: identities, devices, repos, members.

use std::io::Write;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use e2ee_core::client::RelayClient;
use e2ee_core::device::{Device, short};
use e2ee_core::engine::Engine;
use e2ee_core::git::Git;
use e2ee_helper::{Session, has_account, print_report, print_warnings, runtime, printable};
use e2ee_core::store::{account_dir, accounts, relay_host};
use e2ee_proto::{Member, Message, user_id_of};

#[derive(Parser)]
#[command(name = "git-e2ee", bin_name = "git e2ee", about = "End-to-end encrypted, deniable git remotes")]
struct Cli {
    /// The relay whose account to use (accounts are per relay). Default: the
    /// current repo's relay, or your only account.
    #[arg(long, global = true)]
    relay: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create your account on a relay (a user with its own master key, this
    /// device as device 1) and register it. Accounts on different relays are
    /// separate users.
    InitUser {
        relay_url: String,
        /// Registration token from the relay operator (invite-only relays).
        #[arg(long)]
        token: Option<String>,
    },
    /// List your accounts (one per relay).
    Accounts,
    /// Show this account's code and id.
    Whoami,
    /// Manage your contacts: the people you can add to repos and accept
    /// invitations from.
    #[command(subcommand)]
    Contact(ContactCmd),
    /// Register this account's device with its relay again (say, with a
    /// token after the relay became invite-only). `init-user` and
    /// `device finish` register already.
    Register {
        relay_url: String,
        /// Registration token from the relay operator (invite-only relays;
        /// needed once per user, not per device).
        #[arg(long)]
        token: Option<String>,
    },
    /// Manage this user's devices.
    #[command(subcommand)]
    Device(DeviceCmd),
    /// Manage repos.
    #[command(subcommand)]
    Repo(RepoCmd),
    /// Manage repo members.
    #[command(subcommand)]
    Member(MemberCmd),
    /// Send the current repo state to this user's other devices.
    SendHistory {
        #[command(flatten)]
        remote: RemoteArg,
        /// Only this device id.
        #[arg(long)]
        device: Option<u32>,
    },
    /// Fetch and process everything from the relay (acks, heartbeats, ...).
    Sync {
        #[command(flatten)]
        remote: RemoteArg,
    },
    /// Show who made each change to the repo's refs and membership, as this
    /// device saw it.
    Log {
        #[command(flatten)]
        remote: RemoteArg,
        /// Show at most this many of the newest entries.
        #[arg(short = 'n', long, default_value_t = 50)]
        limit: usize,
    },
    /// Make `git e2ee log` entries disappear after a while, for every member:
    /// e.g. `30m`, `12h`, `7d`, `2w`, or `off`. Each entry keeps the timer that
    /// was set when it happened; who set the timer stays shown until it's
    /// changed again. Relies on every member's client deleting honestly.
    LogTimer {
        #[command(flatten)]
        remote: RemoteArg,
        duration: String,
    },
    /// Show replication state and any detected conflict.
    Status {
        #[command(flatten)]
        remote: RemoteArg,
    },
    /// Replace your delivery token, so someone who got hold of the old one
    /// (a former collaborator, a leak) can only use the relays' small request
    /// lane to reach you. Current collaborators learn the new one from your
    /// next message.
    RotateDeliveryToken,
    /// Clear a recorded conflict after investigating it.
    ClearConflict {
        #[command(flatten)]
        remote: RemoteArg,
    },
}

#[derive(Subcommand)]
enum ContactCmd {
    /// Add a contact by the user id they sent you over a channel you trust
    /// (a verified Signal chat, in person): that is what vouches for them.
    /// Both of you add each other; then either can add the other to repos.
    Add {
        /// Your name for them (only on this device), used in commands and
        /// shown instead of their user id.
        name: String,
        /// Their user id (`git e2ee whoami` shows it).
        user_id: String,
    },
    /// List your contacts.
    List,
    /// Remove a contact (by name or user id). Repos they're in keep them.
    Remove { contact: String },
}

#[derive(Subcommand)]
enum DeviceCmd {
    /// On a new device: start joining your account on this relay; prints a
    /// link code to paste on the master device.
    Link { relay_url: String },
    /// On the master device: approve a link code.
    Approve { link_code: String },
    /// On the new device: finish linking with the approval code.
    Finish { approval_code: String },
    /// On the master device: revoke a device.
    Revoke { device_id: u32 },
    /// List this user's devices.
    List,
}

#[derive(Subcommand)]
enum RepoCmd {
    /// Create an encrypted repo on a relay and add it as a git remote.
    Init {
        relay_url: String,
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Allow a SHA-1 repository. Its commit ids are only about 80-bit
        /// collision resistant, which SHA-1 collision detection doesn't
        /// cover for generic attacks; see the README.
        #[arg(long)]
        allow_sha1: bool,
    },
    /// Leave a repo: tell the other members, then forget it on this device.
    /// The next member to sync rotates the repo secret, cutting you off from
    /// later pushes. As the only member, this just forgets the repo.
    Leave {
        #[command(flatten)]
        remote: RemoteArg,
        /// Don't ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
    /// Delete this device's local state for a repo (replication state, keys,
    /// mirror). You stay a member until someone removes you.
    Forget {
        #[command(flatten)]
        remote: RemoteArg,
        /// Don't ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum MemberCmd {
    /// Add a contact and send them the history.
    Add {
        /// Contact name or user id.
        user: String,
        #[command(flatten)]
        remote: RemoteArg,
    },
    /// Remove a user and rotate the repo secret.
    Remove {
        /// Contact name or user id.
        user: String,
        #[command(flatten)]
        remote: RemoteArg,
    },
    /// List members.
    List {
        #[command(flatten)]
        remote: RemoteArg,
    },
}

#[derive(clap::Args)]
struct RemoteArg {
    /// Git remote name (in the current repository).
    #[arg(long, default_value = "origin")]
    remote: String,
    /// Remote URL, instead of reading it from the current repository.
    #[arg(long)]
    url: Option<String>,
}

impl RemoteArg {
    /// An engine for this repo, honoring its git config (`e2ee.pushLog`).
    fn engine(&self, session: &Session) -> Result<Engine> {
        let mut eng = Engine::new(session.device()?, &self.url()?)?;
        if self.url.is_none()
            && let Ok(git) = Git::discover()
        {
            eng.push_log = git.config_flag("e2ee.pushLog")?.unwrap_or(true);
        }
        Ok(eng)
    }

    fn url(&self) -> Result<String> {
        if let Some(u) = &self.url {
            return Ok(u.clone());
        }
        let git = Git::discover()?;
        git.config(&format!("remote.{}.url", self.remote))?
            .filter(|u| u.starts_with("e2ee::"))
            .ok_or_else(|| anyhow!("remote {:?} is not an e2ee:: remote (or pass --url)", self.remote))
    }
}

fn main() {
    if let Err(e) = run(Cli::parse()) {
        eprintln!("error: {}", e2ee_core::printable_text(&format!("{e:#}")));
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    let rt = runtime()?;
    // Commands that create an account's state, or span accounts.
    match &cli.cmd {
        Cmd::InitUser { relay_url, token } => return init_user(&rt, relay_url, token.clone()),
        Cmd::Accounts => return list_accounts(),
        Cmd::Device(DeviceCmd::Link { relay_url }) => return begin_link(relay_url),
        Cmd::Device(DeviceCmd::Finish { approval_code }) => return finish_link(&rt, approval_code),
        _ => {}
    }
    let (session, account_relay) = open_account(&cli)?;
    match cli.cmd {
        Cmd::InitUser { .. } | Cmd::Accounts => unreachable!(),
        Cmd::Whoami => {
            let dev = session.device()?;
            if let Some(r) = &account_relay {
                println!("relay:     {}", relay_host(r)?);
            }
            println!("user id:   {}  (send it to collaborators over a channel you trust)", hex::encode(&dev.user));
            println!("device id: {}{}", dev.device_id, if dev.master.is_some() { " (master)" } else { "" });
        }
        Cmd::Contact(c) => contact_cmd(&session, &rt, c, account_relay.as_deref())?,
        Cmd::Register { relay_url, token } => register(&session, &rt, &relay_url, token)?,
        Cmd::Device(d) => device_cmd(&session, &rt, d, account_relay.as_deref())?,
        Cmd::Repo(RepoCmd::Init { relay_url, remote, allow_sha1 }) => {
            let git = Git::discover()?;
            let format = git.object_format()?;
            match format.as_str() {
                "sha256" => {}
                "sha1" if allow_sha1 => {
                    if !e2ee_core::git::sha1_collision_detection() {
                        bail!("this git isn't built with SHA-1 collision detection (SHA1_DC); refusing a SHA-1 repo");
                    }
                    eprintln!(
                        "warning: SHA-1 repo. Commit ids resist generic collision attacks only to about 2^80 \
                         work, so a well-funded member could equivocate about what a commit contains."
                    );
                }
                "sha1" => bail!(
                    "this repository uses SHA-1 object ids. Use SHA-256 (`git init --object-format=sha256`), \
                     or pass --allow-sha1 to accept SHA-1's weaker collision resistance (see the README)"
                ),
                f => bail!("unsupported object format {f}"),
            }
            let eng = rt.block_on(Engine::init_repo(session.device()?, &relay_url, &format))?;
            // The directory's name at the end, so `git clone` names its
            // directory the same (the relay never sees it).
            let toplevel = std::process::Command::new("git").args(["rev-parse", "--show-toplevel"]).output()?;
            let name = toplevel
                .status
                .success()
                .then(|| String::from_utf8_lossy(&toplevel.stdout).trim().to_string())
                .and_then(|p| std::path::Path::new(&p).file_name().map(|n| n.to_string_lossy().into_owned()))
                .and_then(|n| e2ee_core::engine::url_name(&n));
            let url = match name {
                Some(n) => format!("e2ee::{}/{n}", eng.url()),
                None => format!("e2ee::{}", eng.url()),
            };
            let st = std::process::Command::new("git").args(["remote", "add", &remote, &url]).status()?;
            if !st.success() {
                bail!("could not add remote {remote}; add it manually: git remote add {remote} {url}");
            }
            println!("Created encrypted repo; remote {remote} -> {url}");
        }
        Cmd::Repo(RepoCmd::Leave { remote, yes }) => {
            let mut eng = remote.engine(&session)?;
            if !yes && !confirm(&format!("Leave {} for all your devices?", eng.url()))? {
                bail!("cancelled");
            }
            sync(&rt, &mut eng)?;
            if rt.block_on(eng.leave())? {
                println!("Left {}. The next member to sync rotates the repo secret, which cuts you off.", eng.url());
                println!("Your other devices get the news too; run `git e2ee repo forget` there to delete their copies.");
            } else {
                println!("You were the only member, so this just forgot {} on this device.", eng.url());
                println!("Your other devices keep their copies (run this there too); the relay keeps the encrypted log.");
            }
            println!("The git remote is unchanged; remove it with `git remote remove <name>` if you like.");
        }
        Cmd::Repo(RepoCmd::Forget { remote, yes }) => {
            let url = remote.url()?;
            if !yes && !confirm(&format!("Delete this device's state for {url}?"))? {
                bail!("cancelled");
            }
            let eng = Engine::new(session.device()?, &url)?;
            rt.block_on(eng.forget())?;
            println!("Forgot {url} on this device. You are still a member: use `git e2ee repo leave` to leave.");
            println!("The git remote is unchanged; remove it with `git remote remove <name>` if you like.");
        }
        Cmd::Member(MemberCmd::Add { user, remote }) => {
            let uid = resolve_user(&session, &user)?;
            let key = match session.db.pinned(&uid)? {
                Some((k, true)) => k,
                _ => bail!("{user} isn't one of your contacts: add them first with `git e2ee contact add <name> <their user id>`"),
            };
            let mut eng = remote.engine(&session)?;
            sync(&rt, &mut eng)?;
            if eng.require_state()?.roster.members.iter().any(|m| m.user_id == uid) {
                // Already a member: re-send the invitation if they haven't
                // cloned yet (it can expire on the relay after a week).
                match rt.block_on(eng.reinvite(&uid))? {
                    0 => println!("{} is already a member (and has cloned).", short(&uid)),
                    n => println!(
                        "{} is already a member but hasn't cloned yet: invitation re-sent to {n} device(s).\n\
                         They can run `git clone {}` now.",
                        short(&uid),
                        remote.url()?
                    ),
                }
            } else {
                rt.block_on(eng.change_roster(Some(Member { user_id: uid.to_vec(), master_key: key }), None))?;
                println!(
                    "Added {} and sent them the history. They clone with:\n  git clone {}\n\
                     Until they clone, this device re-sends it about weekly (when you use the repo); \
                     `git e2ee status` shows who hasn't cloned yet.",
                    short(&uid),
                    remote.url()?
                );
            }
        }
        Cmd::Member(MemberCmd::Remove { user, remote }) => {
            let uid = resolve_user(&session, &user)?;
            let mut eng = remote.engine(&session)?;
            sync(&rt, &mut eng)?;
            rt.block_on(eng.change_roster(None, Some(uid.clone())))?;
            println!("Removed {} and rotated the repo secret.", short(&uid));
        }
        Cmd::Member(MemberCmd::List { remote }) => {
            let eng = remote.engine(&session)?;
            let s = eng.require_state()?;
            for m in &s.roster.members {
                let verified = session.db.pinned(&m.user_id)?.is_some_and(|p| p.1);
                let me = if m.user_id == eng.dev.user { " (you)" } else { "" };
                let name = session.db.name_of(&m.user_id)?.map(|n| format!("{n}  ")).unwrap_or_default();
                println!(
                    "{name}{}{me}  {}",
                    hex::encode(&m.user_id),
                    if verified { "contact" } else { "not your contact: added by another member" }
                );
                let devices: Vec<String> = session.db.devices_of(&m.user_id)?.iter().map(|(d, _)| d.to_string()).collect();
                let version = session.db.device_list_state(&m.user_id)?.map_or(0, |v| v.0);
                println!("    devices: {} (device list v{version})", devices.join(", "));
            }
        }
        Cmd::SendHistory { remote, device } => {
            let mut eng = remote.engine(&session)?;
            sync(&rt, &mut eng)?;
            let user = eng.dev.user.clone();
            let mut w = vec![];
            rt.block_on(eng.refresh_device_lists(std::slice::from_ref(&user), &mut w))?;
            print_warnings(&w);
            let to: Vec<(Vec<u8>, u32)> = session
                .db
                .devices_of(&user)?
                .into_iter()
                .filter(|(d, _)| *d != eng.dev.device_id && device.is_none_or(|x| x == *d))
                .map(|(d, _)| (user.clone(), d))
                .collect();
            if to.is_empty() {
                bail!("no other devices to send to");
            }
            rt.block_on(eng.send_history(&to))?;
            println!("Sent history to {} device(s).", to.len());
        }
        Cmd::Sync { remote } => {
            let mut eng = remote.engine(&session)?;
            let r = sync(&rt, &mut eng)?;
            println!("applied {} entries", r.applied);
        }
        Cmd::LogTimer { remote, duration } => {
            let secs = e2ee_core::engine::parse_ttl(&duration)?;
            let mut eng = remote.engine(&session)?;
            sync(&rt, &mut eng)?;
            rt.block_on(eng.set_log_timer(secs))?;
            match secs {
                0 => println!("Log entries no longer disappear (for every member, from now on)."),
                s => println!(
                    "Log entries recorded from now on disappear after {} (for every member). Entries already \
                     recorded keep their own timer.",
                    e2ee_core::engine::fmt_ttl(s)
                ),
            }
        }
        Cmd::Log { remote, limit } => {
            let eng = remote.engine(&session)?;
            let entries = eng.push_log_entries(limit)?;
            if let Some(st) = eng.state()?
                && st.roster.log_ttl_secs != 0
            {
                println!("Disappearing log entries: new entries are deleted {} after they happen.\n", e2ee_core::engine::fmt_ttl(st.roster.log_ttl_secs));
            }
            if entries.is_empty() {
                println!("no push log for this repo on this device (e2ee.pushLog may be off)");
            }
            let me = eng.dev.user.clone();
            for (e, source) in entries {
                let who = if e.user_id == me {
                    "you".to_string()
                } else {
                    let verified = session.db.pinned(&e.user_id)?.is_some_and(|p| p.1);
                    if verified {
                        contact_label(&session, &e.user_id)?
                    } else {
                        format!("{} (not your contact)", contact_label(&session, &e.user_id)?)
                    }
                };
                let when = fmt_time(e.at_ms);
                // Entries this device didn't see itself are that member's word.
                let tag = match source {
                    Some(s) if s.is_empty() => "  [according to another member]".to_string(),
                    Some(s) => format!("  [according to {}]", contact_label(&session, &s)?),
                    None => String::new(),
                };
                let gone = if e.expires_ms > 0 {
                    format!("  (disappears {})", fmt_time(e.expires_ms))
                } else {
                    String::new()
                };
                println!("{:>5}  {when}  {who} dev {}{tag}{gone}", e.seq, e.device_id);
                if !e.note.is_empty() {
                    println!("         {}", printable(&e.note));
                }
                for c in &e.changes {
                    let s = |o: &str| if o.is_empty() { "-".to_string() } else { printable(&o.chars().take(12).collect::<String>()) };
                    let what = match (c.old_oid.is_empty(), c.new_oid.is_empty()) {
                        (true, _) => format!("created {}", s(&c.new_oid)),
                        (_, true) => format!("deleted (was {})", s(&c.old_oid)),
                        _ if c.forced => format!(
                            "{} -> {}  FORCED ({} commit(s) dropped)",
                            s(&c.old_oid),
                            s(&c.new_oid),
                            c.dropped
                        ),
                        _ => format!("{} -> {}", s(&c.old_oid), s(&c.new_oid)),
                    };
                    println!("         {}  {what}", printable(&c.name));
                }
            }
        }
        Cmd::Status { remote } => {
            let eng = remote.engine(&session)?;
            let Some(s) = eng.state()? else {
                println!("no state for this repo on this device yet");
                return Ok(());
            };
            println!("repo:        {}", eng.url());
            println!("log seq:     {}", s.seq);
            println!("log head:    {}", hex::encode(&s.head));
            println!("view:        {}", hex::encode(&s.view));
            println!("members:     {} (roster v{})", s.roster.members.len(), s.roster.version);
            println!("outbox:      {} pending", eng.pending_outbox()?);
            println!("own entries: {} awaiting acks", eng.unacked_own_entries()?);
            match &s.conflict {
                Some(c) => {
                    println!("CONFLICT:    {}", printable(c));
                    println!("             {}", e2ee_helper::CONFLICT_HELP);
                }
                None => println!("conflict:    none"),
            }
            if let Some(b) = eng.behind_status()? {
                println!("behind:      {b}");
            }
            for (u, devs, sends, last) in eng.pending_invites()? {
                let devs: Vec<String> = devs.iter().map(|d| d.to_string()).collect();
                println!(
                    "invited:     {} hasn't cloned yet (device {}; invitation sent {sends} time(s), last {} ago)",
                    contact_label(&session, &u)?,
                    devs.join(", "),
                    e2ee_core::engine::fmt_age(e2ee_core::now_ms().saturating_sub(last))
                );
            }
        }
        Cmd::RotateDeliveryToken => {
            let dev = session.device()?;
            dev.rotate_delivery_token()?;
            // Register it everywhere and tell every repo's members right away.
            let mut told = 0;
            for url in known_repo_urls(&session)? {
                let mut eng = Engine::new(session.device()?, &url)?;
                eng.force_gossip()?;
                match rt.block_on(eng.sync()) {
                    Ok(r) => {
                        print_report(&r);
                        told += 1;
                    }
                    Err(e) => eprintln!("warning: could not update {url}: {}", printable(&format!("{e:#}"))),
                }
            }
            println!("Rotated your delivery token and told the members of {told} repo(s).");
        }
        Cmd::ClearConflict { remote } => {
            let eng = remote.engine(&session)?;
            eng.clear_conflict()?;
            println!("Conflict cleared.");
        }
    }
    Ok(())
}

/// A user from a command line: a contact name or a hex user id.
fn resolve_user(session: &Session, s: &str) -> Result<Vec<u8>> {
    if let Some(u) = session.db.user_named(s)? {
        return Ok(u);
    }
    parse_user_id(s).ok_or_else(|| anyhow!("no contact named {s:?}, and it isn't a user id: see `git e2ee contact list`"))
}

/// A user id: 64 hex characters.
fn parse_user_id(s: &str) -> Option<Vec<u8>> {
    hex::decode(s.trim()).ok().filter(|u| u.len() == 32)
}

/// `git e2ee contact ...`
fn contact_cmd(session: &Session, rt: &tokio::runtime::Runtime, cmd: ContactCmd, relay: Option<&str>) -> Result<()> {
    match cmd {
        ContactCmd::Add { name, user_id } => {
            let dev = session.device()?;
            let uid = parse_user_id(&user_id)
                .ok_or_else(|| anyhow!("{user_id:?} isn't a user id (64 hex characters; `git e2ee whoami` shows one)"))?;
            if uid == dev.user {
                bail!("that's your own user id");
            }
            let name = name.trim().to_string();
            if name.is_empty() || name.chars().any(char::is_control) || name.chars().count() > 64 {
                bail!("a contact name must be 1 to 64 printable characters");
            }
            if hex::decode(&name).is_ok_and(|b| b.len() == 32) {
                bail!("a contact name can't look like a user id");
            }
            if let Some(other) = session.db.user_named(&name)?
                && other != uid
            {
                bail!("you already have a contact named {name:?} (user {}): pick another name", short(&other));
            }
            let relay = match relay {
                Some(r) => r.to_string(),
                None => session.db.relays()?.into_iter().next().ok_or_else(|| anyhow!("this account isn't registered with its relay yet"))?,
            };
            // Their key comes from the relay; the user id (from a channel you
            // trust) is its hash, so the relay can't substitute another.
            let host = relay_host(&relay)?;
            let bytes = rt.block_on(RelayClient::new(&relay)?.get_device_list(&hex::encode(&uid)))?.ok_or_else(|| {
                anyhow!(
                    "{host} has no account with user id {}: check the id, and that they created their account on \
                     this relay (accounts are per relay; `git e2ee whoami` there shows the id)",
                    hex::encode(&uid)
                )
            })?;
            let signed = e2ee_proto::SignedDeviceList::decode(bytes.as_slice())?;
            let body = e2ee_proto::DeviceListBody::decode(signed.body.as_slice())?;
            if user_id_of(&body.master_key).as_slice() != uid {
                bail!("{host} served a key that doesn't match this user id: refusing it (the relay may be misbehaving)");
            }
            e2ee_core::identity::verify_device_list(&signed, &body.master_key, None)
                .context("their device list on the relay doesn't verify: refusing it")?;
            session.db.pin(&uid, &body.master_key, true)?;
            session.db.set_name(&uid, &name)?;
            dev.accept_device_list(&uid, &signed)?;
            println!("Added contact {name} (user {}).", short(&uid));
            // Start post-quantum handshakes with their devices now, so the
            // first messages between you aren't held up waiting for one.
            let r = Engine::new(session.device()?, &format!("{}/{}", relay.trim_end_matches('/'), "0".repeat(32)))
                .and_then(|mut eng| rt.block_on(eng.pq_introduce(&uid)));
            if let Err(e) = r {
                eprintln!("note: could not start handshakes with their devices: {} (they'll happen on first contact)", printable(&format!("{e:#}")));
            }
            println!("Once they've added you too, either of you can add the other to repos (`git e2ee member add {name}`).");
        }
        ContactCmd::List => {
            let all = session.db.contacts()?;
            if all.is_empty() {
                println!("no contacts yet: add one with `git e2ee contact add <name> <user id>`");
            }
            for (u, n) in all {
                println!("{:<20} {}", printable(&n), hex::encode(&u));
            }
        }
        ContactCmd::Remove { contact } => {
            let uid = resolve_user(session, &contact)?;
            if !session.db.pinned(&uid)?.is_some_and(|p| p.1) {
                bail!("{contact} isn't one of your contacts");
            }
            session.db.remove_contact(&uid)?;
            // Not a member of any repo of ours either: forget their key, so
            // they can't send us invitations any more.
            let mut in_repo = false;
            for url in known_repo_urls(session)? {
                let eng = Engine::new(session.device()?, &url)?;
                in_repo |= eng.state()?.is_some_and(|s| s.roster.members.iter().any(|m| m.user_id == uid));
            }
            if !in_repo {
                session.db.unpin_unverified(&uid)?;
            }
            println!("Removed {} from your contacts. Repos they're in keep them; remove them there with `git e2ee member remove`.", short(&uid));
        }
    }
    Ok(())
}

/// How to show a user: "you", the name you gave them, or a short id.
fn contact_label(session: &Session, user: &[u8]) -> Result<String> {
    if session.device().is_ok_and(|d| d.user == user) {
        return Ok("you".into());
    }
    Ok(session.db.name_of(user)?.unwrap_or_else(|| short(user)))
}

fn sync(rt: &tokio::runtime::Runtime, eng: &mut Engine) -> Result<e2ee_core::engine::SyncReport> {
    let r = rt.block_on(eng.sync())?;
    print_report(&r);
    if let Some(why) = &r.behind {
        eprintln!("e2ee: note: {why}");
    }
    if let Some(c) = eng.state()?.and_then(|s| s.conflict) {
        bail!("conflict: {c}\n{}", e2ee_helper::CONFLICT_HELP);
    }
    Ok(r)
}

/// Which account a command uses, opened: the relay a command names, else
/// `--relay`, else the current repo's relay, else your only account. Also
/// returns that relay's URL, when it's known.
fn open_account(cli: &Cli) -> Result<(Session, Option<String>)> {
    let named: Option<String> = match &cli.cmd {
        Cmd::Register { relay_url, .. } | Cmd::Repo(RepoCmd::Init { relay_url, .. }) => Some(relay_url.clone()),
        Cmd::SendHistory { remote, .. }
        | Cmd::Sync { remote }
        | Cmd::Log { remote, .. }
        | Cmd::LogTimer { remote, .. }
        | Cmd::Status { remote }
        | Cmd::ClearConflict { remote }
        | Cmd::Repo(RepoCmd::Leave { remote, .. })
        | Cmd::Repo(RepoCmd::Forget { remote, .. })
        | Cmd::Member(MemberCmd::Add { remote, .. })
        | Cmd::Member(MemberCmd::Remove { remote, .. })
        | Cmd::Member(MemberCmd::List { remote }) => Some(e2ee_core::engine::parse_url(&remote.url()?)?.0),
        _ => None,
    };
    if let Some(r) = named.or_else(|| cli.relay.clone()) {
        return Ok((Session::open_existing(&r)?, Some(r)));
    }
    // In a repo with an e2ee remote: its relay.
    if let Ok(u) = (RemoteArg { remote: "origin".into(), url: None }).url()
        && let Ok((r, _)) = e2ee_core::engine::parse_url(&u)
    {
        return Ok((Session::open_existing(&r)?, Some(r)));
    }
    match accounts()?.as_slice() {
        [] => bail!("you have no git-e2ee account yet: create one with `git e2ee init-user <relay-url>`"),
        [(_, dir)] => {
            let s = Session::open_dir(dir)?;
            let relay = s.db.relays()?.into_iter().next();
            Ok((s, relay))
        }
        many => bail!(
            "you have accounts on several relays ({}): pick one with `--relay <url>`",
            many.iter().map(|(h, _)| h.as_str()).collect::<Vec<_>>().join(", ")
        ),
    }
}

/// `git e2ee init-user <relay>`: a new account on that relay, registered.
fn init_user(rt: &tokio::runtime::Runtime, relay_url: &str, token: Option<String>) -> Result<()> {
    let dir = account_dir(relay_url)?;
    if has_account(&dir) {
        let s = Session::open_dir(&dir)?;
        bail!(
            "you already have an account on {} (user {}); accounts are one per relay",
            relay_host(relay_url)?,
            short(&s.device()?.user)
        );
    }
    let session = Session::open_dir(&dir)?;
    let dev = Device::create_user(&session.db)?;
    println!("Created your account on {}: user {}", relay_host(relay_url)?, hex::encode(&dev.user));
    println!(
        "Your user id (send it to collaborators over a channel you trust, e.g. a verified Signal chat):\n  {}",
        hex::encode(&dev.user)
    );
    if let Err(e) = register(&session, rt, relay_url, token) {
        bail!(
            "{e:#}\nThe account is created; register it when you can: `git e2ee register {relay_url}` \
             (with `--token <token>` on an invite-only relay)"
        );
    }
    Ok(())
}

/// Show the relay's policy and register this account's device with it.
fn register(session: &Session, rt: &tokio::runtime::Runtime, relay_url: &str, token: Option<String>) -> Result<()> {
    let dev = session.device()?;
    let policy = e2ee_core::client::RelayClient::new(relay_url).and_then(|c| rt.block_on(c.policy()));
    match policy {
        Ok(p) => println!("Policy of {relay_url}:\n\n{}\n", e2ee_core::printable_text(p.trim_end())),
        Err(e) => eprintln!("note: could not fetch the relay's policy: {}", printable(&format!("{e:#}"))),
    }
    // Registration is per relay; any repo id works for the URL shape.
    let mut eng = Engine::new(dev, &format!("{}/{}", relay_url.trim_end_matches('/'), "0".repeat(32)))?;
    eng.registration_token = token;
    rt.block_on(eng.ensure_registered())?;
    println!("Registered device with {relay_url}");
    // Handshake with our other devices right away (see `verify`).
    let me = session.device()?.user;
    if let Err(e) = rt.block_on(eng.pq_introduce(&me)) {
        eprintln!("note: could not start handshakes with your other devices: {}", printable(&format!("{e:#}")));
    }
    Ok(())
}

/// `git e2ee accounts`
fn list_accounts() -> Result<()> {
    let all = accounts()?;
    if all.is_empty() {
        println!("no accounts yet: create one with `git e2ee init-user <relay-url>`");
    }
    for (host, dir) in all {
        let s = Session::open_dir(&dir)?;
        match s.device() {
            Ok(d) => println!("{host}  user {}  device {}{}", short(&d.user), d.device_id, if d.master.is_some() { " (master)" } else { "" }),
            Err(_) => println!("{host}  (device not linked yet: finish with `git e2ee device finish`)"),
        }
    }
    Ok(())
}

/// `git e2ee device link <relay>`: this device's keys for joining your
/// account on that relay.
fn begin_link(relay_url: &str) -> Result<()> {
    let dir = account_dir(relay_url)?;
    if has_account(&dir) {
        bail!("this device already has an account on {}", relay_host(relay_url)?);
    }
    let session = Session::open_dir(&dir)?;
    let code = Device::begin_link(&session.db)?;
    println!(
        "Run this on your master device (add `--relay {relay_url}` there if it has accounts on several relays):\n  \
         git e2ee device approve {code}"
    );
    Ok(())
}

/// `git e2ee device finish <code>`: fetch the account's device list from
/// its relay (checked against the user id in the code), then register.
fn finish_link(rt: &tokio::runtime::Runtime, code: &str) -> Result<()> {
    let approval = e2ee_core::identity::decode_approval(code)?;
    let relay_url = approval.relay_url.clone();
    let session = Session::open_dir(&account_dir(&relay_url)?)?;
    let bytes = rt
        .block_on(RelayClient::new(&relay_url)?.get_device_list(&hex::encode(&approval.user_id)))?
        .ok_or_else(|| anyhow!("{relay_url} has no device list for that user: run `git e2ee device approve` on the master device again (it publishes it)"))?;
    let signed = e2ee_proto::SignedDeviceList::decode(bytes.as_slice())?;
    let dev = Device::finish_link(&session.db, &approval, &signed)?;
    println!("Linked as device {} of user {} on {}.", dev.device_id, short(&dev.user), relay_host(&relay_url)?);
    register(&session, rt, &relay_url, None)?;
    println!(
        "Your devices that have repos send them here on their next fetch, push or `git e2ee sync`; \
         then clone them here (`git e2ee send-history` in a repo there sends it right away)."
    );
    Ok(())
}

fn device_cmd(session: &Session, rt: &tokio::runtime::Runtime, cmd: DeviceCmd, relay: Option<&str>) -> Result<()> {
    match cmd {
        DeviceCmd::Link { .. } | DeviceCmd::Finish { .. } => unreachable!(),
        DeviceCmd::Approve { link_code } => {
            let dev = session.device()?;
            let relay = match relay {
                Some(r) => r.to_string(),
                None => session.db.relays()?.into_iter().next().ok_or_else(|| anyhow!("this account isn't registered with its relay yet"))?,
            };
            let (signed, approval, id) = dev.approve_link(&link_code, &relay)?;
            publish(session, rt, &dev, &signed.encode_to_vec())?;
            println!("Approved as device {id}. On the new device run:\n  git e2ee device finish {approval}");
        }
        DeviceCmd::Revoke { device_id } => {
            let dev = session.device()?;
            let signed = dev.revoke(device_id)?;
            publish(session, rt, &dev, &signed.encode_to_vec())?;
            // Don't rely on the relay serving the new list: message every repo's
            // members now. Each message carries the new list in-band.
            let mut told = 0;
            for url in known_repo_urls(session)? {
                let mut eng = Engine::new(session.device()?, &url)?;
                eng.force_gossip()?;
                match rt.block_on(eng.sync()) {
                    Ok(r) => {
                        print_report(&r);
                        told += 1;
                    }
                    Err(e) => eprintln!("warning: could not notify members of {url}: {}", printable(&format!("{e:#}"))),
                }
            }
            println!("Revoked device {device_id} and notified the members of {told} repo(s).");
        }
        DeviceCmd::List => {
            let dev = session.device()?;
            let list = dev.own_device_list()?;
            println!("device list version {}", list.body.version);
            for d in &list.body.devices {
                let me = if d.device_id == dev.device_id { " (this device)" } else { "" };
                println!("  {}{me}  key {}", d.device_id, &hex::encode(&d.identity_key)[..16]);
            }
        }
    }
    Ok(())
}

/// URLs of every repo this device has state for.
fn known_repo_urls(session: &Session) -> Result<Vec<String>> {
    let mut st = session.db.conn().prepare("SELECT relay_url, repo_id FROM repos")?;
    let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)))?;
    Ok(rows.map(|r| r.map(|(u, id)| format!("{u}/{}", hex::encode(id)))).collect::<rusqlite::Result<_>>()?)
}

/// Upload our new device list to every relay we use.
fn publish(session: &Session, rt: &tokio::runtime::Runtime, dev: &Device, signed: &[u8]) -> Result<()> {
    for url in session.db.relays()? {
        let client = RelayClient::new(&url)?;
        if let Err(e) = rt.block_on(client.put_device_list(&hex::encode(&dev.user), signed)) {
            eprintln!("warning: could not publish device list to {url}: {}", printable(&format!("{e:#}")));
        }
    }
    Ok(())
}

/// UTC timestamp `YYYY-MM-DD HH:MM` from Unix milliseconds.
fn fmt_time(ms: u64) -> String {
    let secs = ms / 1000;
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}Z", rem / 3600, rem % 3600 / 60)
}

fn confirm(q: &str) -> Result<bool> {
    print!("{q} [y/N] ");
    std::io::stdout().flush()?;
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)?;
    Ok(matches!(s.trim(), "y" | "Y" | "yes"))
}
