//! End-to-end tests: real `git` driving the built `git-remote-e2ee` helper
//! against an in-process relay, with isolated state per device.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;

use e2ee_relay::{Adversary, Relay};

struct TestRelay {
    relay: Arc<Relay>,
    /// Honest listener (log branch 0).
    url: String,
    /// Second listener; shows a forked log when `fork_at` is set.
    url_fork: String,
}

fn start_relay_with(limits: e2ee_relay::Limits) -> TestRelay {
    let relay = Relay::open_in_memory_with(limits).unwrap();
    relay.enable_test_instrumentation();
    let (tx, rx) = std::sync::mpsc::channel();
    let r = relay.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let l0 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let l1 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            tx.send((l0.local_addr().unwrap(), l1.local_addr().unwrap())).unwrap();
            let a = tokio::spawn(e2ee_relay::serve(l0, r.clone(), 0));
            let b = tokio::spawn(e2ee_relay::serve(l1, r, 1));
            let _ = tokio::join!(a, b);
        });
    });
    let (a, b) = rx.recv().unwrap();
    TestRelay { relay, url: format!("http://{a}"), url_fork: format!("http://{b}") }
}

impl TestRelay {
    fn adversary(&self, f: impl FnOnce(&mut Adversary)) {
        f(&mut self.relay.adversary.lock().unwrap());
    }
}

fn bin_dir() -> PathBuf {
    Path::new(env!("CARGO_BIN_EXE_git-remote-e2ee")).parent().unwrap().to_path_buf()
}

/// One device: its own state dir, sharing the test's git config.
#[derive(Clone)]
struct Dev {
    home: PathBuf,
    root: PathBuf,
    env: Vec<(String, String)>,
}

impl Dev {
    fn new(root: &Path, name: &str) -> Self {
        Self { home: root.join(name), root: root.to_path_buf(), env: vec![] }
    }

    fn with_env(&self, k: &str, v: &str) -> Self {
        let mut d = self.clone();
        d.env.push((k.into(), v.into()));
        d
    }

    fn cmd(&self, prog: &str, cwd: &Path) -> Command {
        let mut c = Command::new(prog);
        let path = format!("{}:{}", bin_dir().display(), std::env::var("PATH").unwrap_or_default());
        c.current_dir(cwd)
            .env("PATH", path)
            .env("HOME", &self.root)
            .env("GIT_E2EE_HOME", &self.home)
            .env("GIT_CONFIG_GLOBAL", self.root.join("gitconfig"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("E2EE_HEARTBEAT_SECS", "100000000")
            .env_remove("GIT_DIR");
        for (k, v) in &self.env {
            c.env(k, v);
        }
        c
    }

    fn run(&self, prog: &str, cwd: &Path, args: &[&str]) -> Output {
        self.cmd(prog, cwd).args(args).output().unwrap()
    }

    fn ok(&self, prog: &str, cwd: &Path, args: &[&str]) -> String {
        let out = self.run(prog, cwd, args);
        assert!(
            out.status.success(),
            "{prog} {args:?} failed\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr)
    }

    fn e2ee(&self, cwd: &Path, args: &[&str]) -> String {
        self.ok("git-e2ee", cwd, args)
    }

    fn git(&self, cwd: &Path, args: &[&str]) -> String {
        self.ok("git", cwd, args)
    }

    fn init_user(&self, relay: &str) -> String {
        let out = self.e2ee(&self.root, &["init-user"]);
        self.e2ee(&self.root, &["register", relay]);
        code_from(&out, "e2eeu1:")
    }

    /// Every mailbox this device reads on the relay: the one named by its
    /// user id and device, and its pseudonymous per-repo ones (device 0).
    fn mailboxes(&self) -> Vec<(String, u32)> {
        let db = rusqlite::Connection::open(self.home.join("device.sqlite")).unwrap();
        let dev: Vec<u8> = db.query_row("SELECT v FROM meta WHERE k = 'device_id'", [], |r| r.get(0)).unwrap();
        let mut out = vec![(self.user_hex(), u64::from_be_bytes(dev.try_into().unwrap()) as u32)];
        let mut st = db.prepare("SELECT mailbox FROM own_mailboxes").unwrap();
        out.extend(st.query_map([], |r| r.get::<_, Vec<u8>>(0)).unwrap().map(|m| (hex::encode(m.unwrap()), 0)));
        out
    }

    fn user_hex(&self) -> String {
        let out = self.e2ee(&self.root, &["whoami"]);
        out.lines().find_map(|l| l.strip_prefix("user id:")).unwrap().trim().to_string()
    }

    fn status(&self, repo: &Path) -> String {
        self.e2ee(repo, &["status"])
    }
}

fn code_from(out: &str, prefix: &str) -> String {
    out.split_whitespace().find(|w| w.starts_with(prefix)).unwrap_or_else(|| panic!("no {prefix} code in {out}")).to_string()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn log_seq(status: &str) -> u64 {
    status.lines().find_map(|l| l.strip_prefix("log seq:")).unwrap().trim().parse().unwrap()
}

fn commit(dev: &Dev, repo: &Path, file: &str, content: &str, msg: &str) -> String {
    std::fs::write(repo.join(file), content).unwrap();
    dev.git(repo, &["add", file]);
    dev.git(repo, &["commit", "-q", "-m", msg]);
    dev.git(repo, &["rev-parse", "HEAD"]).trim().to_string()
}

struct World {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    relay: TestRelay,
    alice: Dev,
    bob: Dev,
    arepo: PathBuf,
    brepo: PathBuf,
    url: String,
    bob_code: String,
}

/// Alice creates a repo with one commit, verifies and adds Bob, Bob clones.
fn world() -> World {
    world_with(e2ee_relay::Limits::default())
}

fn world_with(limits: e2ee_relay::Limits) -> World {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    std::fs::write(
        root.join("gitconfig"),
        "[user]\n\tname = Anon\n\temail = anon@example.invalid\n[init]\n\tdefaultBranch = main\n",
    )
    .unwrap();
    let relay = start_relay_with(limits);
    let alice = Dev::new(&root, "alice");
    let bob = Dev::new(&root, "bob");
    let alice_code = alice.init_user(&relay.url);
    let bob_code = bob.init_user(&relay.url);

    let arepo = root.join("arepo");
    alice.git(&root, &["init", "-q", "--object-format=sha256", arepo.to_str().unwrap()]);
    commit(&alice, &arepo, "plans.txt", "the secret plans\n", "first secret commit");
    alice.e2ee(&arepo, &["repo", "init", &relay.url]);
    alice.git(&arepo, &["push", "-q", "-u", "origin", "main"]);
    let url = alice.git(&arepo, &["config", "remote.origin.url"]).trim().to_string();

    alice.e2ee(&root, &["verify", &bob_code, "--yes"]);
    bob.e2ee(&root, &["verify", &alice_code, "--yes"]);
    alice.e2ee(&arepo, &["member", "add", &bob_code]);

    let brepo = root.join("brepo");
    bob.git(&root, &["clone", "-q", &url, brepo.to_str().unwrap()]);
    World { _tmp: tmp, root, relay, alice, bob, arepo, brepo, url, bob_code }
}

#[test]
fn push_invite_clone_roundtrip_without_plaintext_on_relay() {
    let w = world();
    assert_eq!(std::fs::read_to_string(w.brepo.join("plans.txt")).unwrap(), "the secret plans\n");
    assert_eq!(w.bob.git(&w.brepo, &["rev-parse", "--show-object-format"]).trim(), "sha256");

    let c = commit(&w.bob, &w.brepo, "bob.txt", "bob's contribution\n", "bob commit");
    w.bob.git(&w.brepo, &["push", "-q"]);
    w.alice.git(&w.arepo, &["pull", "-q", "--ff-only"]);
    assert_eq!(w.alice.git(&w.arepo, &["rev-parse", "HEAD"]).trim(), c);

    // Acks flow back; once everyone acked, pushers delete blobs and pack keys.
    w.alice.e2ee(&w.arepo, &["sync"]);
    w.bob.e2ee(&w.brepo, &["sync"]);
    w.alice.e2ee(&w.arepo, &["sync"]);
    assert!(w.alice.status(&w.arepo).contains("own entries: 0"), "{}", w.alice.status(&w.arepo));
    assert!(w.bob.status(&w.brepo).contains("own entries: 0"));

    let dump = w.relay.relay.dump_all_bytes();
    let has = |needle: &str| dump.windows(needle.len()).any(|x| x == needle.as_bytes());
    for secret in ["secret plans", "plans.txt", "bob's contribution", "first secret commit", "refs/heads/main", "anon@example"] {
        assert!(!has(secret), "relay stored plaintext {secret:?}");
    }
    assert!(!has(&c), "relay stored a commit id");
}

#[test]
fn stale_push_is_rejected() {
    let w = world();
    commit(&w.alice, &w.arepo, "a.txt", "a\n", "alice");
    w.alice.git(&w.arepo, &["push", "-q"]);
    commit(&w.bob, &w.brepo, "b.txt", "b\n", "bob");
    let out = w.bob.run("git", &w.brepo, &["push", "-q"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("rejected") || stderr(&out).contains("fetch first"), "{}", stderr(&out));
    // After pulling, Bob's push goes through.
    w.bob.git(&w.brepo, &["pull", "-q", "--rebase"]);
    w.bob.git(&w.brepo, &["push", "-q"]);
}

#[test]
fn linked_device_receives_history_and_can_push() {
    let w = world();
    let laptop = Dev::new(&w.root, "alice-laptop");
    let link = code_from(&laptop.e2ee(&w.root, &["device", "link"]), "e2eed1:");
    let approval = code_from(&w.alice.e2ee(&w.root, &["device", "approve", &link]), "e2eea1:");
    laptop.e2ee(&w.root, &["device", "finish", &approval]);
    laptop.e2ee(&w.root, &["register", &w.relay.url]);
    w.alice.e2ee(&w.arepo, &["send-history"]);

    let lrepo = w.root.join("lrepo");
    laptop.git(&w.root, &["clone", "-q", &w.url, lrepo.to_str().unwrap()]);
    assert!(lrepo.join("plans.txt").exists());
    let c = commit(&laptop, &lrepo, "laptop.txt", "from laptop\n", "laptop");
    laptop.git(&lrepo, &["push", "-q"]);
    // Bob hasn't been online since the laptop appeared: its push to him waits
    // for their post-quantum handshake (Bob answers, the laptop sends).
    pq_settle(&w.bob, &w.brepo, &laptop, &lrepo);
    w.bob.git(&w.brepo, &["pull", "-q", "--ff-only"]);
    assert_eq!(w.bob.git(&w.brepo, &["rev-parse", "HEAD"]).trim(), c);
}

/// Let `waiting` answer pending post-quantum handshakes from `new`, and `new`
/// then send what was waiting for them.
fn pq_settle(waiting: &Dev, waiting_repo: &Path, new: &Dev, new_repo: &Path) {
    waiting.e2ee(waiting_repo, &["sync"]);
    new.e2ee(new_repo, &["sync"]);
}

#[test]
fn removed_member_cannot_read_new_pushes() {
    let w = world();
    let bob_hex = w.bob.user_hex();
    w.alice.e2ee(&w.arepo, &["member", "remove", &bob_hex]);
    let c = commit(&w.alice, &w.arepo, "after.txt", "after removal\n", "after removal");
    w.alice.git(&w.arepo, &["push", "-q"]);
    // Bob can't tell removal from a missed rotation (the change removing
    // him isn't sent to him: it carries the new secret), so he's told both.
    let out = w.bob.ok("git", &w.brepo, &["fetch", "-q"]);
    assert!(out.contains("If you were removed"), "{out}");
    let has = w.bob.run("git", &w.brepo, &["cat-file", "-e", &c]);
    assert!(!has.status.success());
    // Bob's re-invite works again.
    w.alice.e2ee(&w.arepo, &["member", "add", &w.bob_code]);
}

#[test]
fn sender_equivocation_is_detected() {
    let w = world();
    let bob_hex = w.bob.user_hex();
    commit(&w.alice, &w.arepo, "x.txt", "x\n", "x");
    let evil = w.alice.with_env("E2EE_TEST_EQUIVOCATE_TO", &bob_hex);
    evil.git(&w.arepo, &["push", "-q"]);
    let out = w.bob.run("git", &w.brepo, &["fetch", "-q"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("equivocation"), "{}", stderr(&out));
    assert!(w.bob.status(&w.brepo).contains("CONFLICT"));
}

#[test]
fn relay_split_view_is_detected() {
    let w = world();
    w.alice.e2ee(&w.arepo, &["sync"]);
    w.bob.e2ee(&w.brepo, &["sync"]);
    let seq = log_seq(&w.alice.status(&w.arepo));
    assert_eq!(seq, log_seq(&w.bob.status(&w.brepo)));
    w.relay.adversary(|a| a.fork_at = Some(seq));
    // Bob talks to the listener that serves the forked log.
    let rid = w.url.rsplit('/').next().unwrap();
    w.bob.git(&w.brepo, &["remote", "set-url", "origin", &format!("e2ee::{}/{rid}", w.relay.url_fork)]);

    commit(&w.alice, &w.arepo, "a.txt", "a\n", "alice on the real log");
    w.alice.git(&w.arepo, &["push", "-q"]);
    commit(&w.bob, &w.brepo, "b.txt", "b\n", "bob on the fork");
    let out = w.bob.run("git", &w.brepo, &["push", "-q"]);
    assert!(stderr(&out).contains("withholding"), "bob should notice alice's entry missing: {}", stderr(&out));

    w.alice.run("git-e2ee", &w.arepo, &["sync"]);
    w.bob.run("git-e2ee", &w.brepo, &["sync"]);
    let a = w.alice.status(&w.arepo);
    let b = w.bob.status(&w.brepo);
    assert!(a.contains("CONFLICT") || b.contains("CONFLICT"), "split view not detected:\n{a}\n{b}");
    assert!(a.contains("CONFLICT"), "{a}");
}

#[test]
fn withheld_envelope_is_resent() {
    let w = world();
    w.relay.adversary(|a| a.drop_mail_to = w.bob.mailboxes());
    let c = commit(&w.alice, &w.arepo, "w.txt", "w\n", "withheld");
    w.alice.git(&w.arepo, &["push", "-q"]);
    let bob = w.bob.with_env("E2EE_RESEND_SECS", "0");
    let out = bob.ok("git", &w.brepo, &["fetch"]);
    assert!(waiting(&out), "{out}");
    w.relay.adversary(|a| a.drop_mail_to.clear());
    w.alice.e2ee(&w.arepo, &["sync"]); // answers the resend request
    bob.git(&w.brepo, &["pull", "-q", "--ff-only"]);
    assert_eq!(bob.git(&w.brepo, &["rev-parse", "HEAD"]).trim(), c);
}

#[test]
fn hidden_log_entries_are_revealed_by_members_mail() {
    let w = world();
    w.alice.e2ee(&w.arepo, &["sync"]);
    let seq = log_seq(&w.alice.status(&w.arepo));
    w.relay.adversary(|a| a.freeze_log_at = Some(seq));
    commit(&w.alice, &w.arepo, "f.txt", "f\n", "hidden by relay");
    w.alice.git(&w.arepo, &["push", "-q"]);
    let out = w.bob.ok("git", &w.brepo, &["fetch"]);
    assert!(out.contains("withholding"), "{out}");
}

/// The reviewer's attack: the relay moves the victim onto a fork, *accepts*
/// the victim's own heartbeats there (keeping its log looking fresh) and
/// drops all mail to it. Freeze detection must still fire, because it only
/// counts authenticated mail from other members.
#[test]
fn full_freeze_is_detected_even_when_the_relay_accepts_our_heartbeats() {
    let w = world();
    w.alice.e2ee(&w.arepo, &["sync"]);
    w.bob.e2ee(&w.brepo, &["sync"]);
    let seq = log_seq(&w.bob.status(&w.brepo));
    w.relay.adversary(|a| {
        a.fork_at = Some(seq);
        a.drop_mail_to = w.bob.mailboxes();
    });
    let rid = w.url.rsplit('/').next().unwrap();
    w.bob.git(&w.brepo, &["remote", "set-url", "origin", &format!("e2ee::{}/{rid}", w.relay.url_fork)]);
    commit(&w.alice, &w.arepo, "hidden.txt", "h\n", "hidden");
    w.alice.git(&w.arepo, &["push", "-q"]);

    std::thread::sleep(std::time::Duration::from_secs(3));
    let bob = w.bob.with_env("E2EE_MAX_STALENESS_SECS", "2");
    // Bob's heartbeat is accepted on the fork, so his log looks fresh...
    bob.with_env("E2EE_HEARTBEAT_SECS", "0").ok("git", &w.brepo, &["fetch"]);
    assert!(log_seq(&w.bob.status(&w.brepo)) > seq, "relay accepted the heartbeat");
    // ...yet on the next run, nobody else has reached him for too long.
    let out = bob.ok("git", &w.brepo, &["fetch"]);
    assert!(out.contains("no other member device has been heard from"), "{out}");
}

/// A relay that refuses our heartbeat append (the real log moved on) while
/// showing us no newer entries is caught at once.
#[test]
fn rejected_heartbeat_with_nothing_newer_is_reported() {
    let w = world();
    w.alice.e2ee(&w.arepo, &["sync"]);
    let seq = log_seq(&w.alice.status(&w.arepo));
    w.relay.adversary(|a| a.freeze_log_at = Some(seq));
    commit(&w.alice, &w.arepo, "x.txt", "x\n", "x");
    w.alice.git(&w.arepo, &["push", "-q"]);
    let out = w.bob.with_env("E2EE_HEARTBEAT_SECS", "0").ok("git", &w.brepo, &["fetch"]);
    assert!(out.contains("refused our heartbeat"), "{out}");
}

#[test]
fn ghost_device_from_relay_is_rejected() {
    let w = world();
    let bob_hex = w.bob.user_hex();
    w.relay.adversary(|a| a.ghost_device_for = Some(bob_hex.clone()));
    let c = commit(&w.alice, &w.arepo, "g.txt", "g\n", "ghost");
    w.alice.ok("git", &w.arepo, &["push"]);
    // Nothing was encrypted to the ghost; Bob still receives the push.
    assert!(!w.relay.relay.mailbox_sizes().contains_key(&(bob_hex.clone(), 99)));
    w.relay.adversary(|a| a.ghost_device_for = None);
    w.bob.git(&w.brepo, &["pull", "-q", "--ff-only"]);
    assert_eq!(w.bob.git(&w.brepo, &["rev-parse", "HEAD"]).trim(), c);
}

#[test]
fn crash_after_decrypt_loses_nothing() {
    let w = world();
    let c = commit(&w.alice, &w.arepo, "c.txt", "c\n", "crash test");
    w.alice.git(&w.arepo, &["push", "-q"]);
    let crashing = w.bob.with_env("E2EE_FAILPOINT", "after_decrypt");
    let out = crashing.run("git", &w.brepo, &["fetch", "-q"]);
    assert!(!out.status.success());
    w.bob.git(&w.brepo, &["pull", "-q", "--ff-only"]);
    assert_eq!(w.bob.git(&w.brepo, &["rev-parse", "HEAD"]).trim(), c);
}

#[test]
fn crash_after_log_append_recovers_fan_out() {
    let w = world();
    let c = commit(&w.alice, &w.arepo, "d.txt", "d\n", "crash after append");
    let crashing = w.alice.with_env("E2EE_FAILPOINT", "after_log_append");
    let out = crashing.run("git", &w.arepo, &["push", "-q"]);
    assert!(!out.status.success());
    // The entry is in the log; the next run applies it and fans it out.
    w.alice.e2ee(&w.arepo, &["sync"]);
    w.bob.git(&w.brepo, &["pull", "-q", "--ff-only"]);
    assert_eq!(w.bob.git(&w.brepo, &["rev-parse", "HEAD"]).trim(), c);
}

#[test]
fn sha1_repositories_are_refused() {
    let w = world();
    let old = w.root.join("sha1repo");
    w.alice.git(&w.root, &["init", "-q", "--object-format=sha1", old.to_str().unwrap()]);
    commit(&w.alice, &old, "x", "x\n", "x");
    // Pushing a SHA-1 repo into a SHA-256 one is refused.
    w.alice.git(&old, &["remote", "add", "origin", &w.url]);
    let out = w.alice.run("git", &old, &["push", "origin", "main"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("sha1 object ids") && stderr(&out).contains("uses sha256"), "{}", stderr(&out));
    // Creating a SHA-1 encrypted repo needs the explicit opt-in.
    let out = w.alice.run("git-e2ee", &old, &["repo", "init", &w.relay.url, "--remote", "e2"]);
    assert!(!out.status.success() && stderr(&out).contains("--allow-sha1"), "{}", stderr(&out));
}

/// An opted-in SHA-1 repo works end to end: clones get SHA-1 local repos,
/// and a SHA-256 repo can't push into it.
#[test]
fn opted_in_sha1_repo_round_trips() {
    let w = world();
    let bob_code = w.bob_code.clone();
    let srepo = w.root.join("sha1-alice");
    w.alice.git(&w.root, &["init", "-q", "--object-format=sha1", srepo.to_str().unwrap()]);
    commit(&w.alice, &srepo, "old.txt", "legacy\n", "legacy history");
    let out = w.alice.run("git-e2ee", &srepo, &["repo", "init", &w.relay.url, "--allow-sha1"]);
    assert!(out.status.success() && stderr(&out).contains("2^80"), "{}", stderr(&out));
    w.alice.git(&srepo, &["push", "-q", "-u", "origin", "main"]);
    let url = w.alice.git(&srepo, &["config", "remote.origin.url"]).trim().to_string();
    w.alice.e2ee(&srepo, &["member", "add", &bob_code]);

    let bclone = w.root.join("sha1-bob");
    w.bob.git(&w.root, &["clone", "-q", &url, bclone.to_str().unwrap()]);
    assert_eq!(w.bob.git(&bclone, &["rev-parse", "--show-object-format"]).trim(), "sha1");
    assert_eq!(std::fs::read_to_string(bclone.join("old.txt")).unwrap(), "legacy\n");
    let c = commit(&w.bob, &bclone, "bob.txt", "b\n", "bob");
    assert_eq!(c.len(), 40);
    w.bob.git(&bclone, &["push", "-q"]);
    w.alice.git(&srepo, &["pull", "-q", "--ff-only"]);
    assert_eq!(w.alice.git(&srepo, &["rev-parse", "HEAD"]).trim(), c);

    // A SHA-256 repo can't push into it.
    w.alice.git(&w.arepo, &["remote", "add", "legacy", &url]);
    let out = w.alice.run("git", &w.arepo, &["push", "legacy", "main"]);
    assert!(!out.status.success() && stderr(&out).contains("uses sha1"), "{}", stderr(&out));
}

#[test]
fn signed_commits_are_refused_in_deniable_mode() {
    let w = world();
    commit(&w.alice, &w.arepo, "s.txt", "s\n", "to be signed");
    let body = w.alice.git(&w.arepo, &["cat-file", "commit", "HEAD"]);
    let (header, msg) = body.split_once("\n\n").unwrap();
    let signed = format!(
        "{header}\ngpgsig -----BEGIN PGP SIGNATURE-----\n \n iQEzBAABCAAdFiEE\n -----END PGP SIGNATURE-----\n\n{msg}"
    );
    let mut c = w.alice.cmd("git", &w.arepo);
    c.args(["hash-object", "-t", "commit", "-w", "--stdin"]).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped());
    let mut child = c.spawn().unwrap();
    use std::io::Write;
    child.stdin.take().unwrap().write_all(signed.as_bytes()).unwrap();
    let oid = String::from_utf8(child.wait_with_output().unwrap().stdout).unwrap();
    w.alice.git(&w.arepo, &["update-ref", "refs/heads/main", oid.trim()]);
    let out = w.alice.run("git", &w.arepo, &["push", "-q"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("signed commit"), "{}", stderr(&out));
    // Explicit opt-out allows it.
    w.alice.git(&w.arepo, &["config", "e2ee.allowSigned", "true"]);
    w.alice.git(&w.arepo, &["push", "-q"]);
}

#[test]
fn hidden_recipient_in_push_is_detected() {
    let w = world();
    commit(&w.alice, &w.arepo, "r.txt", "r\n", "r");
    w.alice.with_env("E2EE_TEST_BAD_RECIPIENTS", "1").git(&w.arepo, &["push", "-q"]);
    let out = w.bob.run("git", &w.brepo, &["fetch", "-q"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("recipient device set"), "{}", stderr(&out));
}

#[test]
fn hidden_recipient_in_roster_change_is_detected() {
    let w = world();
    let carol = Dev::new(&w.root, "carol");
    let carol_code = carol.init_user(&w.relay.url);
    w.alice.e2ee(&w.root, &["verify", &carol_code, "--yes"]);
    w.alice.with_env("E2EE_TEST_BAD_RECIPIENTS", "1").e2ee(&w.arepo, &["member", "add", &carol_code]);
    let out = w.bob.run("git", &w.brepo, &["fetch", "-q"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("recipient device set"), "{}", stderr(&out));
}

#[test]
fn interactive_verify_requires_confirmation() {
    let w = world();
    let carol = Dev::new(&w.root, "carol");
    let carol_code = carol.init_user(&w.relay.url);
    let answer = |a: &str| {
        let mut c = w.alice.cmd("git-e2ee", &w.root);
        c.args(["verify", &carol_code]).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
        let mut child = c.spawn().unwrap();
        use std::io::Write;
        child.stdin.take().unwrap().write_all(a.as_bytes()).unwrap();
        child.wait_with_output().unwrap()
    };
    let no = answer("n\n");
    assert!(!no.status.success());
    assert!(String::from_utf8_lossy(&no.stdout).contains("you:"), "words shown");
    // Not pinned, so adding Carol is refused.
    let add = w.alice.run("git-e2ee", &w.arepo, &["member", "add", &carol_code]);
    assert!(stderr(&add).contains("verify this user first"), "{}", stderr(&add));
    assert!(answer("y\n").status.success());
    w.alice.e2ee(&w.arepo, &["member", "add", &carol_code]);
}

#[test]
fn gossip_reveals_a_frozen_log_within_the_gossip_interval() {
    let w = world();
    w.alice.e2ee(&w.arepo, &["sync"]);
    w.bob.e2ee(&w.brepo, &["sync"]);
    let seq = log_seq(&w.alice.status(&w.arepo));
    // The relay hides Alice's push from Bob: freezes his log and drops the push.
    w.relay.adversary(|a| {
        a.freeze_log_at = Some(seq);
        a.drop_mail_to = w.bob.mailboxes();
    });
    commit(&w.alice, &w.arepo, "q.txt", "q\n", "quiet");
    w.alice.git(&w.arepo, &["push", "-q"]);
    let out = w.bob.ok("git", &w.brepo, &["fetch"]);
    assert!(!out.contains("withholding"), "nothing reached Bob yet: {out}");
    // Later, Alice's periodic gossip gets through.
    w.relay.adversary(|a| a.drop_mail_to.clear());
    w.alice.with_env("E2EE_GOSSIP_SECS", "0").e2ee(&w.arepo, &["sync"]);
    let out = w.bob.ok("git", &w.brepo, &["fetch"]);
    assert!(out.contains("withholding"), "{out}");
}

#[test]
fn prekey_rotation_does_not_break_sessions() {
    let w = world();
    let bob = w.bob.with_env("E2EE_PREKEY_ROTATE_SECS", "0");
    let carol = Dev::new(&w.root, "carol");
    let carol_code = carol.init_user(&w.relay.url);
    let alice_code = code_from(&w.alice.e2ee(&w.root, &["whoami"]), "e2eeu1:");
    carol.e2ee(&w.root, &["verify", &alice_code, "--yes"]);
    for i in 0..3 {
        let c = commit(&w.alice, &w.arepo, &format!("p{i}"), "p\n", "rot");
        w.alice.git(&w.arepo, &["push", "-q"]);
        bob.git(&w.brepo, &["pull", "-q", "--ff-only"]);
        assert_eq!(bob.git(&w.brepo, &["rev-parse", "HEAD"]).trim(), c);
    }
    // A brand-new session with Bob uses his rotated prekeys.
    w.alice.e2ee(&w.root, &["verify", &carol_code, "--yes"]);
    w.alice.e2ee(&w.arepo, &["member", "add", &carol_code]);
    let crepo = w.root.join("crepo");
    carol.git(&w.root, &["clone", "-q", &w.url, crepo.to_str().unwrap()]);
    commit(&carol, &crepo, "carol.txt", "c\n", "carol");
    carol.git(&crepo, &["push", "-q"]);
    pq_settle(&bob, &w.brepo, &carol, &crepo);
    bob.git(&w.brepo, &["pull", "-q", "--ff-only"]);
    assert!(w.brepo.join("carol.txt").exists());
}

/// Carol's first messages to Bob are PreKey messages naming Bob's signed
/// prekey. Bob deletes that prekey (rotation with no grace period) before
/// reading them. Recovery must still deliver Carol's push.
#[test]
fn messages_to_a_deleted_prekey_recover_via_resend() {
    let w = world();
    let carol = Dev::new(&w.root, "carol");
    let carol_code = carol.init_user(&w.relay.url);
    let alice_code = code_from(&w.alice.e2ee(&w.root, &["whoami"]), "e2eeu1:");
    carol.e2ee(&w.root, &["verify", &alice_code, "--yes"]);
    w.alice.e2ee(&w.root, &["verify", &carol_code, "--yes"]);
    w.alice.e2ee(&w.arepo, &["member", "add", &carol_code]);
    let crepo = w.root.join("crepo");
    carol.git(&w.root, &["clone", "-q", &w.url, crepo.to_str().unwrap()]);
    let c = commit(&carol, &crepo, "carol.txt", "c\n", "carol");
    carol.git(&crepo, &["push", "-q"]);

    // Bob rotates and immediately deletes the prekey Carol's session names.
    let bob_rotating = w
        .bob
        .with_env("E2EE_PREKEY_ROTATE_SECS", "0")
        .with_env("E2EE_PREKEY_GRACE_SECS", "0")
        .with_env("E2EE_RESEND_SECS", "0");
    let out = bob_rotating.ok("git", &w.brepo, &["fetch"]);
    assert!(waiting(&out), "{out}");
    // The envelope is missing because decryption failed, not for another reason.
    assert!(out.contains("discarding message from") && out.contains("invalid signed prekey"), "{out}");

    let bob = w.bob.with_env("E2EE_RESEND_SECS", "0");
    // One round trip must suffice: Carol answers the resend request on a
    // fresh session built from Bob's current prekeys. Without the reset this
    // failed about half the time (libsignal's tiebreak kept Carol's session).
    carol.e2ee(&crepo, &["sync"]);
    bob.git(&w.brepo, &["fetch", "-q"]);
    assert!(
        bob.run("git", &w.brepo, &["cat-file", "-e", &c]).status.success(),
        "Bob never received Carol's push after losing the prekey"
    );
}

/// The relay must not be able to spot the sender of a fan-out as the one
/// device that received nothing, nor by message sizes.
#[test]
fn pusher_mailbox_gets_indistinguishable_cover_traffic() {
    let w = world();
    w.bob.e2ee(&w.brepo, &["sync"]); // empty Bob's mailbox
    w.alice.e2ee(&w.arepo, &["sync"]);
    w.bob.e2ee(&w.brepo, &["sync"]);
    assert!(mail_sizes(&w, &w.bob).is_empty());

    commit(&w.alice, &w.arepo, "cover.txt", "c\n", "cover");
    w.alice.git(&w.arepo, &["push", "-q"]);
    let mut mine = mail_sizes(&w, &w.alice);
    let mut bobs = mail_sizes(&w, &w.bob);
    assert!(!bobs.is_empty(), "push reached Bob");
    // Alice's earlier mail (from Bob) was consumed by her own sync; what is
    // left is her cover traffic, one per message to Bob, of the same sizes.
    mine.sort();
    bobs.sort();
    assert_eq!(mine, bobs, "cover traffic mirrors the real fan-out");

    // Cover mail is dropped silently on the next sync.
    let out = w.alice.e2ee(&w.arepo, &["sync"]);
    assert!(!out.contains("discarding"), "{out}");
    assert!(mail_sizes(&w, &w.alice).is_empty());
    w.bob.git(&w.brepo, &["pull", "-q", "--ff-only"]);
    assert!(w.brepo.join("cover.txt").exists());
}

/// One mailbox per device serves every repo; mail is filed by the repo id
/// inside the encrypted envelope.
#[test]
fn one_device_mailbox_serves_several_repos() {
    let w = world();
    let second = w.root.join("arepo2");
    w.alice.git(&w.root, &["init", "-q", "--object-format=sha256", second.to_str().unwrap()]);
    commit(&w.alice, &second, "two.txt", "second repo\n", "two");
    w.alice.e2ee(&second, &["repo", "init", &w.relay.url]);
    w.alice.git(&second, &["push", "-q", "-u", "origin", "main"]);
    w.alice.e2ee(&second, &["member", "add", &w.bob_code]);
    let url2 = w.alice.git(&second, &["config", "remote.origin.url"]).trim().to_string();

    // Activity in repo 1 lands in the same mailbox as repo 2's history bundle.
    let c1 = commit(&w.alice, &w.arepo, "one.txt", "first repo\n", "one");
    w.alice.git(&w.arepo, &["push", "-q"]);
    let b2 = w.root.join("brepo2");
    w.bob.git(&w.root, &["clone", "-q", &url2, b2.to_str().unwrap()]);
    assert_eq!(std::fs::read_to_string(b2.join("two.txt")).unwrap(), "second repo\n");
    w.bob.git(&w.brepo, &["pull", "-q", "--ff-only"]);
    assert_eq!(w.bob.git(&w.brepo, &["rev-parse", "HEAD"]).trim(), c1);
    assert!(!b2.join("one.txt").exists(), "repos stay separate");
    // The relay's mailboxes are keyed by device only.
    // Mailboxes are named by device (user id) or by a random per-repo
    // pseudonym (32 hex digits, device 0) that names no user.
    assert!(w.relay.relay.mailbox_sizes().keys().all(|(u, d)| u.len() == 64 || (u.len() == 32 && *d == 0)));
}

#[test]
fn invite_only_relay_end_to_end() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    std::fs::write(root.join("gitconfig"), "[user]\n\tname = A\n\temail = a@example.invalid\n").unwrap();
    let relay = start_relay_with(e2ee_relay::Limits { invite_only: true, ..Default::default() });
    let alice = Dev::new(&root, "alice");
    alice.e2ee(&root, &["init-user"]);
    let out = alice.run("git-e2ee", &root, &["register", &relay.url]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("invite-only"), "{}", stderr(&out));
    let token = relay.relay.issue_registration_token(std::time::Duration::from_secs(3600)).unwrap();
    alice.e2ee(&root, &["register", &relay.url, "--token", &token]);
    let repo = root.join("r");
    alice.git(&root, &["init", "-q", "--object-format=sha256", "-b", "main", repo.to_str().unwrap()]);
    commit(&alice, &repo, "f", "f\n", "f");
    alice.e2ee(&repo, &["repo", "init", &relay.url]);
    alice.git(&repo, &["push", "-q", "-u", "origin", "main"]);
}

/// Link a second device for `owner` and give it a clone of `url`.
fn link_device(w: &World, owner: &Dev, owner_repo: &Path, name: &str) -> (Dev, PathBuf) {
    let laptop = Dev::new(&w.root, name);
    let link = code_from(&laptop.e2ee(&w.root, &["device", "link"]), "e2eed1:");
    let approval = code_from(&owner.e2ee(&w.root, &["device", "approve", &link]), "e2eea1:");
    laptop.e2ee(&w.root, &["device", "finish", &approval]);
    laptop.e2ee(&w.root, &["register", &w.relay.url]);
    owner.e2ee(owner_repo, &["send-history"]);
    let repo = w.root.join(format!("{name}-repo"));
    laptop.git(&w.root, &["clone", "-q", &w.url, repo.to_str().unwrap()]);
    (laptop, repo)
}

/// The relay hides Bob's revocation of a stolen laptop (keeps serving the old
/// device list and keeps the laptop registered). Bob's next message carries
/// the new signed list in-band, so Alice stops encrypting to the laptop.
#[test]
fn hidden_revocation_reaches_peers_in_band() {
    let w = world();
    let (laptop, _) = link_device(&w, &w.bob, &w.brepo, "bob-laptop");
    w.alice.e2ee(&w.arepo, &["sync"]); // Alice now knows the laptop

    w.relay.relay.freeze_device_lists();
    // Revoking notifies every repo's members right away (no extra step).
    w.bob.e2ee(&w.root, &["device", "revoke", "2"]);

    commit(&w.alice, &w.arepo, "after.txt", "after revocation\n", "after revocation");
    let before = mail_sizes(&w, &laptop).len();
    w.alice.git(&w.arepo, &["push", "-q"]);
    let after = mail_sizes(&w, &laptop).len();
    assert_eq!(before, after, "Alice still encrypted to the revoked laptop");
    // Bob's remaining device still gets the push.
    w.bob.git(&w.brepo, &["pull", "-q", "--ff-only"]);
    assert!(w.brepo.join("after.txt").exists());
}

/// The relay hides Bob's new device from Alice. The device introduces
/// itself: its messages carry Bob's signed device list.
#[test]
fn hidden_new_device_introduces_itself() {
    let w = world();
    w.relay.relay.freeze_device_lists();
    let (laptop, lrepo) = link_device(&w, &w.bob, &w.brepo, "bob-laptop");
    let c = commit(&laptop, &lrepo, "laptop.txt", "from laptop\n", "laptop");
    laptop.git(&lrepo, &["push", "-q"]);
    pq_settle(&w.alice, &w.arepo, &laptop, &lrepo);
    w.alice.git(&w.arepo, &["pull", "-q", "--ff-only"]);
    assert_eq!(w.alice.git(&w.arepo, &["rev-parse", "HEAD"]).trim(), c);
}

/// A seized relay database must not connect users to repos: the repo-side
/// tables hold no user id, device id or identity key.
#[test]
fn seized_relay_database_links_no_user_to_a_repo() {
    let w = world();
    commit(&w.bob, &w.brepo, "b.txt", "b\n", "bob");
    w.bob.git(&w.brepo, &["push", "-q"]);
    let repo_side = w.relay.relay.dump_tables(&["repos", "repo_tokens", "logs", "blobs"]);
    let rid = w.url.rsplit('/').next().unwrap();
    assert!(repo_side.windows(rid.len()).any(|x| x == rid.as_bytes()), "sanity: the repo is stored");
    for user in [w.alice.user_hex(), w.bob.user_hex()] {
        let raw = hex::decode(&user).unwrap();
        assert!(!repo_side.windows(user.len()).any(|x| x == user.as_bytes()), "user id (hex) in repo tables");
        assert!(!repo_side.windows(raw.len()).any(|x| x == raw.as_slice()), "user id (raw) in repo tables");
    }
}

/// A removed member who asks for a resend of a later push (whose envelope
/// carries the pack key) must get nothing.
#[test]
fn removed_member_cannot_obtain_pack_keys_via_resend() {
    let w = world();
    let bob_hex = w.bob.user_hex();
    w.alice.e2ee(&w.arepo, &["member", "remove", &bob_hex]);
    commit(&w.alice, &w.arepo, "secret.txt", "after removal\n", "after removal");
    w.alice.git(&w.arepo, &["push", "-q"]);
    let seq = log_seq(&w.alice.status(&w.arepo));
    // Bob (removed, still pinned, sessions intact) asks Alice for that entry.
    let _ = w.bob.with_env("E2EE_TEST_REQUEST_RESEND", &seq.to_string()).run("git-e2ee", &w.brepo, &["sync"]);
    let mailbox = |w: &World| mail_sizes(w, &w.bob).len();
    let before = mailbox(&w);
    w.alice.e2ee(&w.arepo, &["sync"]);
    assert_eq!(mailbox(&w), before, "Alice sent something to a removed member");
}

#[test]
fn removed_member_cannot_force_a_conflict() {
    let w = world();
    let bob_hex = w.bob.user_hex();
    w.alice.e2ee(&w.arepo, &["member", "remove", &bob_hex]);
    let _ = w.bob.with_env("E2EE_TEST_BOGUS_ACK", "1").run("git-e2ee", &w.brepo, &["sync"]);
    w.alice.e2ee(&w.arepo, &["sync"]);
    assert!(!w.alice.status(&w.arepo).contains("CONFLICT"), "{}", w.alice.status(&w.arepo));
}

/// Sanity check for the hook above: a current member's conflicting ack is
/// indistinguishable from a split view and is flagged.
#[test]
fn current_member_conflicting_ack_is_flagged() {
    let w = world();
    w.alice.e2ee(&w.arepo, &["sync"]);
    w.bob.with_env("E2EE_TEST_BOGUS_ACK", "1").e2ee(&w.brepo, &["sync"]);
    let out = w.alice.run("git-e2ee", &w.arepo, &["sync"]);
    assert!(!out.status.success() && stderr(&out).contains("computed a different view"), "{}", stderr(&out));
    assert!(w.alice.status(&w.arepo).contains("CONFLICT"));
}

#[test]
fn device_additions_are_announced() {
    let w = world();
    let (_laptop, _) = link_device(&w, &w.bob, &w.brepo, "bob-laptop");
    let alice_out = w.alice.e2ee(&w.arepo, &["sync"]);
    assert!(alice_out.contains("added device 2"), "{alice_out}");
    // Bob's master approved it itself: no alarm there.
    let bob_out = w.bob.e2ee(&w.brepo, &["sync"]);
    assert!(!bob_out.contains("added device"), "{bob_out}");
    assert!(w.alice.e2ee(&w.arepo, &["member", "list"]).contains("devices: 1, 2"));
    // Each change is announced once.
    assert!(!w.alice.e2ee(&w.arepo, &["sync"]).contains("added device"));
}

/// A newcomer takes everyone's device lists from the history bundle, so a
/// relay serving stale lists cannot make them encrypt to a revoked device.
#[test]
fn newcomer_gets_device_lists_from_the_history_bundle() {
    let w = world();
    let (laptop, _) = link_device(&w, &w.bob, &w.brepo, "bob-laptop");
    w.alice.e2ee(&w.arepo, &["sync"]);
    w.relay.relay.freeze_device_lists(); // relay keeps serving Bob's list with the laptop
    w.bob.e2ee(&w.root, &["device", "revoke", "2"]); // Alice learns in-band
    w.alice.e2ee(&w.arepo, &["sync"]);

    let carol = Dev::new(&w.root, "carol");
    let carol_code = carol.init_user(&w.relay.url);
    let alice_code = code_from(&w.alice.e2ee(&w.root, &["whoami"]), "e2eeu1:");
    carol.e2ee(&w.root, &["verify", &alice_code, "--yes"]);
    w.alice.e2ee(&w.root, &["verify", &carol_code, "--yes"]);
    w.alice.e2ee(&w.arepo, &["member", "add", &carol_code]);
    let crepo = w.root.join("crepo");
    carol.git(&w.root, &["clone", "-q", &w.url, crepo.to_str().unwrap()]);

    let laptop_mail = || mail_sizes(&w, &laptop).len();
    let before = laptop_mail();
    commit(&carol, &crepo, "c.txt", "c\n", "carol");
    carol.git(&crepo, &["push", "-q"]);
    assert_eq!(laptop_mail(), before, "Carol encrypted to Bob's revoked laptop");
}

/// Rows in a device's local inbox for repos it has no state for.
fn orphan_inbox_rows(dev: &Dev) -> i64 {
    let db = rusqlite::Connection::open(dev.home.join("device.sqlite")).unwrap();
    db.query_row("SELECT COUNT(*) FROM inbox WHERE repo_id NOT IN (SELECT repo_id FROM repos)", [], |r| r.get(0))
        .unwrap()
}

/// A pinned user cannot fill another device's disk with mail for made-up
/// repos; only history bundles are kept for unknown repos, and they expire.
#[test]
fn inbox_keeps_only_bundles_for_unknown_repos_and_expires_them() {
    let w = world();
    w.alice.with_env("E2EE_TEST_JUNK_REPOS", "20").e2ee(&w.arepo, &["sync"]);
    let out = w.bob.e2ee(&w.brepo, &["sync"]);
    assert!(out.contains("ignored 20 message(s) for repos this device is not in"), "{out}");
    assert_eq!(orphan_inbox_rows(&w.bob), 0);

    // An invitation Bob doesn't take up yet: its history bundle waits...
    let second = w.root.join("arepo2");
    w.alice.git(&w.root, &["init", "-q", "--object-format=sha256", "-b", "main", second.to_str().unwrap()]);
    commit(&w.alice, &second, "x", "x\n", "x");
    w.alice.e2ee(&second, &["repo", "init", &w.relay.url]);
    w.alice.git(&second, &["push", "-q", "-u", "origin", "main"]);
    w.alice.e2ee(&second, &["member", "add", &w.bob_code]);
    w.bob.e2ee(&w.brepo, &["sync"]);
    assert_eq!(orphan_inbox_rows(&w.bob), 1);
    // ...until it expires, taking its pack key with it.
    w.bob.with_env("E2EE_INBOX_TTL_SECS", "0").e2ee(&w.brepo, &["sync"]);
    assert_eq!(orphan_inbox_rows(&w.bob), 0);
}

/// Normal syncs never fetch device lists from the relay: doing so next to the
/// repo's log fetch would tell it who is in the repo.
#[test]
fn syncs_do_not_fetch_members_device_lists() {
    let w = world();
    w.alice.e2ee(&w.arepo, &["sync"]);
    w.bob.e2ee(&w.brepo, &["sync"]);
    let gets = || w.relay.relay.device_list_gets.load(std::sync::atomic::Ordering::Relaxed);
    let before = gets();
    commit(&w.alice, &w.arepo, "n.txt", "n\n", "n");
    w.alice.git(&w.arepo, &["push", "-q"]);
    w.bob.git(&w.brepo, &["pull", "-q", "--ff-only"]);
    commit(&w.bob, &w.brepo, "m.txt", "m\n", "m");
    w.bob.git(&w.brepo, &["push", "-q"]);
    w.alice.git(&w.arepo, &["pull", "-q", "--ff-only"]);
    assert_eq!(gets(), before, "a sync fetched device lists from the relay");
    // Device changes still propagate (in-band): Bob links a laptop and
    // Alice's next push reaches it without any relay fetch by Alice.
    let (_laptop, lrepo) = link_device(&w, &w.bob, &w.brepo, "bob-laptop");
    let after_link = gets();
    let c = commit(&w.alice, &w.arepo, "o.txt", "o\n", "o");
    w.alice.git(&w.arepo, &["pull", "-q", "--ff-only"]);
    w.alice.git(&w.arepo, &["push", "-q"]);
    let _ = c;
    _laptop.git(&lrepo, &["pull", "-q", "--ff-only"]);
    assert!(lrepo.join("o.txt").exists());
    assert_eq!(gets(), after_link, "Alice fetched device lists from the relay");
}

/// A member cannot inject lines into the remote-helper protocol (or pass
/// malformed refs to git) through ref names in a push.
#[test]
fn malformed_refs_from_a_member_are_rejected() {
    let w = world();
    commit(&w.alice, &w.arepo, "r.txt", "r\n", "r");
    w.alice.with_env("E2EE_TEST_BAD_REF", "1").git(&w.arepo, &["push", "-q"]);
    let out = w.bob.run("git", &w.brepo, &["fetch", "-q"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("invalid ref name"), "{}", stderr(&out));
}

/// Members learn each other's delivery tokens in-band and use the relay's
/// normal lane; only the first contact (the invitation) needs the request
/// lane. With a request lane of 3 messages a day, sustained work only
/// succeeds if that's true.
#[test]
fn members_use_delivery_tokens_after_first_contact() {
    let w = world_with(e2ee_relay::Limits { request_lane_per_day: 3, ..Default::default() });
    for i in 0..4 {
        let a = commit(&w.alice, &w.arepo, &format!("a{i}"), "a\n", "a");
        w.alice.git(&w.arepo, &["push", "-q"]);
        w.bob.git(&w.brepo, &["pull", "-q", "--ff-only"]);
        assert_eq!(w.bob.git(&w.brepo, &["rev-parse", "HEAD"]).trim(), a);
        let b = commit(&w.bob, &w.brepo, &format!("b{i}"), "b\n", "b");
        w.bob.git(&w.brepo, &["push", "-q"]);
        w.alice.git(&w.arepo, &["pull", "-q", "--ff-only"]);
        assert_eq!(w.alice.git(&w.arepo, &["rev-parse", "HEAD"]).trim(), b);
    }
    let out = w.alice.e2ee(&w.arepo, &["sync"]) + &w.bob.e2ee(&w.brepo, &["sync"]);
    assert!(!out.contains("request lane"), "{out}");
}

/// A relay that holds a peer's mail back and releases it later can't use it
/// to stretch a freeze: freshness counts the authenticated send time, and the
/// delay itself is reported.
#[test]
fn delayed_mail_is_reported_and_does_not_look_fresh() {
    let w = world();
    w.alice.e2ee(&w.arepo, &["sync"]);
    w.bob.e2ee(&w.brepo, &["sync"]);
    w.relay.adversary(|a| a.hold_mail_to = w.bob.mailboxes());
    // Alice's gossip and push go out now but are held.
    w.alice.with_env("E2EE_GOSSIP_SECS", "0").e2ee(&w.arepo, &["sync"]);
    std::thread::sleep(std::time::Duration::from_secs(4));
    w.relay.adversary(|a| a.hold_mail_to.clear());
    let out = w
        .bob
        .with_env("E2EE_MAX_DELAY_SECS", "2")
        .with_env("E2EE_MAX_STALENESS_SECS", "3")
        .ok("git", &w.brepo, &["fetch"]);
    assert!(out.contains("before it arrived"), "{out}");
    // The released mail was sent >3s ago, so it doesn't reset the freeze timer.
    assert!(out.contains("no other member device has been heard from"), "{out}");
}

/// A bad history bundle is discarded instead of blocking every later sync;
/// a good invitation afterwards still works.
#[test]
fn bad_history_bundle_is_discarded_not_blocking() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    std::fs::write(root.join("gitconfig"), "[user]\n\tname = A\n\temail = a@example.invalid\n").unwrap();
    let relay = start_relay_with(e2ee_relay::Limits::default());
    let (alice, bob) = (Dev::new(&root, "alice"), Dev::new(&root, "bob"));
    let alice_code = alice.init_user(&relay.url);
    let bob_code = bob.init_user(&relay.url);
    alice.e2ee(&root, &["verify", &bob_code, "--yes"]);
    bob.e2ee(&root, &["verify", &alice_code, "--yes"]);
    let arepo = root.join("a");
    alice.git(&root, &["init", "-q", "--object-format=sha256", "-b", "main", arepo.to_str().unwrap()]);
    commit(&alice, &arepo, "f", "f\n", "f");
    alice.e2ee(&arepo, &["repo", "init", &relay.url]);
    alice.git(&arepo, &["push", "-q", "-u", "origin", "main"]);
    let url = alice.git(&arepo, &["config", "remote.origin.url"]).trim().to_string();

    alice.with_env("E2EE_TEST_BAD_BUNDLE", "1").e2ee(&arepo, &["member", "add", &bob_code]);
    let brepo = root.join("b");
    let out = bob.run("git", &root, &["clone", "-q", &url, brepo.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("discarded a history bundle"), "{}", stderr(&out));

    // Alice re-invites Bob properly; the earlier bad bundle doesn't get in the way.
    let bob_hex = bob.user_hex();
    alice.e2ee(&arepo, &["member", "remove", &bob_hex]);
    alice.e2ee(&arepo, &["member", "add", &bob_code]);
    bob.git(&root, &["clone", "-q", &url, brepo.to_str().unwrap()]);
    assert!(brepo.join("f").exists());
}

/// A linked device that never registered with the relay can't be delivered
/// to. Senders back off instead of spending tokens on it every sync, report
/// it, and eventually stop waiting for it (expiring mail and releasing pack
/// keys it will never ack).
#[test]
fn unreachable_device_is_backed_off_reported_and_expired() {
    let w = world();
    // Bob links a laptop but never runs `register` on it.
    let laptop = Dev::new(&w.root, "bob-laptop");
    let link = code_from(&laptop.e2ee(&w.root, &["device", "link"]), "e2eed1:");
    let approval = code_from(&w.bob.e2ee(&w.root, &["device", "approve", &link]), "e2eea1:");
    laptop.e2ee(&w.root, &["device", "finish", &approval]);
    w.bob.with_env("E2EE_GOSSIP_SECS", "0").e2ee(&w.brepo, &["sync"]); // tells Alice about the laptop (in-band)

    let misses = || w.relay.relay.bundle_misses.load(std::sync::atomic::Ordering::Relaxed);
    let before = misses();
    let mut outputs = String::new();
    for i in 0..5 {
        commit(&w.alice, &w.arepo, &format!("u{i}"), "u\n", "u");
        outputs += &w.alice.ok("git", &w.arepo, &["push"]);
    }
    assert!(misses() - before <= 1, "retried the dead device {} times", misses() - before);
    assert_eq!(outputs.matches("deferred").count(), 1, "{outputs}");
    // Bob's real device still gets everything.
    w.bob.git(&w.brepo, &["pull", "-q", "--ff-only"]);
    assert!(w.brepo.join("u4").exists());

    // Reported (once a day per device).
    let alice = w.alice.with_env("E2EE_UNREACHABLE_REPORT_SECS", "0");
    let out = alice.e2ee(&w.arepo, &["sync"]);
    assert!(out.contains("device 2 of user") && out.contains("unreachable"), "{out}");
    assert!(!alice.e2ee(&w.arepo, &["sync"]).contains("unreachable"));

    // Past the mail lifetime: queued mail and unacked pushes are dropped.
    assert!(!w.alice.status(&w.arepo).contains("own entries: 0"));
    let expired = w.alice.with_env("E2EE_OUTBOX_TTL_SECS", "0");
    expired.e2ee(&w.arepo, &["sync"]);
    let status = w.alice.status(&w.arepo);
    assert!(status.contains("outbox:      0") && status.contains("own entries: 0"), "{status}");
}

/// Token issuance is always one fixed-size batch, topped up apart from the
/// actions that spend tokens, so its size can't be matched to an upload.
#[test]
fn token_issuance_reveals_nothing_about_upload_sizes() {
    let w = world();
    // A push needing several tokens (blob upload: 1 + 1 per MiB).
    let big: String = (0u64..3 * 1024 * 1024).map(|i| char::from(b'a' + (i * 7919 % 26) as u8)).collect();
    commit(&w.alice, &w.arepo, "big.txt", &big, "big");
    w.alice.git(&w.arepo, &["push", "-q"]);
    w.bob.git(&w.brepo, &["pull", "-q", "--ff-only"]);
    let sizes = w.relay.relay.issuance_sizes.lock().unwrap().clone();
    assert!(!sizes.is_empty());
    assert!(sizes.iter().all(|&n| n == 100), "{sizes:?}");
}

/// One cumulative ack per sync, not one per entry per device, and pushers
/// still release their pack keys once those acks arrive.
#[test]
fn acks_are_batched_per_sync() {
    let w = world();
    w.alice.e2ee(&w.arepo, &["sync"]);
    w.bob.e2ee(&w.brepo, &["sync"]);
    w.alice.e2ee(&w.arepo, &["sync"]); // Alice's mailbox is now empty
    for i in 0..3 {
        commit(&w.alice, &w.arepo, &format!("k{i}"), "k\n", "k");
        w.alice.git(&w.arepo, &["push", "-q"]);
    }
    let in_alice = || mail_sizes(&w, &w.alice).len();
    let before = in_alice();
    w.bob.git(&w.brepo, &["pull", "-q", "--ff-only"]); // applies three entries
    assert!(in_alice() - before <= 1, "Bob sent {} messages for three entries", in_alice() - before);
    w.alice.e2ee(&w.arepo, &["sync"]);
    assert!(w.alice.status(&w.arepo).contains("own entries: 0"), "{}", w.alice.status(&w.arepo));
}

/// Incompressible test data.
fn noise(len: usize, seed: u64) -> String {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            char::from(b'a' + (x % 26) as u8)
        })
        .collect()
}

/// Packs travel as many encrypted chunks, streamed on both ends, and arrive
/// intact; history bundles too.
#[test]
fn packs_are_chunked_and_streamed() {
    let w = world();
    let alice = w.alice.with_env("E2EE_CHUNK_BYTES", "65536");
    let data = noise(1 << 20, 7);
    commit(&alice, &w.arepo, "noise.txt", &data, "noise");
    let blobs_before = w.relay.relay.blob_count();
    alice.git(&w.arepo, &["push", "-q"]);
    assert!(w.relay.relay.blob_count() - blobs_before >= 8, "a 1 MiB pack in 64 KiB chunks");
    w.bob.git(&w.brepo, &["pull", "-q", "--ff-only"]);
    assert_eq!(std::fs::read_to_string(w.brepo.join("noise.txt")).unwrap(), data);
    // A new member's history bundle is chunked the same way.
    let carol = Dev::new(&w.root, "carol");
    let carol_code = carol.init_user(&w.relay.url);
    let alice_code = code_from(&w.alice.e2ee(&w.root, &["whoami"]), "e2eeu1:");
    carol.e2ee(&w.root, &["verify", &alice_code, "--yes"]);
    w.alice.e2ee(&w.root, &["verify", &carol_code, "--yes"]);
    alice.e2ee(&w.arepo, &["member", "add", &carol_code]);
    let crepo = w.root.join("crepo");
    carol.git(&w.root, &["clone", "-q", &w.url, crepo.to_str().unwrap()]);
    assert_eq!(std::fs::read_to_string(crepo.join("noise.txt")).unwrap(), data);
}

/// Receivers refuse packs over their size limit (counted on decrypted bytes).
#[test]
fn oversized_packs_are_refused() {
    let w = world();
    commit(&w.alice, &w.arepo, "big.txt", &noise(1 << 20, 3), "big");
    w.alice.with_env("E2EE_CHUNK_BYTES", "65536").git(&w.arepo, &["push", "-q"]);
    let out = w.bob.with_env("E2EE_MAX_PACK_BYTES", "200000").run("git", &w.brepo, &["fetch", "-q"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("exceeds E2EE_MAX_PACK_BYTES"), "{}", stderr(&out));
}

/// A relay that fails to serve a pack chunk causes a retry later, not a
/// conflict that would block the repo.
#[test]
fn unavailable_chunks_are_retried_not_treated_as_misbehaviour() {
    let w = world();
    let c = commit(&w.alice, &w.arepo, "h.txt", "h\n", "h");
    w.alice.git(&w.arepo, &["push", "-q"]);
    w.relay.adversary(|a| a.hide_blobs = true);
    let out = w.bob.ok("git", &w.brepo, &["fetch"]);
    assert!(out.contains("could not apply entry"), "{out}");
    assert!(!w.bob.status(&w.brepo).contains("CONFLICT"));
    w.relay.adversary(|a| a.hide_blobs = false);
    w.bob.git(&w.brepo, &["pull", "-q", "--ff-only"]);
    assert_eq!(w.bob.git(&w.brepo, &["rev-parse", "HEAD"]).trim(), c);
}

#[test]
fn forgetting_a_repo_removes_local_state_and_ignores_its_mail() {
    let w = world();
    // A second shared repo, so Bob keeps using this relay.
    let second = w.root.join("arepo2");
    w.alice.git(&w.root, &["init", "-q", "--object-format=sha256", "-b", "main", second.to_str().unwrap()]);
    commit(&w.alice, &second, "two", "2\n", "two");
    w.alice.e2ee(&second, &["repo", "init", &w.relay.url]);
    w.alice.git(&second, &["push", "-q", "-u", "origin", "main"]);
    w.alice.e2ee(&second, &["member", "add", &w.bob_code]);
    let url2 = w.alice.git(&second, &["config", "remote.origin.url"]).trim().to_string();
    let b2 = w.root.join("brepo2");
    w.bob.git(&w.root, &["clone", "-q", &url2, b2.to_str().unwrap()]);

    w.bob.e2ee(&w.brepo, &["repo", "forget", "--yes"]);
    assert!(w.bob.status(&w.brepo).contains("no state for this repo"));
    let rid = w.url.rsplit('/').next().unwrap();
    assert!(!w.bob.home.join("mirrors").join(format!("{rid}.git")).exists());
    commit(&w.alice, &w.arepo, "after.txt", "x\n", "x");
    w.alice.git(&w.arepo, &["push", "-q"]);
    // Syncing the other repo drains Bob's mailbox; the forgotten repo's mail
    // is dropped instead of piling up.
    let out = w.bob.e2ee(&b2, &["sync"]);
    assert!(out.contains("ignored"), "{out}");
    assert_eq!(orphan_inbox_rows(&w.bob), 0);
}

/// Each member keeps a log of who changed which refs, from the authenticated
/// sender of each entry; members agree on it; newcomers' early history is
/// marked as the inviter's word ("according to …"). it can be turned off.
#[test]
fn push_log_records_who_changed_what() {
    let w = world();
    // Bob creates a branch and moves main; Alice deletes the branch.
    w.bob.git(&w.brepo, &["checkout", "-q", "-b", "feature"]);
    commit(&w.bob, &w.brepo, "f.txt", "f\n", "feature");
    w.bob.git(&w.brepo, &["push", "-q", "origin", "feature"]);
    w.bob.git(&w.brepo, &["checkout", "-q", "main"]);
    commit(&w.bob, &w.brepo, "m.txt", "m\n", "main");
    w.bob.git(&w.brepo, &["push", "-q", "origin", "main"]);
    w.alice.git(&w.arepo, &["pull", "-q", "--ff-only"]);
    w.alice.git(&w.arepo, &["push", "-q", "origin", "--delete", "feature"]);
    w.bob.git(&w.brepo, &["fetch", "-q"]);

    let alog = w.alice.e2ee(&w.arepo, &["log"]);
    let blog = w.bob.e2ee(&w.brepo, &["log"]);
    let bob_short = &w.bob.user_hex()[..12];
    let alice_short = &w.alice.user_hex()[..12];
    // Alice's view: Bob created feature and moved main; she deleted it.
    assert!(alog.contains(&format!("{bob_short} (verified) dev 1")), "{alog}");
    assert!(alog.contains("refs/heads/feature  created"), "{alog}");
    assert!(alog.contains("refs/heads/main  ") && alog.contains(" -> "), "{alog}");
    assert!(alog.contains("refs/heads/feature  deleted"), "{alog}");
    assert!(alog.contains(&format!("added {bob_short}")), "{alog}");
    // Bob's view of the entries both witnessed is the same; earlier ones are
    // marked as the inviter's word ("according to …").
    assert!(blog.contains("[according to "), "{blog}");
    for line in alog.lines().filter(|l| l.contains(" dev ") && !l.contains("[according to ")) {
        let seq = line.split_whitespace().next().unwrap();
        let bob_line = blog.lines().find(|l| l.split_whitespace().next() == Some(seq)).unwrap_or("");
        let pusher = |l: &str| l.split_whitespace().nth(3).map(str::to_string);
        let a = pusher(line).map(|p| if p == "you" { alice_short.to_string() } else { p });
        let b = pusher(bob_line).map(|p| if p == "you" { bob_short.to_string() } else { p });
        if !bob_line.contains("[according to ") {
            assert_eq!(a, b, "members disagree on who made entry {seq}:\n{alog}\n{blog}");
        }
    }
    // Turned off, nothing new is recorded.
    w.alice.git(&w.arepo, &["config", "e2ee.pushLog", "false"]);
    commit(&w.bob, &w.brepo, "q.txt", "q\n", "quiet");
    w.bob.git(&w.brepo, &["push", "-q"]);
    let before = w.alice.e2ee(&w.arepo, &["log"]).lines().count();
    w.alice.git(&w.arepo, &["pull", "-q", "--ff-only"]);
    assert_eq!(w.alice.e2ee(&w.arepo, &["log"]).lines().count(), before);
}

/// Force pushes aren't blocked, but they're marked in every member's push
/// log (with how many commits fell off) and announced to the others.
#[test]
fn force_pushes_are_marked_in_the_push_log() {
    let w = world();
    commit(&w.alice, &w.arepo, "a.txt", "a\n", "a");
    commit(&w.alice, &w.arepo, "b.txt", "b\n", "b");
    w.alice.git(&w.arepo, &["push", "-q"]);
    w.bob.git(&w.brepo, &["pull", "-q", "--ff-only"]);
    // Alice rewrites main, dropping her last two commits.
    w.alice.git(&w.arepo, &["reset", "-q", "--hard", "HEAD~2"]);
    commit(&w.alice, &w.arepo, "c.txt", "c\n", "rewrite");
    w.alice.git(&w.arepo, &["push", "-q", "--force"]);
    let out = w.bob.ok("git", &w.brepo, &["fetch"]);
    assert!(out.contains("force-pushed refs/heads/main (2 commit(s)"), "{out}");
    let blog = w.bob.e2ee(&w.brepo, &["log"]);
    assert!(blog.contains("FORCED (2 commit(s) dropped)"), "{blog}");
    let alog = w.alice.e2ee(&w.arepo, &["log"]);
    assert!(alog.contains("FORCED (2 commit(s) dropped)"), "{alog}");
    // Ordinary pushes aren't marked.
    assert_eq!(blog.matches("FORCED").count(), 1, "{blog}");
}

#[test]
fn force_and_force_with_lease_behave_like_git() {
    let w = world();
    // Plain --force rewrites.
    commit(&w.alice, &w.arepo, "a.txt", "a\n", "a");
    w.alice.git(&w.arepo, &["push", "-q"]);
    w.alice.git(&w.arepo, &["reset", "-q", "--hard", "HEAD~1"]);
    commit(&w.alice, &w.arepo, "a2.txt", "a2\n", "a2");
    let no_force = w.alice.run("git", &w.arepo, &["push", "-q"]);
    assert!(!no_force.status.success(), "non-fast-forward must be rejected");
    w.alice.git(&w.arepo, &["push", "-q", "--force"]);

    // --force-with-lease with an up-to-date lease succeeds.
    w.alice.git(&w.arepo, &["reset", "-q", "--hard", "HEAD~1"]);
    commit(&w.alice, &w.arepo, "a3.txt", "a3\n", "a3");
    w.alice.git(&w.arepo, &["push", "-q", "--force-with-lease"]);

    // Bob pushes; Alice's lease (her remote-tracking ref) is now stale.
    w.bob.git(&w.brepo, &["pull", "-q", "--rebase"]);
    let bob_head = commit(&w.bob, &w.brepo, "b.txt", "b\n", "bob");
    w.bob.git(&w.brepo, &["push", "-q"]);
    w.alice.git(&w.arepo, &["reset", "-q", "--hard", "HEAD~1"]);
    commit(&w.alice, &w.arepo, "a4.txt", "a4\n", "a4");
    let stale = w.alice.run("git", &w.arepo, &["push", "--force-with-lease"]);
    eprintln!("stale lease: {}", stderr(&stale));
    assert!(!stale.status.success(), "a stale lease must not overwrite Bob's push");
    w.bob.git(&w.brepo, &["fetch", "-q"]);
    assert_eq!(w.bob.git(&w.brepo, &["rev-parse", "origin/main"]).trim(), bob_head);

    // "Must not exist yet" leases: creating a branch works once.
    w.alice.git(&w.arepo, &["branch", "-q", "fresh"]);
    w.alice.git(&w.arepo, &["push", "-q", "--force-with-lease=refs/heads/fresh:", "origin", "fresh"]);
    w.alice.git(&w.arepo, &["checkout", "-q", "fresh"]);
    commit(&w.alice, &w.arepo, "f.txt", "f\n", "fresh work");
    let again = w.alice.run("git", &w.arepo, &["push", "--force-with-lease=refs/heads/fresh:", "origin", "fresh"]);
    assert!(!again.status.success(), "the branch exists now: {}", stderr(&again));
    assert!(stderr(&again).contains("stale info"), "{}", stderr(&again));
}

/// A seized relay database holds no timestamps that could be lined up to link
/// people to repos: no time-like columns beyond the explicitly allowed ones,
/// and log entries carry no time.
#[test]
fn relay_database_stores_no_timestamps() {
    let w = world();
    commit(&w.bob, &w.brepo, "t.txt", "t\n", "t");
    w.bob.git(&w.brepo, &["push", "-q"]);
    w.alice.git(&w.arepo, &["pull", "-q", "--ff-only"]);
    w.alice.with_env("E2EE_GOSSIP_SECS", "0").e2ee(&w.arepo, &["sync"]);
    let allowed = [
        ("registration_tokens", "expires"), // the operator's own invite expiry
        ("blobs", "gen"),                   // coarse expiry generation, not a time
        ("mailbox", "gen"),
        ("pmailboxes", "gen"),
        ("device_lists", "gen"),
        ("spent_tokens", "gen"),
    ];
    let timey = ["time", "created", "added", "at", "hour", "day", "epoch", "expires", "ms", "date", "gen", "used"];
    for (table, col) in w.relay.relay.schema_columns() {
        let looks_timey = timey.iter().any(|t| col == *t || col.ends_with(&format!("_{t}")) || col.starts_with(&format!("{t}_")));
        if looks_timey {
            assert!(allowed.contains(&(table.as_str(), col.as_str())), "time-like column {table}.{col}");
        }
    }
    use e2ee_proto::Message;
    let entries = w.relay.relay.log_entries_raw();
    assert!(!entries.is_empty());
    for e in entries {
        // Only seq, prev_head, nonce and an opaque commitment: no time, kind or view.
        let d = e2ee_proto::LogEntry::decode(e.as_slice()).unwrap();
        assert_eq!(d.encode_to_vec(), e, "log entry has unknown fields");
        assert_eq!(d.commitment.len(), 32);
    }
}

/// Carol, whose access tokens the relay issues under a key of her own and
/// who is shown that key on her "anonymous" fetches too (as by a relay that
/// recognizes her connection), so her own checks pass.
fn tagged_carol(w: &World) -> (Dev, String) {
    let carol = Dev::new(&w.root, "carol");
    let carol_code = carol.init_user(&w.relay.url);
    let alice_code = code_from(&w.alice.e2ee(&w.root, &["whoami"]), "e2eeu1:");
    w.relay.relay.tag_tokens(Some(&carol.user_hex()), true);
    // Her own periodic re-check is off: only comparing with members can tell.
    let carol = carol.with_env("E2EE_TOKEN_GEN_CHECK_SECS", "999999");
    carol.e2ee(&w.root, &["verify", &alice_code, "--yes"]); // her first tokens: tagged
    w.relay.relay.tag_tokens(Some(&carol.user_hex()), false); // everyone else: the real key
    w.alice.e2ee(&w.root, &["verify", &carol_code, "--yes"]);
    (carol, carol_code)
}

/// The tagged member notices: the members' mail reports a different key.
#[test]
fn tagged_member_notices_its_token_key_differs_from_members() {
    let w = world();
    let (carol, carol_code) = tagged_carol(&w);
    w.alice.e2ee(&w.arepo, &["member", "add", &carol_code]);
    let crepo = w.root.join("crepo");
    let out = carol.run("git", &w.root, &["clone", "-q", &w.url, crepo.to_str().unwrap()]);
    assert!(!out.status.success() && stderr(&out).contains("different access-token key"), "{}", stderr(&out));
}

/// The other members notice: the tagged member's mail reports its key.
#[test]
fn members_notice_a_member_given_its_own_token_key() {
    let w = world();
    let (carol, _) = tagged_carol(&w);
    let alice_code = code_from(&w.alice.e2ee(&w.root, &["whoami"]), "e2eeu1:");
    let crepo = w.root.join("carol-own");
    carol.git(&w.root, &["init", "-q", "--object-format=sha256", crepo.to_str().unwrap()]);
    commit(&carol, &crepo, "c.txt", "c\n", "c");
    carol.e2ee(&crepo, &["repo", "init", &w.relay.url]);
    carol.git(&crepo, &["push", "-q", "-u", "origin", "main"]);
    let url = carol.git(&crepo, &["config", "remote.origin.url"]).trim().to_string();
    carol.e2ee(&crepo, &["member", "add", &alice_code]);
    let arepo2 = w.root.join("alice-clone-of-carol");
    let out = w.alice.run("git", &w.root, &["clone", "-q", &url, arepo2.to_str().unwrap()]);
    assert!(!out.status.success() && stderr(&out).contains("different access-token key"), "{}", stderr(&out));
}

/// A ban rotates the token key for everyone (a new, public generation):
/// members' keys then differ by generation, which is not a conflict, and
/// clients drop their voided tokens instead of spending them.
#[test]
fn honest_token_key_rotation_is_not_a_conflict() {
    let w = world();
    w.relay.relay.ban(&"ab".repeat(32)).unwrap();
    let alice = w.alice.with_env("E2EE_TOKEN_GEN_CHECK_SECS", "0");
    let bob = w.bob.with_env("E2EE_TOKEN_GEN_CHECK_SECS", "0");
    let c = commit(&alice, &w.arepo, "after-ban.txt", "x\n", "after ban");
    alice.git(&w.arepo, &["push", "-q"]);
    bob.git(&w.brepo, &["pull", "-q", "--ff-only"]);
    assert_eq!(bob.git(&w.brepo, &["rev-parse", "HEAD"]).trim(), c);
    bob.with_env("E2EE_GOSSIP_SECS", "0").e2ee(&w.brepo, &["sync"]);
    alice.e2ee(&w.arepo, &["sync"]);
    assert!(!alice.status(&w.arepo).contains("CONFLICT"), "{}", alice.status(&w.arepo));
    assert!(!bob.status(&w.brepo).contains("CONFLICT"), "{}", bob.status(&w.brepo));
}

/// Carol forwards Alice's push to Bob (whose copy from Alice the relay holds
/// back), hoping to be credited. The push names its author inside the view,
/// so Bob ignores the forwarded copy (no conflict either) and credits Alice
/// once her own copy arrives.
#[test]
fn a_member_cannot_take_credit_for_someone_elses_push() {
    let w = world();
    let carol = Dev::new(&w.root, "carol");
    let carol_code = carol.init_user(&w.relay.url);
    let alice_code = code_from(&w.alice.e2ee(&w.root, &["whoami"]), "e2eeu1:");
    carol.e2ee(&w.root, &["verify", &alice_code, "--yes"]);
    w.alice.e2ee(&w.root, &["verify", &carol_code, "--yes"]);
    w.alice.e2ee(&w.arepo, &["member", "add", &carol_code]);
    let crepo = w.root.join("crepo");
    carol.git(&w.root, &["clone", "-q", &w.url, crepo.to_str().unwrap()]);
    for _ in 0..2 {
        pq_settle(&w.bob, &w.brepo, &carol, &crepo); // Bob and Carol shake hands
    }

    // The relay drops Alice's copy to Bob.
    w.relay.adversary(|a| a.drop_mail_to = w.bob.mailboxes());
    let c = commit(&w.alice, &w.arepo, "alice.txt", "a\n", "alice's work");
    w.alice.git(&w.arepo, &["push", "-q"]);
    w.relay.adversary(|a| a.drop_mail_to.clear());
    carol.with_env("E2EE_TEST_FORWARD_PUSHES", "1").e2ee(&crepo, &["sync"]);
    let out = stderr(&w.bob.run("git", &w.brepo, &["fetch"]));
    assert!(waiting(&out), "Bob applied the forwarded copy: {out}");
    assert!(!w.bob.status(&w.brepo).contains("CONFLICT"), "{}", w.bob.status(&w.brepo));

    // Alice answers Bob's resend request with her own copy.
    w.alice.with_env("E2EE_RESEND_SECS", "0").e2ee(&w.arepo, &["sync"]);
    w.bob.with_env("E2EE_RESEND_SECS", "0").git(&w.brepo, &["pull", "-q", "--ff-only"]);
    assert_eq!(w.bob.git(&w.brepo, &["rev-parse", "HEAD"]).trim(), c);
    let log = w.bob.e2ee(&w.brepo, &["log"]);
    // The newest entry (Alice's push) names Alice.
    let newest = log
        .lines()
        .filter(|l| l.split_whitespace().next().is_some_and(|t| t.parse::<u64>().is_ok()))
        .max_by_key(|l| l.split_whitespace().next().unwrap().parse::<u64>().unwrap())
        .unwrap();
    assert!(newest.contains(&w.alice.user_hex()[..12]), "{log}");
    assert!(!newest.contains(&carol.user_hex()[..12]), "Carol was credited: {log}");
}

/// Spent access tokens and repo-token requests never travel on a connection
/// that also carried device-signed requests (which name the device).
#[test]
fn anonymous_requests_never_share_a_connection_with_signed_ones() {
    let w = world();
    commit(&w.bob, &w.brepo, "b.txt", "b\n", "b");
    w.bob.git(&w.brepo, &["push", "-q"]);
    w.alice.git(&w.arepo, &["pull", "-q", "--ff-only"]);
    let kinds = w.relay.relay.connection_kinds.lock().unwrap().clone();
    assert!(kinds.values().any(|k| k.0) && kinds.values().any(|k| k.1), "{kinds:?}");
    let mixed: Vec<_> = kinds.iter().filter(|(_, k)| k.0 && k.1).collect();
    assert!(mixed.is_empty(), "connections carrying both: {mixed:?}");
}

/// Write a raw git object (as `hash-object -w` does) and return its id.
fn write_object(dev: &Dev, repo: &Path, kind: &str, body: &str) -> String {
    let mut c = dev.cmd("git", repo);
    c.args(["hash-object", "-t", kind, "-w", "--stdin"]).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped());
    let mut child = c.spawn().unwrap();
    use std::io::Write;
    child.stdin.take().unwrap().write_all(body.as_bytes()).unwrap();
    String::from_utf8(child.wait_with_output().unwrap().stdout).unwrap().trim().to_string()
}

/// A signed tag wrapped in an unsigned tag is still refused: every tag in
/// the push is checked, not just the ones refs point at.
#[test]
fn signed_tags_nested_in_unsigned_ones_are_refused() {
    let w = world();
    let head = w.alice.git(&w.arepo, &["rev-parse", "HEAD"]).trim().to_string();
    let inner = write_object(
        &w.alice,
        &w.arepo,
        "tag",
        &format!(
            "object {head}\ntype commit\ntag inner\ntagger Anon <anon@example.invalid> 0 +0000\n\nsigned\n\
             -----BEGIN PGP SIGNATURE-----\n\niQEzBAABCAAdFiEE\n-----END PGP SIGNATURE-----\n"
        ),
    );
    let outer = write_object(
        &w.alice,
        &w.arepo,
        "tag",
        &format!("object {inner}\ntype tag\ntag outer\ntagger Anon <anon@example.invalid> 0 +0000\n\nwrapper\n"),
    );
    w.alice.git(&w.arepo, &["update-ref", "refs/tags/outer", &outer]);
    let out = w.alice.run("git", &w.arepo, &["push", "-q", "origin", "refs/tags/outer"]);
    assert!(!out.status.success() && stderr(&out).contains("signed tag"), "{}", stderr(&out));
}

/// The pseudonym check covers taggers, not just authors and committers.
#[test]
fn tagger_must_match_a_required_pseudonym() {
    let w = world();
    w.alice.git(&w.arepo, &["config", "e2ee.pseudonym", "Anon <anon@example.invalid>"]);
    w.alice.git(&w.arepo, &["config", "e2ee.requirePseudonym", "true"]);
    w.alice.git(&w.arepo, &["-c", "user.name=Real Name", "-c", "user.email=real@example.com", "tag", "-a", "v1", "-m", "v1"]);
    let out = w.alice.run("git", &w.arepo, &["push", "-q", "origin", "v1"]);
    assert!(!out.status.success() && stderr(&out).contains("tagger"), "{}", stderr(&out));
}

/// Bob leaves. His departure reaches Alice, whose next sync rotates the repo
/// secret: the relay drops the token Bob knew, and Alice keeps working.
#[test]
fn a_member_can_leave_and_is_cut_off_after_rotation() {
    let w = world();
    let tokens_before = w.relay.relay.dump_tables(&["repo_tokens"]);
    let out = w.bob.e2ee(&w.brepo, &["repo", "leave", "--yes"]);
    assert!(out.contains("Left"), "{out}");
    // This device forgot the repo.
    let st = w.bob.run("git-e2ee", &w.brepo, &["status"]);
    assert!(!String::from_utf8_lossy(&st.stdout).contains("log seq"), "{}", String::from_utf8_lossy(&st.stdout));
    // Bob's departure alone doesn't rotate anything (he holds the secret).
    assert_eq!(w.relay.relay.dump_tables(&["repo_tokens"]), tokens_before);

    let out = w.alice.e2ee(&w.arepo, &["sync"]);
    assert!(out.contains("rotated the repo secret"), "{out}");
    let tokens_after = w.relay.relay.dump_tables(&["repo_tokens"]);
    assert_ne!(tokens_after, tokens_before, "the token Bob knew is still valid");
    assert!(!w.alice.e2ee(&w.arepo, &["member", "list"]).contains(&w.bob.user_hex()[..12]));
    // Only one rotation, and Alice can still push.
    assert!(!w.alice.e2ee(&w.arepo, &["sync"]).contains("rotated"));
    commit(&w.alice, &w.arepo, "after.txt", "after\n", "after bob left");
    w.alice.git(&w.arepo, &["push", "-q"]);
    // Bob can't come back by cloning.
    let again = w.root.join("bob-again");
    assert!(!w.bob.run("git", &w.root, &["clone", "-q", &w.url, again.to_str().unwrap()]).status.success());
}

/// The only member leaving just forgets the repo; removing yourself with
/// `member remove` points to `repo leave`.
#[test]
fn leaving_as_the_only_member_forgets_and_self_removal_points_to_leave() {
    let w = world();
    let out = w.alice.run("git-e2ee", &w.arepo, &["member", "remove", &w.alice.user_hex()]);
    assert!(!out.status.success() && stderr(&out).contains("repo leave"), "{}", stderr(&out));

    let solo = w.root.join("solo");
    w.alice.git(&w.root, &["init", "-q", "--object-format=sha256", solo.to_str().unwrap()]);
    commit(&w.alice, &solo, "s.txt", "s\n", "s");
    w.alice.e2ee(&solo, &["repo", "init", &w.relay.url]);
    w.alice.git(&solo, &["push", "-q", "-u", "origin", "main"]);
    let out = w.alice.e2ee(&solo, &["repo", "leave", "--yes"]);
    assert!(out.contains("only member"), "{out}");
}

/// Sizes of the messages waiting in all of a device's mailboxes.
fn mail_sizes(w: &World, dev: &Dev) -> Vec<usize> {
    let all = w.relay.relay.mailbox_sizes();
    dev.mailboxes().iter().flat_map(|k| all.get(k).cloned().unwrap_or_default()).collect()
}

/// Once members know each other's per-repo mailboxes, a push reaches Bob
/// through his pseudonymous mailbox: nothing lands in the mailbox named by
/// his user id, so the relay can't tell the fan-out reached user Bob.
#[test]
fn repo_traffic_goes_to_pseudonymous_mailboxes() {
    let w = world();
    w.bob.e2ee(&w.brepo, &["sync"]);
    w.alice.e2ee(&w.arepo, &["sync"]); // Alice learns Bob's mailbox for this repo
    let bob_named = (w.bob.user_hex(), 1);
    let named = |w: &World| w.relay.relay.mailbox_sizes().get(&bob_named).map_or(0, Vec::len);
    let before = named(&w);
    let c = commit(&w.alice, &w.arepo, "p.txt", "p\n", "pseudonymous");
    w.alice.git(&w.arepo, &["push", "-q"]);
    assert_eq!(named(&w), before, "the push went to Bob's user-id mailbox");
    assert!(mail_sizes(&w, &w.bob).len() > before, "the push didn't reach any of Bob's mailboxes");
    w.bob.git(&w.brepo, &["pull", "-q", "--ff-only"]);
    assert_eq!(w.bob.git(&w.brepo, &["rev-parse", "HEAD"]).trim(), c);
}

/// Bob rotates his mailbox; Alice, who hasn't heard the new address yet,
/// still reaches him at the old one (read until it expires), and later uses
/// the new one.
#[test]
fn mailbox_rotation_loses_nothing() {
    let w = world();
    w.bob.e2ee(&w.brepo, &["sync"]);
    w.alice.e2ee(&w.arepo, &["sync"]);
    w.bob.with_env("E2EE_MAILBOX_ROTATE_SECS", "0").e2ee(&w.brepo, &["sync"]);
    let db = rusqlite::Connection::open(w.bob.home.join("device.sqlite")).unwrap();
    let n: i64 = db.query_row("SELECT COUNT(*) FROM own_mailboxes", [], |r| r.get(0)).unwrap();
    assert!(n >= 2, "no rotation happened");
    let c = commit(&w.alice, &w.arepo, "r.txt", "r\n", "after rotation");
    w.alice.git(&w.arepo, &["push", "-q"]);
    w.bob.git(&w.brepo, &["pull", "-q", "--ff-only"]);
    assert_eq!(w.bob.git(&w.brepo, &["rev-parse", "HEAD"]).trim(), c);
    let current: Vec<u8> = db
        .query_row("SELECT mailbox FROM own_mailboxes WHERE retired_ms IS NULL", [], |r| r.get(0))
        .unwrap();
    w.alice.e2ee(&w.arepo, &["sync"]); // hears Bob's new address from his ack
    let adb = rusqlite::Connection::open(w.alice.home.join("device.sqlite")).unwrap();
    let known: Vec<u8> = adb.query_row("SELECT mailbox FROM peer_mailboxes WHERE device_id = 1", [], |r| r.get(0)).unwrap();
    assert_eq!(known, current, "Alice didn't learn Bob's new mailbox");
}

/// Registering shows the relay's policy.
#[test]
fn register_prints_the_relay_policy() {
    let w = world();
    let dana = Dev::new(&w.root, "dana");
    dana.e2ee(&w.root, &["init-user"]);
    let out = dana.e2ee(&w.root, &["register", &w.relay.url]);
    assert!(out.contains("Policy of") && out.contains("Repeat infringers"), "{out}");
}

/// Bob is away so long that everything addressed to him expires on the
/// relay: Alice's push message, its pack, even his mailboxes. Back online he
/// is stuck at the missing entry, asks for history, and catches up from
/// Alice's bundle (checked to be on his chain of the log).
#[test]
fn a_device_offline_past_the_relay_ttl_catches_up() {
    let w = world();
    w.bob.e2ee(&w.brepo, &["sync"]);
    w.alice.e2ee(&w.arepo, &["sync"]);
    let c = commit(&w.alice, &w.arepo, "while-away.txt", "w\n", "while Bob was away");
    w.alice.git(&w.arepo, &["push", "-q"]);
    // Two expiry generations pass with Bob reading nothing.
    for _ in 0..2 {
        w.relay.relay.advance_generation_for_tests().unwrap();
        w.relay.relay.gc().unwrap();
    }
    let bob = w.bob.with_env("E2EE_HISTORY_AFTER_SECS", "0").with_env("E2EE_RESEND_SECS", "0");
    let out = bob.ok("git", &w.brepo, &["fetch"]);
    assert!(waiting(&out), "{out}");
    w.alice.with_env("E2EE_HISTORY_AFTER_SECS", "0").e2ee(&w.arepo, &["sync"]); // answers with a bundle
    let out = bob.ok("git", &w.brepo, &["pull", "--ff-only"]);
    assert!(out.contains("caught up:"), "{out}");
    assert_eq!(w.bob.git(&w.brepo, &["rev-parse", "HEAD"]).trim(), c);
    // And normal replication resumes.
    let c2 = commit(&w.alice, &w.arepo, "after.txt", "a\n", "after catch-up");
    w.alice.git(&w.arepo, &["push", "-q"]);
    w.bob.git(&w.brepo, &["pull", "-q", "--ff-only"]);
    assert_eq!(w.bob.git(&w.brepo, &["rev-parse", "HEAD"]).trim(), c2);
}

/// A history bundle is only taken if it continues our own verified chain:
/// here Bob's recorded head isn't in the relay log (as on a fork), so the
/// bundle is refused instead of silently moving him onto another history.
#[test]
fn catch_up_refuses_a_bundle_off_our_chain() {
    let w = world();
    w.bob.e2ee(&w.brepo, &["sync"]);
    w.alice.e2ee(&w.arepo, &["sync"]);
    commit(&w.alice, &w.arepo, "x.txt", "x\n", "x");
    w.alice.git(&w.arepo, &["push", "-q"]);
    for _ in 0..2 {
        w.relay.relay.advance_generation_for_tests().unwrap();
        w.relay.relay.gc().unwrap();
    }
    let bob = w.bob.with_env("E2EE_HISTORY_AFTER_SECS", "0").with_env("E2EE_RESEND_SECS", "0");
    bob.ok("git", &w.brepo, &["fetch"]); // stuck; asks for history
    let before = w.bob.git(&w.brepo, &["rev-parse", "HEAD"]);
    rusqlite::Connection::open(w.bob.home.join("device.sqlite"))
        .unwrap()
        .execute("UPDATE repos SET head = randomblob(32)", [])
        .unwrap();
    w.alice.with_env("E2EE_HISTORY_AFTER_SECS", "0").e2ee(&w.arepo, &["sync"]);
    let out = stderr(&bob.run("git", &w.brepo, &["pull", "--ff-only"]));
    assert!(out.contains("ignored a history bundle") && out.contains("our verified head"), "{out}");
    assert_eq!(w.bob.git(&w.brepo, &["rev-parse", "HEAD"]), before);
}

/// Carol joins the world's repo (and shakes hands with Bob).
fn add_carol(w: &World) -> (Dev, PathBuf) {
    let carol = Dev::new(&w.root, "carol");
    let carol_code = carol.init_user(&w.relay.url);
    let alice_code = code_from(&w.alice.e2ee(&w.root, &["whoami"]), "e2eeu1:");
    carol.e2ee(&w.root, &["verify", &alice_code, "--yes"]);
    w.alice.e2ee(&w.root, &["verify", &carol_code, "--yes"]);
    w.alice.e2ee(&w.arepo, &["member", "add", &carol_code]);
    let crepo = w.root.join("crepo");
    carol.git(&w.root, &["clone", "-q", &w.url, crepo.to_str().unwrap()]);
    for _ in 0..2 {
        pq_settle(&w.bob, &w.brepo, &carol, &crepo);
    }
    (carol, crepo)
}

/// Push while Bob is "away" (`others` stay current) and let everything still
/// addressed to him expire.
fn strand_bob(w: &World, others: &[(&Dev, &Path)]) -> String {
    w.bob.e2ee(&w.brepo, &["sync"]);
    w.alice.e2ee(&w.arepo, &["sync"]);
    let c = commit(&w.alice, &w.arepo, "away.txt", "a\n", "while Bob was away");
    w.alice.git(&w.arepo, &["push", "-q"]);
    for (d, repo) in others {
        d.git(repo, &["pull", "-q", "--ff-only"]);
        assert_eq!(d.git(repo, &["rev-parse", "HEAD"]).trim(), c);
    }
    for _ in 0..2 {
        w.relay.relay.advance_generation_for_tests().unwrap();
        w.relay.relay.gc().unwrap();
    }
    c
}

/// The request goes to every member device, but only one of them answers:
/// the first to claim in the log; the others see the claim and stand down.
#[test]
fn only_one_member_answers_a_history_request() {
    let w = world();
    let (carol, crepo) = add_carol(&w);
    let c = strand_bob(&w, &[(&carol, &crepo)]);
    let fast = |d: &Dev| d.with_env("E2EE_HISTORY_AFTER_SECS", "0").with_env("E2EE_RESEND_SECS", "0");
    fast(&w.bob).ok("git", &w.brepo, &["fetch"]); // stuck; asks everyone
    let a = fast(&w.alice).e2ee(&w.arepo, &["sync"]);
    // Carol may need two syncs to see Alice's claim entry and announcement.
    let c1 = fast(&carol).e2ee(&crepo, &["sync"]);
    let c2 = fast(&carol).e2ee(&crepo, &["sync"]);
    let answered = [&a, &c1, &c2].iter().filter(|o| o.contains("sent history to")).count();
    assert_eq!(answered, 1, "alice: {a}\\ncarol: {c1}{c2}");
    fast(&w.bob).git(&w.brepo, &["pull", "-q", "--ff-only"]);
    assert_eq!(w.bob.git(&w.brepo, &["rev-parse", "HEAD"]).trim(), c);
    assert!(w.alice.e2ee(&w.arepo, &["log"]).contains("sent history to"));
}

/// Alice claims but never delivers. Carol stands down while the claim is
/// fresh; once it has expired with Bob still behind, Bob asks again without
/// Alice, Carol answers, and Bob catches up.
#[test]
fn a_claim_that_never_delivers_only_delays_catch_up() {
    let w = world();
    let (carol, crepo) = add_carol(&w);
    let c = strand_bob(&w, &[(&carol, &crepo)]);
    let slow = |d: &Dev| {
        d.with_env("E2EE_HISTORY_AFTER_SECS", "2").with_env("E2EE_CLAIM_SECS", "2").with_env("E2EE_RESEND_SECS", "0")
    };
    let bob = slow(&w.bob);
    bob.ok("git", &w.brepo, &["fetch"]); // stuck: the clock starts
    std::thread::sleep(std::time::Duration::from_secs(3));
    bob.ok("git", &w.brepo, &["fetch"]); // stuck for a while: asks everyone
    slow(&w.alice).with_env("E2EE_TEST_CLAIM_WITHOUT_SENDING", "1").e2ee(&w.arepo, &["sync"]);
    assert!(w.alice.e2ee(&w.arepo, &["log"]).contains("sent history to"), "Alice made no claim");
    let c1 = slow(&carol).e2ee(&crepo, &["sync"]);
    assert!(!c1.contains("sent history to"), "Carol didn't stand down: {c1}");
    bob.ok("git", &w.brepo, &["fetch"]); // learns of Alice's claim
    std::thread::sleep(std::time::Duration::from_secs(3)); // the claim expires
    bob.ok("git", &w.brepo, &["fetch"]); // asks again, excluding Alice
    let c2 = slow(&carol).e2ee(&crepo, &["sync"]);
    assert!(c2.contains("sent history to"), "{c2}");
    bob.git(&w.brepo, &["pull", "-q", "--ff-only"]);
    assert_eq!(w.bob.git(&w.brepo, &["rev-parse", "HEAD"]).trim(), c);
}

/// The long-absence experience: Bob's device last synced three weeks ago.
/// It explains why (mail expired), asks for history right away without the
/// usual wait, doesn't blame the relay for the silence, tells Bob to ask
/// someone to run `git e2ee sync`, and `status` says the same. Once Alice
/// syncs, Bob's next pull catches up.
#[test]
fn coming_back_after_weeks_explains_itself_and_says_what_to_do() {
    let w = world();
    let c = strand_bob(&w, &[]);
    let db = rusqlite::Connection::open(w.bob.home.join("device.sqlite")).unwrap();
    let three_weeks_ago = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64
        - 21 * 24 * 3600 * 1000;
    db.execute("UPDATE meta SET v = ?1 WHERE k LIKE 'last-sync:%'", [three_weeks_ago.to_be_bytes().to_vec()]).unwrap();
    let bob = w.bob.with_env("E2EE_MAX_STALENESS_SECS", "1");
    let out = bob.ok("git", &w.brepo, &["fetch"]);
    assert!(out.contains("last synced this repo 21 days ago") && out.contains("expired"), "{out}");
    assert!(out.contains("run `git e2ee sync` in this repo"), "{out}");
    assert!(!out.contains("freeze attack"), "blamed the relay for our own absence: {out}");
    assert!(!out.contains("404"), "{out}");
    let status = w.bob.status(&w.brepo);
    assert!(status.contains("behind:") && status.contains("git e2ee sync"), "{status}");
    // No hour of waiting: Alice can answer right away.
    let a = w.alice.e2ee(&w.arepo, &["sync"]);
    assert!(a.contains("note: sent history to"), "{a}");
    let out = bob.ok("git", &w.brepo, &["pull", "--ff-only"]);
    assert!(out.contains("note: caught up:"), "{out}");
    assert_eq!(w.bob.git(&w.brepo, &["rev-parse", "HEAD"]).trim(), c);
    assert!(!w.bob.status(&w.brepo).contains("behind:"));
}

/// Whether a fetch reported being stuck at a missing log entry.
fn waiting(out: &str) -> bool {
    out.contains("waiting for the message of log entry") || out.contains("behind at log entry")
}

/// Contacts can be given local names, which `git e2ee log` shows: as the
/// author, and as the source of entries this device didn't see itself.
#[test]
fn log_names_contacts_and_where_inherited_entries_came_from() {
    let w = world();
    let alice_short = &w.alice.user_hex()[..12];
    let log = w.bob.e2ee(&w.brepo, &["log"]);
    assert!(log.contains(&format!("[according to {alice_short}]")), "{log}");
    let alice_code = code_from(&w.alice.e2ee(&w.root, &["whoami"]), "e2eeu1:");
    w.bob.e2ee(&w.root, &["name", &alice_code, "Alice"]);
    commit(&w.alice, &w.arepo, "n.txt", "n\n", "named");
    w.alice.git(&w.arepo, &["push", "-q"]);
    w.bob.git(&w.brepo, &["pull", "-q", "--ff-only"]);
    let log = w.bob.e2ee(&w.brepo, &["log"]);
    assert!(log.contains("[according to Alice]"), "{log}");
    assert!(log.contains("Alice (verified)"), "{log}");
    assert!(!log.contains(alice_short), "{log}");
    assert!(w.bob.e2ee(&w.brepo, &["member", "list"]).contains("Alice  "));
}

/// A signed commit hidden behind a replace ref (`git replace S U`) is still
/// seen: the policy check reads objects as pushed, not as replaced.
#[test]
fn replace_refs_dont_hide_signed_commits() {
    let w = world();
    commit(&w.alice, &w.arepo, "s.txt", "s\n", "to be signed");
    let body = w.alice.git(&w.arepo, &["cat-file", "commit", "HEAD"]);
    let (header, msg) = body.split_once("\n\n").unwrap();
    let signed = write_object(
        &w.alice,
        &w.arepo,
        "commit",
        &format!("{header}\ngpgsig -----BEGIN PGP SIGNATURE-----\n \n iQEzBAABCAAdFiEE\n -----END PGP SIGNATURE-----\n\n{msg}"),
    );
    let unsigned = w.alice.git(&w.arepo, &["rev-parse", "HEAD"]).trim().to_string();
    w.alice.git(&w.arepo, &["update-ref", "refs/heads/main", &signed]);
    w.alice.git(&w.arepo, &["replace", &signed, &unsigned]);
    let out = w.alice.run("git", &w.arepo, &["push", "-q"]);
    assert!(!out.status.success() && stderr(&out).contains("signed commit"), "{}", stderr(&out));
}

/// `e2ee.requirePseudonym` without `e2ee.pseudonym` refuses instead of
/// silently checking nothing; and the key database is owner-only.
#[test]
fn require_pseudonym_needs_a_pseudonym_and_keys_are_owner_only() {
    let w = world();
    w.alice.git(&w.arepo, &["config", "e2ee.requirePseudonym", "true"]);
    commit(&w.alice, &w.arepo, "p.txt", "p\n", "p");
    let out = w.alice.run("git", &w.arepo, &["push", "-q"]);
    assert!(!out.status.success() && stderr(&out).contains("e2ee.pseudonym isn't"), "{}", stderr(&out));
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(w.alice.home.join("device.sqlite")).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "device.sqlite mode {mode:o}");
}

/// A history bundle's refs must be the ones its view commits to: Alice sends
/// Carol a bundle with the real view but `main` pointing elsewhere, and
/// Carol discards it instead of cloning a made-up state.
#[test]
fn bundles_with_refs_not_matching_their_view_are_refused() {
    let w = world();
    let first = w.alice.git(&w.arepo, &["rev-parse", "HEAD"]).trim().to_string();
    commit(&w.alice, &w.arepo, "two.txt", "2\n", "second");
    w.alice.git(&w.arepo, &["push", "-q"]);
    let carol = Dev::new(&w.root, "carol");
    let carol_code = carol.init_user(&w.relay.url);
    let alice_code = code_from(&w.alice.e2ee(&w.root, &["whoami"]), "e2eeu1:");
    carol.e2ee(&w.root, &["verify", &alice_code, "--yes"]);
    w.alice.e2ee(&w.root, &["verify", &carol_code, "--yes"]);
    w.alice.with_env("E2EE_TEST_FORGE_BUNDLE_REFS", &first).e2ee(&w.arepo, &["member", "add", &carol_code]);
    let crepo = w.root.join("crepo");
    let out = carol.run("git", &w.root, &["clone", "-q", &w.url, crepo.to_str().unwrap()]);
    assert!(!out.status.success(), "Carol cloned a forged state");
    assert!(stderr(&out).contains("refs aren't the ones the repo's view commits to"), "{}", stderr(&out));
}

/// A member "upgrading" the repo to a protocol no device supports is a bad
/// change (a conflict naming the cause), not an endless "upgrade" stall.
/// Adding a member is announced to the others.
#[test]
fn fake_upgrades_are_conflicts_and_new_members_are_announced() {
    let w = world();
    let carol = Dev::new(&w.root, "carol");
    let carol_code = carol.init_user(&w.relay.url);
    w.alice.e2ee(&w.root, &["verify", &carol_code, "--yes"]);
    w.alice.e2ee(&w.arepo, &["member", "add", &carol_code]);
    let out = w.bob.e2ee(&w.brepo, &["sync"]);
    assert!(out.contains(&format!("added user {}", &carol.user_hex()[..12])) && out.contains("haven't verified"), "{out}");

    let dana = Dev::new(&w.root, "dana");
    let dana_code = dana.init_user(&w.relay.url);
    w.alice.e2ee(&w.root, &["verify", &dana_code, "--yes"]);
    // Alice's own client already refuses what it just appended.
    let out = w
        .alice
        .with_env("E2EE_TEST_ROSTER_PROTOCOL", "99")
        .with_env("E2EE_TEST_FAN_OUT_ANYWAY", "1")
        .run("git-e2ee", &w.arepo, &["member", "add", &dana_code]);
    assert!(stderr(&out).contains("raises the protocol to 99"), "{}", stderr(&out));
    let out = w.bob.run("git", &w.brepo, &["fetch"]);
    assert!(!out.status.success());
    let status = w.bob.status(&w.brepo);
    assert!(status.contains("CONFLICT") && status.contains("raises the protocol to 99"), "{status}");
    assert!(!stderr(&out).contains("upgrade git-e2ee"), "{}", stderr(&out));
}

/// Revoking a device rotates the repo secret, like a member leaving: the
/// revoked device knew the repo token.
#[test]
fn revoking_a_device_rotates_the_repo_secret() {
    let w = world();
    let (_laptop, _) = link_device(&w, &w.bob, &w.brepo, "bob-laptop");
    w.alice.e2ee(&w.arepo, &["sync"]);
    w.bob.e2ee(&w.brepo, &["sync"]);
    let tokens_before = w.relay.relay.dump_tables(&["repo_tokens"]);
    w.bob.e2ee(&w.root, &["device", "revoke", "2"]);
    let a = w.alice.e2ee(&w.arepo, &["sync"]);
    let b = w.bob.e2ee(&w.brepo, &["sync"]);
    assert!(format!("{a}{b}").contains("rotated the repo secret"), "alice: {a}\nbob: {b}");
    assert_ne!(w.relay.relay.dump_tables(&["repo_tokens"]), tokens_before);
}

/// Alice and Bob both remove Carol at the same moment: both rotate the repo
/// token. Only the append that wins changes it, so whichever way the race
/// goes, Alice and Bob keep working, the relay holds exactly one token, and
/// Carol is cut off.
#[test]
fn concurrent_rotations_never_lock_members_out() {
    let w = world();
    let (carol, crepo) = add_carol(&w);
    w.bob.e2ee(&w.brepo, &["sync"]);
    w.alice.e2ee(&w.arepo, &["sync"]);
    let carol_hex = carol.user_hex();
    let a = w.alice.cmd("git-e2ee", &w.arepo).args(["member", "remove", &carol_hex]).spawn().unwrap();
    let b = w.bob.cmd("git-e2ee", &w.brepo).args(["member", "remove", &carol_hex]).spawn().unwrap();
    let (a, b) = (a.wait_with_output().unwrap(), b.wait_with_output().unwrap());
    assert!(a.status.success() || b.status.success(), "neither removal went through:\n{}\n{}", stderr(&a), stderr(&b));
    let tokens = w.relay.relay.dump_tables(&["repo_tokens"]);
    // One row: the repo id and one token hash (64 hex).
    let rid = w.url.rsplit('/').next().unwrap();
    assert_eq!(tokens.len(), rid.len() + 64, "expected exactly one repo token");
    for (dev, repo) in [(&w.alice, &w.arepo), (&w.bob, &w.brepo)] {
        dev.e2ee(repo, &["sync"]);
        assert!(!dev.e2ee(repo, &["member", "list"]).contains(&carol_hex[..12]));
    }
    let c = commit(&w.alice, &w.arepo, "after.txt", "after\n", "after the race");
    w.alice.git(&w.arepo, &["push", "-q"]);
    w.bob.git(&w.brepo, &["pull", "-q", "--ff-only"]);
    assert_eq!(w.bob.git(&w.brepo, &["rev-parse", "HEAD"]).trim(), c);
    carol.ok("git", &crepo, &["fetch", "-q"]);
    assert!(!carol.run("git", &crepo, &["cat-file", "-e", &c]).status.success(), "removed member got a new push");
}

/// Bob misses the membership change that rotated the repo token (its mail
/// expired while he was away). The relay refuses his old token, so he can't
/// even read the log: he says so, asks the members for the current state
/// right away, and once Alice syncs he's back, secret included.
#[test]
fn a_device_that_missed_a_rotation_gets_back_in() {
    let w = world();
    let (carol, crepo) = add_carol(&w);
    w.bob.e2ee(&w.brepo, &["sync"]);
    w.alice.e2ee(&w.arepo, &["sync"]);
    w.alice.e2ee(&w.arepo, &["member", "remove", &carol.user_hex()]);
    let c = commit(&w.alice, &w.arepo, "after.txt", "after\n", "after Carol left");
    w.alice.git(&w.arepo, &["push", "-q"]);
    for _ in 0..2 {
        w.relay.relay.advance_generation_for_tests().unwrap();
        w.relay.relay.gc().unwrap();
    }
    let out = w.bob.ok("git", &w.brepo, &["fetch"]);
    assert!(out.contains("no longer accepts its access secret") && out.contains("git e2ee sync"), "{out}");
    assert!(w.bob.e2ee(&w.brepo, &["status"]).contains("asked"), "status doesn't say what's being done");
    w.alice.e2ee(&w.arepo, &["sync"]);
    w.bob.git(&w.brepo, &["pull", "-q", "--ff-only"]);
    assert_eq!(w.bob.git(&w.brepo, &["rev-parse", "HEAD"]).trim(), c);
    // And Bob works normally again.
    commit(&w.bob, &w.brepo, "bob.txt", "bob\n", "bob is back");
    w.bob.git(&w.brepo, &["push", "-q"]);
    // Carol, removed, asks too, but nobody answers her.
    let out = carol.ok("git", &crepo, &["fetch"]);
    assert!(out.contains("no longer accepts its access secret"), "{out}");
    w.alice.e2ee(&w.arepo, &["sync"]);
    carol.ok("git", &crepo, &["fetch"]);
    assert!(!carol.run("git", &crepo, &["cat-file", "-e", &c]).status.success(), "removed member got a new push");
}

/// Deleting a branch and creating it again at unrelated history in a later
/// push is a force push too (tracked with the push log, the default).
#[test]
fn delete_then_recreate_is_flagged_as_a_force_push() {
    let w = world();
    w.alice.git(&w.arepo, &["checkout", "-q", "-b", "topic"]);
    commit(&w.alice, &w.arepo, "t1.txt", "t1\n", "t1");
    commit(&w.alice, &w.arepo, "t2.txt", "t2\n", "t2");
    w.alice.git(&w.arepo, &["push", "-q", "origin", "topic"]);
    let bob = &w.bob;
    bob.ok("git", &w.brepo, &["fetch", "-q"]);
    w.alice.git(&w.arepo, &["push", "-q", "origin", ":topic"]);
    bob.ok("git", &w.brepo, &["fetch", "-q"]);
    w.alice.git(&w.arepo, &["checkout", "-q", "main"]);
    w.alice.git(&w.arepo, &["checkout", "-q", "-b", "topic2"]);
    commit(&w.alice, &w.arepo, "x.txt", "x\n", "unrelated");
    w.alice.git(&w.arepo, &["push", "-q", "origin", "topic2:topic"]);
    let out = bob.ok("git", &w.brepo, &["fetch"]);
    assert!(out.contains("force-pushed refs/heads/topic (2 commit(s)"), "{out}");
}

/// Your own pushes get the checks receivers apply: replace refs and names
/// receivers would reject are refused before anything is sent. A misspelt
/// boolean setting is an error, not "off".
#[test]
fn own_pushes_get_receivers_checks_and_bad_booleans_are_errors() {
    let w = world();
    let head = w.alice.git(&w.arepo, &["rev-parse", "HEAD"]).trim().to_string();
    let out = w.alice.run("git", &w.arepo, &["push", "-q", "origin", &format!("{head}:refs/replace/{head}")]);
    assert!(!out.status.success() && stderr(&out).contains("replace refs"), "{}", stderr(&out));
    let long = format!("refs/heads/{}", "x".repeat(1100));
    let out = w.alice.run("git", &w.arepo, &["push", "-q", "origin", &format!("HEAD:{long}")]);
    assert!(!out.status.success(), "an over-long ref name was pushed");
    w.alice.git(&w.arepo, &["config", "e2ee.requirePseudonym", "ture"]);
    commit(&w.alice, &w.arepo, "p.txt", "p\n", "p");
    let out = w.alice.run("git", &w.arepo, &["push", "-q"]);
    assert!(!out.status.success() && stderr(&out).contains("not a boolean"), "{}", stderr(&out));
    // Nothing reached Bob, and the repo isn't stuck.
    w.alice.git(&w.arepo, &["config", "e2ee.requirePseudonym", "false"]);
    w.alice.git(&w.arepo, &["push", "-q"]);
    w.bob.git(&w.brepo, &["pull", "-q", "--ff-only"]);
}

/// The relay shows Bob (only) an entry claiming a newer protocol, while
/// Alice pushes on the real log, twice. No honest member can write such an
/// entry (the repo's protocol only rises once every member device, Bob's
/// included, supports the new one), so Bob calls it a conflict at once,
/// without waiting for Alice to report anything.
#[test]
fn a_fake_newer_protocol_entry_is_caught_as_a_fork() {
    let w = world();
    w.alice.e2ee(&w.arepo, &["sync"]);
    w.bob.e2ee(&w.brepo, &["sync"]);
    let seq = log_seq(&w.alice.status(&w.arepo));
    w.relay.adversary(|a| a.fork_at = Some(seq));
    let rid = w.url.rsplit('/').next().unwrap().to_string();
    w.bob.git(&w.brepo, &["remote", "set-url", "origin", &format!("e2ee::{}/{rid}", w.relay.url_fork)]);
    w.relay.relay.append_raw_to_fork_for_tests(&rid, 1, |seq, head| {
        use e2ee_proto::Message;
        e2ee_proto::LogEntry { seq, prev_head: head.to_vec(), nonce: vec![1; 16], commitment: vec![2; 32], version: 999 }.encode_to_vec()
    });
    for i in 0..2 {
        commit(&w.alice, &w.arepo, &format!("a{i}.txt"), "a\n", "alice on the real log");
        w.alice.git(&w.arepo, &["push", "-q"]);
    }
    let out = w.bob.run("git", &w.brepo, &["fetch"]);
    assert!(!out.status.success() && stderr(&out).contains("claims protocol 999"), "{}", stderr(&out));
    let b = w.bob.status(&w.brepo);
    assert!(b.contains("CONFLICT"), "{b}");
}

/// Disappearing log entries. A timer any member sets applies to everyone.
/// Each entry keeps the timer it was recorded under: a push made under a one-
/// week timer survives a later switch to seconds. Who set the timer stays in
/// the log until the next change replaces it.
#[test]
fn log_entries_disappear_on_the_timer_they_were_recorded_under() {
    let w = world();
    w.bob.e2ee(&w.brepo, &["sync"]);
    w.bob.e2ee(&w.brepo, &["log-timer", "1w"]);
    w.alice.e2ee(&w.arepo, &["sync"]);
    let p1 = commit(&w.alice, &w.arepo, "p1.txt", "p1\n", "under a week");
    w.alice.git(&w.arepo, &["push", "-q"]);
    w.bob.git(&w.brepo, &["pull", "-q", "--ff-only"]);
    w.alice.e2ee(&w.arepo, &["log-timer", "3s"]);
    let p2 = commit(&w.alice, &w.arepo, "p2.txt", "p2\n", "under three seconds");
    w.alice.git(&w.arepo, &["push", "-q"]);
    w.bob.git(&w.brepo, &["pull", "-q", "--ff-only"]);
    let before = w.bob.e2ee(&w.brepo, &["log"]);
    assert!(before.contains(&p2[..12]) && before.contains("disappears"), "{before}");
    std::thread::sleep(std::time::Duration::from_secs(4));
    for (dev, repo) in [(&w.alice, &w.arepo), (&w.bob, &w.brepo)] {
        let log = dev.e2ee(repo, &["log"]);
        assert!(log.contains(&p1[..12]), "the push under the week-long timer went early:\n{log}");
        assert!(!log.contains(&p2[..12]), "the push under the 3-second timer is still shown:\n{log}");
        assert!(log.contains("set log entries to disappear after 3 seconds"), "who set the timer isn't shown:\n{log}");
        assert!(!log.contains("after 1 week"), "the replaced timer notice is still shown:\n{log}");
        assert!(log.contains("new entries are deleted 3 seconds after"), "{log}");
    }
    // Deleted, not hidden.
    let db = rusqlite::Connection::open(w.bob.home.join("device.sqlite")).unwrap();
    let mut st = db.prepare("SELECT entry FROM push_log").unwrap();
    let rows: Vec<Vec<u8>> = st.query_map([], |r| r.get(0)).unwrap().map(|r| r.unwrap()).collect();
    assert!(!rows.iter().any(|r| r.windows(12).any(|x| x == &p2.as_bytes()[..12])), "the expired entry is still stored");
    // Off again: who turned it off is what's shown.
    w.bob.e2ee(&w.brepo, &["log-timer", "off"]);
    let log = w.bob.e2ee(&w.brepo, &["log"]);
    assert!(log.contains("turned disappearing log entries off") && !log.contains("after 3 seconds"), "{log}");
}

/// Invite Carol, who then doesn't clone before the relay expires the
/// invitation. `env` is Alice's environment for the re-send step.
fn invite_and_let_it_expire(w: &World) -> (Dev, String) {
    let carol = Dev::new(&w.root, "carol");
    let carol_code = carol.init_user(&w.relay.url);
    let alice_code = code_from(&w.alice.e2ee(&w.root, &["whoami"]), "e2eeu1:");
    carol.e2ee(&w.root, &["verify", &alice_code, "--yes"]);
    w.alice.e2ee(&w.root, &["verify", &carol_code, "--yes"]);
    let out = w.alice.e2ee(&w.arepo, &["member", "add", &carol_code]);
    assert!(out.contains("re-sends it about weekly"), "{out}");
    for _ in 0..2 {
        w.relay.relay.advance_generation_for_tests().unwrap();
        w.relay.relay.gc().unwrap();
    }
    let crepo = w.root.join("crepo");
    let out = carol.run("git", &w.root, &["clone", "-q", &w.url, crepo.to_str().unwrap()]);
    assert!(!out.status.success() && stderr(&out).contains("`git e2ee member add <your user code>` again"), "{}", stderr(&out));
    assert!(w.alice.status(&w.arepo).contains("hasn't cloned yet"), "{}", w.alice.status(&w.arepo));
    (carol, carol_code)
}

fn clone_and_check(w: &World, carol: &Dev) {
    let crepo = w.root.join("crepo");
    carol.git(&w.root, &["clone", "-q", &w.url, crepo.to_str().unwrap()]);
    assert!(crepo.join("plans.txt").exists());
    // Once Carol has cloned (and acknowledged), Alice stops re-sending.
    carol.e2ee(&crepo, &["sync"]);
    w.alice.e2ee(&w.arepo, &["sync"]);
    assert!(!w.alice.status(&w.arepo).contains("hasn't cloned yet"), "{}", w.alice.status(&w.arepo));
}

/// A missed invitation: running `member add` again re-sends it.
#[test]
fn member_add_again_resends_a_missed_invitation() {
    let w = world();
    let (carol, carol_code) = invite_and_let_it_expire(&w);
    let out = w.alice.e2ee(&w.arepo, &["member", "add", &carol_code]);
    assert!(out.contains("hasn't cloned yet: invitation re-sent to 1 device"), "{out}");
    clone_and_check(&w, &carol);
    let out = w.alice.e2ee(&w.arepo, &["member", "add", &carol_code]);
    assert!(out.contains("already a member (and has cloned)"), "{out}");
}

/// The inviter's device re-sends a pending invitation by itself before it
/// can expire, so nobody has to do anything.
#[test]
fn invitations_are_resent_automatically_until_taken_up() {
    let w = world();
    let (carol, _) = invite_and_let_it_expire(&w);
    let out = w.alice.with_env("E2EE_INVITE_RESEND_SECS", "0").e2ee(&w.arepo, &["sync"]);
    assert!(out.contains("re-sent the invitation to 1 device"), "{out}");
    assert!(w.alice.status(&w.arepo).contains("sent 2 time(s)"), "{}", w.alice.status(&w.arepo));
    clone_and_check(&w, &carol);
}
