//! git remote helper for `e2ee::<relay-url>/<repo-id>` remotes.
//! See gitremote-helpers(7) for the protocol.

use std::io::{BufRead, Write};

use anyhow::{Context, Result, bail};
use e2ee_core::engine::Engine;
use e2ee_core::git::Git;
use e2ee_helper::{Session, print_report, printable, runtime};

fn main() {
    if let Err(e) = run() {
        eprintln!("e2ee: error: {}", e2ee_core::printable_text(&format!("{e:#}")));
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let url = args.get(2).or(args.get(1)).context("usage: git-remote-e2ee <remote> <url>")?.clone();
    let git_dir = std::env::var("GIT_DIR").context("GIT_DIR not set; this program is run by git")?;
    // Accounts are per relay: the remote's relay picks the account.
    let (relay_url, _) = e2ee_core::engine::parse_url(&url)?;
    let session = Session::open_existing(&relay_url)?;
    let rt = runtime()?;
    let mut eng = Engine::new(session.device()?, &url)?;
    let real = Git::new(git_dir);
    eng.push_log = real.config_flag("e2ee.pushLog")?.unwrap_or(true);

    let stdin = std::io::stdin();
    let mut lines = stdin.lock().lines();
    let mut out = std::io::stdout().lock();
    let mut synced = false;
    let mut object_format = false;
    let mut leases: std::collections::HashMap<String, String> = Default::default();

    while let Some(line) = lines.next() {
        let line = line?;
        let (cmd, rest) = line.split_once(' ').unwrap_or((line.as_str(), ""));
        match cmd {
            "capabilities" => {
                writeln!(out, "fetch\npush\noption\nobject-format\n")?;
            }
            "option" => {
                let (name, value) = rest.split_once(' ').unwrap_or((rest, ""));
                let reply = match name {
                    "object-format" => {
                        object_format = value == "true";
                        "ok"
                    }
                    "verbosity" | "progress" => "ok",
                    // --force-with-lease: "cas <ref>:<expected oid>" (empty or
                    // all zeros: the ref must not exist yet).
                    "cas" => match value.split_once(':') {
                        Some((r, oid)) => {
                            leases.insert(r.to_string(), oid.to_string());
                            "ok"
                        }
                        None => "error --force-with-lease needs an explicit expected value here",
                    },
                    _ => "unsupported",
                };
                writeln!(out, "{reply}")?;
            }
            "list" => {
                if !synced {
                    let report = rt.block_on(eng.sync())?;
                    print_report(&report);
                    match (&report.behind, report.waiting_for) {
                        (Some(why), _) => eprintln!("e2ee: note: {why}"),
                        (None, Some(seq)) => eprintln!(
                            "e2ee: waiting for the message of log entry {seq} from its author; showing the last \
                             verified state. It usually arrives by the next fetch; if this persists, ask a member to \
                             run `git e2ee sync` in this repo, and if that doesn't help, the relay may be withholding mail"
                        ),
                        (None, None) => {}
                    }
                    synced = true;
                }
                let Some(state) = eng.state()? else {
                    bail!(
                        "this device has no history for this repo yet.\n\
                         If you were invited, the invitation may not have arrived yet, or may have expired:\n\
                         ask the member who invited you to run `git e2ee member add <your name>` again\n\
                         (it re-sends the invitation), then run `git clone` again. You must have added them as a\n\
                         contact (`git e2ee contact add <name> <their user id>`), as they did you.\n\
                         For your own device: your device that has the repo sends it on its next fetch, push or\n\
                         `git e2ee sync` (run one there), then clone again."
                    );
                };
                if let Some(c) = &state.conflict {
                    bail!(
                        "refusing to use this remote: {c}\n{}",
                        e2ee_helper::CONFLICT_HELP
                    );
                }
                if object_format {
                    // git clone creates the local repo in this format.
                    writeln!(out, ":object-format {}", state.roster.object_format)?;
                }
                // Only refs that pass the same checks as members' pushes reach
                // git (whatever path put them in the state).
                let visible: Vec<_> = state.refs.iter().filter(|r| e2ee_core::engine::ref_visible(&r.name)).cloned().collect();
                // HEAD names a hidden ref? Point clones at a visible branch
                // instead, picked the way the engine picks one.
                let head = e2ee_core::engine::pick_head(&state.head_ref, &visible);
                if !head.is_empty() {
                    writeln!(out, "@{head} HEAD")?;
                }
                for r in visible {
                    writeln!(out, "{} {}", r.oid, r.name)?;
                }
                writeln!(out)?;
            }
            "fetch" => {
                let mut wants = vec![rest.split(' ').next().unwrap_or("").to_string()];
                for l in lines.by_ref() {
                    let l = l?;
                    if l.is_empty() {
                        break;
                    }
                    if let Some(r) = l.strip_prefix("fetch ") {
                        wants.push(r.split(' ').next().unwrap_or("").to_string());
                    }
                }
                real.require_format(&eng.object_format()?)?;
                eng.export_objects(&real, &wants)?;
                writeln!(out)?;
            }
            "push" => {
                let mut specs = vec![rest.to_string()];
                for l in lines.by_ref() {
                    let l = l?;
                    if l.is_empty() {
                        break;
                    }
                    if let Some(r) = l.strip_prefix("push ") {
                        specs.push(r.to_string());
                    }
                }
                let results = push(&rt, &mut eng, &real, &specs, synced, &leases);
                match results {
                    Ok(rs) => {
                        for (dst, r) in rs {
                            match r {
                                Ok(()) => writeln!(out, "ok {dst}")?,
                                Err(why) => writeln!(out, "error {dst} {}", printable(&why))?,
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("e2ee: error: {}", e2ee_core::printable_text(&format!("{e:#}")));
                        for s in &specs {
                            let dst = s.rsplit_once(':').map(|x| x.1).unwrap_or(s);
                            writeln!(out, "error {dst} {}", printable(format!("{e}").lines().next().unwrap_or("push failed")))?;
                        }
                    }
                }
                writeln!(out)?;
            }
            "" => break,
            other => bail!("unsupported helper command {other:?}"),
        }
        out.flush()?;
    }
    Ok(())
}

type PushResults = Vec<(String, Result<(), String>)>;

fn push(
    rt: &tokio::runtime::Runtime,
    eng: &mut Engine,
    real: &Git,
    specs: &[String],
    synced: bool,
    leases: &std::collections::HashMap<String, String>,
) -> Result<PushResults> {
    if !synced {
        print_report(&rt.block_on(eng.sync())?);
    }
    real.require_format(&eng.object_format()?)?;
    // Current verified remote values, for --force-with-lease.
    let current: std::collections::HashMap<String, String> = eng
        .state()?
        .map(|s| s.refs.into_iter().map(|r| (r.name, r.oid)).collect())
        .unwrap_or_default();
    let mut updates = Vec::new();
    let mut stale = Vec::new();
    for spec in specs {
        let (mut force, spec) = match spec.strip_prefix('+') {
            Some(s) => (true, s),
            None => (false, spec.as_str()),
        };
        let (src, dst) = spec.split_once(':').context("malformed push spec")?;
        if let Some(expected) = leases.get(dst) {
            // The lease holds if the ref still has the value the user last
            // saw (or still doesn't exist); then the update may force.
            let must_be_absent = expected.is_empty() || expected.bytes().all(|b| b == b'0');
            let holds = match current.get(dst) {
                Some(cur) => !must_be_absent && cur == expected,
                None => must_be_absent,
            };
            if !holds {
                stale.push(dst.to_string());
                continue;
            }
            force = true;
        }
        let src = if src.is_empty() { None } else { Some(real.rev_parse(src)?) };
        updates.push((src, dst.to_string(), force));
    }
    let mut results = if updates.is_empty() { vec![] } else { rt.block_on(eng.push(real, &updates))? };
    results.extend(stale.into_iter().map(|d| (d, Err("stale info".to_string()))));
    Ok(results)
}
