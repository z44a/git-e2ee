//! Shared setup for the `git-remote-e2ee` and `git-e2ee` binaries.

use anyhow::Result;
use e2ee_core::device::Device;
use e2ee_core::store::{Db, DeviceLock, account_dir};

/// Locked device state for the duration of one process.
pub struct Session {
    pub _lock: DeviceLock,
    pub db: Db,
}

impl Session {
    /// The account on this relay (see `account_dir`): each relay has its own.
    pub fn open(relay_url: &str) -> Result<Self> {
        Self::open_dir(&account_dir(relay_url)?)
    }

    /// The account on this relay, which must exist.
    pub fn open_existing(relay_url: &str) -> Result<Self> {
        let dir = account_dir(relay_url)?;
        if !has_account(&dir) {
            anyhow::bail!(
                "you have no git-e2ee account on {} yet: create one with `git e2ee init-user {relay_url}` \
                 (or, for another device of an existing account, `git e2ee device link {relay_url}`)",
                e2ee_core::store::relay_host(relay_url)?
            );
        }
        Self::open_dir(&dir)
    }

    pub fn open_dir(dir: &std::path::Path) -> Result<Self> {
        let lock = DeviceLock::acquire(dir)?;
        Ok(Self { db: Db::open(dir)?, _lock: lock })
    }

    pub fn device(&self) -> Result<Device> {
        Device::require(&self.db)
    }
}

/// Does this state directory hold an account (a user, linked or not yet)?
pub fn has_account(dir: &std::path::Path) -> bool {
    dir.join("device.sqlite").exists()
        && Db::open(dir).ok().is_some_and(|db| db.meta_get("master_pub").ok().flatten().is_some())
}

pub fn runtime() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_current_thread().enable_all().build()?)
}

pub use e2ee_core::printable;

/// Warnings can quote the relay or other members: printed via `printable`.
pub fn print_warnings(ws: &[String]) {
    for w in ws {
        eprintln!("e2ee: warning: {}", printable(w));
    }
}

/// What to do about a conflict (printed with every conflict message).
pub const CONFLICT_HELP: &str = "compare `git e2ee status` (log seq and head) with a collaborator over a channel you trust; once you've dealt with the cause, run `git e2ee clear-conflict` (it comes back if the cause is still there). See the README's \"Conflicts\" section.";

/// Print a sync's notes (information) and warnings (need attention).
pub fn print_report(r: &e2ee_core::engine::SyncReport) {
    for n in &r.notes {
        eprintln!("e2ee: note: {}", printable(n));
    }
    print_warnings(&r.warnings);
}
