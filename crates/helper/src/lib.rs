//! Shared setup for the `git-remote-e2ee` and `git-e2ee` binaries.

use anyhow::Result;
use e2ee_core::device::Device;
use e2ee_core::store::{Db, DeviceLock, data_dir};

/// Locked device state for the duration of one process.
pub struct Session {
    pub _lock: DeviceLock,
    pub db: Db,
}

impl Session {
    pub fn open() -> Result<Self> {
        let dir = data_dir()?;
        let lock = DeviceLock::acquire(&dir)?;
        Ok(Self { db: Db::open(&dir)?, _lock: lock })
    }

    pub fn device(&self) -> Result<Device> {
        Device::require(&self.db)
    }
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
