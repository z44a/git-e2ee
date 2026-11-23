//! Versioned SQLite schemas.
//!
//! A database's schema version is SQLite's `user_version`. `migrations[i]`
//! takes a database from version `i` to `i + 1`, so the current version is
//! `migrations.len()`. Never edit a migration once released: append a new
//! one.

use rusqlite::{Connection, TransactionBehavior};

#[derive(Debug)]
pub enum MigrateError {
    /// The database was written by a newer build.
    TooNew { name: &'static str, found: u32, supported: u32 },
    Sql(rusqlite::Error),
}

impl std::fmt::Display for MigrateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooNew { name, found, supported } => write!(
                f,
                "the {name} database has schema version {found}, but this build only knows up to {supported}: \
                 it was written by a newer version; upgrade instead of downgrading"
            ),
            Self::Sql(e) => write!(
                f,
                "database migration failed: {e}. If this database was made by a pre-release (protocol 1) build, \
                 it can't be upgraded: move it aside and start fresh (see CHANGELOG.md)"
            ),
        }
    }
}

impl std::error::Error for MigrateError {}

impl From<rusqlite::Error> for MigrateError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sql(e)
    }
}

pub fn schema_version(conn: &Connection) -> rusqlite::Result<u32> {
    conn.pragma_query_value(None, "user_version", |r| r.get(0))
}

/// Bring `conn` up to the latest schema. Each step runs in its own
/// transaction together with the version bump, so a crash leaves the
/// database at a well-defined version.
pub fn migrate(conn: &mut Connection, name: &'static str, migrations: &[&str]) -> Result<u32, MigrateError> {
    let supported = migrations.len() as u32;
    loop {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let found = schema_version(&tx)?;
        if found > supported {
            return Err(MigrateError::TooNew { name, found, supported });
        }
        if found == supported {
            return Ok(found);
        }
        tx.execute_batch(migrations[found as usize])?;
        tx.pragma_update(None, "user_version", found + 1)?;
        tx.commit()?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const V1: &str = "CREATE TABLE IF NOT EXISTS t (a INTEGER);";
    const V2: &str = "ALTER TABLE t ADD COLUMN b INTEGER NOT NULL DEFAULT 7;";

    #[test]
    fn fresh_database_gets_every_migration() {
        let mut c = Connection::open_in_memory().unwrap();
        assert_eq!(migrate(&mut c, "test", &[V1, V2]).unwrap(), 2);
        c.execute("INSERT INTO t (a) VALUES (1)", []).unwrap();
        assert_eq!(c.query_row("SELECT b FROM t", [], |r| r.get::<_, i64>(0)).unwrap(), 7);
        // Idempotent.
        assert_eq!(migrate(&mut c, "test", &[V1, V2]).unwrap(), 2);
    }

    #[test]
    fn older_database_is_upgraded_keeping_data() {
        let mut c = Connection::open_in_memory().unwrap();
        migrate(&mut c, "test", &[V1]).unwrap();
        c.execute("INSERT INTO t (a) VALUES (5)", []).unwrap();
        assert_eq!(migrate(&mut c, "test", &[V1, V2]).unwrap(), 2);
        assert_eq!(c.query_row("SELECT a, b FROM t", [], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))).unwrap(), (5, 7));
    }

    #[test]
    fn newer_database_is_refused_untouched() {
        let mut c = Connection::open_in_memory().unwrap();
        migrate(&mut c, "test", &[V1, V2]).unwrap();
        let e = migrate(&mut c, "test", &[V1]).unwrap_err();
        assert!(matches!(e, MigrateError::TooNew { found: 2, supported: 1, .. }), "{e}");
        assert_eq!(schema_version(&c).unwrap(), 2);
    }

    #[test]
    fn failed_migration_leaves_the_previous_version() {
        let mut c = Connection::open_in_memory().unwrap();
        assert!(migrate(&mut c, "test", &[V1, "THIS IS NOT SQL"]).is_err());
        assert_eq!(schema_version(&c).unwrap(), 1);
    }
}
