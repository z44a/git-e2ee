//! The relay binary refuses to expose plaintext HTTP beyond loopback.

use std::process::Command;

#[test]
fn refuses_plaintext_on_non_loopback_address() {
    let db = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("cli-test.sqlite");
    let _ = std::fs::remove_file(&db);
    let out = Command::new(env!("CARGO_BIN_EXE_git-e2ee-relay"))
        .args(["--listen", "0.0.0.0:0", "--public-url", "https://relay.example", "--db"])
        .arg(&db)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("refusing to serve plaintext"), "{err}");
}

#[test]
fn public_url_is_required_beyond_loopback() {
    let db = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("cli-test2.sqlite");
    let _ = std::fs::remove_file(&db);
    let out = Command::new(env!("CARGO_BIN_EXE_git-e2ee-relay"))
        .args(["--listen", "0.0.0.0:0", "--plaintext-behind-proxy", "--db"])
        .arg(&db)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--public-url is required"));
}
