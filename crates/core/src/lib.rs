//! Core of git-e2ee: identity, sessions, encrypted replication.

pub mod client;
pub mod device;
pub mod engine;
pub mod git;
pub mod identity;
pub mod pack;
pub mod pqauth;
pub mod store;
pub mod tls;

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Text from others (members, the relay), made safe for a terminal: no
/// control characters (so no escape sequences or line breaks that could fake
/// or hide output), and no invisible formatting characters (bidi overrides
/// and isolates, zero-width and filler characters, tag characters...) that
/// can reorder or hide text on screen.
pub fn printable(s: &str) -> String {
    let invisible = |c: char| {
        matches!(c,
            '\u{00AD}' | '\u{034F}' | '\u{061C}' | '\u{115F}' | '\u{1160}' | '\u{17B4}' | '\u{17B5}'
            | '\u{180B}'..='\u{180F}' | '\u{200B}'..='\u{200F}' | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}' | '\u{3164}' | '\u{FE00}'..='\u{FE0F}' | '\u{FEFF}' | '\u{FFA0}'
            | '\u{FFF0}'..='\u{FFFB}' | '\u{1BCA0}'..='\u{1BCA3}' | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0000}'..='\u{E0FFF}')
    };
    s.chars().filter(|c| !c.is_control() && !invisible(*c)).collect()
}

/// `printable` for multi-line text (keeps the line breaks).
pub fn printable_text(s: &str) -> String {
    s.lines().map(printable).collect::<Vec<_>>().join("\n")
}

#[cfg(test)]
mod printable_tests {
    #[test]
    fn strips_escapes_and_invisible_formatting() {
        let s = "ok\x1b[2K\re2ee: warning\u{202E}evil\u{E0041}\u{2028}\u{200B}x\ny";
        assert_eq!(super::printable(s), "ok[2Ke2ee: warningevilxy");
        assert_eq!(super::printable("Zoë 日本"), "Zoë 日本");
    }
}
