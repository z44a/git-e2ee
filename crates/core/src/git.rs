//! Thin wrappers around the git CLI.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, anyhow, bail};

/// A `git` command that sees objects as they are: replace refs are off
/// (otherwise the signature and pseudonym checks would read a replacement
/// while the pack carries the original), and environment overrides that
/// would point it at another object store or work tree are cleared.
pub fn git_command() -> Command {
    let mut c = Command::new("git");
    c.env("GIT_NO_REPLACE_OBJECTS", "1");
    for v in [
        "GIT_DIR",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_INDEX_FILE",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_NAMESPACE",
        "GIT_REPLACE_REF_BASE",
        "GIT_GRAFT_FILE",
        "GIT_SHALLOW_FILE",
    ] {
        c.env_remove(v);
    }
    c
}

#[derive(Clone)]
pub struct Git {
    pub git_dir: PathBuf,
}

impl Git {
    pub fn new(git_dir: impl Into<PathBuf>) -> Self {
        Self { git_dir: git_dir.into() }
    }

    /// Open (creating if needed) a bare repository in `format`. An existing
    /// one must already be in that format.
    pub fn init_mirror(path: &Path, format: &str) -> Result<Self> {
        if format == e2ee_proto::object_format::SHA1 && !sha1_collision_detection() {
            bail!(
                "this repo uses SHA-1 object ids, which needs a git built with SHA-1 collision \
                 detection (`git version --build-options` should list SHA1_DC)"
            );
        }
        if path.join("HEAD").exists() {
            let git = Self::new(path);
            let have = git.object_format()?;
            if have != format {
                bail!("local mirror uses {have} object ids but the repo uses {format}");
            }
            return Ok(git);
        }
        {
            std::fs::create_dir_all(path)?;
            let out = git_command()
                .args(["init", "-q", "--bare", &format!("--object-format={format}")])
                .arg(path)
                .env_remove("GIT_DIR")
                .output()?;
            if !out.status.success() {
                bail!("creating mirror repo: {}", String::from_utf8_lossy(&out.stderr));
            }
        }
        Ok(Self::new(path))
    }

    /// Oids of all refs in this repository.
    pub fn ref_oids(&self) -> Result<Vec<String>> {
        let out = self.run(&["for-each-ref", "--format=%(objectname)"], None)?;
        Ok(String::from_utf8(out)?.lines().map(str::to_string).collect())
    }

    /// The repository containing the current directory.
    pub fn discover() -> Result<Self> {
        // Here the user's own GIT_DIR / GIT_WORK_TREE should count.
        let out = Command::new("git").args(["rev-parse", "--absolute-git-dir"]).output()?;
        if !out.status.success() {
            bail!("not inside a git repository");
        }
        Ok(Self::new(String::from_utf8(out.stdout)?.trim()))
    }

    fn cmd(&self) -> Command {
        let mut c = git_command();
        c.env("GIT_DIR", &self.git_dir);
        c
    }

    fn run(&self, args: &[&str], input: Option<&[u8]>) -> Result<Vec<u8>> {
        let mut c = self.cmd();
        c.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
        c.stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() });
        let mut child = c.spawn().with_context(|| format!("running git {}", args.join(" ")))?;
        if let Some(data) = input {
            let mut stdin = child.stdin.take().unwrap();
            let data = data.to_vec();
            // Write on a thread so large inputs cannot deadlock against stdout.
            let writer = std::thread::spawn(move || stdin.write_all(&data));
            let out = child.wait_with_output()?;
            writer.join().map_err(|_| anyhow!("stdin writer panicked"))??;
            return check(args, out);
        }
        check(args, child.wait_with_output()?)
    }

    pub fn object_format(&self) -> Result<String> {
        Ok(String::from_utf8(self.run(&["rev-parse", "--show-object-format"], None)?)?.trim().to_string())
    }

    /// Refuse unless this repository uses the e2ee repo's object format.
    pub fn require_format(&self, format: &str) -> Result<()> {
        let f = self.object_format()?;
        if f != format {
            bail!("this repository uses {f} object ids, but the encrypted repo uses {format}");
        }
        Ok(())
    }

    pub fn rev_parse(&self, rev: &str) -> Result<String> {
        Ok(String::from_utf8(self.run(&["rev-parse", "--verify", "--quiet", &format!("{rev}^{{object}}")], None)?)?
            .trim()
            .to_string())
    }

    pub fn has_object(&self, oid: &str) -> bool {
        self.run(&["cat-file", "-e", oid], None).is_ok()
    }

    pub fn object_type(&self, oid: &str) -> Result<String> {
        Ok(String::from_utf8(self.run(&["cat-file", "-t", oid], None)?)?.trim().to_string())
    }

    pub fn cat(&self, kind: &str, oid: &str) -> Result<Vec<u8>> {
        self.run(&["cat-file", kind, oid], None)
    }

    pub fn is_ancestor(&self, ancestor: &str, descendant: &str) -> Result<bool> {
        let st = self
            .cmd()
            .args(["merge-base", "--is-ancestor", ancestor, descendant])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        Ok(st.success())
    }

    /// Number of commits reachable from `from` but not from `not`.
    pub fn count_commits(&self, from: &str, not: &str) -> Result<u32> {
        let out = self.run(&["rev-list", "--count", from, &format!("^{not}")], None)?;
        Ok(String::from_utf8(out)?.trim().parse()?)
    }

    /// Commits reachable from `include` but not `exclude`.
    pub fn new_commits(&self, include: &[String], exclude: &[String]) -> Result<Vec<String>> {
        let mut input = String::new();
        for i in include {
            input.push_str(&format!("{i}\n"));
        }
        for e in exclude.iter().filter(|e| self.has_object(e)) {
            input.push_str(&format!("^{e}\n"));
        }
        let out = self.run(&["rev-list", "--stdin"], Some(input.as_bytes()))?;
        Ok(String::from_utf8(out)?.lines().map(str::to_string).collect())
    }

    /// Tag objects reachable from `include` but not `exclude`, including tags
    /// nested inside other tags.
    pub fn new_tags(&self, include: &[String], exclude: &[String]) -> Result<Vec<String>> {
        let mut input = String::new();
        for i in include {
            input.push_str(&format!("{i}\n"));
        }
        for e in exclude.iter().filter(|e| self.has_object(e)) {
            input.push_str(&format!("^{e}\n"));
        }
        let listed = String::from_utf8(self.run(&["rev-list", "--objects", "--stdin"], Some(input.as_bytes()))?)?;
        let ids: String = listed.lines().filter_map(|l| l.split(' ').next()).map(|o| format!("{o}\n")).collect();
        let typed = String::from_utf8(self.run(&["cat-file", "--batch-check=%(objectname) %(objecttype)"], Some(ids.as_bytes()))?)?;
        Ok(typed
            .lines()
            .filter_map(|l| l.split_once(' '))
            .filter(|(_, t)| *t == "tag")
            .map(|(o, _)| o.to_string())
            .collect())
    }

    /// Pack of objects reachable from `include` but not `exclude`.
    pub fn pack(&self, include: &[String], exclude: &[String], thin: bool) -> Result<Vec<u8>> {
        let mut input = String::new();
        for i in include {
            input.push_str(&format!("{i}\n"));
        }
        for e in exclude.iter().filter(|e| self.has_object(e)) {
            input.push_str(&format!("^{e}\n"));
        }
        let mut args = vec!["pack-objects", "--stdout", "--revs", "-q"];
        if thin {
            args.push("--thin");
        }
        self.run(&args, Some(input.as_bytes()))
    }

    /// Import a pack, completing thin packs and running strict fsck checks.
    pub fn index_pack(&self, pack: &[u8]) -> Result<()> {
        if pack_object_count(pack)? == 0 {
            return Ok(());
        }
        std::fs::create_dir_all(self.git_dir.join("objects/pack"))?;
        self.run(&["index-pack", "--stdin", "--fix-thin", "--strict"], Some(pack))?;
        Ok(())
    }

    /// Stream a pack (as `pack`, without buffering it) for reading in chunks.
    pub fn pack_stream(&self, include: &[String], exclude: &[String], thin: bool) -> Result<PackStream> {
        let mut input = String::new();
        for i in include {
            input.push_str(&format!("{i}\n"));
        }
        for e in exclude.iter().filter(|e| self.has_object(e)) {
            input.push_str(&format!("^{e}\n"));
        }
        let mut c = self.cmd();
        c.args(["pack-objects", "--stdout", "--revs", "-q"]);
        if thin {
            c.arg("--thin");
        }
        let mut child = c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
        let mut stdin = child.stdin.take().unwrap();
        let writer = std::thread::spawn(move || stdin.write_all(input.as_bytes()));
        let out = child.stdout.take().unwrap();
        Ok(PackStream { child, out, writer: Some(writer) })
    }

    /// Feed a pack to `index-pack` piece by piece (strict checks, thin packs
    /// completed from local objects).
    pub fn index_pack_stream(&self) -> Result<IndexPackStream> {
        std::fs::create_dir_all(self.git_dir.join("objects/pack"))?;
        let mut child = self
            .cmd()
            .args(["index-pack", "--stdin", "--fix-thin", "--strict"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        let stdin = child.stdin.take();
        Ok(IndexPackStream { child, stdin })
    }

    pub fn config(&self, key: &str) -> Result<Option<String>> {
        let out = self.cmd().args(["config", "--get", key]).output()?;
        Ok(out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string()))
    }

    /// A boolean setting if present (`None` when unset). Like
    /// `config_bool`, a value that isn't a boolean is an error.
    pub fn config_flag(&self, key: &str) -> Result<Option<bool>> {
        let out = self.cmd().args(["config", "--type=bool", "--get", key]).output()?;
        match out.status.code() {
            Some(0) => Ok(Some(String::from_utf8_lossy(&out.stdout).trim() == "true")),
            Some(1) => Ok(None),
            _ => bail!(
                "git config {key} is not a boolean ({}); set it to true or false",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        }
    }

    /// A boolean setting, false when unset. A value git can't read as a
    /// boolean is an error, not "false": a typo in a setting that turns a
    /// check on mustn't silently turn it off.
    pub fn config_bool(&self, key: &str) -> Result<bool> {
        let out = self.cmd().args(["config", "--type=bool", "--get", key]).output()?;
        match out.status.code() {
            Some(0) => Ok(String::from_utf8_lossy(&out.stdout).trim() == "true"),
            Some(1) => Ok(false), // unset
            _ => bail!(
                "git config {key} is not a boolean ({}); set it to true or false",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        }
    }

    pub fn path(&self) -> &Path {
        &self.git_dir
    }
}

/// A running `git pack-objects`, read in chunks.
pub struct PackStream {
    child: std::process::Child,
    out: std::process::ChildStdout,
    writer: Option<std::thread::JoinHandle<std::io::Result<()>>>,
}

impl PackStream {
    /// Up to `max` bytes; an empty result means the pack is complete.
    pub fn read_chunk(&mut self, max: usize) -> Result<Vec<u8>> {
        use std::io::Read;
        let mut buf = vec![0u8; max];
        let mut n = 0;
        while n < max {
            let r = self.out.read(&mut buf[n..])?;
            if r == 0 {
                break;
            }
            n += r;
        }
        buf.truncate(n);
        Ok(buf)
    }

    pub fn finish(mut self) -> Result<()> {
        if let Some(w) = self.writer.take() {
            w.join().map_err(|_| anyhow!("pack input writer panicked"))??;
        }
        let out = self.child.wait_with_output()?;
        if !out.status.success() {
            bail!("git pack-objects failed: {}", String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(())
    }
}

/// A running `git index-pack --stdin`, fed in chunks.
pub struct IndexPackStream {
    child: std::process::Child,
    stdin: Option<std::process::ChildStdin>,
}

impl IndexPackStream {
    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        self.stdin.as_mut().ok_or_else(|| anyhow!("index-pack input closed"))?.write_all(data)?;
        Ok(())
    }

    pub fn finish(mut self) -> Result<()> {
        drop(self.stdin.take());
        let out = self.child.wait_with_output()?;
        if !out.status.success() {
            bail!("git index-pack failed: {}", String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(())
    }
}

fn check(args: &[&str], out: std::process::Output) -> Result<Vec<u8>> {
    if !out.status.success() {
        bail!("git {} failed: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(out.stdout)
}

pub fn pack_object_count(pack: &[u8]) -> Result<u32> {
    if pack.len() < 12 || &pack[..4] != b"PACK" {
        bail!("not a git pack");
    }
    Ok(u32::from_be_bytes(pack[8..12].try_into()?))
}

/// Whether a commit or tag object carries a signature.
/// Whether a commit or tag object carries a signature. For commits this
/// includes `mergetag` headers: merging a signed tag embeds the tag, with its
/// signature, in the merge commit.
pub fn object_is_signed(kind: &str, body: &[u8]) -> bool {
    let text = String::from_utf8_lossy(body);
    let has_marker = |t: &str| {
        // Git accepts both OpenPGP armors as a signature.
        t.contains("-----BEGIN PGP SIGNATURE-----")
            || t.contains("-----BEGIN PGP MESSAGE-----")
            || t.contains("-----BEGIN SSH SIGNATURE-----")
            || t.contains("-----BEGIN SIGNED MESSAGE-----")
    };
    match kind {
        "commit" => {
            // Header continuation lines start with a space, so the embedded
            // tag's own blank line does not end the header.
            let header = text.split("\n\n").next().unwrap_or("");
            header.lines().any(|l| l.starts_with("gpgsig ") || l.starts_with("gpgsig-sha256 ")) || has_marker(header)
        }
        "tag" => has_marker(&text),
        _ => false,
    }
}


/// An object id in `format`: exactly 64 (SHA-256) or 40 (SHA-1) lowercase
/// hex digits.
pub fn valid_oid(oid: &str, format: &str) -> bool {
    e2ee_proto::object_format::oid_len(format) == Some(oid.len())
        && oid.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Whether the git on PATH uses collision-detecting SHA-1 (SHA-1DC), which
/// refuses objects made with the known SHA-1 collision attacks.
pub fn sha1_collision_detection() -> bool {
    git_command()
        .args(["version", "--build-options"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_ascii_lowercase().contains("sha1_dc"))
        .unwrap_or(false)
}

/// Ref names from other members are written into the remote-helper protocol
/// and passed to git, so they must follow git's ref-name rules
/// (git-check-ref-format) and live under refs/. A newline would inject lines
/// into the protocol.
pub fn valid_ref_name(name: &str) -> bool {
    if !name.starts_with("refs/") || name.len() > 1024 {
        return false;
    }
    if name.ends_with('/') || name.ends_with('.') || name.ends_with(".lock") || name.contains("..")
        || name.contains("//") || name.contains("@{") || name == "@"
    {
        return false;
    }
    if name.bytes().any(|b| b < 0x20 || b == 0x7f || b" ~^:?*[\\".contains(&b)) {
        return false;
    }
    name.split('/').all(|c| !c.is_empty() && !c.starts_with('.') && !c.ends_with(".lock"))
}

/// The `Name <email>` of the author and committer headers of a commit (and
/// the tagger of any tag merged into it), or the tagger header of a tag.
pub fn commit_identities(body: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(body);
    let header = text.split("\n\n").next().unwrap_or("");
    header
        .lines()
        .filter_map(|l| {
            l.strip_prefix("author ")
                .or_else(|| l.strip_prefix("committer "))
                .or_else(|| l.strip_prefix("tagger "))
                // The tagger of a tag merged in (a `mergetag` header's
                // continuation lines start with a space).
                .or_else(|| l.strip_prefix(" tagger "))
        })
        .map(|rest| rest.rfind('>').map_or(rest, |i| &rest[..=i]).to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pgp_message_armor_and_merged_taggers_are_seen() {
        let tag = b"object aa\ntype commit\ntag v1\ntagger T <t@x> 0 +0000\n\nv1\n-----BEGIN PGP MESSAGE-----\nx\n-----END PGP MESSAGE-----\n";
        assert!(object_is_signed("tag", tag));
        let merge = "tree aa\nparent bb\nparent cc\nauthor A <a@x> 1 +0000\ncommitter A <a@x> 1 +0000\n\
                     mergetag object cc\n type commit\n tag v1\n tagger Real Name <real@x> 0 +0000\n \n v1\n\
                      -----BEGIN PGP MESSAGE-----\n x\n -----END PGP MESSAGE-----\n\nMerge tag 'v1'\n";
        assert!(object_is_signed("commit", merge.as_bytes()));
        assert!(commit_identities(merge.as_bytes()).contains(&"Real Name <real@x>".to_string()));
    }

    #[test]
    fn ref_and_oid_validation() {
        for ok in ["refs/heads/main", "refs/tags/v1.0", "refs/heads/feature/x-y_z"] {
            assert!(valid_ref_name(ok), "{ok}");
        }
        for bad in [
            "main", "refs/heads/a\nb", "refs/heads/a b", "refs/heads/..", "refs/heads/a..b", "refs/heads/x.lock",
            "refs/heads/", "refs//heads", "refs/heads/.hidden", "refs/heads/a~1", "refs/heads/a^", "refs/heads/a:b",
            "refs/heads/a@{1}", "refs/heads/a\\b", "refs/heads/a*", "refs/heads/a?", "refs/heads/a[", "refs/heads/end.",
        ] {
            assert!(!valid_ref_name(bad), "{bad:?}");
        }
        assert!(valid_oid(&"a".repeat(64), "sha256"));
        assert!(!valid_oid(&"A".repeat(64), "sha256"));
        assert!(!valid_oid(&"a".repeat(40), "sha256"));
        assert!(!valid_oid(&format!("{} x", "a".repeat(62)), "sha256"));
        assert!(valid_oid(&"a".repeat(40), "sha1"));
        assert!(!valid_oid(&"a".repeat(64), "sha1"));
        assert!(!valid_oid(&"a".repeat(40), "md5"));
    }

    #[test]
    fn detects_signatures_including_mergetags() {
        let plain = "tree aa\nauthor A <a> 1 +0000\ncommitter A <a> 1 +0000\n\nmsg\n";
        assert!(!object_is_signed("commit", plain.as_bytes()));
        let gpgsig = "tree aa\ngpgsig -----BEGIN PGP SIGNATURE-----\n x\n -----END PGP SIGNATURE-----\n\nmsg\n";
        assert!(object_is_signed("commit", gpgsig.as_bytes()));
        let mergetag = "tree aa\nparent bb\nparent cc\nmergetag object cc\n type commit\n tag v1\n tagger T <t> 1 +0000\n \n release\n -----BEGIN PGP SIGNATURE-----\n x\n -----END PGP SIGNATURE-----\nauthor A <a> 1 +0000\n\nMerge tag 'v1'\n";
        assert!(object_is_signed("commit", mergetag.as_bytes()));
        // A signature-looking string in the message body is not a signature.
        let in_message = "tree aa\n\nsee -----BEGIN PGP SIGNATURE----- in docs\n";
        assert!(!object_is_signed("commit", in_message.as_bytes()));
        assert!(object_is_signed("tag", b"object aa\n\nv1\n-----BEGIN SSH SIGNATURE-----\nx\n"));
    }
}
