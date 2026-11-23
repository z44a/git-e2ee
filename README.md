# git-remote-e2ee

End-to-end encrypted git remotes. You push and pull with plain `git`. The server (the
*relay*) only ever stores ciphertext, and can't read your code, forge your history or
learn who you work with from what it stores.

```sh
git clone e2ee::https://relay.example/3f9c1a7e5b2d4c8f9a0b1c2d3e4f5a6b
```

> **Status: prototype, not audited.** It builds on [libsignal] in a way Signal doesn't
> support, and the rest of the protocol is custom. Don't rely on it for anything that
> matters yet.

How everything works, and every known limitation in detail, is in
[docs/DESIGN.md](docs/DESIGN.md).

[libsignal]: https://github.com/signalapp/libsignal

## Security properties

| | Property | Notes |
|---|---|---|
| ✅ | **Confidentiality** | File contents, file names, commit messages, authors, branch, tag and repo names are hidden from the relay and the network. |
| ✅ | **Post-quantum confidentiality** | Traffic recorded today stays private even against a future quantum computer. |
| ✅ | **Integrity** | The commit history (what `git log` shows) can't be altered: commits are content-addressed with SHA-256 (SHA-1 only if a repo opts in; see below). The relay can't change, forge, reorder or silently drop pushes without members noticing. Replace refs (`refs/replace/*`, which make git show other content for an existing commit) can't be pushed, so no member can use them to change what an already-pushed commit looks like to others. |
| ✅ | **Consistency (fork and equivocation detection)** | Neither the relay nor a member can show different members different versions of the repo without being caught. |
| ✅ | **Authentication** | Collaborators are verified once by safety number (digits, words or QR). Nobody can pass off a *push* as someone else's. Commit authors are a different matter (see **Commit authorship**). |
| ✅ | **Device-list integrity** | The relay can't add eavesdropping devices or hide additions and revocations. You're told whenever a collaborator's devices change. |
| ✅ | **Post-quantum message authentication** | libsignal authenticates with Curve25519 only, so every pair of devices also runs a Kyber1024 (ML-KEM's predecessor, the version libsignal treats as stable) handshake, and each message is encrypted and authenticated again under the resulting key. Posing as someone's device, or reading their messages after taking over a session, takes breaking Kyber too. The handshake runs once per pair of devices, so its key is as long-lived as the devices' own keys (see post-compromise security below). It uses no signatures, so it stays deniable. The cost: a new member's or device's first messages to someone wait until that person has been online once. |
| ✅ | **Post-quantum device lists and relay logins** | Master keys and relay request signatures are hybrid (Curve25519 plus ML-DSA-87), and safety numbers cover both. Even a quantum computer can't add a device to someone's account or act as their device toward the relay. |
| ✅ | **Forward secrecy** | Recorded ciphertext can't be decrypted with keys stolen later. |
| ✅ | **Post-compromise security** | Covers session state: after a temporary compromise, access ends as the device keeps syncing. Not identity keys (see below). |
| ✅ | **Deniability** | Collaborators know who pushed each change, but nobody can prove it to anyone else. Signed commits and tags are refused by default, including signed tags nested inside unsigned ones or merged into commits, and commits hidden behind `git replace`. |
| ✅ | **Removal (forward revocation)** | Removed members can't read anything pushed afterwards, and can't keep a way in: a repo has exactly one relay token and every rotation replaces it, so nothing a member planted survives one. (A member can still lock the others out by rotating to a secret only it knows: an insider risk, see `docs/DESIGN.md`.) Revoking a device rotates the repo's secret too. |
| ✅ | **Sender anonymity toward the relay** | No request says who sent a message, and anonymous requests never share a connection with requests your device signs. The relay still sees your IP address and timing, so this holds in what it stores, not against live traffic analysis. |
| ✅ | **Membership unlinkability in stored data** | A seized relay database doesn't show who created a repo or who is in it. It stores no links between people and repos and no per-user timestamps. Nor does it record the order things arrived in: message and blob contents sit in slots picked at random (see Timing below). It does show how many log entries each repo has (not which are pushes, membership changes or heartbeats) and, for undelivered mail, only whether it arrived in the last 7 days or the 7 before. Run any reverse proxy without request logging. |
| ✅ | **Anonymous rate limiting** | Each user has a daily budget for anonymous actions that the operator can't link back to them. Strangers get only a small daily allowance to message you. Members compare the token keys they were given, so a relay that singles out one person with a key of their own is caught once that person and a collaborator exchange messages. It is **not** caught if the relay gives a whole group of collaborators the same separate key: nobody in the group sees a mismatch, and every token they spend reveals which group spent it. Catching that needs comparison outside the group (a transparency log). |
| ✅ | **Freshness** | You're warned if the relay hides new pushes or holds back your collaborators' messages. |
| ✅ | **Replay protection** | Captured requests can't be replayed, to the same relay or another, including across a relay restart. |
| ✅ | **Push attribution (deniable)** | `git e2ee log` (not `git log`) reliably shows which member pushed each branch or tag change, and flags force pushes. A member can't take credit for someone else's push by forwarding it. It records who *pushed*, not who *wrote* the commits, and proves nothing to outsiders. |
| ❌ | **Traffic-analysis resistance** | The relay sees IP addresses, timing and rough sizes, and can infer who pushes, who is in which repo and when people work. No Tor support. This is the biggest gap. |
| ❌ | **Availability** | The relay can refuse service. You'll notice, but can't prevent it. |
| ❌ | **Post-quantum relay connection and rate limits** | TLS certificates and the anonymous access tokens are classical. A quantum attacker could pose as the relay toward the network (learning only what the relay sees) or mint tokens to get past rate limits. Token anonymity holds regardless. |
| ❌ | **Post-compromise security for identity keys** | If a device's long-term key may have leaked, revoke the device; healing won't help. This includes the pairwise post-quantum keys: someone who copied a device's state keeps them, and with a quantum computer could then pose as that device's contacts to it, until the device is revoked (which deletes them everywhere). |
| ❌ | **Encryption at rest** | The repo and keys sit unencrypted on every member's disk; the key database is readable by your user only. Use full disk encryption. |
| ❌ | **Protection from insiders** | Members can leak what they read, force-push, delete branches, block the repo with a conflict, stall it with log entries nobody can match, or lock others out by rotating its relay token. Force pushes are flagged (deleting a branch and recreating it elsewhere counts), not prevented, and adding a member is announced to everyone, including members who catch up after an absence. A new member trusts the first history it gets from someone who has been a member: a former member, with the relay's help, could hand them a stale or forked copy. |
| ❌ | **Retroactive revocation** | Removed members keep everything they already had. |
| ❌ | **Enforced disappearing log entries** | `git e2ee log-timer` deletes `git e2ee log` entries on schedule, but only on honest clients: a member can keep them (modified client, backups, screenshots). See "Disappearing log entries". |
| ❌ | **Commit authorship** | The author and committer shown by `git log` are free text that whoever creates a commit can set. Any member can push commits that claim to be written by someone else. Only *who pushed* is verified (`git e2ee log`). Signing commits would prove authorship, but would also give up deniability. |
| ❌ | **Privacy of commit metadata** | Author names, emails and timestamps are stored inside the commits every member receives. Use `e2ee.pseudonym` if that matters. |
| ❌ | **Push attribution before you joined** | `git e2ee log` entries from before you joined, or from while your device was offline for over two weeks, come from another member's own log and are only their word. The commits themselves (`git log`) still can't have been altered, though their authors are unverified as always. |
| ❌ | **Master key recovery** | Lose the device holding your master key and you need a new identity. |
| ❌ | **Independent audit** | Prototype; the protocol beyond libsignal is custom and unreviewed. |

Freshness checks assume reasonably correct clocks.

## What the relay knows

**Users**
- Stores which user IDs exist.
- Stores their public keys and devices, and when devices are added or revoked.
- Stores who is registered (on invite-only relays) and who is banned.
- Can't know names, emails or anything else about who a user is.
- Sees but doesn't store¹ your IP when you act as yourself (fetching your own mail,
  registering, getting your daily access tokens), and so when you're online and how
  active you are.

**Repos**
- Stores that each repo exists, as a random ID with no name.
- Stores how many log entries each repo has.
- Can't know a repo's name, files, branches or commits.
- Can't know what any log entry is (push, membership change or heartbeat).
- Can't know who creates, reads or pushes to a repo from the requests themselves (they
  are anonymous).
- Sees but doesn't store¹ the IP those requests come from.
- Can't know which user IDs are a repo's members. Repo traffic goes to random
  per-repo mailbox addresses that name no user and change regularly, so the mail after
  a push to R doesn't say who received it.
- Can estimate how many member devices a repo has, from how many mailboxes get mail
  after a push¹.
- Can guess who pushed¹: the IP that pushed also fetches its own user's mail under its
  user ID. That needs Tor to hide. Either way these are user IDs (random pseudonyms),
  never names or emails.
- Can't know a repo's size, but can estimate it from the encrypted uploads it sees¹.

**Mail**
- Mail is how devices talk to each other through the relay: every push, membership
  change, acknowledgement, heartbeat and invitation is an end-to-end encrypted message
  left in the recipient device's mailbox until that device fetches it.
- Stores encrypted mail waiting in each mailbox, and how much there is. Each device has
  a mailbox named by its user ID, used only for first contact (invitations and
  handshakes), and a random-address mailbox per repo for everything else. The random
  addresses are known only to that repo's members and change weekly and whenever
  someone is removed.
- Can't know whose a random-address mailbox is, or link one device's mailboxes for
  different repos, from what it stores. It's read with a secret, not by signing in.
- Stores, per message, only whether it arrived in the last 7 days or the 7 before
  (that's how it expires).
- Sees but doesn't store¹ delivered mail: the device deletes it once it has processed it.
- Can't know who sent a message (messages are sealed sender).
- Sees but doesn't store¹ the IP a message comes from.
- Can't know which repo a message belongs to.
- Sees but doesn't store¹ whether a message carried the recipient's anti-spam token,
  so whether the sender is an existing contact (not who).

**Blobs** (encrypted packs)
- Stores the encrypted data and its size.
- Can't know the contents.
- Can't know which repo a blob belongs to, but can guess from timing¹.
- Can't know who uploads or downloads a blob.
- Sees but doesn't store¹ the IP uploads and downloads come from.

**Timing**
- Sees but doesn't store¹ when each request happens.
- Doesn't store exact times for anything users do. The only exact times in the
  database are the operator's own: when each unused invite expires, and when the
  current 7-day expiry period started.
- Stores, as the only coarse time marks, which 7-day period a mailbox was last read
  in and a spent anonymous token was used in (that's how they expire), and each log
  entry's protocol version (which shows roughly when a repo's members upgraded).
- Keeps the nonces of signed requests from the last 15 minutes or so (to refuse
  replays, even across a restart), filed by which of four 5-minute slots they fall
  in. They name no user.
- Order of arrival: a database file would record it for large rows (SQLite puts
  them on new pages in write order), so mail and blob contents aren't kept in the
  database. They go into fixed-size slots of files next to it (`<db>.slots/`), each
  slot picked at random among the free ones, and a freed slot is overwritten with
  zeros. Where something is stored says nothing about when it came. New file space is
  written with zeros when the file grows, so writing a slot later changes no
  filesystem metadata. What remains:
  - the slot files only grow, so slots past an old end of a file were first used
    after it grew, and the files' size shows the busiest the relay has been;
  - the database's own small rows reuse SQLite's free pages in SQLite's fixed order,
    which can hint at how recently a mailbox's or blob's row was written;
  - all of this is what the files show. Overwriting doesn't erase on the storage
    itself: SSDs write every change to a new flash page and keep the old one until
    they reclaim it, hard disks can leave old data in remapped sectors, and
    filesystems, volume managers and cloud disks may keep their own copies
    (copy-on-write, snapshots, backups). So rewritten or zeroed rows and slots, and
    the order they were written in, can persist below the filesystem.

¹ Visible to the running relay but never written to its database. A malicious or
compromised relay can choose to record it. "Doesn't store" protects you if the database
is seized later, not against a relay that is misbehaving while you use it.

## Install

`git-remote-e2ee` and `git-e2ee` must be on your `PATH`; git then runs `git-e2ee` as
`git e2ee`.

### With Nix

The repository is a flake with two packages, `git-e2ee` (both client tools, the
default) and `git-e2ee-relay`:

```sh
nix profile install github:z44a/git-e2ee                  # git-e2ee and git-remote-e2ee
nix profile install github:z44a/git-e2ee#git-e2ee-relay   # only for running a relay
nix build github:z44a/git-e2ee#git-e2ee-relay             # just build it, into ./result
nix run github:z44a/git-e2ee -- --help                    # try git-e2ee without installing
```

From a checkout, use `.#git-e2ee` and `.#git-e2ee-relay` instead. Nix only sees files
git tracks there: `git add` new files first.

On NixOS, add the flake as an input and use its overlay (`pkgs.git-e2ee`) and module.
The module runs the relay as a hardened systemd service:

```nix
{
  inputs.git-e2ee.url = "github:z44a/git-e2ee";
  outputs = { nixpkgs, git-e2ee, ... }: {
    nixosConfigurations.relay = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        git-e2ee.nixosModules.default
        ({ pkgs, ... }: {
          nixpkgs.overlays = [ git-e2ee.overlays.default ];
          environment.systemPackages = [ pkgs.git-e2ee ];   # the client tools, if wanted here
          services.git-e2ee-relay = {
            enable = true;
            publicUrl = "https://relay.example";
            inviteOnly = true;
            contact = "abuse@example.com";
            # Behind a reverse proxy (the default: listens on 127.0.0.1:8470).
            # The proxy must offer the X25519MLKEM768 TLS group. Or built-in TLS:
            # listen = "0.0.0.0:443";
            # tlsCert = "/var/lib/acme/relay.example/fullchain.pem";  # quoted strings:
            # tlsKey = "/var/lib/acme/relay.example/key.pem";         # never copied to the store
            # Every relay flag has a typed option (null: the relay's default):
            # ttlDays = 14;
            # maxStorageGiB = 256;
            # policy = "...";                  # or policyFile = ./policy.txt;
          };
        })
      ];
    };
  };
}
```

Every relay flag has a typed option (`inviteOnly`, `ttlDays`, `maxStorageGiB`,
`ratePerSec`, `policy`, …; see `nix/relay-flags.nix` and `nix/relay-module.nix`), so
a wrong value fails when the configuration is evaluated, not when the service starts.
The relay's state lives in `/var/lib/git-e2ee-relay`. Issue
invites with `sudo -u git-e2ee-relay git-e2ee-relay --db /var/lib/git-e2ee-relay/relay.sqlite invite`.

### With Cargo

Linux is what's tested; macOS should work but isn't tested.

**1. Build tools.** You need a C compiler (for the bundled TLS library and SQLite),
`protoc` 3.12 or newer (protobuf, used by libsignal's build), and git:

```sh
sudo apt install build-essential protobuf-compiler git     # Debian, Ubuntu
sudo dnf install gcc protobuf-compiler git                 # Fedora
sudo pacman -S --needed base-devel protobuf git            # Arch
brew install protobuf git                                  # macOS (plus Xcode's command line tools)
```

`protoc` is found on your `PATH` (e.g. `/usr/bin/protoc`). Only if it's somewhere
else, set `PROTOC=/path/to/protoc`.

**2. Rust 1.95 or newer**, from [rustup](https://rustup.rs) if you don't have it:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup update stable        # if you already have it: make sure it's 1.95+
```

**3. Install.** `--locked` builds with the exact dependency versions this repository
was tested with:

```sh
cargo install --locked --git https://github.com/z44a/git-e2ee e2ee-helper   # git-e2ee and git-remote-e2ee
cargo install --locked --git https://github.com/z44a/git-e2ee e2ee-relay    # git-e2ee-relay, only to run a relay
```

The binaries go to `~/.cargo/bin`. rustup puts that on your `PATH`; if `git e2ee`
says "not a git command", add it (for bash: `export PATH="$HOME/.cargo/bin:$PATH"`
in `~/.bashrc`). Check with:

```sh
git e2ee --help
command -v git-remote-e2ee      # git runs this for e2ee:: remotes
```

To update, run the same `cargo install` again with `--force`; to remove,
`cargo uninstall e2ee-helper` (or `e2ee-relay`).

**From a checkout** instead:

```sh
git clone https://github.com/z44a/git-e2ee && cd git-e2ee
cargo install --locked --path crates/helper   # git-e2ee and git-remote-e2ee
cargo install --locked --path crates/relay    # git-e2ee-relay
```

(With Nix, `nix-shell` gives you a shell with Rust's build tools and `protoc` for this.)

## Quick start

**1. Set up each device** (once):

```sh
git e2ee init-user                          # creates your identity; prints your user code (e2eeu1:…)
git e2ee register https://relay.example     # add --token <token> if the relay is invite-only
```

**2. Verify your collaborators.** Both of you run this, and compare the safety number
in person or on a call:

```sh
git e2ee verify e2eeu1:<their user code> --name Alice   # the name stays on your device
```

**3. Create a repo** (SHA-256; for an existing SHA-1 repo see "SHA-1 repos" below):

```sh
git init --object-format=sha256 -b main project && cd project
git commit --allow-empty -m "start"
git e2ee repo init https://relay.example    # adds the remote "origin"
git push -u origin main
```

**4. Add a collaborator**, who has registered and been verified:

```sh
git e2ee member add e2eeu1:<their user code>
```

They clone with plain git:

```sh
git clone e2ee::https://relay.example/<repo id>
```

**5. Work as usual:** `git pull`, `git push`, `git push --force-with-lease`, and so on.

**Sync each repo at least every two weeks**, on every device. The relay keeps
undelivered mail and pushed packs for only 14 days by default (relay operators can
change this with `--ttl-days`). Any `git fetch`, `git pull` or `git push` in the repo
counts, as does `git e2ee sync`. A device that misses that window can't fetch what was
sent meanwhile. It asks the other members for the current state instead, and catches up
once one of them runs `git e2ee sync` in the repo. For a device you rarely use, a
scheduled job (cron, a systemd timer) that runs `git e2ee sync` in each repo avoids this.

## Your devices

Add a device (the codes must travel over a channel you trust):

```sh
new$    git e2ee device link                  # prints a link code
master$ git e2ee device approve <link code>   # prints an approval code
new$    git e2ee device finish <approval code>
new$    git e2ee register https://relay.example
master$ git e2ee send-history                 # inside each repo
new$    git clone e2ee::https://relay.example/<repo id>
```

If a device is lost or retired, revoke it from your first device (the *master
device*):

```sh
git e2ee device list
git e2ee device revoke <device id>
```

## Members

| Task | Command |
|---|---|
| Add someone (verify them first) | `git e2ee member add <user code>` |
| Remove someone | `git e2ee member remove <user code or id>` |
| List members and their devices | `git e2ee member list` |
| Limit how much mail someone you no longer work with can send you | `git e2ee rotate-delivery-token` |

**Inviting someone.** `member add` sends them the repo's history, and they run
`git clone` with the URL you give them. The relay keeps an invitation for at least a
week (up to two), so your device sends it again about weekly, whenever you use the
repo, until they've cloned; `git e2ee status` shows who hasn't yet. If their clone says
the history hasn't arrived, run `git e2ee member add <their code>` again: for someone
who hasn't cloned, it re-sends the invitation at once. Your device stops re-sending
after two months.

Any member can add or remove members. To leave a repo yourself, run `git e2ee repo leave`:
the other members are told, and the next one to sync rotates the repo secret, which cuts
you off from later pushes. (If you're the only member, it just forgets the repo on this
device.) To drop a repo from one device but stay a member, use `git e2ee repo forget`.

Your **delivery token** is only an anti-spam measure. Everyone you exchange messages
with learns it, and mail that carries it skips the relay's small daily limit for
strangers. It doesn't decrypt or authenticate anything: every message is still
end-to-end encrypted and checked as coming from a verified device. A leaked token only
means more mail can reach your mailbox. Rotating it moves people you no longer send
messages to back into the stranger limit; it doesn't block them completely. Rotation is
manual for now.

## All commands

| Command | Purpose |
|---|---|
| `init-user`, `whoami` | Create or show your identity and user code |
| `verify <code> [--name <name>]` | Compare safety numbers and trust a collaborator |
| `name <code or id> <name>` | Name a contact (only on this device); names are shown instead of user IDs |
| `register <relay> [--token]` | Make this device reachable on a relay |
| `device link / approve / finish / revoke / list` | Manage your devices |
| `repo init <relay> [--allow-sha1]` | Create a repo |
| `repo leave`, `repo forget` | Leave a repo (all your devices); drop it from this device only |
| `member add / remove / list` | Manage who is in a repo |
| `send-history` | Give your other devices a repo's current state |
| `sync` | Process pending messages without pulling |
| `log` | Who changed which branches, and membership |
| `log-timer <duration>` | Make `log` entries disappear after `30m`, `12h`, `7d`, `2w`… (`off` to stop), for every member |
| `status` | Sync state, and any detected **CONFLICT** |
| `clear-conflict` | Clear a conflict after investigating it |
| `rotate-delivery-token` | Replace your anti-spam delivery token (see Members) |

Repo commands work in the current repository (`--remote <name>` or `--url e2ee::…` to
choose another).

## Disappearing log entries

`git e2ee log-timer 1w` makes entries of `git e2ee log` disappear a week after they
happen, on every member's devices. Any member can change it, and the change goes
through the repo's log like a membership change, so everyone applies the same timer
from the same point on.

- **Each entry keeps the timer it was recorded under.** If the timer is a week, a
  push happens, and a day later someone sets it to one second, that push still
  disappears a week after it happened. Only entries recorded after the change get
  the new timer.
- **Who set the timer, and when, stays in the log** until someone sets it again; then
  the new notice replaces it. `git e2ee log` also shows the current timer at the top,
  and when each entry will disappear.
- `git e2ee log-timer off` stops entries from disappearing (again, from then on).
- Expired entries are deleted from a device's database (overwritten, not just
  unlinked) the next time git-e2ee runs there: a `git fetch`, `pull` or `push` on the
  remote, `git e2ee sync`, or `git e2ee log`. They aren't passed on to new members.

What it doesn't do:

- **A device that doesn't run git-e2ee doesn't delete.** Nothing deletes in the
  background: a laptop that's off, or a clone nobody syncs, keeps expired entries
  on disk until it next runs git-e2ee.
- **It relies on every member's client deleting honestly.** Nothing can force another
  device to forget: a modified client, a backup of the device's state, or a copy of
  its database keeps entries for as long as its owner wants. Screenshots, terminal
  scrollback and logs of `git e2ee log` output are out of reach too.
- It covers only `git e2ee log` (who pushed what). The commits themselves, with their
  authors, dates and messages, stay in everyone's repository like any git history.
- Your storage device is likely to retain deleted data. See section 5.18/5.19 of the
  [cryptsetup FAQ](https://gitlab.com/cryptsetup/cryptsetup/-/wikis/FrequentlyAskedQuestions)

## Conflicts

A conflict means your client caught the relay or a member presenting a history that
doesn't add up. It's raised when:

- the relay's log doesn't continue from the last entry you verified (a fork, or
  tampering), or contains an entry that isn't one;
- a push or membership change doesn't match the log entry it belongs to, or breaks the
  rules (malformed refs, the wrong set of recipients, a protocol downgrade);
- a member's messages show a different repo state or log than yours at the same point:
  the relay showed you different logs, or a member sent different people different
  versions of a push;
- members were given different access-token keys (the relay trying to recognize
  someone's anonymous requests).

What happens:

- That repo stops: push and fetch refuse, and `git e2ee status` says why. Your other
  repos are unaffected.
- Nothing is lost or changed. Your local commits and branches stay as they are, and
  your client has applied nothing it didn't verify.
- Nothing is resolved automatically, not even by history another member sends. A
  conflict means someone lied, and there's no honest way to pick which version is
  right.
- `git e2ee clear-conflict` forgets the conflict. Evidence that arrived only once
  (a member's acknowledgement or copy of a push) isn't kept, so if that was the
  cause, the conflict won't come back by itself: only clear it once you've compared
  with a collaborator.

What to do:

1. Run `git e2ee status` and compare its log position and head with a collaborator's,
   over a channel you trust (in person, a call).
2. If you see the same thing and the reason was something you've since dealt with,
   run `git e2ee clear-conflict`. This only removes the flag: if the cause is still
   there (the relay keeps showing a forked log), the next sync raises it again.
3. If it comes back, the relay or a member is still misbehaving. Remove the member if
   it's them. If it's the relay, there's no way to move a repo between relays yet:
   create a new repo on another relay (`git e2ee repo init`), push your local copy,
   and add the members again.

## Settings

Per repository (`git config`):

| Setting | Default | Meaning |
|---|---|---|
| `e2ee.allowSigned` | `false` | Allow signed commits and tags (they're proof of authorship) |
| `e2ee.pseudonym` | (none) | `Name <email>` your commits are expected to use |
| `e2ee.requirePseudonym` | `false` | Refuse pushes whose commits use another identity (a value that isn't a boolean is an error, never "off") |
| `e2ee.pushLog` | `true` | Keep the local log of who changed what. With it off nothing about refs is kept, so force pushes are still flagged but deleting a branch and recreating it elsewhere isn't recognised as one |

Environment:

| Variable | Meaning |
|---|---|
| `GIT_E2EE_HOME` | Where this device's keys and state live (default `~/.local/share/git-e2ee`) |
| `E2EE_RELAY_CA_FILE` | Extra CA certificate to trust for a self-hosted relay |
| `E2EE_MAX_STALENESS_SECS` | Warn after this long without hearing from collaborators (default 7 days) |
| `E2EE_MAX_PACK_BYTES` | Largest push you'll send or accept, as compressed pack bytes (default 4 GiB). Like plain git, nothing limits how much a pack expands when git unpacks it |
| `E2EE_MAX_CHUNKS` | Most chunks a push may have (default 1024): each costs you an access token to fetch |

## Running a relay

TLS is required (with post-quantum key exchange) for anything but localhost:

```sh
git-e2ee-relay --listen 0.0.0.0:443 --db relay.sqlite --public-url https://relay.example \
          --tls-cert fullchain.pem --tls-key privkey.pem
```

Or behind a reverse proxy that supports X25519MLKEM768:

```sh
git-e2ee-relay --listen 127.0.0.1:8470 --db relay.sqlite --public-url https://relay.example \
          --trust-forwarded-for
```

Operator commands (on the same database, while running):

```sh
git-e2ee-relay --db relay.sqlite invite            # registration token for one new user, valid 24h
git-e2ee-relay --db relay.sqlite invite --uses 5 --hours 72   # one token for up to 5 different users
git-e2ee-relay --db relay.sqlite ban <user id>     # and: unban <user id>
```

Use `--invite-only` to require tokens. `git-e2ee-relay --help` lists quotas and rate limits.

**Limits.** The relay caps request sizes per endpoint (refusing oversized bodies
before reading them), total waiting mail (`--max-mail-gib`), the number of mailboxes
(`--max-mailboxes`) and concurrent connections, in total and per address
(`--max-connections`, `--max-connections-per-ip`; IPv6 counts per /64). It speaks
HTTP/1.1 only, one request per connection, and drops clients that are slow: TLS
handshakes over 10 s, request headers over 10 s, request bodies that pause for 10 s
or average under 16 KiB/s, clients that stop reading the response for 30 s or read
it slower than 16 KiB/s, connections open over 35 minutes, and
requests over a minute (30 minutes for blob uploads). Mail costs an access token per
started 64 KiB. Blob uploads are charged before their body is read and are at most
32 MiB (`--max-blob-mib`, at most 63); uploads and downloads are streamed, not held
in memory or holding up the database. The storage files take at most
`--max-storage-gib` (default 128): a slot can be up to a quarter bigger than what it
holds, and the files never shrink, so keep this above the mail and blob quotas with
room to spare.
Mailboxes are read in pages of up to 4 MiB. New users and new devices cost no tokens
(they have none yet), so they're limited per address and hour and in total
(`--new-users-per-ip-hour`, `--new-devices-per-ip-hour`, `--max-users`,
`--max-devices`). Request rate limits count IPv6 per /64. Someone with a larger
block (a /48 from a tunnel provider) gets more /64s, so the totals are the real
bound.

What the limits don't do:
- Each anonymous-token budget is per user, not per device, but on an open relay
  identities are free, so it's really per identity. Use `--invite-only` if that matters.
- Budgets and the stranger lane are counted in memory only (storing them would record
  who was active when), so a relay restart resets them.
- Anyone can use up a device's stranger lane for the day (20 messages by default),
  delaying invitations and first handshakes to it until the next day.
- Connection slots can still be held for up to 20 s each without spending anything, so
  a large enough botnet can keep a relay busy. Availability isn't something this
  design promises.

**Behind a proxy.** Let the proxy terminate TLS and run the relay with
`--plaintext-behind-proxy --trust-forwarded-for` on a loopback `--listen` address. The
relay then rate-limits by `X-Forwarded-For`, but connections from loopback don't count
against the per-address connection cap, so the proxy should limit connections per
client itself. `--trust-forwarded-for` is refused with `--tls-cert` (a proxy can't add
headers inside TLS) and with a non-loopback `--listen`.

**Invites.** On an invite-only relay a new user's device list is stored only with a
valid invite, which that redeems: one use per new user (`--uses N` for an invite
several people share), and only the count of uses left is kept, nothing that links
users to it. You can turn `--invite-only` on later: users who already registered a
device keep working; only new ones need a token. Lists of users who never registered
a device expire.

**Policy.** `git e2ee register` shows users the relay's policy. By default it's a
repeat-infringer policy (the operator may ban users who repeatedly infringe others'
rights) with the address from `--contact abuse@relay.example`; without `--contact` it
says no contact address is published, and the relay warns at startup. Use
`--policy policy.txt` to serve your own text instead (up to 64 KiB of plain text).

## SHA-1 repos

Repos are SHA-256 by default. To bring an existing SHA-1 repo along unchanged, opt in
when creating it: `git e2ee repo init <relay> --allow-sha1`.

- The choice is recorded in the repo's member list and can't change later. Clones get a
  SHA-1 local repo automatically, and SHA-256 and SHA-1 repos can't push into each other.
- Every member's git must be built with SHA-1 collision detection (`SHA1_DC` in
  `git version --build-options`, the default for git). It refuses objects made with
  the known SHA-1 collision attacks.
- **The caveat:** a brute-force collision costs only about 2^80 work and isn't
  detected. A well-funded *member* could make two different commits with the same id
  and show different contents to different members without anyone noticing. Everything
  else (encryption, the log, attribution) is unaffected. Converting the repo to SHA-256
  (`git fast-export | git fast-import`) avoids this but changes every commit id.

## Upgrades

Everything is versioned, so newer builds can migrate without losing state:

- **Local and relay databases** record their schema version and migrate
  automatically when a newer build opens them. An older build refuses a newer
  database instead of misreading it, so roll back from backups, not by downgrading.
- **The protocol** has a version on every message, log entry, device list, repo and
  relay request. If you see "uses protocol version N … upgrade git-e2ee", a
  collaborator, the repo or the relay is newer than your build. Your state is kept;
  upgrade and retry. `GET /info` on a relay shows the versions it speaks.
- **Protocol 2 drops the prototype (protocol 1).** Repos made with a protocol 1
  build can't be opened by newer builds: push their contents to a new repo made
  with the new build, and have everyone clone that. See `CHANGELOG.md`.
