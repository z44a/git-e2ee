# git-remote-e2ee: design and security notes

This is the detailed companion to the [README](../README.md): how each property is
achieved, the threat model, every limitation we know of, and implementation notes. It
is written for reviewers and contributors.


A git remote helper that makes a git remote **end-to-end encrypted, forward-secret,
post-compromise-secure, post-quantum-confidential and deniable**. The server (the
*relay*) is untrusted: it stores ciphertext, a hash-chained commitment log and sealed
mailboxes, and learns nothing about repository contents, file names, ref names,
commit metadata or who sent what.

```
git clone e2ee::https://relay.example/3f9c…a1      # just git, after a one-time setup
```

> **Status:** an unaudited prototype. It uses [libsignal] outside Signal, which
> upstream does not support, and its own cross-signing and replication layers have not
> been reviewed. Don't rely on it for anything that matters yet.

[libsignal]: https://github.com/signalapp/libsignal

## Design in one picture

```
          Alice (pusher)                        relay (untrusted)                  Bob, Carol, … (each device)
 ┌──────────────────────────────┐      ┌──────────────────────────────┐     ┌──────────────────────────────┐
 │ git pack-objects --thin      │      │                              │     │                              │
 │ K = random 256-bit key       │ blob │ blobs:   XChaCha20(K, pack)  │     │ fetch blob, check SHA-256(C) │
 │ C = XChaCha20-Poly1305(K, …) ├─────►│                              ├────►│ == H, decrypt with K,        │
 │ H = SHA-256(C)               │      │ log:  seq │ commitment │ head │     │ git index-pack --strict      │
 │ view = H(seq, H, refs,       │ CAS  │          hash chain, CAS     │     │                              │
 │   roster, recipients, prev…) ├─────►│                              ├────►│ check view == log entry      │
 │                              │      │ mailboxes (per device):      │     │                              │
 │ per device: Double Ratchet   │ mail │   sealed-sender ciphertexts  │     │ Ack{seq, view, head} to all  │
 │  {K, H, refs, view} ─────────┼─────►│                              ├────►│ members (ratchets + gossip)  │
 └──────────────────────────────┘      └──────────────────────────────┘     └──────────────────────────────┘
```

* **Bulk data:** each push is one packfile encrypted *once* with a fresh random key and
  Padmé padding.
* **Everything security-relevant:** the pack key, the pack hash, the refs and the view
  travel over **pairwise libsignal sessions** (PQXDH + the triple ratchet with ML-KEM),
  wrapped in sealed sender. libsignal's sender keys / group APIs are deliberately not
  used: they sign messages (not deniable) and have no post-compromise security.
* **Commitment log:** the relay keeps an append-only, hash-chained log of `view` hashes.
  Appends are compare-and-swap on the previous head, which also orders pushes. Every
  receiver checks that what a member told them matches what the log says.
* **Cross-signing:** each user has a master key that signs a versioned list of their
  device keys. Members pin each other's master keys after comparing **safety numbers**,
  and libsignal is only allowed to open sessions with devices in a valid signed list.
  The relay can't add devices.
* **No server-side history:** the relay is a mailbox. New members and new devices get
  the current state as a *history bundle* sent by an existing member. Blobs and pack
  keys are deleted once every recipient has acknowledged them.

## Threat model

| Adversary | Assumed capabilities |
|---|---|
| **Relay operator** | Reads, stores, drops, delays, reorders, replays and forges anything it handles; can show different members different data; can collude with members. |
| **Network observer** | Sees all traffic, including TLS metadata. |
| **Malicious member** | A legitimate member trying to forge other members' pushes, equivocate, or keep others from noticing. |
| **Future quantum adversary** | Records traffic today, decrypts it later with a quantum computer. |
| **Device thief / one-time compromise** | Copies a device's key material once (and possibly its disk). |

The user's own devices, while uncompromised, and the people they verified safety numbers
with are trusted.

## Cryptographic properties we uphold

**Confidentiality.**
- File contents, paths, commit messages, author identities, ref names and object ids
  are hidden from the relay and the network.
- The end-to-end tests dump every byte the relay stores and check for plaintext,
  ref names and commit ids.

**Post-quantum confidentiality.**
- Session keys come from PQXDH (X25519 + Kyber/ML-KEM-1024). Ongoing messages use
  libsignal's triple ratchet, which mixes in a post-quantum (SPQR) ratchet.
- Kyber prekeys are mandatory in every bundle.
- Packs use 256-bit symmetric keys, which leaves about 128-bit security against Grover.
- Recording traffic today doesn't help a future quantum attacker.

**Deniable authentication.**
- No message is signed: pairwise messages are authenticated with MACs from the Double
  Ratchet.
- Sealed-sender certificates are signed by a throwaway key that proves nothing.
- The pack's AEAD key is known to every recipient, so its tag proves nothing either.
- A recipient knows who pushed, but can't prove it to anyone else.

**No insider forgery.**
- Pack keys are shared with every recipient, but the pack's ciphertext hash is pinned
  inside the *pairwise* MAC-authenticated envelope.
- Another member therefore can't substitute a different pack "from Alice".

**Prekey hygiene.**
- Each device rotates its signed EC prekey and its last-resort Kyber prekey every
  `E2EE_PREKEY_ROTATE_SECS` (default 7 days) and republishes them to every relay it uses.
- Superseded prekeys are kept for `E2EE_PREKEY_GRACE_SECS` (default 14 days, counted from
  when they stopped being current, not from when they were created), so first
  messages that were already in flight still decrypt, and are then deleted. This bounds
  how long a stolen prekey can decrypt delayed session-setup messages.
- Sessions prefer one-time EC *and* one-time Kyber prekeys, which are deleted on first
  use. The last-resort Kyber key is only used when they run out, and a replayed
  session-setup message for it is rejected.
- **Prekeys can't be drained.** Fetching a bundle costs an anonymous access token
  (registered devices only, see below), and the relay hands out one-time keys at most
  `--max-one-time-handouts-per-hour` (default 20) times per device per hour. Past that,
  bundles carry only the signed and last-resort keys, so an attacker can force
  fallback sessions but can't burn through a device's supply.
- If a first message names prekeys the recipient already deleted (it was delivered after
  the grace period), the recipient asks for a resend. The sender then retires its
  session with that device and opens a fresh one from the current bundle.
  - Without this, resends would keep naming the deleted prekey. libsignal's tiebreak
    between the two sides' sessions is random, so about half the time it would keep
    the broken one.
  - Resets are rate-limited per peer device (`E2EE_SESSION_RESET_SECS`, default 1 hour),
    so resend requests can't be used to drain the peer's one-time prekeys.
- The grace period trades delivery against forward secrecy:
  - Sessions set up with one-time prekeys lose nothing.
  - Sessions that fell back to the signed and last-resort Kyber prekeys stay decryptable
    by anyone who steals the device during the grace period.
  - The default (14 days) matches the relay's default mail TTL. If you raise
    `--ttl-days`, raise the grace period to match.

**Forward secrecy of relayed data.**
- Pack keys are deleted after import.
- Pushers delete blobs and their copy of the key once every recipient has acked, or
  after `E2EE_OUTBOX_TTL_SECS` (default 14 days, the relay's mail lifetime) even if some
  device never did. One dead device can't make a pusher keep its pack keys forever.
- Ratchet message keys are deleted by libsignal.
- Ciphertext an attacker recorded can't be decrypted with keys stolen later.

**Post-compromise security (for session state, not identity keys).**
- Every sync that applies entries sends one cumulative ack (views chain, so an ack for
  the newest entry confirms all earlier ones), and heartbeats and gossip run on a
  schedule. All are ratchet messages, so sessions heal after an attacker briefly copies a device's *session
  state*, even on devices that never push.
- Every push uses a fresh random pack key that isn't derived from anything else.
- This does **not** cover theft of a device's *identity private key* (the key in its
  user's signed device list). With it, plus the relay's help, an attacker can start
  new sessions as that device, which peers accept because the key is genuinely listed.
  They can also provoke a session reset (withhold mail, which leads to a resend request
  and a fresh bundle from the relay) and serve a bundle signed with the stolen key.
  Ratcheting never heals this. The only remedy is **revoking the device** (and linking
  a new one), which removes the key from the signed list. Theft of the master key is
  worse still (it can add devices), and the device-change notices are what reveal it.

**Integrity.**
- Content addressing uses **SHA-256 object ids** by default. A repo can opt in to
  SHA-1 at creation (`repo init --allow-sha1`). The format is recorded in the roster
  (`Roster.object_format`), roster changes can't alter it, and object ids are checked
  against it (40 or 64 hex digits). For SHA-1 repos every client requires a git with
  SHA-1 collision detection (SHA-1DC), which catches the known cryptanalytic
  collision attacks but not a generic birthday attack (about 2^80 work). A member who
  pays for one can make two commits share an id and equivocate about what a ref
  contains, undetected, because views commit to ids. Encryption, the log, views and
  device lists use SHA-256 regardless.
- Packs are imported with `index-pack --strict`.
- Every push must build on the previous verified view.
- Ref names and object ids from other members are validated before they reach git or
  the remote-helper protocol. Ref names must follow git's rules (`git check-ref-format`),
  sit under `refs/` and contain no control characters (so no line injection); object ids
  must be 64 lowercase hex digits; and HEAD must name a ref in the push. A history
  bundle's refs must point to objects that actually arrived.

**Envelope sizes reveal little.**
- Every pairwise envelope is padded to a size bucket before encryption: powers of two
  from 1 KiB to 64 KiB, then multiples of 64 KiB. Acks, heartbeats, gossip, resend
  requests and pushes of up to roughly 20 refs are the same size. More refs or longer
  names only move a push up a bucket.
- Cover messages copy the size of the real copy, so they match too.

**No roster leak through device-list fetches.**
- Clients don't routinely fetch members' device lists from the relay. Fetching every
  member's list next to the repo's log fetch would tell the relay who is in the repo.
- Lists travel in-band instead:
  - with every sealed message;
  - inside pushes and roster changes (the lists the author computed recipients from);
  - inside history bundles.
- The relay is asked only when you add a member (to get the newcomer's list) or send
  history to your own devices.

**Signed requests are bound to one relay.**
- Every request signature covers the **origin the client connected to**: scheme, host
  and port, taken from the relay URL and authenticated by TLS. Nothing the relay says
  about itself goes into it.
- Each relay checks signatures against its own configured `--public-url`, never the
  `Host` header, which a replaying relay controls.
- So a malicious relay can't replay a device's signed requests to another relay where
  the same device is registered (for example to obtain access tokens on its budget or
  delete its mail). An earlier design signed a relay-reported identity, which a
  malicious relay could simply report as another relay's.
- Every signed request also carries a random **nonce**. The relay records it after
  verifying the signature and refuses repeats within the time window, so a request
  captured where TLS ends (a reverse proxy, a CDN) can't be replayed to the same relay
  either. Seen nonces are stored, so a restart doesn't reopen the window, but only
  while a request with that nonce could still be accepted: each is filed under which
  of four 5-minute slots its request's time falls in, and the slot two away from now
  (holding only requests too old to accept) is cleared on every request. The table
  holds about 15 minutes of nonces whatever the traffic, and no user or time. Requests signed before the relay started are also
  refused.

**Equivocation detection.**
- A member can't tell different members different things about the same push.
- Each envelope's `view` must match the single view the log commits to at that seq.

**Split-view and fork detection.**
- If the relay shows members different logs, it is caught in three ways:
  - the hash chain;
  - members' acks, heartbeats and gossip, which carry their view and log head;
  - copies of entries arriving through the mailbox that don't match the log.
- Every device gossips its log position by mail at most every `E2EE_GOSSIP_SECS`
  (default 4 hours), with no log entry. It skips devices it already messaged in that
  interval (acks and pushes carry the same information). A member who never pushes
  still reveals a fork or a hidden entry within that interval of both sides syncing.

**Rollback protection.**
- Device lists are versioned and hash-chained; old or forked versions are rejected.
  They keep a tombstone for every revoked device (with the versions it was added
  and revoked in), and device ids are never reused, so a peer served v3 without v2
  still learns a device came and went.
- The log is hash-chained, and each device remembers its head.

**Hybrid post-quantum signatures.**
- The master key is a pair: a Curve25519 key and an ML-DSA-87 key (FIPS 204,
  libcrux). Device lists carry both signatures over the same domain-separated input,
  and verifiers (clients and the relay) require both.
- The **master id** is the classical key followed by `H("git-e2ee/v1/pq-key",
  ML-DSA key)`, 65 bytes. It is what peers pin and what user codes contain, and the
  user id is its hash. The full ML-DSA key (2592 bytes) travels with each device list
  and must hash to the pinned value. Safety numbers use libsignal's fingerprint over
  the classical key with the user id as stable identifier, so they commit to both.
- Each device also has an ML-DSA-87 key. Its hash is in the device entry (so link
  codes grow by 32 bytes) and the full key is uploaded at registration. The relay
  only accepts it if it matches the master-signed list, and requires both a
  Curve25519 and an ML-DSA signature on every authenticated request.
- Sessions: libsignal authenticates with Curve25519 device identity keys only and
  has no post-quantum signatures, so messages get their own post-quantum
  authentication (next section). Signing inside sessions with ML-DSA would break
  deniability, so that layer is KEM- and MAC-based.
- Not covered: TLS certificates and the VOPRF access tokens are classical (a quantum
  attacker could forge tokens and so evade rate limits; token anonymity holds
  regardless).
- Cost: each device list grows by about 7.2 KB (key plus signature), and because
  the sender's list rides in every sealed message, so does every message. Each
  authenticated request carries a 4.6 KB signature header.

**Post-quantum message authentication** (`core/src/pqauth.rs`).
- Each device has a long-term Kyber1024 *authentication key* (libsignal's own KEM,
  the one PQXDH uses). Kyber1024 is the round-3 submission ML-KEM-1024 (FIPS 203)
  grew out of. This libsignal also has ML-KEM-1024, but marks it as possibly changing
  incompatibly, so we use the version it treats as stable. Its hash is in the device entry, so the hybrid-signed list
  binds it; the full key is in the device's prekey bundle and in its handshake init.
- Every pair of devices runs a handshake once:
  - A → B `INIT`: handshake id, A's KEM key, `ct_B = Encaps(B's key)`.
  - B → A `RESP`: `ct_A = Encaps(A's key)`, `MAC(K, "resp")`.
  - `K = HKDF(ss_B ‖ ss_A, salt = id, info = H(both devices, both KEM keys, both
    ciphertexts))`.
- Every later message is a `DATA` frame: the payload encrypted with
  XChaCha20-Poly1305 under a per-direction key derived from K, with sender,
  recipient, handshake id and protocol version as associated data, inside the
  libsignal plaintext. Delivery tokens in handshake frames are sealed the same way
  under their own purpose strings, so neither can pass for the other. The frame's
  protocol version is bound everywhere it matters: in that associated data, in K's
  derivation (the init's version) and in the response MAC.
  The receiver rejects anything that doesn't decrypt under a key it holds for that
  device.
- Why it authenticates *and* keeps messages confidential: only the real B can
  decapsulate `ct_B`, only the real A `ct_A`. An attacker who can pose as A to
  libsignal (a quantum computer that recovered A's Curve25519 key) can send an init
  with A's public KEM key, but B's response encapsulates to A, so the attacker
  can't compute K. Such an init can also make B's libsignal session to A the
  attacker's (libsignal adopts a new session from a PreKey message); encrypting
  under K is what keeps B's messages unreadable then. Posing as B fails the same
  way at the response MAC.
- Limits: a forged init can still make B send under a key the real A doesn't have,
  or put B's libsignal session to A in the attacker's hands until a real message
  from A replaces it. Both are denial of service, not disclosure; A's own
  handshake attempts recover. Handshake ids are 16 random bytes and can't be
  reused, so an init can't overwrite an existing key. A device gets at most one
  answered init per half hour (an honest one retries hourly), and at most eight
  unconfirmed keys are kept per device: a flood of inits from a peer's device costs
  us one key, one answer and one session reset per half hour, not one each.
- Healing: an impostor's inits can still push a real unconfirmed key out (or take
  the half-hour slot first). The real initiator then sends under a key we don't
  have. A data frame under an unknown handshake marks the device as owed a
  handshake, and our next sync starts one, which only the real device can answer,
  so our key is confirmed by its real response. We send under it from then on (the
  newest confirmed key); it confirms the key on its side when our first message
  under it arrives, and switches too. Until a message from it decrypts again, its
  messages under older keys are expected, not another loss, so they don't restart
  anything: the heal is driven by events, not timers. Any message that decrypts
  ends the wait (after simultaneous handshakes it may keep using another key we
  have), and the bookkeeping goes with the device's keys when it is removed,
  rekeyed or unpinned. The mark never stops us sending; a
  forged message under a random handshake id costs us one (rate-limited)
  handshake. Messages lost meanwhile are recovered by the engine's resend requests.
  While the impostor keeps going, first contact can be delayed (denial of service,
  nothing more).
- K is identity-grade: it never rotates while both devices exist. Rotating it alone
  wouldn't heal anything, since a compromise that leaks K leaks the devices' KEM
  secret keys from the same database too. Healing needs new device keys, which is
  what revoking a device does; a revoked device's pairwise keys are deleted by
  everyone who sees the new device list. Nothing zeroizes key material in memory
  (keys at rest are out of scope).
- Why it stays deniable: K is symmetric and both ends hold it, so either could
  have produced any message; there is nothing an outsider can verify.
- Replays: the encryption binds direction, payload and handshake, not a counter.
  Replaying a genuine message needs control of the libsignal session (so a broken
  Curve25519 key) and only works within the same pair; the engine's messages are
  idempotent (keyed by log sequence, acks cumulative), so a replay changes nothing.
- Latency: B trusts A's messages only after A answered B's challenge, so the first
  messages between two devices wait. They wait in the sender's outbox, not
  unauthenticated in the receiver's inbox. Messages that arrive under a handshake
  we started, before its response, are held and applied once it arrives. To keep
  this rare, handshakes start eagerly:
  - on `git e2ee verify`, with the verified user's devices (this fetches their
    device list from the relay, without saying who asks);
  - on `git e2ee init-user`, `device finish` and `register`, with our own other devices;
  - on every sync, with member devices we have no key with.

  What remains: a new member's or device's first push to someone waits until that
  person has synced once, then reaches them after the newcomer's next sync.
- An init is only classically authenticated: anyone able to pose as the sender to
  libsignal (the attacker this layer exists for) can send one. So the responder's key
  from an init stays *unconfirmed* until a valid MAC arrives under it. It never
  displaces a confirmed key for sending (a forged init can't break traffic that
  already works). The init's delivery token is used only if we have none for that
  user yet (first contact); it never replaces a known one, which only MAC-checked
  frames can do. That leaves a window on first contact: an attacker who can pose as
  A to libsignal could give B a delivery token of its choosing for A, so a colluding
  relay could recognize B's mail to A by it, until A's first authenticated message
  replaces it. It reveals who B writes to, not what.
  Response frames are MAC-checked first, so their delivery token is trusted at once.
- If the receiver has no confirmed key with the sender, an init also retires its
  libsignal session with the sender: the init means the sender has no working state
  with us, and our session could name prekeys it has deleted. With a confirmed key it
  doesn't, so forged inits can't keep resetting sessions.
- Handshake frames are padded to 4 KiB and carry the sender's delivery token.

**Versioning and upgrades.**
- *Protocol version* (`e2ee_proto::PROTOCOL_VERSION`, currently 2; a build accepts
  `MIN_PROTOCOL_VERSION..=PROTOCOL_VERSION`). It is carried by:
  - every device-to-device frame (`PqFrame.version`), which covers the envelope
    inside. It's the newest version both devices speak (ours, capped at what the
    peer's signed device entry says it supports), so a device running a newer build
    keeps talking to older ones until they upgrade too; a pending handshake keeps
    the version its init carried, which the key derivation binds;
  - every log entry (`LogEntry.version`; the only one the relay can see, and the
    same for everyone). It's the repo's protocol (`Roster.protocol`), not the
    writer's build, so a member running a newer build writes what everyone can
    read; the roster change that raises the protocol is itself written at the old
    one;
  - device lists (`DeviceListBody.protocol`), and per device the newest version it
    supports (`DeviceEntry.max_protocol`);
  - the repo's roster (`Roster.protocol`): the version the repo's members use;
  - every relay request and response (`x-e2ee-protocol` header). Requests without
    one, or with one the relay doesn't speak, are refused with a message naming
    both versions. `GET /info` lists the relay's range.
- A relay newer than the build stops with an "upgrade git-e2ee" error (nothing is
  discarded), and a history bundle for a newer repo stays in the inbox without
  blocking others. A log entry claiming a version other than the repo's is a
  conflict at once: older is never valid, and newer can't come from an honest
  member while we're one, since the protocol only rises once every member device,
  this one included, supports the new version. So a relay can't turn a fork into
  an endless "upgrade" note. The entry's version is part of its log commitment.
- A roster change raising the protocol is accepted only if every member device's
  signed device list says it supports the new version. This device's own entry
  says what this build supports, so a raise beyond it can't be valid: it's a
  conflict naming the member, not an endless "upgrade" stall. The roster hash
  covers the protocol and object format, so a raise can't be shown to some members
  only.
- A member device that can't speak the repo's protocol (an old build, added after
  an upgrade) is reported once ("can't take part until it runs a newer
  git-e2ee") rather than failing silently.
- How a future version would be rolled out: devices first advertise it in
  `max_protocol` (by publishing a new device list). Once every member device does, a
  member switches the repo with a roster change that raises `Roster.protocol`, and
  from that log entry on everyone writes the new format. Roster changes can't lower
  it, so a member can't force a downgrade.
- Codes carry their own version (`e2eeu1:`, `e2eed1:`, `e2eea2:`), and every
  domain-separation string contains `v1`. A new version that changes a hash or
  signature input gets new strings, so nothing signed under one version verifies
  under another.
- *Database schema version*: SQLite's `user_version`, for both the device database
  and the relay's (`e2ee_proto::migrate`). Migrations are an ordered list; opening a
  database applies the missing ones, each in its own transaction with its version
  bump, so a crash leaves a well-defined version. A database newer than the build is
  refused untouched. Released migrations are never edited, only appended to.

**Catching up after a long absence.**
- Undelivered mail and packs expire on the relay after 14 days, and senders stop
  holding pushes for a device that long unreachable. A device offline longer finds
  log entries whose messages and packs are gone; resend requests can't help.
- After being stuck at an entry for `E2EE_HISTORY_AFTER_SECS` (default an hour) it
  sends a **history request** to every other member device, and repeats it every
  interval until it catches up.
- **Claims.** A member answering first appends a *claim* entry: like a heartbeat it
  commits to the unchanged view (kind `CLAIM`), so any device, newcomers included,
  can apply it from the log alone, and bundles can be checked against it. The
  entry's nonce is `H(repo, seq, claimant, target, salt)`, and a `HistoryClaim`
  announcement tells members the salt, so they can check who claimed for whom and
  nobody can attach a false announcement to another's entry. The log's
  compare-and-swap makes the claim a lock: one member uploads the full pack, not all.
  Other members stand down while a claim is fresh (`E2EE_CLAIM_SECS`, default an
  hour). Claims appear in the push log as "sent history to …".
- **Claims that never deliver.** A claim counts as failed once it is older than the
  claim interval while the target still hasn't acknowledged anything past it.
  Members ignore claims by someone who already failed that device, a failed claimant
  waits an extra interval before claiming again, and the stuck device lists
  claimants that didn't deliver in its next request, so they can't claim for it.
  Claims only coordinate: the stuck device accepts any valid bundle, claimed or not.
  So one dishonest member delays catch-up by one claim interval and leaves a visible
  trail, in line with the insider abuse the design already doesn't prevent.
- **Accepting the bundle.** A device with existing state takes a bundle only if it
  asked for one, the sender is a current member, the roster doesn't change the
  object format, downgrade the protocol or roll back, and the relay log shows the
  device's own last verified head at its position with an unbroken hash chain from
  there to the bundle's position. A bundle can therefore not move a device onto a
  fork. While catching up it never replaces members' mailbox addresses or
  delivery tokens it already knows.
- **Every bundle proves its state.** It carries the last push and every roster
  change after it; the receiver recomputes their views, which must chain from the
  push (or the zero view of a new repo) to the bundle's view, and the bundle's refs,
  default branch and roster must be the ones those views commit to. So no sender
  can pair the real view with refs or members of its own choosing. What remains
  the sender's word is the *push log* for the skipped entries (who pushed what in
  between), marked "according to <member>".
- There's no daemon: requests are answered whenever a member next syncs the repo, which
  is why the client tells the stuck user to ask another member to run `git e2ee sync`.
- **Recognising a long absence.** Each device records when it last synced each repo,
  and the relay reports how long it keeps mail (`mail_ttl_secs` in `GET /info`). If
  the last sync is older than that, the client says so, asks for history at once,
  and doesn't count the silence as a possible freeze attack: the staleness clock
  starts again from when the device came back.

**Opaque log entries.**
- The relay stores only `{seq, prev_head, nonce, commitment}` per entry, where
  `commitment = H("git-e2ee/v1/log-commit", repo_id, seq, kind, view, nonce)` and the
  nonce is random. Pushes, membership changes and heartbeats look identical and have
  the same size; even a heartbeat over an unchanged view gives a fresh commitment.
  Entries carry no timestamps.
- Members recompute the commitment: from the matching envelope for pushes and
  membership changes, from their own current view for heartbeats. A mismatch is
  treated like a mismatching view.
- Limit: an entry that commits to something no member can match (for example a
  heartbeat over a forked view) isn't flagged immediately. It shows up as a missing
  envelope (resend requests, then a withholding warning), and the fork itself is still
  caught through log-head gossip.

**Ghost-device resistance.**
- Sessions are gated on a cross-signed device list under a pinned master key
  (`is_trusted_identity`).
- Device lists from the relay that are unsigned, tampered with or rolled back are
  rejected.
- Senders commit to the full recipient set they believe in (`recipients_hash`), and
  receivers check it against their own verified lists. This catches members who were
  *misled* about the device set, for example by stale or injected lists. It does **not**
  stop a member who deliberately encrypts to extra devices while claiming the honest
  set; a malicious member can always leak plaintext anyway.

**Device revocation without re-verification.**
- The master key signs a new list without the lost device.
- Safety numbers are computed over master keys, so they don't change.

**Device additions are never silent.**
- Devices signed by a pinned master key are trusted automatically; that's the point of
  cross-signing. It also means a compromised master device could add an attacker's
  device unnoticed.
- So every change to a known device list is recorded and shown once on the next sync:
  "user … added device 3 (device list v4); if they did not do this, their master device
  is compromised".
- Changes to your *own* user made by another device are flagged the same way.
- `git e2ee member list` shows every member's devices and device-list version.

**Newcomers don't take device lists from the relay.**
- A history bundle carries every member's current signed device list. A new member's
  first view of everyone's devices comes from the member who added them, never from the
  relay, so a relay serving stale lists can't make them encrypt to a revoked device.

**User ids are bound to master keys.**
- A user id is the hash of its master key, and every place that pins a key enforces it
  (verification, rosters, history bundles), as does storing a device list under a user.
  A malicious inviter can't bind a real person's user id to their own key.

**Push log: who changed which refs.**
- Every member's client records, for each log entry it applies, the time, **who made
  it** (user and device) and what changed: refs created, moved or deleted, or members
  added and removed. `git e2ee log` shows it.
- The pusher's identity comes from the pairwise authenticated session the entry arrived
  on, so the relay can't alter it and a member can't pass off a push as someone
  else's. All members record the same pusher for each entry.
- Every recipient gets the same envelope bytes, so a member could otherwise forward
  someone else's push (say, while the relay holds the author's own copy back) and be
  credited. The author's user and device are therefore part of the push's (and
  roster change's) view, and must equal the authenticated sender. A forwarded copy is
  ignored rather than treated as a conflict, and the entry waits for the author's own
  copy (a resend request asks for it). This stays deniable: the author is
  authenticated pairwise, never signed.
- **Force pushes are marked.** A ref that moves to something that doesn't contain its
  old value is logged as `FORCED`, with the number of commits no longer reachable from
  it, and other members get a warning on sync ("user … force-pushed refs/heads/main (2
  commit(s) no longer reachable from it)").
  - They aren't blocked. The relay can't see refs, so the only fast-forward check is
    the one in the pusher's own client (`git push` refuses non-fast-forwards unless you
    force). A modified client could skip it.
  - Your old commits stay in your local repo and reflog either way.
- It's a local record, not a signature: it convinces you but proves nothing to anyone
  else (deniability holds).
- Entries from before you joined come from the inviter's own log in the history bundle
  and are marked `[according to <member>]`, naming the member they came from (by the name you gave them, if any): that's their word, not something you witnessed.
- Recording can be turned off per repo with `git config e2ee.pushLog false`. Whoever
  seizes a member's device learns who pushed what, which is more precise than commit
  metadata.

**Only members can act in a repo.**
- Acks, heartbeats, gossip and resend requests are processed only from devices of the
  repo's current members, and push or roster envelopes only from members of the roster
  at that point in the log. Removed members (still pinned, sessions intact) can't
  trigger conflicts or warnings.
- A resend, which carries the pack key, goes only to a device that was an original
  recipient of that entry and is still a verified device of a current member.

**Device-list updates the relay can't hide.**
- Every sealed message carries the sender's current master-signed device list, in the
  sealed-sender layer (libsignal's otherwise unused `group_id` field). The recipient
  reads it before the inner message, verifies it against the pinned master key, and
  adopts it if it's newer.
- A relay that keeps serving an old list therefore can't hide a revocation. It would
  try that to keep members encrypting to a stolen device. The revocation reaches each
  peer with the next message from any of the user's devices.
- A relay also can't keep a new device from being recognized: the device's own messages
  introduce it.
- The relay can only delay the user's mail, which shows up as missing acks and the
  withholding warnings.

**Membership changes are logged.**
- Adds and removals go through the log like pushes.
- Removal rotates the repo secret and the relay delivery token.
- Removed members can't read new pushes.
- A device catching up through a history bundle (after a long absence) announces
  members added in the entries it skipped, and rotates its mailboxes after any
  membership change in them (someone may have been removed and re-added, which the
  rosters alone don't show).
- A history bundle never applies while the repo has a conflict: the conflict stops
  the repo until the user clears it, whatever arrives.

**Disappearing push-log entries** (`git e2ee log-timer`).
- The timer is a roster field (`Roster.log_ttl_secs`), so setting it is a roster
  change through the log: any member can, every member applies it at the same log
  position, and the roster hash covers it (only when set, so rosters without one
  keep the hash they had).
- Each push-log entry gets its own expiry when it's recorded: its authenticated
  send time plus the timer in effect at its position in the log. Later changes
  never move it. The entry recording a timer change is the timer's notice instead:
  it never expires, and the next change's notice replaces it.
- Expired rows are deleted on every sync and every `git e2ee log` (there's no
  background process: a device that doesn't run git-e2ee keeps them until it does), with SQLite's
  `secure_delete` on and the write-ahead log emptied afterwards. History bundles
  carry only unexpired entries, each with its expiry.
- Enforcement is the clients' honesty, nothing more: a member's device can keep
  anything it was shown.

**Invitations are re-sent until taken up.**
- A newcomer who hasn't cloned can't ask for history the way a member who fell
  behind does: it has no roster, repo token or mailbox addresses yet. So the device
  that ran `member add` keeps the invitation pending, per invited device, and on
  every sync re-sends a fresh history bundle (the current state, not the original
  one) once the last copy is 6 days old, before the relay can expire it
  (`E2EE_INVITE_RESEND_SECS`). It deletes the previous copy's blobs, so the relay
  holds one copy at a time.
- A device counts as joined once it has acknowledged the log or otherwise been heard
  from in the repo; then the invitation is forgotten. So is one for a device or user
  that's no longer in the roster. After 60 days (`E2EE_INVITE_GIVE_UP_SECS`) it stops,
  with a note.
- The first copy may have expired together with our half of the post-quantum
  handshake, and the newcomer's device holds messages under that key until the reply
  arrives. So a re-send also re-queues our handshake reply (kept until the key is
  confirmed), or starts a new handshake if we have no key with that device.
- `member add` for someone already in the roster who hasn't cloned re-sends at once.
  Only the inviting device re-sends on its own, so there are no duplicates and no
  claims are needed; if it stops syncing, the newcomer asks to be re-added.

**A repo's id proves which repo a roster is for.**
- The repo id is `repo_id_for_token(delivery_token(genesis_secret))`, from the repo's
  first secret, and every roster carries that genesis secret (it never changes, and
  the roster hash covers it). A device bootstrapping or catching up from a history
  bundle checks it against the id in its clone URL.
- The relay only ever sees the token derived from it, so a contact who was never a
  member can't pass off a repo of its own as this one, even with the relay's help.
  A former member knows the genesis secret, so a former member plus the relay could
  still hand a newcomer a stale or forked copy (insider risk, as below).
- Each sender can have at most 1000 envelopes waiting for one repo in a device's
  inbox, so one contact (say, a removed member who still knows a mailbox address)
  can't fill the repo's share and crowd out the members. Envelopes from people who
  still aren't members after the inbox TTL (14 days) are deleted. A real member
  pushing more than that during a long freeze has the excess dropped; resend
  requests recover it once the log moves again.
- A push's refs are checked by name only if they're new or changed, so a ref
  accepted under older rules can't make every later push fail; deleting one is
  always allowed. A history bundle's refs are checked for syntax only (a newcomer
  can't tell old refs from new); one our rules refuse (say, an old replace ref) is
  kept in the repo state, so members' pushes still match it, but the helper never
  shows it to git.

**Token rotation is part of the log append.**
- A repo has exactly one relay token. A rotation is the membership change's log
  append itself, carrying the hash of the new token (`x-e2ee-replace-token`); the
  relay swaps the token in the same step, under the same compare-and-swap check. There
  is no other way to add or change a token.
- So a rotation happens exactly if its append wins. If two members rotate at once,
  the loser's change never takes effect; it is told to fetch and retry, and finds the
  new secret in the winner's membership change. Nobody is left holding a token the
  relay no longer accepts.
- There is never a second, planted token that could outlive a rotation: whatever
  token the last append set is the only one. (Who may set it is the insider risk
  under "Known gaps".)
- The remover saves the new secret before appending, so a crash after the relay
  accepted the rotation loses nothing. The relay swaps the token and appends the
  entry in one database transaction, so a crash there can't leave the repo without a
  token either. Members who haven't applied the change yet read the log with the
  secret from the change waiting in their inbox.
- A device that never gets that change (it was away past the mail TTL, or the relay
  dropped it) finds that the relay accepts none of its tokens. It can't tell this
  from being removed, so it says both, sends a history request at once (as after a
  long absence; repeated at most every 5 minutes, `E2EE_HISTORY_REPEAT_SECS`) and
  carries on with the rest of the sync. A member answers with a
  history bundle carrying the current roster and secret. A removed device gets no
  answer, because members only answer devices in their roster.
- **Known gaps.**
  - Leaving and device revocation rotate the token later: on the next sync of a
    remaining member (or the revoking user's devices), not in the same append. Until
    then the leaver or the revoked device still holds a valid token. It can read the
    log and append, but new pushes are already encrypted only to the new roster's
    devices. It can also rotate the token itself in that window (see the next
    point), locking the remaining members out.
  - The relay can't tell what kind of entry an append is, so any member's append can
    rotate the token. A member doing this out of turn, with a secret only it knows,
    locks everyone else out of the repo for good: only it could hand them the new
    secret. The others still have their clones and can recreate the repo without it.
    This is the same kind of insider risk as a member pushing junk, which the design
    already accepts.

**Relay abuse controls.**
- A device can register prekeys only if it appears in its user's master-signed device
  list, which the relay checks. Nobody can squat device slots or mailboxes for another
  user.
- New repos are capped relay-wide per hour (`--max-new-repos-per-hour`). There is
  deliberately no per-user count, since that would require knowing who created what.
- Quotas cover:
  - pack size;
  - total stored blob bytes on the relay;
  - mail size and mailbox depth (mailboxes are read in pages of at most 4 MiB);
  - one-time prekeys per device;
  - new users and new devices per address (IPv6: /64) and hour, and in total: they
    cost no access tokens, because they have none yet.
- Clients bound what they accept from the relay too: every response has a size
  limit, a chunk can't exceed what's left of `E2EE_MAX_PACK_BYTES`, and a push has
  at most `E2EE_MAX_CHUNKS` chunks (each costs every receiver a token).
- **Payloads record no arrival order** (`relay/src/slots.rs`). SQLite puts large rows
  on new overflow pages in write order, which would show which mail and blobs
  arrived together. So payloads live outside it, in per-size-class files (four
  classes per doubling, 4 KiB to 64 MiB, so a slot wastes at most a quarter), each
  in a slot picked uniformly at random among the free ones; the database keeps a
  small row naming the slot (class, index, a random tag, length). The default pack
  chunk (15.5 MiB) seals to just under 16 MiB, so it fills a 16 MiB slot.
  - A file grows by half (at least 16 slots, at most 256 MiB at a time) only when
    none is free, up to a cap on all slot files together (`--max-storage-gib`),
    reserved before growing so classes growing at once can't pass it. Growing
    doesn't hold the class (only allocations in it wait). The new region is written
    with zeros at once, so a later write only overwrites the file in place: no
    allocation and no unwritten-extent conversion for the file's metadata to record.
    Growth is visible: slots past an old end were first used after the file grew.
  - This works at the level of the files. Overwriting doesn't erase on the storage
    itself: SSDs write every change to a new flash page and keep the old one until
    they reclaim it, hard disks can leave old data in remapped sectors, and
    filesystems, volume managers and cloud disks may keep their own copies
    (copy-on-write, snapshots, backups). So rewritten or zeroed rows and slots, and
    the order they were written in, can persist below the filesystem.
  - Freeing clears the slot's tag at once, so no reader gets the payload after
    that, but keeps its length as a mark that it still needs zeroing; a background
    thread zeroes the body, flushes, then clears the header and flushes again (so a
    crash or out-of-order writeback never leaves a clean-looking header over an old
    body), and only then makes the slot reusable, so no request waits for it. The tag guards readers: a download from a slot freed
    meanwhile fails instead of serving another payload.
  - No payload I/O happens while holding the database, nor on the async runtime's
    workers: mail is written to its slot and flushed, and its row inserted, in one
    blocking task that finishes or cleans up after itself even if the client goes
    away (its bytes are counted against the mail total first, so
    concurrent posts can't pass it; the per-mailbox message count can be passed by
    the posts in flight at that moment), mailbox pages are read after the rows
    are fetched, uploads and downloads go to and from the slot directly, and an
    upload holds no row until it is complete and on disk. Two uploads to the same
    blob id with different delete tokens: the second to finish is refused.
  - Crashes: writes are flushed before their row is committed. Opening the store
    scrubs every slot no row refers to whose header isn't all zero: a tag (written
    but never recorded) or a length alone (freed but not yet zeroed). A row whose slot turns out not to
    hold it (its write never reached the disk) is deleted when found.
  - This replaced an hourly `VACUUM`, which paused the relay and left the last
    hour's order on disk.
- The relay rate-limits requests per client IP with a token bucket. Clients back off
  and retry on HTTP 429.
- **Invite-only registration** (`--invite-only`). The operator issues registration
  tokens (`git-e2ee-relay invite`, valid 24 hours by default, for one new user, or up
  to N with `--uses N`), and a new user's first device must present one, when its
  master-signed device list is first stored. That takes one use (the last one deletes
  the invite), so an invite for N makes at most N identities, and the relay keeps
  only the count left, nothing that links users to it. Later devices of the same user need none. Identities
  are free to create, so this is what stops a banned spammer from coming straight back
  under a new identity.
- **Bans** (`git-e2ee-relay ban <user id>`). The user's device registrations and prekeys are
  deleted, they're refused from then on, and the access-token key is rotated
  immediately, so every outstanding token (theirs included) dies. Everyone else's
  clients just obtain new ones. Since every write (mail, blobs, mailbox creation, log
  appends) costs a token, a banned user can't send or push anything through the relay.
  What they keep, by design: reading their own pseudonymous mailboxes (the relay can't
  tell whose they are; without tokens they can't download blobs, and the mailboxes
  expire once nobody writes to them) and reading logs of repos whose token they know,
  until members remove them. On an open relay they can come back under a new identity;
  `--invite-only` prevents that. Tokens are bearer and unlinkable, so another user can
  give them some, limited by that user's own budget.
- There is deliberately no reporting feature. Messages are deniable, so a report
  couldn't prove anything anyway. Operators act on what members tell them.

**Repo membership hidden from requests.**
- Each device has a **user-id mailbox** on a relay (`/mailbox/{user}/{device}`, read
  with a device-signed request), shared by all its repos and used for **first
  contact** only: post-quantum handshakes, invitations' history bundles, and mail to a
  device whose repo address we don't know yet. The repo id exists only inside the
  encrypted envelope, and clients file mail by it locally.
- Repo traffic goes to **pseudonymous mailboxes**: each device creates one per repo,
  a random 16-byte address (`/pmail/{id}`) plus a 32-byte secret, created anonymously
  with an access token. The relay stores only the address and the secret's hash.
  - Every envelope a device sends for a repo carries its current address for that
    repo (`Envelope.reply_mailbox`), and history bundles carry every member device's
    (`HistoryBundle.mailboxes`), so newcomers use them at once. Only devices that
    receive the repo's envelopes learn them.
  - Posting needs the address and an access token; reading and deleting need the
    secret, sent on an anonymous connection. Nothing ties the mailbox to a user or a
    device, or one device's mailboxes for different repos to each other.
  - Addresses rotate weekly (`E2EE_MAILBOX_ROTATE_SECS`) and whenever a member is
    removed, since the removed member knows them. A retired address is still read
    until undelivered mail to it would have expired (the outbox's 14 days), then
    deleted. Mailboxes nobody reads expire on the relay like mail. A sender whose
    address is gone gets "not found" and falls back to the user-id mailbox.
  - Forgetting or leaving a repo retires its mailboxes, so members' mail for it falls
    back to the user-id mailbox, where it's dropped as for any repo the device isn't in.
  - Cover traffic goes to the sender's own pseudonymous mailbox, so it still looks like
    the real copies.
  - What's left: a push is still followed by mail to N mailboxes, which estimates a
    repo's device count, and live traffic can tie a mailbox to the repo whose log the
    same IP just read. The IP that reads a pseudonymous mailbox also signs requests
    with its user id (token issuance, its user-id mailbox), so without Tor a running
    relay can link them by IP. What changes is that the fan-out no longer *names* the
    recipients' user ids, and stored data links nothing.
- Anonymous actions (mail, blobs, prekey bundles, mailboxes, log appends) are paid for with
  **anonymous rate-limited access tokens** (see below). They show that *some* registered
  device paid; they name neither the sender nor the repo.
- **No creation step.** A repo's log comes into existence with its first append, paid
  for with access tokens and nothing else; the repo token presented then becomes the
  log's token. The relay never learns or stores who created a repo. A log that doesn't
  exist yet just reads as empty.
- **Repo ids are bound to the repo secret.** The id is a hash of the first repo token,
  and the relay only creates a log if the token presented hashes to its id. Someone
  who learns a repo's URL before its first push can't claim it.
- **One global blob store.** Packs are stored under random ids, independent of any
  repo, and uploaded and downloaded with access tokens. Deleting one needs a token
  derived from that pack's key, so only members who can read a blob can delete it.
- So no request ties a device to a repo:
  - mailbox reads name a device but no repo;
  - log requests name a repo but no device (only its shared repo token);
  - blob requests and posts name neither.
- A **seized relay database** shows which users exist and which opaque logs exist, with
  their activity, but nothing connecting the two. The tests check that the repo-side
  tables contain no user id.

**Anonymous rate-limited access tokens** (Privacy Pass style; VOPRF, RFC 9497, over
ristretto255).
- A device obtains tokens by sending *blinded* random nonces in a device-signed request,
  and the relay evaluates them under the day's key. The relay sees which device asks and
  how many tokens it takes; each device gets `--access-tokens-per-day` (default 5000).
- Every anonymous action spends tokens:

  | Action | Cost |
  |---|---|
  | delivering mail | 1 per started 64 KiB |
  | fetching a prekey bundle | 1 |
  | downloading a blob | 1 |
  | uploading a blob (charged from `Content-Length`, before the body is read) | 1 + 1 per MiB |
  | creating a repo log | 5 |
  | every later log append (push, membership change, heartbeat) | 1 |
  | creating a pseudonymous mailbox | 1 |

  Rotating the repo token (on removal, leaving, or revoking a device, which knew the
  token) happens inside a log append; see "Token rotation is part of the log
  append" above.
  Later appends also need the repo token, which shows the appender is a member; the
  access token shows the relay currently lets them act. Without it, a banned member
  could keep writing to repos it was in until members removed it. An append that
  loses the compare-and-swap race isn't charged.

  The relay recomputes each token with its key and records it as spent; a reused token
  is refused.
- **The relay can't link a spent token to the device it issued it to.** At issuance it
  only saw r·H(n) for a random secret r, which is statistically independent of the
  nonce n it later sees spent. This holds even against a quantum computer. (Forging
  tokens, by contrast, needs only classical discrete log.)
- So abuse is bounded **per registered identity**, not per IP: an abuser with a botnet
  still has one device's budget, and invite-only registration limits how many
  identities they get. That holds even for abuse that can't be attributed, like filling
  blob storage or creating junk repos. A ban ends it within the token lifetime (at once,
  in fact: banning rotates the key).
- The relay must use one key for everyone; a key of one device's own would let it
  recognize that device's "anonymous" tokens when spent. Two checks:
  - *Locally:* the issuance proof must verify under the key the client fetched without
    authenticating, over a connection of its own (no pooling, no TLS session reuse).
    This alone isn't enough: the fetch comes from the same IP, so a relay that wants to
    can recognize it and answer with the tagging key too.
  - *Across members (the real check):* every envelope reports a hash of each key its
    sender was given for the current and previous day, per key *generation*. Members
    compare those reports with their own keys over the authenticated, end-to-end
    channel the relay can't fake, the way they compare log heads. A different key for
    the same day and generation is a conflict. So is a generation the relay, asked
    anonymously, says doesn't exist yet, because the relay invented a rotation for one
    device. Detection needs the tagged device and at least one other member to exchange
    mail. Both sides then flag it: the tagged device sees members' reports, and members
    see its report.
  - *What it can't catch:* members only compare with co-members. A relay can give a
    whole group of collaborators (say, everyone in one repo) a key of their own under
    the same generation number; nobody sees a mismatch, and every token they spend
    then reveals which group spent it, linking anonymous repo creation, uploads and
    bundle fetches to that set of people. Detecting this needs comparison outside the
    group, such as keys published in a transparency log or gossiped across unrelated
    users.
  - *Generations:* a ban rotates the key mid-day. Each rotation gets a public,
    increasing generation number (`GET /token-key/{day}?gen=N` returns any past
    generation's key), so honest rotations look the same to everyone and aren't
    conflicts. A client that sees a new generation drops its tokens of older ones (they
    were voided); it checks at most every 15 minutes. A generation going backwards is
    treated as tagging.

**Delivery tokens (who can reach you).**
- Each user has a secret delivery token, shared by its devices (it travels in the
  approval code). The relay stores only a hash of it.
- Contacts learn it in-band: every envelope carries the sender's current token, and
  history bundles carry those of the members the inviter knows.
- Mail presenting the recipient's delivery token goes into the normal lane. Mail
  without it can only use a small **request lane** (`--request-lane-per-day`, default 20
  per device). That's enough for invitations, but a stranger can't flood you even with
  valid access tokens.
- `git e2ee rotate-delivery-token` replaces yours (after a leak, or to cut off a former
  collaborator). Current collaborators learn the new one from your next message, which
  the command sends right away.

**Sender hiding toward the relay** (application layer only; see the limits below).
- Mail is sealed-sender: the relay sees the destination mailbox, not the sender.
- Deliveries are paid for with anonymous access tokens and addressed with the
  recipient's delivery token, which all its contacts share. Neither identifies the
  sender.
- **Cover traffic.** Every time a device sends anything, it also mails its *own*
  mailbox. Otherwise the relay could name the sender of any fan-out as the one device
  that got nothing.
  - The cover message is a genuine sealed-sender envelope (fresh ephemeral key, real
    certificate inside) addressed to the device's own identity key, wrapping random
    bytes.
  - It is sized exactly like a real copy of the same envelope, and dropped silently on
    receipt. No session with oneself is involved.
- **Every device acks every entry, including its own**, so "the one device that didn't
  ack" doesn't name the author.
- Deliveries in a batch go out in a random interleaving (order per recipient is kept),
  so cover mail isn't always last.

**Dead devices don't cost anything.**
- Deliveries to a device that keeps failing (never registered, deregistered, or with a
  full mailbox) back off exponentially: 1 minute, 2, 4, …, at most a day. No tokens are
  spent on it in between.
- Undelivered mail expires after `E2EE_OUTBOX_TTL_SECS`.
- The client reports such a device once a day: "device 3 of user … has been
  unreachable for 2 days; if it's gone, its owner should revoke it". It does the same
  for devices not heard from in `E2EE_SILENT_REPORT_SECS` (default 7 days).
- The relay checks everything that could reject a request (unknown device, full
  mailbox or request lane, missing blob, full storage, creation cap) **before**
  spending the caller's tokens, so rejected requests cost nothing.

**Large repos and pushes.**
- Packs and history bundles stream out of `git pack-objects` in 15.5 MiB chunks
  (`E2EE_CHUNK_BYTES`; sealed, one fills a relay's 16 MiB storage slot). Each chunk is encrypted with its index and an "is last" flag
  bound in (so chunks can't be reordered, dropped or the pack truncated) and stored as
  its own blob.
- The authenticated `pack_hash` commits to every chunk's hash, in order.
- Receivers verify and decrypt one chunk at a time straight into `git index-pack`.
  Neither side holds more than about one chunk in memory, and repo size isn't limited
  by the relay's per-blob cap.
- Receivers refuse packs whose decrypted size exceeds `E2EE_MAX_PACK_BYTES` (default
  4 GiB).
- A relay that fails to serve a chunk causes a retry on the next sync, not a conflict.
  Only bad data (wrong hash, failed decryption, rejected objects) counts as misbehaviour.

**Freshness (freeze detection).**
- The client warns when **no other member device has been heard from**, through
  authenticated pairwise mail (pushes, acks, heartbeats, gossip), for
  `E2EE_MAX_STALENESS_SECS` (default 7 days).
- "Heard from" uses the **authenticated send time** inside each envelope (stamped when
  it was encrypted, capped at our clock), not the arrival time. A relay that holds a
  peer's mail back and releases it later can't make it look fresh. Mail that arrives
  more than `E2EE_MAX_DELAY_SECS` (default 6 hours) after it was sent is reported as
  possibly delayed by the relay.
- Log entries deliberately don't count. They're authenticated only by the repo token,
  which the relay holds, so a relay could fabricate heartbeat entries or accept the
  victim's own heartbeats on a fork to make a frozen log look fresh. The device's own
  activity doesn't count either.
- If the relay refuses our heartbeat append but then shows no newer entries, the client
  warns immediately: the log it shows us isn't the one it appends to.
- It also warns when members report entries the relay hasn't shown us.

**Transport security (TLS required).**
- Content is protected end to end regardless. TLS exists so that the relay's powers
  stay with the relay alone and aren't shared with everyone on the network path. Those
  powers are:
  - the bearer tokens: the repo token, which can read a repo's ciphertext and
    append to (and so rotate) its log; delivery tokens, which reach a user's normal lane; and access
    tokens, which pay for anonymous actions;
  - replaying device-signed requests within their 5-minute window, for example
    deleting mail before it is read;
  - every id and access pattern in URLs.
- The client refuses `http://` relays except on loopback (127.0.0.0/8, `::1`,
  `localhost`), and never follows redirects.
- TLS 1.3 only, with the **hybrid post-quantum key exchange X25519MLKEM768 required**
  by both the client and the relay's built-in TLS. A classical-only peer is refused, so
  recorded traffic (tokens, ids) can't be decrypted later by a quantum attacker.
  Certificates are still classical, as everywhere on the web today.
- The relay refuses to serve plaintext on a non-loopback address unless told a TLS proxy
  terminates in front of it.
- TLS does nothing against the relay itself, which by design sees all of the above.

**Crash safety.**
- Decrypting a message and persisting its plaintext happen in one SQLite transaction.
- Sends go through an outbox.
- Our own entries are persisted before appending and fanned out on recovery.
- An exclusive lock stops concurrent processes from forking ratchet state.

## What we do *not* uphold

**Attribution of misbehaviour.**
- Deniability cuts both ways: we *detect* equivocation and split views, but nobody can
  cryptographically *prove* which member (or whether the relay) did it.

**Availability.**
- The relay can drop everything or refuse service to anyone. We make it visible
  (resend requests, warnings, conflicts); we can't prevent it.

**Instant freeze detection.**
- A relay that drops all mail to a device and freezes its log is only noticed once the
  staleness bound passes, or when some member's mail gets through.
- The warning can't distinguish an attack from everyone simply being offline for that
  long.

**Instant split-view detection.**
- Log heads cross between members only through acks, heartbeats and gossip. A fork is
  detected once one side's mail reaches the other: within the gossip interval (4 hours
  by default) of both syncing, not immediately.
- A relay that drops *all* mail between two members keeps them apart indefinitely; only
  the staleness warning remains.

**Sender anonymity against a traffic-analysing relay.**
- Cover traffic makes every mailbox receive the same mail, but the relay still sees
  *connections*. The pusher appends to the log, uploads the blob and posts all the mail
  in one burst from one IP.
- The same IP usually also reads that device's mailbox, and mailbox reads are
  device-authenticated. Linking the two names the sender.
- Timing patterns (a burst after a log append, then everyone fetching) allow
  statistical disclosure even across separate connections.
- Real sender anonymity needs separate unlinkable connections for authenticated reads
  and anonymous posts (Tor or a mixnet, separate circuits) plus randomized delays. None
  of that is implemented.

**Network metadata.**
- The relay and the network see IP addresses, timing, push frequency, approximate sizes
  (Padmé padding of packs and bucketed envelopes leak only coarse size classes), how many
  devices get mail, and which mailbox belongs to which device.
- Setting up a new pairwise session fetches that device's prekey bundle. That's rare,
  but it happens next to the repo's other requests, so it can hint at who a client is
  working with.
- There's no Tor or mixnet support.

**Repo membership privacy toward a traffic-analysing relay.**
- No request names both a device and a repo, but one client makes both kinds of request,
  from one IP, in one burst. So the relay can link "device X read its mailbox" with "repo
  R's log was fetched".
- The relay always sees each mailbox's volume and timing, and the extra traffic of a
  device gaining a new collaborator.
- Each log's entry count is stored (the relay must know which entries form one chain),
  though not which entries are pushes, membership changes or heartbeats. Stored rows
  carry no timestamps; blobs and undelivered mail only record their expiry generation
  (which half of the 14-day lifetime they arrived in). SQLite's write-ahead log would
  keep rows in arrival order, so the relay checkpoints it (emptying it) after every
  write request.

**Post-quantum authentication of the relay connection and of rate limits.**
- Device lists, safety numbers, relay request signatures (ML-DSA-87) and messages
  (ML-KEM handshake plus MACs) are post-quantum authenticated.
- TLS certificates are classical: a quantum attacker could pose as the relay toward
  the network and learn what the relay sees anyway.
- The VOPRF access tokens are classical: a quantum attacker could mint them and get
  past rate limits. Their anonymity holds regardless. Practical post-quantum
  anonymous tokens don't exist yet.

**No replace refs.**
- `git replace` makes git show another object wherever an existing one appears,
  without changing any hash. A member pushing `refs/replace/<commit>` could change
  what an already-verified commit shows (message, author, content) to anyone who
  fetches that ref (with `clone --mirror` or a `refs/*` refspec), and every hash check
  would still pass.
- So `refs/replace/` is refused: when pushing (before anything is sent) and in what
  members receive. The default refspec never fetches replace refs anyway, so this
  costs normal use nothing. History that needs grafting can still be rewritten
  properly and force-pushed.

**Deniability of git metadata.**
- Commits carry author and committer names, emails and timestamps.
- The helper refuses signed commits and tags by default (`e2ee.allowSigned` overrides
  this), including merge commits that embed a signed tag (`mergetag`) and signed tags
  nested inside unsigned ones (every tag object in the push is checked, not just those
  at ref tips), signatures in either OpenPGP armor (`PGP SIGNATURE` or `PGP
  MESSAGE`), and objects hidden behind replace refs (git runs with
  `GIT_NO_REPLACE_OBJECTS=1`, so the check reads exactly what the pack carries). It
  can enforce a pseudonym (`e2ee.pseudonym`, `e2ee.requirePseudonym`) on authors,
  committers, taggers and the taggers of merged tags; `requirePseudonym` without a
  pseudonym is refused rather than silently checking nothing.
- Push-log entries received from other members are checked (valid ref names and
  object ids) and printed without control characters, so they can't fake or hide
  terminal output.
- Writing style, content and timing still identify people.

**Deniability of possession, and coercion resistance.**
- The plaintext repo and the helper's state live on every member's disk.
- Anyone who can force someone to unlock a device gets everything.

**Forward secrecy against device compromise.**
- A device keeps the full plaintext history in `.git` and in its mirror repo.
- FS protects relayed ciphertext, not what's on disk.

**Secure deletion on real storage.**
- "Deleted" keys may survive in SQLite's WAL/freelist, filesystem journals, SSD wear
  levelling, swap and backups. Backups or sync of the state directory (Time Machine,
  Dropbox, …) cancel FS and PCS entirely.
- This is an explicit non-goal of this prototype.

**Instant revocation.**
- A peer stops encrypting to a revoked device once it hears from any of the owner's
  remaining devices, or gets the new list inside a push, roster change or history bundle
  from another member. Syncs never ask the relay for device lists; the relay is only
  asked during `member add` and `send-history`.
- `git e2ee device revoke` immediately syncs every repo the master device is in, so the
  new list goes out at once. If the relay withholds that mail, the revoked device can
  still receive new pushes until something gets through.

**Protection against what recipients do.**
- Members can always leak plaintext or keys.
- Removed members keep everything they already had.

**Trusted time.**
- Ordering comes from the log. Commit timestamps are whatever the author wrote.

**An admin model.**
- Any member can add or remove members.
- Members added by someone else are trusted transitively; `git e2ee member list` shows
  who you verified yourself.

**Safety against malicious content.**
- A member can push anything (huge packs, hostile objects). Strict `index-pack` and
  size limits are the only defence.

**Protection from a current member faking a conflict.**
- A member can send an ack claiming a different view. That's indistinguishable from the
  relay showing members different logs, so it's recorded as a conflict and blocks the
  repo until it's cleared. The conflict message names whose report caused it.

**Unlinkability of access tokens against traffic analysis.**
- The cryptography hides which device a spent token came from. Metadata may not:
  - **The anonymity set** is every device that obtained tokens that day or the day
    before. On a relay with few users, that's little cover.
  - **IP and timing.** Tokens are always obtained in batches of exactly 100, and a
    reserve of 300 is topped up at the start of each sync, apart from the actions that
    spend them. A shortfall is never requested as "exactly what this upload needs",
    which would let the relay match a device-signed issuance to an anonymous upload by
    count. Every request that isn't device-signed (token-paid, repo-token or public)
    goes over a fresh connection of its own: no pooling, no HTTP/2 multiplexing, no
    TLS session reuse. So the relay can't tie a spent token to the device that just
    signed in on the same connection. The same IP address still does both, and an
    upload bigger than the reserve forces refills while it's in progress.
  - **The key-consistency check** relies on members. A device's own anonymous key
    fetch comes from the same IP as its signed requests, so a relay can serve a
    recognized device its tagging key both times. Comparing keys between members
    catches that (see "Anonymous rate limiting"), but only once the tagged device and
    another member exchange mail. A user with no collaborators on the relay, or tokens
    spent before that exchange, aren't protected, and a key shared by a whole group of
    collaborators isn't caught at all. A full fix needs a separate network path (Tor)
    and keys published in a transparency log.
- How many tokens a request spends reveals roughly how big an upload was, not who made
  it.

**Invitations can be crowded out.**
- Anyone with access tokens can fill your 20-message daily request lane, delaying
  genuine invitations (first contact goes through it) until the next day. That's
  bounded by their token budget, and bannable.

**Correct clocks.**
- Freshness and delay warnings compare the sender's clock with ours. A peer whose clock
  runs days slow can trigger false "not heard from" or "delayed" warnings. A fast clock
  is capped at ours and harmless.

**Spam protection from co-members.**
- Everyone you share a repo with holds your delivery token and their own access-token
  budget, so they can fill your mailbox up to its quota. Rotating your token doesn't
  help against someone still in a shared repo, since your messages to that repo give it
  to them. Removing them from the repo, or an operator ban, does.

**Full token hygiene against removed members.**
- Before being removed, a malicious member can register extra *repo* tokens of its own.
  These survive the removal unless the remaining members revoke them, which they can
  only do if they know them.
- Such a token only reads the repo's log, which is ciphertext and metadata: no keys,
  and no new plaintext. The member also still holds the other members' delivery tokens,
  so it can mail them until they rotate (`git e2ee rotate-delivery-token`), which now
  does cut it off, since it no longer receives their messages.
- A malicious *current* member can revoke the shared token and lock everyone out. Like
  everything a member can do to availability, this can't be prevented without an admin
  model.

**Assurance.**
- The cross-signing, replication and relay code are unaudited.
- libsignal is pinned to a tag commit but used in a way upstream doesn't support.

## Safety numbers

`git e2ee verify` shows the safety number between two users in three encodings of the
same fingerprints. Each person's fingerprint is libsignal's: 5200 iterations of SHA-512
over their **master key** and user id, so it doesn't change when devices are added or
revoked.

| Encoding | Per person | Total | Notes |
|---|---|---|---|
| QR code | 256 bits | 512 bits | Strongest; scan it when you are together. |
| 60 digits (12 blocks of 5) | ≈ 99.7 bits | ≈ 199 bits | Signal's format: each 5-digit block is 40 hash bits mod 100 000. |
| 20 BIP39 words (10 per person) | 110 bits | 220 bits | Easiest to read aloud. |

```
Or as words (the same order on both sides):
  them:  eyebrow only quality rose copy reopen ride mixture wolf able
  you:   paddle service hybrid view option trick correct pledge upgrade mixture
```

**Why 10 words.**
- A BIP39 word carries 11 bits. Ten words (110 bits) is the smallest count that is at
  least as strong as Signal's 30 digits per person (≈ 99.7 bits); nine words would be
  99 bits.
- An attacker who wants to pass verification has to find a key whose fingerprint
  matches a specific value. That's a second-preimage search, with each guess costing
  5200 SHA-512 iterations (about 2¹²), so it costs about 2¹²² hashes for 110 bits.
- 8 words (88 bits) would still be out of reach, at about 2¹⁰⁰ hashes. We chose
  parity with Signal over brevity.

**How the words are made.**
- The words are the first 110 bits of each person's 256-bit fingerprint, read as ten
  11-bit indexes into the [BIP39 English list]. The list is checked against its
  well-known SHA-256 in the tests.
- The BIP39 *mnemonic algorithm* (checksum, seed derivation) is not used; the list is
  only an alphabet.
- The two groups are shown in a canonical order (smaller fingerprint first) and
  labelled `you`/`them`, so both people read the same sequence.

**Tradeoffs we accepted.**
- *Errors in comparison affect usability, not security.*
  - A misread, misheard, swapped or skipped word almost always just causes a false
    mismatch, and people read again.
  - For an error to turn an attacker's key into an apparent match, the attacker's
    fingerprint would have to sit exactly one human mistake away from the real one.
    Accepting every "one mistake away" variant costs only about 4–5 bits.
  - So we don't use the PGP word list's even/odd scheme, which detects transpositions
    and omissions, at 8 bits per word, about 13 words per person.
  - BIP39 words are unique in their first four letters and avoid near-duplicates, but
    they were chosen for writing down, not for being distinct when spoken. Read slowly
    on calls, or use the QR code.
- *The real risk is partial comparison.*
  - If people check only the first few words, the attacker only has to match those:
    4 words is 44 bits, which is feasible.
  - Compare **all** words, both groups, or scan the QR code.
  - The digits and the words come from the same fingerprints, so they are alternatives,
    not independent checks; comparing both adds no security.
- *Post-quantum.* Safety numbers commit to both halves of the hybrid master key
  (Curve25519 and ML-DSA-87): the user id, a hash of the master id, is the
  fingerprint's stable identifier. Matching numbers therefore also rule out a
  substituted ML-DSA key.

[BIP39 English list]: https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt

## Install

libsignal's build needs `protoc`. On Nix: `nix-shell`; otherwise install protobuf and
set `PROTOC`.

```sh
cargo install --path crates/helper   # git-remote-e2ee and git-e2ee
cargo install --path crates/relay    # git-e2ee-relay
```

`git-remote-e2ee` must be on `PATH` for git to find it.

## Usage

Everything below assumes `git-e2ee`, `git-remote-e2ee` and (for operators) `git-e2ee-relay`
are on `PATH`. Git finds the helper by name: a remote URL starting with `e2ee::` makes
git run `git-remote-e2ee`.

### Concepts in one paragraph

You are a **user**, identified by a **master key** created on your first device
(device 1, the *master device*). Every device has its own keys, and the master key signs
the list of your devices. People trust each other by comparing **safety numbers** once;
after that, devices you add are trusted automatically. A **repo** lives on a **relay**,
an untrusted server that stores only ciphertext. Its URL looks like
`e2ee::https://relay.example/<repo id>/<name>`. Day-to-day work is plain `git push` / `pull`;
`git-e2ee` is only needed for identity, devices and membership.

### 1. Run a relay (operator)

TLS is required for anything but loopback. Either terminate TLS in the relay itself:

```sh
git-e2ee-relay --listen 0.0.0.0:443 --db /var/lib/git-e2ee-relay/relay.sqlite \
          --public-url https://relay.example \
          --tls-cert /etc/git-e2ee-relay/fullchain.pem --tls-key /etc/git-e2ee-relay/privkey.pem
```

or put it behind a TLS reverse proxy that offers the post-quantum key exchange
X25519MLKEM768 (for example Caddy built with Go ≥ 1.24, or nginx with OpenSSL ≥ 3.5),
and keep the relay on loopback:

```sh
git-e2ee-relay --listen 127.0.0.1:8470 --db relay.sqlite --trust-forwarded-for \
          --public-url https://relay.example
```

* `--trust-forwarded-for` rate-limits by the client address the proxy reports. Without
  it, every request seems to come from the proxy.
* Plaintext on a non-loopback address is refused unless you pass
  `--plaintext-behind-proxy`.
* `--allow-classical-tls` also accepts clients without post-quantum key exchange.
* Quotas and rate limits are listed in `git-e2ee-relay --help`, among them `--max-mail-gib`,
  `--max-mailboxes`, `--max-connections` and `--max-connections-per-ip`. `--ttl-days`
  (default 14, at least 4 so spent access tokens are remembered for as long as they're
  valid) is how long undelivered mail and blobs are kept. Keep it at or below the
  clients' `E2EE_PREKEY_GRACE_SECS`.
* For a private CA or self-signed certificate, clients set
  `E2EE_RELAY_CA_FILE=/path/to/ca.pem`.

**Who may register.** By default anyone can register. For a relay you run for a
group, use `--invite-only` and issue each new person a token:

```sh
git-e2ee-relay --db relay.sqlite invite            # prints a token for one new user, valid 24h
git-e2ee-relay --db relay.sqlite invite --hours 72
git-e2ee-relay --db relay.sqlite invite --uses 10   # one token for up to 10 different users
```

Send the token to the person over any channel; it only grants registration, nothing
else. It registers one user. Their additional devices don't need one.

**Banning abusers.** If someone floods mailboxes or otherwise abuses the relay:

```sh
git-e2ee-relay --db relay.sqlite ban <hex user id>     # unban <hex user id> to undo
```

This deletes their device registrations, refuses them from then on, and rotates the
access-token key, so every token they stockpiled dies immediately. On an invite-only relay
an unbanned user needs a new token to register again. These commands work on the same
database while the relay is running. Senders are hidden from the relay, so the user id
comes from the people affected: their clients show who mail came from.

The relay database holds only ciphertext and metadata; losing it loses undelivered
mail, not repositories (every member has a full copy).

### 2. Set up each device (everyone)

On your **first** device, create your account on the relay:

```sh
git e2ee init-user https://relay.example
git e2ee init-user https://relay.example --token <token>   # invite-only relays
```

This creates your master key, makes this device 1, and registers it: it uploads your
signed device list and prekeys (including post-quantum Kyber prekeys). After this,
prekeys are rotated and topped up automatically whenever you use the relay. It prints
your **user code** (`e2eeu1:…`), which is safe to share: it's your public master key.
`git e2ee whoami` prints it again.

**An account belongs to one relay.** On another relay, `init-user` creates another
account: a separate user with its own master key, user code, devices and contacts.
Accounts share nothing, so relays (or anyone who seizes several) can't link them, and
"who am I here" is always the relay's account. A person on two relays is two users,
and collaborators verify each one separately. The account is picked by the relay:
a repo's remote URL for repo commands and git, otherwise `--relay <url>`, the current
repo's relay, or your only account. `git e2ee accounts` lists them. The account key
is the relay's host name (without port), so the same relay reached directly or
through a proxy is one account.

State lives in `~/.local/share/git-e2ee/accounts/<relay host>/` (the base can be
overridden with `GIT_E2EE_HOME`). An identity created before accounts were per relay
(at the top of that directory) stays the account for the relays it registered with.
The state contains your private keys: don't sync it to cloud storage or back it up
casually (see "What we do not uphold").

### 3. Verify the people you work with

Before you share a repo, both of you verify each other, **in both directions**:

```sh
alice$ git e2ee verify e2eeu1:<bob's code>
bob$   git e2ee verify e2eeu1:<alice's code>
```

`verify` shows the safety number for the pair: 60 digits, 10 words per person and a QR
code. Compare them over a channel an attacker can't tamper with (in person, or a voice
call where you recognize each other). Read *all* the words, and answer `y` only if they
match. This pins the other person's master key.

* Exchanging user codes over a chat app is fine. The comparison step is what protects
  you.
* Both directions matter. Alice must have pinned Bob to add him, and Bob must have
  pinned Alice to accept what she sends. Mail from users you haven't pinned (or who
  aren't in a repo you're in) is left unread.
* `--yes` skips the prompt. Only use it if you compared out of band.

### 4. Create a repo

Repos should use SHA-256 object ids. Git can't convert an existing SHA-1 repo in place,
so start fresh, import with `git fast-export | git fast-import` into a SHA-256 repo, or
keep it as SHA-1 with `git e2ee repo init <relay> --allow-sha1` (weaker collision
resistance; see the README's "SHA-1 repos"):

```sh
git init --object-format=sha256 -b main project && cd project
git commit --allow-empty -m "start"          # or add your files
git e2ee repo init https://relay.example      # creates the repo, adds remote "origin"
git push -u origin main
```

`repo init` creates a random repo secret, derives the repo id from it, and runs
`git remote add origin e2ee::https://relay.example/<id>/<name>`, all locally. `<name>`
is the repo directory's name (letters, digits, `.`, `-`, `_`; anything else becomes
`-`), there only so `git clone` names its directory after it. The helper never sends
it to the relay, and the URL works without it, but it travels wherever you share
the URL. Nothing reaches
the relay until the first push (or member change), which anonymously creates the
repo's log.
Use `--remote <name>` for another remote name.

### 5. Add members

Prerequisites: the newcomer has registered with the relay (step 2), and you've
verified each other (step 3). Then, inside the repo:

```sh
alice$ git e2ee member add e2eeu1:<bob's code>
```

This records the membership change in the relay log and sends Bob's devices a
*history bundle*: the current state of the repo, encrypted to each of his devices. Bob
then clones with plain git:

```sh
bob$ git clone e2ee::https://relay.example/<id>/project
```

Other members' devices learn about Bob on their next fetch. They trust him because a
member they trust added him: `git e2ee member list` shows each member as *verified* (you
compared safety numbers) or *unverified* (added by someone else). Run `git e2ee verify`
to upgrade.

### 6. Everyday work

Use git normally:

```sh
git pull
git push
git fetch
```

Each fetch, pull or push makes the helper sync with the relay. It:

* decrypts new mail;
* verifies new log entries against what members sent;
* imports the encrypted packs;
* sends acknowledgements (which also heal sessions after a compromise);
* answers resend requests;
* gossips its log position.

A push encrypts one pack for everyone and sends each device a small pairwise message
with its key.

* **Pushes behave like a normal git server's:**
  * Non-fast-forward updates are rejected unless you `--force`.
  * `--force-with-lease` is supported: the update forces only if the ref still has the
    value you expected (or, with an empty lease, doesn't exist yet), checked against
    the freshly synced state; otherwise it's refused as `stale info`.
  * Concurrent pushes can't overwrite each other: a push must extend exactly the log
    state your client verified, or it's refused with "fetch first".
  * All of these checks run in the pusher's client, since the relay can't see refs. A
    modified client could skip them, which is why force pushes are marked in everyone's
    push log.
* **Signed commits and tags are refused** by default, because signatures are
  non-repudiable proof of authorship. `git config e2ee.allowSigned true` allows them in
  a repo.
* To keep commit metadata pseudonymous, set the identity you commit under and tell the
  helper to enforce it:

  ```sh
  git config user.name "Anon" && git config user.email anon@example.invalid
  git config e2ee.pseudonym "Anon <anon@example.invalid>"
  git config e2ee.requirePseudonym true     # refuse pushes with other identities
  ```

* `git e2ee sync` does a sync without fetching or pushing. That's useful on a device
  that rarely pulls, so its acks, heartbeats and gossip still flow.
* `git e2ee log` shows who changed which refs (and membership), newest last:

  ```
     14  2026-11-12 10:03Z  a1b2c3d4e5f6 (verified) dev 1
           refs/heads/main  3f9c1a7e5b2d -> 77ab90c1d2e3
     15  2026-11-12 11:40Z  you dev 2
           refs/heads/feat  created 91cd0e8f7a6b
     16  2026-11-12 12:02Z  a1b2c3d4e5f6 (verified) dev 1
           refs/heads/main  77ab90c1d2e3 -> 0c4d5e6f7a8b  FORCED (2 commit(s) dropped)
  ```

* `git e2ee status` shows:
  * the log position and head;
  * your current view;
  * the member count;
  * undelivered messages, and your pushes not yet acknowledged by everyone;
  * any **CONFLICT**.

Commands that operate on a repo (`member`, `send-history`, `sync`, `status`,
`clear-conflict`) use the current directory's `origin` remote. Pass
`--remote <name>`, or `--url e2ee::…` to run them outside the repo.

### 7. Add another device of your own

Linking needs both devices and two copy-pastes. Move the codes over a channel you
trust: whoever's link code you approve **becomes your device**.

```sh
new$    git e2ee device link https://relay.example # prints a link code (e2eed1:…)
master$ git e2ee device approve e2eed1:…            # signs and publishes a new device list, prints an approval code (e2eea2:…)
new$    git e2ee device finish e2eea2:…             # joins your account and registers
new$    git clone e2ee::https://relay.example/<id>/project
```

The new device gets your repos from your devices that have them: each sends a repo
(a history bundle, like an invitation) to your devices without it, on its next fetch,
push or sync, and a new repo goes to your other devices with its first push. Of your
devices that have the repo, the lowest-numbered one sends; the others step in if the
device still doesn't have it two days later. Each device is sent a repo once, then
re-sent like an invitation until it clones (or for 60 days), so a device that left a
repo isn't offered it again. `git e2ee send-history` in a repo sends it right away.

The approval code is short: your user id, the new device's id, your delivery token
and the relay. The new device fetches the signed device list from the relay and
accepts it only if its master key hashes to that user id, the signature verifies, and
the list includes this device's key. A relay can withhold the list (then `finish`
fails and says to approve again) but can't substitute one.

Only the master device (device 1) can approve or revoke devices. `send-history` sends
the repo state to all your other devices now; use `--device <id>` to target one.
Collaborators start encrypting to the new device automatically. Its key is in a list
signed by your master key, so they don't re-verify, and your safety number doesn't
change.

### 8. Lose or retire a device

```sh
master$ git e2ee device list
master$ git e2ee device revoke <device id>
```

Revocation publishes a new signed device list without that device and immediately
messages the members of every repo you're in. Your other devices pick the new list up
from the relay on their next sync (and from those messages). Every message carries the new list, so
members stop encrypting to the revoked device as soon as they receive it, even if the
relay keeps serving the old list. An honest relay also drops the device's registration. Anything
the device already had stays on it. If it was stolen, treat that data as exposed.

**If you lose the master device**, you can't approve or revoke devices any more. Your
other devices keep working, but there's no recovery of the master key (by design, it
exists only on device 1). To regain control, create a new user with
`git e2ee init-user <relay>` on a fresh device. Have your collaborators verify the new
identity, add it, and remove the old one.

### 9. Remove a member

```sh
git e2ee member remove e2eeu1:<code>        # or the hex user id from `member list`
```

This records the removal in the log, gives the remaining members a new repo secret,
and rotates the relay token so the removed member is locked out of new data. They keep
everything they already had. Removal is per repo; remove them from each repo
separately.

To leave a repo yourself:

```sh
git e2ee repo leave
```

You can't cut yourself off: whoever rotates the secret knows the new one. So leaving
is a roster change that removes you but *keeps* the current secret (which you hold
anyway), sent to the remaining members and to your own other devices. Any member
device that applies a change in which someone was removed without a new secret marks
the repo for rotation, and the next one to sync rotates it with a normal roster
change; that is what cuts you off. If several race, the log takes one and the others'
attempts are dropped. Until then you could still read new pushes with the secret you
kept, so the window is "until the next remaining member syncs". This device then
forgets the repo; your other devices see that you left and keep their copies until
you run `git e2ee repo forget` there. If you're the only member there is nobody to
tell or rotate for, so `leave` just forgets the repo on this device (the relay keeps
the encrypted log). `member remove` with your own id points you to `leave`.

Any member can add or remove members; there is no admin role.

To drop a repo from one of your devices, run `git e2ee repo forget` inside it. It
deletes that device's state, keys and mirror for the repo, and later mail for it is
ignored. You stay a member until you leave or someone removes you.

The removed member still holds your delivery token. Run
`git e2ee rotate-delivery-token` if you no longer want them to reach your normal lane;
the remaining members learn the new token from your next message.

### Configuration

| Setting | Meaning |
|---|---|
| `e2ee.allowSigned` (git config) | Allow signed commits/tags (non-repudiable!). Default `false`. |
| `e2ee.pseudonym` | `Name <email>` that commits are expected to use; mismatches warn. |
| `e2ee.requirePseudonym` | Turn pseudonym mismatches into errors. |
| `e2ee.pushLog` | Record who changed which refs (`git e2ee log`). Default `true`. |
| `GIT_E2EE_HOME` | Device state directory (default `~/.local/share/git-e2ee`); each account in `accounts/<relay host>/`. |
| `E2EE_HEARTBEAT_SECS` | Heartbeat interval (default 86400). |
| `E2EE_MAX_STALENESS_SECS` | Freeze-warning threshold (default 604800). |
| `E2EE_RESEND_SECS` | Minimum interval between resend requests (default 30). |
| `E2EE_GOSSIP_SECS` | Minimum interval between log-position gossip messages (default 14400). |
| `E2EE_TOKEN_RESERVE` | Access tokens kept on hand per relay (default 300). |
| `E2EE_CHUNK_BYTES` | Plaintext bytes per encrypted pack chunk (default 15.5 MiB, which fills a relay's 16 MiB storage slot; at most 31 MiB, so a sealed chunk fits what receivers and a default relay accept). |
| `E2EE_MAX_PACK_BYTES` | Largest pack accepted or sent (default 4294967296). |
| `E2EE_PREKEY_ROTATE_SECS` | Signed and last-resort Kyber prekey rotation interval (default 604800). |
| `E2EE_PREKEY_GRACE_SECS` | How long superseded prekeys are kept (default 2592000). |
| `E2EE_MAX_DELAY_SECS` | Warn when mail arrives this long after it was sent (default 21600). |
| `E2EE_OUTBOX_TTL_SECS` | Drop undelivered mail and stop waiting for acks after this long (default 2592000). |
| `E2EE_UNREACHABLE_REPORT_SECS` | Report a device whose deliveries have failed this long (default 86400). |
| `E2EE_SILENT_REPORT_SECS` | Report a device not heard from this long (default 604800). |
| `E2EE_INBOX_TTL_SECS` | How long a history bundle for a repo you haven't cloned is kept (default 2592000). |
| `E2EE_SESSION_RESET_SECS` | Minimum interval between forced session resets per peer device (default 3600). |
| `E2EE_RELAY_CA_FILE` | Extra PEM root certificates to trust for relays (self-hosted / private CA). |
| `E2EE_ALLOW_CLASSICAL_TLS` | `1`: accept relays without post-quantum TLS key exchange. |
| `E2EE_ALLOW_INSECURE_RELAY` | `1`: allow plaintext `http://` to non-loopback relays (don't). |

## Implementation notes

* **Mirror repo.** `git clone` only switches a new repository to the repo's object
  format after the helper's `list` returns, so the helper imports packs into a
  per-device bare mirror in that format (created once the format is known from the
  history bundle) (`<account dir>/mirrors/<repo-id>.git`) and copies the requested objects into
  the working repository on `fetch`. This doubles disk usage.
* **One clone per repo per device.** Replication state is keyed by repo id in the
  device database, so two clones of the same repo on one device would share one state.
* **Mail filing.** Whichever repo a sync is for, the client drains the device's whole
  mailbox on that relay and files each envelope under the repo id inside it. Another
  repo's mail waits in the local inbox until that repo syncs.
  * For repos the device has no state for, only **history bundles** (invitations) are
    kept; anything else is dropped. This stops a pinned user from filling your disk
    with mail for made-up repos.
  * Unclaimed bundles expire after `E2EE_INBOX_TTL_SECS` (default 14 days), and the
    pack keys inside them go with them.
  * At most 50 bundles for unknown repos and 10 000 envelopes per known repo are kept.
* **Prekeys.** Each device keeps a current signed EC prekey and a current last-resort
  Kyber prekey (rotated, see above), plus batches of one-time EC and Kyber prekeys that
  are topped up automatically when fewer than 10 remain on a relay.
* **Relay limits.** `git-e2ee-relay --help` lists the quota and rate-limit flags. Defaults:
  * 512 MiB per pack;
  * 64 GiB of blobs in total;
  * 256 KiB per message;
  * 20 000 queued messages per mailbox;
  * 200 one-time prekeys of each kind per device;
  * 1000 new repos per hour, relay-wide;
  * 5000 anonymous access tokens per device per day;
  * 20 request-lane messages (without the recipient's delivery token) per device per
    day;
  * 100 requests/s per IP, with bursts of 1000.
* **Layout.**
  * `crates/proto`: wire types, domain separation, view/log hashing.
  * `crates/core`: identity and cross-signing, libsignal stores, sessions, pack
    crypto, relay client, replication engine.
  * `crates/relay`: the server.
  * `crates/helper`: the binaries, plus end-to-end tests that drive real `git`,
    including an adversarial relay (forks, freezes, dropped mail, ghost devices),
    equivocation and crash recovery.

## Tests

```sh
cargo test --workspace
```

## License

AGPL-3.0-only (required by libsignal).
