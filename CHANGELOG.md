# Changelog

## Unreleased: protocol 2 (first release)

Protocol 2 is the first supported version. It is **not compatible** with the
pre-release (protocol 1) builds.

**Existing repos stop working.** Builds speaking protocol 2 refuse protocol 1
repos, relays and collaborators. To move a repo over:

1. Everyone upgrades.
2. One member makes a new repo (`git e2ee repo init <relay>`), pushes the branches
   to it and adds the others.
3. Everyone clones the new repo.

Users and devices carry over if your local state is from a recent pre-release
build. If `git e2ee` or `git-e2ee-relay` reports "database migration failed", the
database is from an older pre-release build: move it aside and start fresh (for
clients, `~/.local/share/git-e2ee` or `$GIT_E2EE_HOME`, then `git e2ee init-user`
and verify contacts again; for relays, the `--db` file).

Repos made with earlier builds of this pre-release (protocol 2 before rosters
carried the genesis secret) keep working for their members, but newcomers can't
join them: recreate them the same way.

Relay operators: the database migration drops stored blobs and repo tokens. They
only served protocol 1 repos. Invites are kept. Waiting mail and blobs are dropped
too (they move to a slot store, `<db>.slots/`, next to the database; senders'
resend requests cover undelivered mail). Keep that directory with the database in
backups, and give it a size cap with `--max-storage-gib` (default 128).

What changed on the wire:

- A push's view commits to the hash of the pack key, not the key.
- Repo-token rotation is part of the log append (`x-e2ee-replace-token`); the
  `/repos/{rid}/tokens` endpoint is gone.
- Post-quantum handshake frames carry delivery tokens encrypted.
- Delivering mail costs an access token per started 64 KiB.
- The relay speaks HTTP/1.1 only, one request per connection.
- Mailboxes are read in pages (`?after=<seq>`).
- Rosters carry the repo's genesis secret, which the repo id is derived from.
- The relay database migration also adds a table of seen request nonces.
