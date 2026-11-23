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
and add contacts again; for relays, the `--db` file).

**Accounts are per relay.** `git e2ee init-user <relay-url> [--token]` creates your
account on that relay and registers it; another relay gets another, separate
account (user, devices, contacts), kept in `~/.local/share/git-e2ee/accounts/<host>/`.
Commands pick the account from the repo's remote, or `--relay <url>`; `git e2ee
accounts` lists them. An existing identity keeps working on the relays it's
registered with. `device link` now takes the relay, `device finish` registers, and
approval codes (`e2eea2:`) are short: the new device fetches the signed device list
from the relay and checks it against the user id. Devices also pick up their
account's device-list changes from the relay on every sync.

**No more manual `send-history`.** Your devices send repos to your other devices that
don't have them: a new repo with its first push, and any repo on the next fetch, push
or `git e2ee sync` of a device that has it (once per device, then re-sent like an
invitation until it clones).

**Repo names in URLs.** `repo init` ends the remote URL with the repo directory's
name (`e2ee::https://relay.example/<id>/project`), so `git clone` names its
directory after it. The name is never sent to the relay; URLs without it still work.
`member add` prints the clone command.

**Contacts replace verification.** `git e2ee verify` and `git e2ee name` are gone.
Share your user id (`git e2ee whoami`) over a channel you trust, and add people with
`git e2ee contact add <name> <user id>`: it fetches their key from the relay and
checks it hashes to the id. No safety numbers to compare. `member add` and
`member remove` take contact names. Add each other before inviting, so the first
clone works at once. User codes (`e2eeu1:`) are gone:
user ids are the only way to name a user.

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
