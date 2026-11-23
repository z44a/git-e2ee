# The relay's tunable flags, for the NixOS module (one typed option each)
# and for the flake check that every one exists in `git-e2ee-relay --help`.
# `default` is the relay's own default, only for documentation: an option
# left at null passes nothing, so the relay's default applies.
lib:
let
  t = lib.types;
in
{
  ttlDays = {
    flag = "--ttl-days";
    type = t.ints.between 4 36500;
    default = 14;
    description = "Days to keep undelivered mail and blobs (at least 4). Members must sync this often; longer absences catch up from other members.";
  };
  maxBlobMiB = {
    flag = "--max-blob-mib";
    type = t.ints.between 1 63;
    default = 32;
    description = "Largest single blob (an encrypted pack chunk), in MiB. Clients send 15.5 MiB chunks, at most 31 MiB.";
  };
  maxTotalBlobMiB = {
    flag = "--max-total-blob-mib";
    type = t.ints.positive;
    default = 65536;
    description = "Stored blob bytes across all repos, in MiB.";
  };
  maxMailGiB = {
    flag = "--max-mail-gib";
    type = t.ints.positive;
    default = 16;
    description = "Waiting mail across all mailboxes, in GiB.";
  };
  maxStorageGiB = {
    flag = "--max-storage-gib";
    type = t.ints.positive;
    default = 128;
    description = "Disk the mail and blob storage files may take, in GiB. They never shrink, and a slot can be up to a quarter bigger than what it holds: keep it above the mail and blob quotas, with room.";
  };
  maxMailboxMessages = {
    flag = "--max-mailbox-messages";
    type = t.ints.positive;
    default = 20000;
    description = "Queued messages per mailbox.";
  };
  maxMailboxes = {
    flag = "--max-mailboxes";
    type = t.ints.positive;
    default = 1000000;
    description = "Pseudonymous (per-repo) mailboxes in total.";
  };
  maxOneTimeHandoutsPerHour = {
    flag = "--max-one-time-handouts-per-hour";
    type = t.ints.positive;
    default = 20;
    description = "One-time prekeys handed out per device per hour (protects against draining them).";
  };
  maxNewReposPerHour = {
    flag = "--max-new-repos-per-hour";
    type = t.ints.positive;
    default = 1000;
    description = "New repos per hour, relay-wide (creating a repo is anonymous, so there's no per-user count).";
  };
  ratePerSec = {
    flag = "--rate-per-sec";
    type = t.numbers.nonnegative;
    default = 100;
    description = "Sustained requests per second per client address (IPv6: per /64); 0: unlimited.";
  };
  rateBurst = {
    flag = "--rate-burst";
    type = t.numbers.positive;
    default = 1000;
    description = "Burst size for the per-address request rate limit.";
  };
  accessTokensPerDay = {
    flag = "--access-tokens-per-day";
    type = t.ints.positive;
    default = 5000;
    description = "Anonymous access tokens each user may obtain per day (their budget for anonymous actions).";
  };
  requestLanePerDay = {
    flag = "--request-lane-per-day";
    type = t.ints.unsigned;
    default = 20;
    description = "Messages a device accepts per day from senders without its delivery token (strangers, first contact).";
  };
  maxConnections = {
    flag = "--max-connections";
    type = t.ints.positive;
    default = 1024;
    description = "Concurrent connections in total.";
  };
  maxConnectionsPerIp = {
    flag = "--max-connections-per-ip";
    type = t.ints.positive;
    default = 32;
    description = "Concurrent connections from one address (IPv6: per /64). Loopback (a local reverse proxy) is exempt: the proxy should limit per client.";
  };
  newUsersPerIpHour = {
    flag = "--new-users-per-ip-hour";
    type = t.ints.unsigned;
    default = 10;
    description = "New users (identities) per address (IPv6: per /64) per hour. They cost no access tokens, so on an open relay this bounds them.";
  };
  newDevicesPerIpHour = {
    flag = "--new-devices-per-ip-hour";
    type = t.ints.unsigned;
    default = 30;
    description = "New device registrations per address (IPv6: per /64) per hour.";
  };
  maxUsers = {
    flag = "--max-users";
    type = t.ints.positive;
    default = 1000000;
    description = "Users (identities) in total.";
  };
  maxDevices = {
    flag = "--max-devices";
    type = t.ints.positive;
    default = 2000000;
    description = "Registered devices in total.";
  };
}
