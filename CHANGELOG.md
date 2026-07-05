# Changelog

All notable changes to `nftgeo` are documented here. Versions follow
[Semantic Versioning](https://semver.org/). The running version is reported by
`nftgeo-update --version` and in the `Loaded` log line of each run.

## [1.0.0] - 2026-07-05

First tagged release. Captures the current feature set and recent hardening.

### Features
- Declarative per-direction geo firewall for `nftables` (`in`/`out`/`fwd-in`/`fwd-out`).
- Match by country, region, literal IPv4/IPv6, CIDR, named groups, `any`, and the
  AbuseIPDB blacklist (`abuse`), with tcp/udp/sctp/icmp/icmpv6/esp/ah/gre.
- Opt-in AbuseIPDB blocking with retained state across download failures.
- `WHITELIST` of always-allowed addresses, plus `WHITELIST_HOSTS` for
  hostname-based whitelisting that is re-resolved on every run (fail-safe, with
  retention through DNS failures).
- Twice-daily refresh via a `systemd` timer; atomic, validated ruleset loads.

### Fixed / hardened
- Ship `rules.conf.example` without an active rule so a fresh install cannot
  lock out SSH.
- A single unresolvable country no longer aborts the whole update; deny-only
  empty geo groups are skipped, allow-backed ones still fail safe.
- Serialize runs with a lock so the timer and a manual run cannot race.

### Notes
- Documented that `allow <dir> any - <target>` closes the entire direction.
- Refreshed stale `systemd` unit descriptions.

[1.0.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.0.0
