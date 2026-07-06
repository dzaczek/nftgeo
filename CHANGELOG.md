# Changelog

All notable changes to `nftgeo` are documented here. Versions follow
[Semantic Versioning](https://semver.org/). The running version is reported by
`nftgeo-update --version` and in the `Loaded` log line of each run.

## [1.5.1] - 2026-07-06

### Fixed
- `nftgeo status` reported `1` for an empty set instead of `0`. Document the
  engine's URL / path / table environment overrides in the README.

## [1.5.0] - 2026-07-06

### Added
- No-op detection: when a run renders a ruleset byte-identical to the one already
  loaded, the reload is skipped so per-rule counters are preserved instead of
  being zeroed twice a day. A live-table check keeps a fresh boot loading
  normally.

## [1.4.1] - 2026-07-06

### Fixed
- Strip bogon / private / reserved ranges (RFC1918, loopback, link-local, CGNAT,
  multicast, documentation) from the abuse sets. Feeds such as FireHOL level1
  include these, and with a `deny ... abuse` egress rule they dropped traffic to
  the local resolver `127.0.0.53`, the LAN, and a VPN resolver - breaking DNS on
  the host. The abuse sets now only ever hold public, routable addresses.

## [1.4.0] - 2026-07-06

### Added
- `RESOLVERS` for `WHITELIST_HOSTS`: a list of resolvers tried in order (the first
  that answers wins). `local` uses the system resolver (getent); an IP queries
  that DNS server directly via dig/host/nslookup. Listing public servers before
  `local` (e.g. `RESOLVERS="1.1.1.1 8.8.8.8 local"`) keeps hostname whitelisting
  working when the local/VPN resolver is down and yields the public-facing
  address. `RESOLVE_TIMEOUT` (default 5s) bounds each lookup. Default `local`
  keeps prior behaviour.

## [1.3.1] - 2026-07-06

### Fixed
- Bound each `WHITELIST_HOSTS` lookup with `RESOLVE_TIMEOUT` (default 5s) so a
  hung resolver can no longer stall the whole update, including the scheduled
  timer run; a timed-out lookup just falls back to the retained address.
- `nftgeo validate`/`plan` (RENDER_ONLY) no longer re-resolve hostnames or mutate
  state - they reuse the last resolved addresses, staying fast and side-effect
  free even when DNS is down.

## [1.3.0] - 2026-07-06

### Added
- `nftgeo validate` - render the ruleset from the current config and check it
  with `nft -c` without loading it; exits non-zero on an invalid config.
- `nftgeo plan` - show how the rendered ruleset differs from what is loaded, as a
  policy diff with set contents (abuse/geo addresses) elided so only rule changes
  show. Backed by a new `RENDER_ONLY` mode in the engine that skips the lock, the
  network fetches, and the live load.

## [1.2.0] - 2026-07-06

### Added
- `nftgeo` operator CLI (installed alongside `nftgeo-update`):
  - `nftgeo check <ip>` - show whether an address is whitelisted, on the abuse
    list, or in a geo set, the rules that match it, and the resulting verdict.
  - `nftgeo status` - one-screen summary: version, last run, set sizes, live drop
    counters, abuse-feed cache freshness, and the next scheduled run.
  - `nftgeo apply` / `nftgeo version` wrap the update engine.

## [1.1.1] - 2026-07-05

### Fixed
- Add `auto-merge` to the address sets so overlapping/adjacent entries no longer
  fail to load with "conflicting intervals" - which happened once `ABUSE_FEEDS`
  CIDRs were merged with AbuseIPDB single IPs, and could also affect a whitelist
  or geo target that mixed an address with a subnet containing it.

## [1.1.0] - 2026-07-05

### Added
- `ABUSE_FEEDS`: extra plaintext IP/CIDR blocklists (e.g. FireHOL level1,
  Spamhaus DROP, blocklist.de, GreenSnow) merged into the same `abuse` sets, so
  existing `deny ... abuse` rules cover them. Feeds are fetched only when a rule
  targets `abuse`, and each feed's last good copy is cached per URL and reused on
  a download failure so an outage never shrinks the blocklist.

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

[1.5.1]: https://github.com/dzaczek/nftgeo/releases/tag/v1.5.1
[1.5.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.5.0
[1.4.1]: https://github.com/dzaczek/nftgeo/releases/tag/v1.4.1
[1.4.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.4.0
[1.3.1]: https://github.com/dzaczek/nftgeo/releases/tag/v1.3.1
[1.3.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.3.0
[1.2.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.2.0
[1.1.1]: https://github.com/dzaczek/nftgeo/releases/tag/v1.1.1
[1.1.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.1.0
[1.0.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.0.0
