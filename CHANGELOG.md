# Changelog

All notable changes to `nftgeo` are documented here. Versions follow
[Semantic Versioning](https://semver.org/). The running version is reported by
`nftgeo-update --version` and in the `Loaded` log line of each run.

## [Unreleased]

Planned work (P3 egress NAT, P4 port forwarding, P5 internal firewall /
segmentation) is tracked in [ROADMAP.md](ROADMAP.md).

## [1.15.0] - 2026-07-06

### Added
- nftgeo-ui Objects & theme polish: address groups and custom regions expand to
  their members as chips (IP/CIDR chips and whitelist IPs are click-to-lookup);
  a light/dark theme toggle (persisted in localStorage, keeping the dark
  FortiGate-style sidebar); a responsive layout that collapses the sidebar on
  narrow screens; and tooltips.

## [1.14.0] - 2026-07-06

### Added
- nftgeo-ui Dashboard widgets: a System card (next scheduled run, established
  connections, abuse-feed freshness pills, last load), top destination countries
  for egress drops alongside sources, and a drops-over-time sparkline (24h
  hourly), backed by `health` in /api/status and a `timeline` in /api/drops.

## [1.13.0] - 2026-07-06

### Added
- nftgeo-ui Policy view: live hit counts per rule (each `rules.conf` rule is
  joined to the chain rules that implement it - by hook, verdict, port, address
  side, and the target's set name - and their counters summed), sortable columns,
  and a click-through rule drawer showing the generated nft lines with counters.
  The side match cleanly separates ingress vs egress rules that share a set (e.g.
  `deny in ... abuse` vs `deny out ... abuse`).

## [1.12.0] - 2026-07-06

### Added
- nftgeo-ui: a FortiGate-style navigation shell for ergonomics - a left sidebar
  with Dashboard / Policy / Logs & Drops / Objects views:
  - **Policy** — your `rules.conf` (+ `rules.d`) as a readable policy table
    (action/dir/service/target/interface/file/comment), from `/api/rules`.
  - **Logs & Drops** — the drop feed as a filterable table (direction, country,
    port, IP search) with click-to-lookup.
  - **Objects** — address groups, custom regions, whitelist/hosts, abuse feeds,
    and live set sizes, from `/api/objects`.
  Still read-only; editing is roadmap P6 phase B.

## [1.11.1] - 2026-07-06

### Added
- nftgeo-ui: click any IP in the recent-drops feed to look it up - reverse DNS
  (PTR) plus whois via RDAP (network, org, country, range), served by a new
  `/api/lookup` endpoint (no `whois` CLI dependency). RDAP also fills in the
  country when an IP isn't in a cached geo zone.

## [1.11.0] - 2026-07-06

### Added
- `nftgeo-ui` (roadmap P6, Phase A): an optional, read-only local web dashboard -
  a single dependency-free Go binary that serves `127.0.0.1:8787` with a world
  map of where drops come from (geolocated from the local ipdeny zones, no
  external GeoIP), live drop-rule counters, set sizes, top source countries and
  ports, and a recent-drops feed. It only reads `nft`/`journalctl`/`nftgeo-update`
  and never writes; feed the map by enabling `LOG_DROPS`. Built from `./ui` with a
  `nftgeo-ui.service` unit.

## [1.10.1] - 2026-07-06

### Added
- `on <iface>` works with arbitrary interface names (VPN tunnels, VLANs, bridges,
  predictable names - e.g. `home-Client-10`, `eth0.100`, `br-lan`, `enp3s0`,
  `wg0`), preserved verbatim. If a referenced interface is not currently present,
  the update prints a non-fatal warning (visible in `nftgeo validate`) so a typo
  can't silently break a rule - while a legitimately-down tunnel still works once
  it appears.

## [1.10.0] - 2026-07-06

### Added
- Per-interface rules: an optional `on <iface>` qualifier on any rule, e.g.
  `allow in tcp 22 europe on eth0` or `deny fwd-out any - abuse on wan0`. It maps
  to `iifname` on the source side (`in`/`fwd-in`) and `oifname` on the
  destination side (`out`/`fwd-out`), so you can scope a rule to one interface.
  Deny-by-default stays interface-agnostic (it closes the port on all interfaces
  except where an allow admits it). Foundation for NAT (P3/P4).

## [1.9.0] - 2026-07-06

### Added
- `HARDEN=1` — baseline firewall hardening on every managed chain: accept
  loopback (`iifname lo` / `oifname lo`), drop `ct state invalid`, and always
  permit the essential ICMPv6 types (NDP, PTB, echo, errors) so locking down IPv6
  cannot break it. Off by default; `ICMPV6_ESSENTIAL` is configurable. First step
  of growing nftgeo from a geo overlay toward a complete edge firewall.

## [1.8.2] - 2026-07-06

### Fixed
- Deadman cleanup: the 1.8.1 `setsid` group-kill did not reliably reap the
  waiter on all hosts, leaving a stray `sleep` behind. The deadman now polls the
  sentinel once a second and self-exits within ~1s of it being removed, so
  `--commit`/`rollback` leave nothing behind regardless of the platform. (It was
  always functionally correct - cancellation is sentinel-based - this only tidies
  the leftover process.)

## [1.8.1] - 2026-07-06

### Changed
- Polish: match the dynamic-block state file by exact field (awk) instead of a
  regex, run the deadman in its own session (`setsid`) and group-kill it on
  confirm/rollback so no stray `sleep` is left behind, and drop the undocumented
  `blocks` alias. Added a command cheat sheet ([CHEATSHEET.md](CHEATSHEET.md)).
  (The deadman cleanup here was superseded by 1.8.2.)

## [1.8.0] - 2026-07-06

### Added
- Safe-apply deadman and rollback. `nftgeo apply --confirm [T]` snapshots the
  loaded ruleset, applies the new one, and auto-rolls-back after T seconds
  (default 120) unless you run `nftgeo apply --commit` (alias `nftgeo confirm`) -
  a guard against a rule change that locks you out. `nftgeo rollback` restores the
  previous generation. Ruleset generations are kept under
  `/var/lib/nftgeo/generations/` (last 10) with a `previous` pointer; the deadman
  is a detached process that survives the CLI exiting and cleans up after itself.

## [1.7.0] - 2026-07-06

### Added
- Optional drop logging: set `LOG_DROPS=1` to emit a rate-limited
  `log prefix "nftgeo-drop "` before every drop rule, so dropped packets appear
  in the kernel log / journald (`journalctl -k | grep nftgeo-drop`). Off by
  default; `LOG_PREFIX` and `LOG_LIMIT` are configurable.

## [1.6.0] - 2026-07-06

### Added
- `nftgeo block <ip> [ttl]` / `unblock <ip>` / `blocklist` - drop an address right
  now for a TTL (default 1h) without editing rules or reloading. Blocks live in a
  separate `nftgeo_dyn` table that `nftgeo-update` never rebuilds, so they survive
  ruleset reloads; entries carry an in-kernel timeout and are restored after a
  reboot from `/var/lib/nftgeo/dynblock.tsv` (via the service's ExecStartPost).
  `block` refuses a whitelisted address or your current SSH source unless
  `--force`, to prevent self-lockout.

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

[1.15.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.15.0
[1.14.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.14.0
[1.13.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.13.0
[1.12.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.12.0
[1.11.1]: https://github.com/dzaczek/nftgeo/releases/tag/v1.11.1
[1.11.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.11.0
[1.10.1]: https://github.com/dzaczek/nftgeo/releases/tag/v1.10.1
[1.10.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.10.0
[1.9.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.9.0
[1.8.2]: https://github.com/dzaczek/nftgeo/releases/tag/v1.8.2
[1.8.1]: https://github.com/dzaczek/nftgeo/releases/tag/v1.8.1
[1.8.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.8.0
[1.7.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.7.0
[1.6.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.6.0
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
