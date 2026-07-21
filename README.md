# nftgeo

**Declarative geo-aware firewall manager for Linux nftables.**

nftgeo lets you write readable firewall policy such as `allow in tcp 22 europe`
or `deny in any - abuse`, then resolves geo zones and blocklists, renders an
nftables ruleset, validates it, and loads it atomically.

```text
# /etc/nftgeo/rules.conf
deny  in tcp 22 abuse
allow in tcp 22 europe
allow in tcp 22 203.0.113.10
deny  in tcp 22 any

deny  in tcp 80,443 abuse
allow in tcp 80,443 any

allow out udp 53 any
```

## Why use it?

- Human-readable policy instead of hand-written nftables sets.
- Country and region targets from ipdeny.com, plus AbuseIPDB and custom
  plaintext IP/CIDR blocklists.
- Safe apply flow: render, `nft -c`, atomic `nft -f`, and a deadman rollback
  for risky remote changes.
- Direction-aware rules for host traffic and routed/gateway traffic.
- Optional features for throttling, SYN proxy, ingress early drops, NAT,
  inter-zone segmentation, per-rule counters, and a local web dashboard.
- Shell engine plus Go dashboard binary. No Docker or database required.

## Quick start

For the shortest package-based install flow, use
[Quick Start](QUICK_START.md) or [Quick Start PL](QUICK_START_PL.md).

If you want the source installer instead, clone the repo and run
`sudo ./install.sh` on Debian or Ubuntu.

## Install

Package install and first-run steps are documented in
[Quick Start](QUICK_START.md) and [Quick Start PL](QUICK_START_PL.md).

Source install:

```sh
git clone https://github.com/dzaczek/nftgeo.git
cd nftgeo
sudo ./install.sh
```

The installer copies the engine and CLI to `/usr/sbin`, creates `/etc/nftgeo`,
installs systemd units, and enables no firewall policy automatically.

## Rule model

Rules are evaluated top-to-bottom, first match wins, after a fixed baseline
for loopback, invalid state drops, established/related traffic, whitelist, and
optional protections.

```text
<action> <dir> <proto> <port> <target> [on <iface>] [log] [mark <number>]
```

Common examples:

```text
allow in  tcp 22   pl
deny  in  tcp 22   any
allow in  tcp 443  any
deny  in  any -    abuse
allow out udp 53   any
allow fwd-out tcp 80,443 any
throttle in tcp 22 5/minute
```

Important safety note: an `allow` rule does not by itself close the same port
to everyone else when the chain policy is `accept`. Add a catch-all `deny ...
any` below a geo/IP-restricted allow, or use `DEFAULT_INPUT="drop"` once your
policy is ready.

## Dashboard and console

The optional `nftgeo-ui` web dashboard binds to `127.0.0.1:8787` by default
and provides drop maps, counters, interface monitoring, a visual policy
editor, object editors, templates, and a draft-to-commit deploy flow.

```sh
sudo systemctl enable --now nftgeo-ui.service
sudo nftgeo-ui token
```

For remote access, forward it over SSH:

```sh
ssh -L 8787:127.0.0.1:8787 user@host
```

It also includes an interactive terminal console:

```sh
sudo nftgeo-ui cli
```

The console has Dashboard, Logs, Policy, Objects, and System views, and uses
the same draft and deadman deployment path as the web editor. **It is a
demonstration/preview interface for now**: its layout, keys, and editing flow
may change. For routine or scripted administration, use `nftgeo` and the web
dashboard.

## Documentation

- [Full reference](docs/REFERENCE.md) - complete rule syntax, config keys,
  dashboard details, safety model, troubleshooting, and release notes.
- [Cheat sheet](CHEATSHEET.md) - compact operator command reference.
- [Examples](examples/README.md) - ready-to-adapt `rules.d` fragments.
- [Testing guide](TESTING.md) / [Polish testing guide](TESTING_PL.md) - how to
  test nftgeo and report useful results.
- [Test request](TEST_REQUEST.md) / [Test request PL](TEST_REQUEST_PL.md) -
  short copy-ready messages for recruiting testers.
- [Contributing](CONTRIBUTING.md) / [Contributing PL](CONTRIBUTING_PL.md) -
  development workflow and pull request expectations.
- [Security policy](SECURITY.md) - private vulnerability reporting.

Installed manual pages: `nftgeo(8)`, `nftgeo-update(8)`, `nftgeo-ui(8)`, and
`nftgeo.conf(5)`.

## Development

```sh
make test
make lint
make build
```

Useful individual checks:

```sh
go test ./ui/
sh tests/render/run.sh
sh tests/migrate/run.sh
sudo sh tests/render/nft-check.sh
```

Render fixtures live in `tests/render/cases/<name>/`. Each case has a
`rules.conf`, optional `config`, optional helper files, and an `assert` file.

## License

[AGPL-3.0](LICENSE) - Copyright (c) 2026 dzaczek
