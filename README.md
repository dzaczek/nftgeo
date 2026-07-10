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

Requirements: Debian or Ubuntu, `systemd`, `nftables`, `curl`, and root access.
An AbuseIPDB API key is optional unless you use the `abuse` target.

```sh
git clone https://github.com/dzaczek/nftgeo.git
cd nftgeo
sudo ./install.sh

# Add your current admin IP before restricting SSH.
sudoedit /etc/nftgeo/config
#   WHITELIST="YOUR.PUBLIC.IP"

sudoedit /etc/nftgeo/rules.conf
#   allow in tcp 22 YOUR.PUBLIC.IP
#   deny  in tcp 22 any
#   deny  in any - abuse
#   allow out udp 53 any

sudo nftgeo validate
sudo nftgeo apply --confirm
# Verify that SSH still works.
sudo nftgeo apply --commit

sudo systemctl enable --now nftgeo.timer
```

## Install

Package install:

```sh
sudo apt install ./nftgeo_<version>_amd64.deb
sudo dnf install ./nftgeo-<version>-1.x86_64.rpm
```

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
<action> <dir> <proto> <port> <target> [on <iface>] [log]
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

## Dashboard

The optional `nftgeo-ui` dashboard binds to `127.0.0.1:8787` by default and
provides drop maps, counters, interface monitoring, a visual policy editor,
object editors, templates, and a draft-to-commit deploy flow.

```sh
sudo systemctl enable --now nftgeo-ui.service
sudo nftgeo-ui token
```

For remote access, forward it over SSH:

```sh
ssh -L 8787:127.0.0.1:8787 user@host
```

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

[MIT](LICENSE) - Copyright (c) 2026 dzaczek
