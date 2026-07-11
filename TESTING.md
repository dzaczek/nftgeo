# Testing nftgeo

Thank you for testing nftgeo. The most useful feedback is specific: what you
tested, on which system, which commands you ran, what you expected, and what
happened instead.

Do not post real API keys, private IP inventories, production hostnames, SSH
details, or server credentials in public issues.

Download the latest DEB and RPM packages from the
[latest release](https://github.com/dzaczek/nftgeo/releases/latest).

## What to test

Good test areas:

- Fresh install from package or from `install.sh`.
- `nftgeo validate`, `nftgeo plan`, and `nftgeo apply --confirm` / `--commit`.
- SSH geo/IP restriction with a whitelist entry.
- AbuseIPDB or custom blocklist feeds.
- Dashboard startup, token login, read-only token, policy editor, and commit
  flow.
- NAT, forwarding, zones, ingress rules, throttling, and SYN proxy if you run
  those features.
- Upgrade or uninstall behavior on a non-critical machine.

Use a disposable VPS, VM, or lab host when possible. If you test over SSH, keep
provider console access open and whitelist your current public IP before
changing inbound rules.

## Safe smoke test on a lab host

```sh
git clone https://github.com/dzaczek/nftgeo.git
cd nftgeo
sudo ./install.sh

sudoedit /etc/nftgeo/config
# Set:
#   WHITELIST="YOUR.PUBLIC.IP"

cat <<'EOF' | sudo tee /etc/nftgeo/rules.conf
allow in tcp 22 YOUR.PUBLIC.IP
deny  in tcp 22 any
allow out udp 53 any
EOF

sudo nftgeo validate
sudo nftgeo plan
sudo nftgeo apply --confirm
# Open a second SSH session or otherwise verify access.
sudo nftgeo apply --commit
sudo nftgeo status
```

To roll back during the confirmation window:

```sh
sudo nftgeo rollback
```

## Local developer tests

These tests do not change the active firewall:

```sh
go test ./ui/
sh tests/render/run.sh
sh tests/migrate/run.sh
make test
```

Optional real nftables validation:

```sh
sudo sh tests/render/nft-check.sh
```

`nft-check.sh` uses `nft -c` against generated fixtures. It should be run only
on a Linux host with nftables available.

## Add a render test case

Create `tests/render/cases/<case-name>/` with:

- `rules.conf` - input policy.
- `assert` - expected snippets.
- `config` - optional test config.
- `groups.d/*.conf`, `whitelist.conf`, `ingress.conf` - optional fixtures.

Assertion prefixes:

```text
+ text   generated ruleset must contain text
- text   generated ruleset must not contain text
! text   render must fail and stderr must contain text
~ text   render must succeed and stderr must contain warning text
```

Run:

```sh
sh tests/render/run.sh
```

## Useful report template

The easiest option is the
[test report form](https://github.com/dzaczek/nftgeo/issues/new?template=test_report.yml).

```text
Version:
Install method:
OS / kernel:
Environment: VPS / VM / bare metal / container
Feature tested:
Commands run:
Expected result:
Actual result:
Relevant config, with secrets removed:
Relevant logs:
```

Useful commands:

```sh
nftgeo version
uname -a
sudo nftgeo validate
sudo nftgeo status
journalctl -u nftgeo.service -n 100 --no-pager
journalctl -u nftgeo-ui.service -n 100 --no-pager
```

If the issue is security-sensitive, follow [SECURITY.md](SECURITY.md) instead
of opening a public issue.
