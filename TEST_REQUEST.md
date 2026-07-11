# Test request

Hi,

I am looking for testers for nftgeo, a declarative geo-aware firewall manager
for Linux nftables.

Repository: https://github.com/dzaczek/nftgeo
Latest packages (DEB/RPM): https://github.com/dzaczek/nftgeo/releases/latest

What would be most useful to test:

- Fresh install on a disposable Debian/Ubuntu VPS, VM, or lab host.
- `nftgeo validate`, `nftgeo plan`, and safe apply with
  `nftgeo apply --confirm` / `--commit`.
- SSH restriction with a whitelist entry.
- AbuseIPDB or custom blocklist feeds.
- Optional dashboard startup and token login.
- NAT, forwarding, zones, ingress, throttling, or SYN proxy if you already use
  those features in a lab.

Please do not test first on a critical production host. If you test over SSH,
keep emergency console access available and whitelist your current public IP
before applying inbound rules.

Testing guide: TESTING.md
Contribution guide: CONTRIBUTING.md
Test report: https://github.com/dzaczek/nftgeo/issues/new?template=test_report.yml
Security-sensitive issues: SECURITY.md

Useful feedback format:

```text
Version:
Install method:
OS / kernel:
Environment:
Feature tested:
Commands run:
Expected result:
Actual result:
Relevant config, with secrets removed:
Relevant logs:
```

Please remove API keys, private hostnames, private IP inventories, SSH details,
and credentials before posting logs or configs.
