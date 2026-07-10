# Security Policy

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue for an
unpatched vulnerability.

- Preferred: open a [private security advisory](https://github.com/dzaczek/nftgeo/security/advisories/new)
  (GitHub → Security → Report a vulnerability).
- Or email the maintainer at the address on the commit history / GitHub profile.

Include: affected version (`nftgeo-update --version`), a description, and steps
to reproduce. You'll get an acknowledgement as soon as possible; please allow
reasonable time for a fix before any public disclosure.

## Supported versions

nftgeo is developed on a rolling basis; fixes land on `main` and in the newest
tagged release. Please reproduce on the latest release before reporting.

## Scope & threat model

nftgeo generates and loads an nftables ruleset from declarative config, and
ships an optional local dashboard (`nftgeo-ui`).

Security-relevant components:

- **The engine (`nftgeo-update`, `nftgeo`)** runs as root and loads the kernel
  ruleset. Every change is validated with `nft -c` before `nft -f`, and
  `apply --confirm` guards risky changes with a deadman auto-rollback. A reboot
  during a pending dashboard deploy rolls back to the confirmed config.
- **The dashboard (`nftgeo-ui`)** binds to `127.0.0.1` by default and uses a
  root-only (`0600`) secret with a token→`HttpOnly`/`SameSite=Strict` cookie
  exchange; untrusted sessions are read-only. Front it with a TLS-terminating
  reverse proxy if you expose it beyond localhost.
- **Config (`/etc/nftgeo/config`)** may hold `ABUSEIPDB_API_KEY`; keep it
  root-readable only. It is never committed — the repo ships only
  `config.example` with an empty key.

Out of scope: issues that require root on the host (which the engine already
has), or misconfiguration that deliberately locks the operator out (the deadman
and the whitelist are the safety nets for that).
