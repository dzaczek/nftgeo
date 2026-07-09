# nftgeo

> A declarative geolocation firewall for `nftables` on Debian/Ubuntu.
> Write rules like sentences — nftgeo builds and maintains the nftables rules for you.

---

## How it works

```
 ┌──────────────────────────────────────────────────────────┐
 │                    You write rules.conf                    │
 │          allow in tcp 22 europe                            │
 │          deny  in any -  abuse                             │
 └────────────────────────┬─────────────────────────────────┘
                          │
                          ▼
 ┌──────────────────────────────────────────────────────────┐
 │                   nftgeo-update engine                     │
 │                                                            │
 │  1. Parse rules.conf + rules.d/*.conf                     │
 │  2. Resolve geo zones (ipdeny.com)                        │
 │  3. Fetch AbuseIPDB + feed blocklists                     │
 │  4. Render nftables ruleset                               │
 │  5. Validate (nft -c)                                     │
 │  6. Atomic load (nft -f)                                  │
 └────────────────────────┬─────────────────────────────────┘
                          │
                          ▼
 ┌──────────────────────────────────────────────────────────┐
 │                   Kernel nftables table                    │
 │                   inet/nftgeo (atomic)                     │
 └──────────────────────────────────────────────────────────┘
```

## Rule evaluation order

Every managed chain evaluates in this fixed order — regardless of file
order or line sequence:

```
 ┌─────────────────────────────────────────────────────┐
 │  CHAIN (input / output / forward)                    │
 │                                                      │
 │  1. ct state established,related  ← replies always   │
 │  2. @whitelist                     ← always-allow IP  │
 │  3. ct state invalid               ← drop bad state  │
 │  4. deny rules (incl. abuse)       ← explicit blocks │
 │  5. allow rules                    ← explicit opens  │
 │  6. deny-by-default                ← port closed if  │
 │                                       any allow rule  │
 │                                       touched it     │
 └─────────────────────────────────────────────────────┘
```

**Key insight:** a port with any `allow` rule becomes closed by default —
only listed sources get through. A port you never mention stays open.

## What nftgeo does

- **Geo-filter** — allow/deny by country (`pl`), region (`europe`), or literal IP/CIDR
- **Abuse blocklist** — AbuseIPDB + custom feeds, scoped exactly where you want
- **Whitelist** — trusted IPs that always bypass everything (protects admin access)
- **Throttle** — reactive per-source rate-limiting with auto-ban (brute-force defense)
- **Synproxy** — SYN-flood protection via kernel synproxy
- **NAT** — masquerade, SNAT, DNAT (port-forward) for gateway/router setups
- **Zones** — internal firewall segmentation (VLANs, inter-zone rules)
- **Dashboard** — local web UI with visual policy editor, drop map, live stats
- **Safe apply** — deadman switch auto-rolls-back changes that lock you out

## Quick start

### Install

```sh
# From package (.deb / .rpm)
sudo apt install ./nftgeo_<version>_amd64.deb
sudo dnf install ./nftgeo-<version>-1.x86_64.rpm

# Or from source
cd /root/nftgeo && sudo ./install.sh
```

### Write your first rule

```sh
sudoedit /etc/nftgeo/rules.conf
```

```text
# Allow SSH from Europe, block known abuse IPs everywhere
allow in tcp 22 europe
deny  in any -  abuse
```

### Apply

```sh
sudo nftgeo apply --confirm      # apply with 120s auto-rollback safety net
# ... verify you still have access ...
sudo nftgeo apply --commit       # keep the change
```

> **Don't lock yourself out!** The moment you add `allow in tcp 22 europe`,
> port 22 is closed to everyone outside Europe. Put your admin IP in
> `WHITELIST` in `/etc/nftgeo/config` first.

## Rule syntax

```
<action> <dir> <proto> <port> <target> [on <iface>] [# comment]
```

| Field   | Values                                                              |
|---------|---------------------------------------------------------------------|
| action  | `allow` · `deny` · `throttle` · `synproxy` · `masquerade` · `snat` · `dnat` |
| dir     | `in` · `out` · `fwd-in` · `fwd-out`                                |
| proto   | `tcp` · `udp` · `sctp` · `all` · `any` · `icmp` · `icmpv6` · `esp` · `ah` · `gre` |
| port    | `22` · `5060-5070` · `80,443` · service name · `-` (portless)       |
| target  | country `pl` · region `europe` · IP `203.0.113.5` · CIDR `10.0.0.0/8` · group `office` · `any` · `abuse` |
| iface   | optional `on eth0` — scope to one interface                         |

### Examples

```text
# Geo-filtering
allow in  tcp 22     europe          # SSH from Europe only
allow in  tcp 443    any             # HTTPS open to the world
deny  in  any -      ru,cn           # Block Russia + China everywhere
deny  in  any -      abuse           # Drop AbuseIPDB blocklist

# Throttle (auto-ban brute force)
throttle in tcp 22   5/minute        # >5 SSH conns/min → ban 1h
throttle in tcp 3389 3/minute ban 2h # custom ban duration

# SYN-flood protection
synproxy in tcp 80,443               # offload handshake for web ports

# NAT (gateway — needs ip_forward=1)
masquerade on eth0                   # NAT LAN out via WAN
dnat tcp 443 to 10.0.0.5:8443       # port-forward WAN:443 → internal

# Internal firewall (zones)
allow lan  -> dmz  tcp 80            # LAN → DMZ web server
deny  dmz  -> lan  any -             # DMZ can't reach LAN
```

## Service templates

nftgeo ships **21 built-in templates** for common services. Import them from
the dashboard's Templates drawer, or copy from `examples/`:

| Template | Service | Key ports |
|----------|---------|-----------|
| `safe-web` | Web server | 80, 443 |
| `nginx` | Nginx | 80, 443, 22 |
| `mail-server` | Mail (SMTP/IMAP) | 25, 465, 587, 993 |
| `kamailio` | Kamailio SIP | 5060, 5061, 10000-20000 |
| `ssh-lockdown` | SSH (group-locked) | 22 |
| `wireguard` | WireGuard VPN | 51820, 22 |
| `openvpn` | OpenVPN | 1194/udp, 22 |
| `redis` | Redis | 6379 |
| `postgres` | PostgreSQL | 5432 |
| `mysql` | MySQL/MariaDB | 3306 |
| `gitlab` | GitLab | 80, 443, 22 |
| `docker-registry` | Docker Registry | 5000 |
| `elasticsearch` | Elasticsearch | 9200, 9300 |
| `grafana` | Grafana | 3000 |
| `prometheus-stack` | Prometheus + Grafana | 9090, 3000 |
| `dns-server` | DNS (BIND/unbound) | 53 |
| `minecraft` | Minecraft | 25565, 25575 |
| `mosh` | Mosh shell | 22, 60000-61000/udp |
| `abuse-block` | Abuse blocklist | — |
| `geo-drop` | Geo-drop | — |
| `geo-drop` | Geo-drop | — |

Each template includes abuse filtering and uses placeholder group names
(`ADMINS`, `APPS`, `MONITORING`) — create the groups in the Objects tab
and edit the targets to fit your setup.

## Configuration

Everything lives in `/etc/nftgeo`:

```
/etc/nftgeo/
  config            # settings: AbuseIPDB key, WHITELIST, WHITELIST_HOSTS, regions, groups
  rules.conf        # rules (optional if you only use rules.d)
  rules.d/*.conf    # rule fragments, included in sorted filename order
  groups.d/*.conf   # GROUP_*/REGION_* definitions, sourced after config
```

### Key config variables

| Variable | Purpose |
|----------|---------|
| `WHITELIST` | Always-allow IPs/CIDRs (space-separated, IPv4+IPv6) |
| `WHITELIST_HOSTS` | Hostnames to whitelist (re-resolved each run) |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key (enables `deny ... abuse`) |
| `ABUSE_FEEDS` | Extra plaintext blocklist URLs |
| `HARDEN` | Baseline: accept loopback, drop invalid, ICMPv6 |
| `LOG_DROPS` | Log dropped packets to journald |
| `DEFAULT_INPUT` | `drop` for default-deny input chain |
| `SEGMENT_DEFAULT` | `deny` for default-deny between zones |
| `ZONE_CACHE_HOURS` | Country zone refresh interval (default 20h) |

### Reusable objects (in config or `groups.d/*.conf`)

```sh
GROUP_OFFICE="203.0.113.5 198.51.100.0/24"     # address group
REGION_NORDICS="dk fi is no se"                 # custom region
SERVICE_WEB="80 443"                            # named ports
HOST_DB1="10.0.20.5"                            # host label
ZONE_LAN="eth1"                                 # network segment
```

## Whitelist

The whitelist is your safety net — these IPs always bypass geo rules,
abuse blocklists, and deny-by-default:

```sh
WHITELIST="203.0.113.10 198.51.100.0/24 2001:db8::/48"
WHITELIST_HOSTS="vpn.example.ch"       # re-resolved on each run
```

### Managing whitelist from the dashboard

The Objects → Reference tab shows all whitelist entries with:
- **+ Add** button — add an IP/CIDR or hostname
- **🗑** button per entry — remove with confirmation

Changes write to `/etc/nftgeo/config` and take effect on the next
`nftgeo apply` or scheduled refresh.

### Rule statistics

`GET /api/rule-stats` returns a breakdown of all rules:

```json
{
  "allow": 5, "deny": 3, "throttle": 1, "synproxy": 0,
  "nat": 0, "zone": 0, "total": 9,
  "denyAbuse": 2, "allowAny": 1,
  "whitelistIPs": 3, "whitelistHosts": 1, "whitelistTotal": 4,
  "whitelistHits": 15432
}
```

This tells you how many rules route through the whitelist path vs
deny vs allow — useful for auditing your policy posture.

## Operator CLI

```sh
nftgeo status              # version, sets, drop counters, next run
nftgeo check 203.0.113.7   # what does the firewall do to this IP?
nftgeo validate            # check config renders/loads, without applying
nftgeo plan                # show how rendered ruleset differs from loaded
nftgeo block 203.0.113.7 1h # drop an address now (no reload)
nftgeo unblock 203.0.113.7 # remove a dynamic block
nftgeo blocklist           # list current dynamic blocks + TTL
nftgeo apply               # rebuild and load now
nftgeo apply --confirm     # apply with auto-rollback safety net
nftgeo apply --commit      # keep the change (cancel rollback)
nftgeo rollback            # restore previous generation
```

## Web dashboard

nftgeo includes a local web UI — a world map of drops, live stats,
and a visual policy editor with a safe Draft → Commit pipeline:

```
 ┌─────────────────────────────────────────────────────┐
 │                  Dashboard (:8787)                    │
 │                                                       │
 │  ┌──────────┐  ┌──────────┐  ┌──────────┐           │
 │  │ Drop Map  │  │  Stats   │  │  Alerts  │           │
 │  │ (world)   │  │ (live)   │  │ (banner) │           │
 │  └──────────┘  └──────────┘  └──────────┘           │
 │                                                       │
 │  ┌───────────────────────────────────────────┐       │
 │  │            Policy Editor                    │       │
 │  │  ┌─────┬───────┬──────┬─────┬──────┐      │       │
 │  │  │  №  │ Src   │ Dst  │ Svc │ Act  │      │       │
 │  │  ├─────┼───────┼──────┼─────┼──────┤      │       │
 │  │  │  1  │ EU    │ any  │ 22  │ ✓    │      │       │
 │  │  │  2  │ abuse │ any  │  *  │ ✗    │      │       │
 │  │  └─────┴───────┴──────┴─────┴──────┘      │       │
 │  │  [+ Rule] [+ Throttle] [+ NAT] [+ Zone]   │       │
 │  └───────────────────────────────────────────┘       │
 │                                                       │
 │  ┌───────────────────────────────────────────┐       │
 │  │  Objects: Groups · Regions · Services      │       │
 │  │           Hosts · Zones · Whitelist (+/🗑) │       │
 │  └───────────────────────────────────────────┘       │
 │                                                       │
 │  ┌───────────────────────────────────────────┐       │
 │  │  [Commit / Deploy bar — pending: 3]        │       │
 │  │  validate → plan diff → apply --confirm    │       │
 │  └───────────────────────────────────────────┘       │
 └─────────────────────────────────────────────────────┘
```

```sh
sudo systemctl enable --now nftgeo-ui
sudo nftgeo-ui token            # read-write login link (15 min)
sudo nftgeo-ui token --ro       # long-lived read-only link
```

### Draft → Commit pipeline

All edits go through a safe pipeline — the live firewall is never
touched until you explicitly deploy:

```
  Edit draft  →  Commit  →  validate  →  plan (diff)
                                         │
                                    ┌────┴────┐
                                    ▼         ▼
                              apply --confirm  cancel
                                    │
                              ┌─────┴─────┐
                              ▼           ▼
                           Keep        Roll back
                        (commit)    (auto after 120s)
```

## How rules are built (example)

For this `rules.conf`:

```text
allow in tcp 22 europe
deny  in any -  abuse
allow in icmp - any
```

The generated nftables chain:

```text
chain input {
    ct state established,related counter accept       # replies always allowed
    ip saddr @whitelist4 counter accept               # whitelist wins first
    ip saddr @abuse4 counter drop                     # deny in any - abuse
    tcp dport 22 ip saddr @g_europe4 counter accept   # geo allow
    meta l4proto icmp counter accept                  # icmp "any"
    tcp dport 22 counter drop                         # deny-by-default
}
```

The table is replaced atomically — no moment where rules are missing.
If a country zone can't be downloaded, the update aborts and leaves
the previous ruleset in place (fail-safe).

## Architecture

```
  ┌─────────────┐     ┌──────────────┐     ┌───────────────┐
  │  rules.conf  │     │   config     │     │  groups.d/    │
  │  rules.d/    │     │ (WHITELIST,  │     │  (GROUP_*,    │
  │  (*.conf)    │     │  ABUSE, ...) │     │   REGION_*)   │
  └──────┬───────┘     └──────┬───────┘     └──────┬────────┘
         │                    │                     │
         └────────────┬───────┴─────────────────────┘
                      ▼
           ┌──────────────────────┐
           │   nftgeo-update       │  (bash engine)
           │   bin/nftgeo-update   │
           └──────────┬───────────┘
                      │
          ┌───────────┼───────────┐
          ▼           ▼           ▼
    ┌──────────┐ ┌────────┐ ┌──────────┐
    │ ipdeny   │ │AbuseIPDB│ │  feeds   │
    │ (zones)  │ │  (API)  │ │ (URLs)   │
    └──────────┘ └────────┘ └──────────┘
                      │
                      ▼
           ┌──────────────────────┐
           │  nft -f (atomic load) │
           │  inet/nftgeo table    │
           └──────────┬───────────┘
                      │
                      ▼
           ┌──────────────────────┐
           │    nftgeo-ui (Go)     │  (dashboard)
           │    ui/main.go         │
           │    :8787 localhost    │
           └──────────────────────┘
```

**Two components:**
- **Engine** (`bin/nftgeo-update`) — bash script, runs via systemd timer
- **UI** (`ui/main.go`) — Go binary, serves local dashboard

The UI is a *view + editor* over the config files — never a second source
of truth. Every change flows through the engine's own `validate → plan →
apply` pipeline.

## Update schedule

The systemd timer runs:
- 2 minutes after boot
- Twice daily (03:00 and 15:00)
- With up to 30 min random delay

## Requirements

- Debian or Ubuntu
- `systemd`, `nftables`, `curl`
- root access
- AbuseIPDB API key (optional — only for `deny ... abuse` rules)

## Development

```sh
# Shell tests (render harness)
sh tests/render/run.sh

# Go tests
go test ./ui/

# Real nft validation (needs root + nftables)
sudo sh tests/render/nft-check.sh
```

Render tests live in `tests/render/cases/<name>/` — each has a `config`,
`rules.conf`, and an `assert` file. Add a case when you fix a bug or add
a rule form.

## Files

```
/etc/nftgeo/config          settings (whitelist, abuse, feeds, logging)
/etc/nftgeo/rules.conf      rules
/etc/nftgeo/rules.d/*.conf  rule fragments (sorted order)
/etc/nftgeo/groups.d/*.conf GROUP_*/REGION_* definitions
/var/lib/nftgeo/            state: zones, feeds, abuseipdb.tsv, generations/
/etc/nftables.d/nftgeo.nft  the generated, loaded ruleset
```

## Data sources

- AbuseIPDB: `https://api.abuseipdb.com/api/v2/blacklist`
- Country IP prefixes: `https://www.ipdeny.com`

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the full plan. In short:

- ✅ Geo/abuse filtering, CLI, HARDEN, throttle, synproxy, NAT, zones
- ✅ Dashboard: drop map, stats, policy editor, objects, templates
- 🔜 Hairpin NAT, Prometheus metrics, multi-host fleet mode

## License

See [LICENSE](LICENSE).
