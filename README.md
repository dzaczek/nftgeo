# nftgeo


https://github.com/user-attachments/assets/2dcec705-e08b-4702-aec9-d42b21d051c6


**Declarative geo-aware firewall manager for Linux nftables.**

Stop hand-feeding nftables country IP sets. Write a readable policy that says
"allow SSH from Europe, block AbuseIPDB on every port, let the LAN browse out"
— and let nftgeo resolve the geo zones, fetch the blocklists, render the
nftables ruleset, validate it, and load it atomically.

```text
# /etc/nftgeo/rules.conf — your entire firewall policy in five columns
deny  in tcp 22 abuse              # drop blocklisted IPs on SSH
allow in tcp 22 europe             # SSH only from Europe
allow in tcp 22 203.0.113.10       # ...and one admin IP
deny  in tcp 22 any                # close SSH to everyone else
deny  in any -  abuse              # drop blocklisted IPs everywhere inbound
allow out udp 53 any               # outbound DNS
```

One `nftgeo apply --confirm` builds the full ruleset — geo sets, abuse sets,
whitelist, counters — validates it with `nft -c`, and loads it atomically with
`nft -f`. If you lose SSH, the deadman rolls back automatically.

---

## Why nftgeo?

Managing geo/IP rules in raw nftables means maintaining thousands of IP
prefixes by hand, fetching zone files from ipdeny, deduplicating blocklists,
and praying you don't typo a set reference and drop your own SSH session.
nftgeo does all of that for you:

- **Human-readable policy.** Rules read like sentences: `allow in tcp 22 europe`.
  No nftables syntax, no set management, no script glue.
- **Geo & blocklist sets, resolved for you.** Country zones from ipdeny.com,
  AbuseIPDB + custom feed blocklists, all fetched, cached, deduplicated, and
  collapsed into CIDR ranges — automatically, on a schedule.
- **Direction-aware.** `in` / `out` / `fwd-in` / `fwd-out` — match by source
  or destination, for the host itself or for routed/gateway traffic.
- **Safe by design.** Validate before load (`nft -c`), atomic table replacement
  (`nft -f`), a deadman auto-rollback on every apply, and a whitelist that
  always wins over everything else.
- **Stateful.** Replies to your own connections are always allowed — a pure
  client needs no rules at all.
- **More than geo.** Reactive brute-force throttling, SYN-flood protection
  (synproxy), anti-spoofing (uRPF), NAT gateway (masquerade/SNAT/DNAT), and
  inter-zone segmentation with default-deny — all from the same `rules.conf`.
- **Per-rule counters.** Every generated rule carries a counter, so `nft list`
  shows exactly what's hitting what.
- **Operator CLI + optional web dashboard.** `nftgeo status`, `nftgeo check <ip>`,
  `nftgeo block`, `nftgeo plan` — plus a local web UI with a world map of drops
  and a visual policy editor with draft → commit → deadman safety.
- **One tool, not a stack.** No Python, no Docker, no database. A shell engine
  + a Go binary + systemd. Runs on any Debian/Ubuntu VPS.

### Who is this for?

- **Linux admins** who want geo-restricted SSH/RDP/SIP without hand-crafted nftables
- **VPS / server owners** exposing SSH, HTTP(S), mail, or VPN endpoints
- **Homelab users** who want a real firewall without learning nftables syntax
- **Small infrastructure teams** who need a declarative, reviewable, testable policy
- **Gateway / VPN hosts** that route or NAT traffic between networks

---

## Quick example

```text
# /etc/nftgeo/rules.conf

# --- SSH: Europe + admin IP only ---
deny  in tcp 22 abuse
allow in tcp 22 europe
allow in tcp 22 203.0.113.10
deny  in tcp 22 any

# --- Public web server ---
deny  in tcp 80,443 abuse
allow in tcp 80,443 any

# --- Block known-bad IPs everywhere ---
deny  in any - abuse

# --- Outbound DNS ---
allow out udp 53 any

# --- Brute-force protection ---
throttle in tcp 22 5/minute        # >5 new SSH conns/min → auto-ban 1h
```

Apply it safely:

```sh
sudo nftgeo validate                 # check the config renders & passes nft -c
sudo nftgeo plan                     # see what would change vs what's loaded
sudo nftgeo apply --confirm          # apply with a 120s auto-rollback deadman
# ... verify you still have SSH access ...
sudo nftgeo apply --commit           # keep it
```

---

## How it works

```
 ┌──────────────────────────────────────────────────────────┐
 │  You write rules.conf                                      │
 │      allow in tcp 22 europe                                │
 │      deny  in any -  abuse                                 │
 └───────────────────────────┬──────────────────────────────┘
                             ▼
 ┌──────────────────────────────────────────────────────────┐
 │  nftgeo-update engine                                     │
 │   1. parse rules.conf + rules.d/*.conf                    │
 │   2. resolve geo zones (ipdeny.com, cached)               │
 │   3. fetch AbuseIPDB + feed blocklists (dedup + aggregate)│
 │   4. render nftables ruleset                              │
 │   5. validate (nft -c)                                    │
 │   6. atomic load (nft -f)                                 │
 └───────────────────────────┬──────────────────────────────┘
                             ▼
 ┌──────────────────────────────────────────────────────────┐
 │  Kernel nftables table  inet/nftgeo  (loaded atomically)  │
 └──────────────────────────────────────────────────────────┘
```

The engine is a POSIX shell script (`nftgeo-update`, ~1700 lines) that parses
your policy, downloads and caches geo zones, fetches and deduplicates
blocklists, renders a complete nftables ruleset, validates it with `nft -c`,
and loads it atomically with `nft -f`. A `systemd` timer refreshes everything
twice a day.

---

## Installation

### Option A: Package (.deb / .rpm)

Grab the package for your arch from the [latest
release](https://github.com/dzaczek/nftgeo/releases/latest):

```sh
sudo apt install ./nftgeo_<version>_amd64.deb     # Debian/Ubuntu
sudo dnf install ./nftgeo-<version>-1.x86_64.rpm   # Fedora/RHEL
```

Packages install to FHS paths (`/usr/sbin`, `/etc/nftgeo`,
`/usr/lib/systemd/system`), seed `config` / `rules.conf` on first install (never
clobbering existing files), and enable **nothing** automatically.

### Option B: From source (Debian/Ubuntu)

```sh
git clone https://github.com/dzaczek/nftgeo.git
cd nftgeo
sudo ./install.sh
```

The installer installs `curl` / `nftables` / `ca-certificates`, copies the
engine and CLI to `/usr/sbin`, creates `/etc/nftgeo/{config,rules.conf}`
plus empty `rules.d/` and `groups.d/`, installs `nftgeo.service` +
`nftgeo.timer`, and enables the service at boot and the twice-daily timer.

### Requirements

- Debian or Ubuntu (the `install.sh` path uses `apt-get`)
- `systemd`, `nftables`, `curl`
- root access
- An AbuseIPDB API key (only if you use the `abuse` target — the tool works
  fine without it; abuse sets stay empty)

---

## Quick start

```sh
# 1. Install (package or install.sh — see above)

# 2. Add your admin IP to the whitelist FIRST (prevents lockout)
sudoedit /etc/nftgeo/config
#   WHITELIST="YOUR.IP.ADDRESS.HERE"

# 3. Write your rules
sudoedit /etc/nftgeo/rules.conf
#   allow in tcp 22 europe
#   deny  in tcp 22 any

# 4. Validate before applying
sudo nftgeo validate

# 5. Apply with the deadman (auto-rollback if you lose access)
sudo nftgeo apply --confirm

# 6. If you still have SSH, keep the change
sudo nftgeo apply --commit

# 7. Enable the scheduled refresh (twice-daily geo/abuse updates)
sudo systemctl enable --now nftgeo.timer

# 8. Optional: start the web dashboard on 127.0.0.1:8787
sudo systemctl enable --now nftgeo-ui.service
sudo nftgeo-ui token    # get a one-time login link
```

---

## 🚀 Fast track / Schnellstart / Szybki start

Three steps from zero to a running geo-firewall. **Before you start:** know your
own public IP address and be physically near the machine or have console access.

### English

```sh
# 1. Install
git clone https://github.com/dzaczek/nftgeo.git && cd nftgeo && sudo ./install.sh

# 2. Whitelist YOUR IP first — prevents lockout
echo 'WHITELIST="YOUR.PUBLIC.IP"' | sudo tee -a /etc/nftgeo/config

# 3. Add your first rules
cat <<'EOF' | sudo tee /etc/nftgeo/rules.conf
allow in tcp 22 YOUR.PUBLIC.IP   # SSH from your IP only
deny  in tcp 22 any              # close SSH to everyone else
deny  in any - abuse             # block known-bad IPs
allow out udp 53 any             # outbound DNS
EOF

# 4. Add AbuseIPDB key + custom blocklists (optional but recommended)
sudoedit /etc/nftgeo/config
#   ABUSEIPDB_API_KEY="your-key-from-abuseipdb.com"
#   ABUSE_FEEDS="https://blocklist.greensnow.co/greensnow.txt
#   https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/refs/heads/main/abuseipdb-s100-3d.ipv4
#   https://raw.githubusercontent.com/ShadowWhisperer/IPs/refs/heads/master/Lists/Threats
#   https://raw.githubusercontent.com/ShadowWhisperer/IPs/refs/heads/master/Lists/Probes
#   https://raw.githubusercontent.com/duggytuxy/Data-Shield_IPv4_Blocklist/refs/heads/main/prod_data-shield_ipv4_blocklist.txt"

# 5. Validate & apply safely
sudo nftgeo validate && sudo nftgeo apply --confirm
# ... verify you still have SSH ...
sudo nftgeo apply --commit

# 6. Enable auto-refresh (twice-daily geo + blocklist updates)
sudo systemctl enable --now nftgeo.timer

# 7. Start the web dashboard
sudo systemctl enable --now nftgeo-ui.service
sudo nftgeo-ui token       # → open the link in your browser
```

### Deutsch

```sh
# 1. Installation
git clone https://github.com/dzaczek/nftgeo.git && cd nftgeo && sudo ./install.sh

# 2. Eigene IP ZUERST whitelisten — verhindert Aussperrung
echo 'WHITELIST="DEINE.ÖFFENTLICHE.IP"' | sudo tee -a /etc/nftgeo/config

# 3. Erste Regeln eintragen
cat <<'EOF' | sudo tee /etc/nftgeo/rules.conf
allow in tcp 22 DEINE.ÖFFENTLICHE.IP   # SSH nur von deiner IP
deny  in tcp 22 any                    # SSH für alle anderen schließen
deny  in any - abuse                   # bekannte schädliche IPs blocken
allow out udp 53 any                   # ausgehendes DNS
EOF

# 4. AbuseIPDB-Key + eigene Blocklisten (optional, aber empfohlen)
sudoedit /etc/nftgeo/config
#   ABUSEIPDB_API_KEY="dein-key-von-abuseipdb.com"
#   ABUSE_FEEDS="https://blocklist.greensnow.co/greensnow.txt
#   https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/refs/heads/main/abuseipdb-s100-3d.ipv4
#   https://raw.githubusercontent.com/ShadowWhisperer/IPs/refs/heads/master/Lists/Threats
#   https://raw.githubusercontent.com/ShadowWhisperer/IPs/refs/heads/master/Lists/Probes
#   https://raw.githubusercontent.com/duggytuxy/Data-Shield_IPv4_Blocklist/refs/heads/main/prod_data-shield_ipv4_blocklist.txt"

# 5. Validieren & sicher anwenden
sudo nftgeo validate && sudo nftgeo apply --confirm
# ... prüfen, ob SSH noch funktioniert ...
sudo nftgeo apply --commit

# 6. Automatische Aktualisierung aktivieren
sudo systemctl enable --now nftgeo.timer

# 7. Web-Dashboard starten
sudo systemctl enable --now nftgeo-ui.service
sudo nftgeo-ui token       # → Link im Browser öffnen
```

### Polski

```sh
# 1. Instalacja
git clone https://github.com/dzaczek/nftgeo.git && cd nftgeo && sudo ./install.sh

# 2. NAJPIERW dodaj własne IP do whitelisty — zapobiega zablokowaniu się
echo 'WHITELIST="TWOJE.PUBLICZNE.IP"' | sudo tee -a /etc/nftgeo/config

# 3. Dodaj pierwsze reguły
cat <<'EOF' | sudo tee /etc/nftgeo/rules.conf
allow in tcp 22 TWOJE.PUBLICZNE.IP   # SSH tylko z Twojego IP
deny  in tcp 22 any                  # zamknij SSH dla całej reszty
deny  in any - abuse                 # blokuj znane złośliwe IP
allow out udp 53 any                 # wychodzący DNS
EOF

# 4. Klucz AbuseIPDB + własne listy blokowanych IP (opcjonalne, zalecane)
sudoedit /etc/nftgeo/config
#   ABUSEIPDB_API_KEY="twój-klucz-z-abuseipdb.com"
#   ABUSE_FEEDS="https://blocklist.greensnow.co/greensnow.txt
#   https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/refs/heads/main/abuseipdb-s100-3d.ipv4
#   https://raw.githubusercontent.com/ShadowWhisperer/IPs/refs/heads/master/Lists/Threats
#   https://raw.githubusercontent.com/ShadowWhisperer/IPs/refs/heads/master/Lists/Probes
#   https://raw.githubusercontent.com/duggytuxy/Data-Shield_IPv4_Blocklist/refs/heads/main/prod_data-shield_ipv4_blocklist.txt"

# 5. Zweryfikuj i zastosuj bezpiecznie
sudo nftgeo validate && sudo nftgeo apply --confirm
# ... sprawdź, czy SSH nadal działa ...
sudo nftgeo apply --commit

# 6. Włącz automatyczne odświeżanie (dwa razy dziennie)
sudo systemctl enable --now nftgeo.timer

# 7. Uruchom dashboard webowy
sudo systemctl enable --now nftgeo-ui.service
sudo nftgeo-ui token       # → otwórz link w przeglądarce
```

---

## Rule model

Rules are evaluated top-to-bottom, **first match wins** — like a classic
firewall. A fixed baseline runs first, then your rules in file order:

```
 ┌──────────────────────────────────────────────────────────┐
 │  CHAIN (input / output / forward)                         │
 │   1. lo accept                    ← loopback always       │
 │   2. ct state invalid   → drop    ← bad state             │
 │   3. ct state established,related ← replies to your conns │
 │   4. @whitelist         → accept  ← always-allow IPs      │
 │   5. throttle / synproxy          ← rate-limit / SYN guard│
 │   6. your allow/deny rules        ← in FILE ORDER,        │
 │                                     first match wins      │
 │   7. chain policy (accept/drop)   ← DEFAULT_INPUT (input) │
 └──────────────────────────────────────────────────────────┘
```

**Default policy is `accept`** (selective blocklist): only what your rules
explicitly deny is dropped; everything else passes. Set
`DEFAULT_INPUT="drop"` in `config` for a **default-deny** posture (only
established/related, loopback, whitelist, and your explicit `allow in` rules
get in).

There is **no automatic deny-by-default per port**. To close a port to everyone
except a target, `allow` the target and then add a catch-all `deny ... any`
below it. `validate` warns when a geo-restricted `allow in` has no catch-all
deny, so you don't leave a port open by accident.

### Rule syntax

```
<action> <dir> <proto> <port> <target> [on <iface>] [log] [# comment]
```

| Field | Values | Notes |
|-------|--------|-------|
| `action` | `allow` \| `deny` | `deny` drops without closing the port for others |
| `dir` | `in` \| `out` \| `fwd-in` \| `fwd-out` | `in`/`out` = host traffic; `fwd-*` = routed/gateway |
| `proto` | `tcp` `udp` `sctp` `all` \| `icmp` `icmpv6` `esp` `ah` `gre` \| `any` | `all` = tcp+udp; `any` = every protocol |
| `port` | `22` \| `5060-5070` \| `80,443` \| service name \| `-` | `-` or blank = every port of the proto |
| `target` | country `pl` · region `europe` · IP `203.0.113.5` · CIDR `10.0.0.0/8` · group `office` · host `db1` · `any` · `abuse` | Comma-separated mix allowed; `abuse` is deny-only |
| `on <iface>` | optional | Scope to one interface (`iifname` for `in`/`fwd-in`, `oifname` for `out`/`fwd-out`) |
| `log` | optional | Log connections this rule matches (independent of `LOG_DROPS`) |

**Built-in service names** resolve in the port field without configuration:
`ssh`, `http`, `https`, `dns`, `smtp`, `rdp`, `postgres`, `wireguard`,
`grafana`, and more (`nftgeo-update --services` lists them all). Define your
own with `SERVICE_<NAME>` in config.

**Built-in regions:** `europe`, `north_america`, `caribbean`, `south_america`,
`middle_east`, `asia`, `africa`, `oceania`. Override or add your own via
`REGION_<NAME>` in config.

### Special rule types

| Type | Syntax | Example |
|------|--------|---------|
| **Throttle** | `throttle <in\|fwd-in> <tcp\|udp> <port> <N/sec\|min\|hour> [ban <dur>] [on <iface>]` | `throttle in tcp 22 5/minute` |
| **SYN proxy** | `synproxy <in\|fwd-in> tcp <port> [on <iface>]` | `synproxy in tcp 80,443` |
| **Masquerade** | `masquerade on <wan> [in <lan>]` | `masquerade on eth0` |
| **SNAT** | `snat out on <wan> to <ip>` | `snat out on eth0 to 203.0.113.7` |
| **DNAT** | `dnat <proto> <port> to <ip>[:<port>] [from <geo>] [on <iface>]` | `dnat tcp 8080 to 10.0.0.5:80 on eth0` |
| **Inter-zone** | `allow\|deny <zone> -> <zone> <proto> <port> [from <geo>]` | `allow lan -> dmz tcp 80` |

### Ingress (early stateless drop)

For DDoS-grade early filtering, put `<accept|drop> <target> [proto] [port] [log]`
rules in `/etc/nftgeo/ingress.conf` (and `ingress.d/*.conf`). They run in the
nftables **ingress** hook — before prerouting and conntrack — so you can shed the
`abuse` set or bad geos the moment packets hit the NIC, before they cost routing
or conntrack CPU:

```text
drop  abuse                # drop the AbuseIPDB set at ingress
drop  cn,ru                # geo early-drop
accept 203.0.113.0/24      # explicit early accept (whitelist is auto-accepted first)
drop  any tcp 22 log       # drop SSH at ingress except whitelisted sources
```

It is **source-based** (no `dir`) and **stateless** (no `ct state`), so it drops
matching packets regardless of connection state — an extra early layer, not a
replacement for `deny … abuse` filter rules. The whitelist is always accepted
first and can never be dropped here. Opt-in: no `ingress.conf` means no ingress
chain at all. Requires Linux ≥ 5.10 (inet ingress); `validate` + the deadman catch
an unsupported kernel safely. The ingress hook is **per-interface** — set
`INGRESS_DEV` (space-separated) in the config, or the default-route interface is
auto-detected.

### Config objects

Define reusable objects in `/etc/nftgeo/config` (or `groups.d/*.conf`):

```sh
# Address groups (mix IPs, CIDRs, countries, regions)
GROUP_OFFICE="203.0.113.5 198.51.100.0/24 2001:db8:1::/48"
GROUP_PARTNERS="de fr 192.0.2.0/24"

# Host labels (single IP/CIDR)
HOST_DB1="10.0.20.5"

# Service objects (named ports, nestable)
SERVICE_WEB="80 443"
SERVICE_STACK="web 8080-8090"        # services can nest other services
SERVICE_DNS="53/tcp 53/udp"          # /proto-tagged member

# Zones (internal firewall / segmentation)
ZONE_LAN="eth1"
ZONE_DMZ="eth2"
ZONE_GUEST="eth0.100"                # VLAN subinterface = just an interface
SEGMENT_DEFAULT="deny"              # micro-segmentation: default-deny between zones
```

---

## Configuration

Everything lives in `/etc/nftgeo`:

```text
/etc/nftgeo/
  config            # settings: AbuseIPDB key, WHITELIST, regions, groups, logging
  rules.conf        # rules (optional if you only use rules.d)
  rules.d/*.conf    # rule fragments, included in sorted filename order
  groups.d/*.conf   # GROUP_*/REGION_* definitions, sourced after config
  whitelist.conf    # always-allow IPs (one per line, comments allowed)
  whitelist-hosts.conf  # always-allow hostnames (re-resolved each run)
```

`rules.conf` is read first, then every `rules.d/*.conf` in `LC_ALL=C` sorted
filename order — use numeric prefixes (`10-ssh.conf`, `20-web.conf`) to make
the order obvious. `groups.d/*.conf` is sourced after `config`, in sorted
order.

### Key config options

| Option | Default | Purpose |
|--------|---------|---------|
| `WHITELIST` | `""` | Always-allow IPs (bypasses all rules + abuse) |
| `WHITELIST_HOSTS` | `""` | Hostnames to whitelist (re-resolved each run) |
| `ABUSEIPDB_API_KEY` | `""` | AbuseIPDB API key (only needed for `abuse` target; can also be saved from the dashboard's Reference tab) |
| `ABUSE_FEEDS` | `""` | Extra plaintext IP/CIDR blocklists (FireHOL, Spamhaus, etc.) |
| `DEFAULT_INPUT` | `accept` | Input chain policy: `accept` (selective) or `drop` (default-deny) |
| `DEFAULT_OUTPUT` / `DEFAULT_FORWARD` | `accept` | Output/forward chain policy; `drop` = strict egress/routing (only established, loopback, essential ICMPv6, and your `allow out`/`allow fwd-*` rules pass). Deploy behind the deadman |
| `LOG_DROPS` | `""` (off) | Log dropped packets to kernel log / journald |
| `LOG_WHITELIST` | `""` (off) | Log whitelist hits as `nftgeo-accept:whitelist` |
| `NFLOG_GROUP` | `5` | Also deliver `log` packets to this NFLOG group so the dashboard sees drops inside containers (LXC/OpenVZ). `0` = kernel log only |
| `HARDEN` | `""` (off) | Baseline: accept loopback, drop invalid, permit essential ICMPv6, rate-limit ping |
| `ICMP_RATE` / `ICMP_BURST` | `1/second` / `5` | With `HARDEN`, rate-limit inbound ping (echo-request); `0` disables |
| `ANTISPOOF` | `""` | Interfaces to protect with strict uRPF (reverse-path filter) |
| `ZONE_CACHE_HOURS` | `20` | How long downloaded country zones are reused |
| `SEGMENT_DEFAULT` | `""` | `deny` = default-deny between zones (micro-segmentation) |

### Custom blocklist feeds

`ABUSE_FEEDS` takes a space- or newline-separated list of URLs pointing to
plain-text IP/CIDR blocklists. Any feed format that's one address per line with
optional comments (`#` or `;`) works: FireHOL, Spamhaus DROP, blocklist.de,
GreenSnow, ShadowWhisperer, duggytuxy, etc.

```sh
ABUSE_FEEDS="https://blocklist.greensnow.co/greensnow.txt
https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/refs/heads/main/abuseipdb-s100-3d.ipv4
https://raw.githubusercontent.com/ShadowWhisperer/IPs/refs/heads/master/Lists/Threats
https://raw.githubusercontent.com/ShadowWhisperer/IPs/refs/heads/master/Lists/Probes
https://raw.githubusercontent.com/duggytuxy/Data-Shield_IPv4_Blocklist/refs/heads/main/prod_data-shield_ipv4_blocklist.txt"
```

- Feeds are only downloaded when a `deny … abuse` rule exists — no rule, no fetch.
- Bogon/private/reserved ranges are stripped automatically (RFC1918, loopback, CGNAT, multicast, documentation).
- Each feed's last good copy is cached under `/var/lib/nftgeo/feeds` — a download failure reuses the cache, so a feed outage never shrinks your blocklist.
- `ABUSE_FEEDS_MAX` (default 200000) caps entries per feed so a runaway list can't build a giant slow set.
- `ABUSE_FEEDS_AGGREGATE` (default on) collapses IPs into CIDR ranges before loading.
- `ABUSE_FEEDS_BATCH` (default 0, off) loads a huge set in paced chunks to keep load low.
- Feeds work with or without an `ABUSEIPDB_API_KEY` — they're merged into the same `abuse4`/`abuse6` sets.
- The WHITELIST always wins over abuse — your own addresses are never blocked.

You can also add/edit feeds from the dashboard: **Objects → Reference → Custom
abuse feeds → + New feed**. Changes are deployed through the same Commit pipeline
as rules.

After editing any file, apply: `sudo systemctl start nftgeo.service`

---

## Examples

The [`examples/`](examples/) directory has ready-to-adapt rule fragments for
common services. Copy the ones you need into `/etc/nftgeo/rules.d/` and edit
the countries/IPs.

### SSH from selected countries + admin IP

```text
deny  in tcp 22 abuse            # drop blocklisted IPs on SSH
allow in tcp 22 pl               # SSH from Poland only
allow in tcp 22 203.0.113.10     # ...and one admin IP
deny  in tcp 22 any              # close SSH to everyone else
```

### Public web server (abuse-filtered, worldwide)

```text
deny  in tcp 80,443 abuse        # drop blocklisted IPs
allow in tcp 80,443 any          # open to the world
```

### Block AbuseIPDB + custom feeds everywhere

```sh
# /etc/nftgeo/config — add your key and any custom blocklists
ABUSEIPDB_API_KEY="your-key"
ABUSE_FEEDS="https://blocklist.greensnow.co/greensnow.txt
https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/refs/heads/main/abuseipdb-s100-3d.ipv4
https://raw.githubusercontent.com/ShadowWhisperer/IPs/refs/heads/master/Lists/Threats
https://raw.githubusercontent.com/ShadowWhisperer/IPs/refs/heads/master/Lists/Probes
https://raw.githubusercontent.com/duggytuxy/Data-Shield_IPv4_Blocklist/refs/heads/main/prod_data-shield_ipv4_blocklist.txt"
```
```text
# /etc/nftgeo/rules.conf
deny in  any - abuse             # block all inbound from abuse IPs
deny out any - abuse             # never talk to blocklisted hosts outbound
```

Custom feeds are plain-text IP/CIDR lists — one per line, comments stripped
automatically. Bogon/private/reserved ranges (RFC1918, loopback, CGNAT, …) are
filtered out so feeds can't accidentally block your LAN. Each feed's last good
copy is cached under `/var/lib/nftgeo/feeds` and reused if a download fails.
Feeds work with or without an `ABUSEIPDB_API_KEY`.

You can also manage feeds from the dashboard: **Objects → Reference → Custom
abuse feeds → + New feed**. See the [CHEATSHEET](CHEATSHEET.md) for feed tuning
knobs (`ABUSE_FEEDS_MAX`, `ABUSE_FEEDS_AGGREGATE`, `ABUSE_FEEDS_BATCH`).

### Allow outbound DNS

```text
allow out udp 53 any             # outbound DNS (replies flow back automatically)
```

### Gateway / router (forwarded traffic)

```text
allow fwd-out tcp 80,443 any     # let the LAN browse out
allow fwd-in  tcp 443 europe     # forward inbound 443 only from Europe
deny  fwd-in  tcp 443 any        # ...close to non-EU sources
deny  fwd-in  any -   abuse      # drop forwarded traffic from blocklisted IPs
```

### NAT gateway (masquerade + port-forward)

```text
masquerade on eth0                       # NAT the LAN out via the WAN
dnat tcp 8080 to 10.0.0.5:80 on eth0     # WAN :8080 -> internal 10.0.0.5:80
dnat tcp 2222 to 10.0.0.5:22 from europe # ...only reachable from Europe
```

### Internal firewall: zones & segmentation

```sh
# config
ZONE_LAN="eth1"
ZONE_DMZ="eth2"
ZONE_GUEST="eth0.100"
SEGMENT_DEFAULT="deny"
```
```text
# rules.conf
allow lan   -> dmz   tcp 80              # LAN reaches the DMZ web server
allow wan   -> dmz   tcp 443 from europe # world -> DMZ HTTPS, geo-filtered
deny  dmz   -> lan   any -               # DMZ can never open into the LAN
deny  guest -> lan   any -               # guests isolated from the LAN
```

### Brute-force protection

```text
throttle in tcp 22   5/minute          # >5 new SSH conns/min → ban 1h
throttle in tcp 3389 3/minute ban 2h   # RDP: 3/min → ban 2h
synproxy in tcp 80,443                 # offload handshake, drop spoofed SYNs
```

---

## Dashboard (nftgeo-ui)

nftgeo includes an optional local web dashboard — a single Go binary with an
embedded frontend, serving `127.0.0.1:8787`:

- **World map of drops** — geolocated source IPs of dropped packets (needs
  `LOG_DROPS="1"`)
- **Live stats** — per-rule hit counters, top source countries, top blocked
  ports, drops-over-time chart, top source IPs with per-IP drop histograms
- **Interface monitoring (SOC view)** — per-NIC in/out throughput area charts
  (last hour, sampled from `/proc/net/dev` every 10 s into RAM — no agents, no
  disk writes), link speed %, up/down state, and per-type error counters
  (errors/drops/fifo/frame/collisions/carrier); plus live conntrack usage and
  total net throughput KPIs
- **Visual policy editor** — Palo-Alto-style table with drag-and-drop
  reordering, per-rule enable/disable, inline quick-edit, and a rule editor
  drawer (action, direction, protocol, port, target with autocomplete, interface
  picker from live NICs)
- **Objects editor** — create/edit/delete address groups, custom regions,
  services, host labels, and zones (with a click-to-add interface picker)
- **Draft → Commit pipeline** — edits stage to a server-side draft; the live
  firewall is untouched until you press Commit, which runs `validate → plan →
  apply --confirm` with a deadman countdown and one-click rollback
- **Templates** — 21 built-in presets (`nginx`, `postgres`, `mail-server`,
  `wireguard`, `ssh-lockdown`, `safe-web`, `abuse-block`, `geo-drop`, …) to
  jump-start a common policy
- **Alerts banner** — drop spikes, stale feeds, failed runs, disabled IP
  forwarding
- **Run status & AbuseIPDB card** — the engine writes
  `/var/lib/nftgeo/status.json` after every run (API key presence, last
  AbuseIPDB/geo fetch times, warnings); the Reference tab shows it and lets you
  save the `ABUSEIPDB_API_KEY` straight into `/etc/nftgeo/config`. The health
  panel shows geo-data freshness (green <24 h)

### Starting the dashboard

```sh
# If installed via package:
sudo systemctl enable --now nftgeo-ui.service

# If installed from source:
make build
sudo install -m 0755 dist/nftgeo-ui-linux-amd64 /usr/sbin/nftgeo-ui
sudo install -m 0644 systemd/nftgeo-ui.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now nftgeo-ui
```

### Access & authentication

The panel is gated by a **per-session token you mint as root**:

```sh
sudo nftgeo-ui token            # short-lived read-write session (15 min inactivity)
sudo nftgeo-ui token --ro       # long-lived read-only session (90 days)
```

Each prints a `http://127.0.0.1:8787/?auth=<token>` link. The page exchanges
the token for a `HttpOnly` session cookie, strips the token from the URL, and
loads. Read-only sessions never see the editor and are refused (403) on any
write.

To view remotely over SSH: `ssh -L 8787:127.0.0.1:8787 <host>`, then open
`http://127.0.0.1:8787`. For production remote access, front it with a reverse
proxy for TLS.

### JSON API

The dashboard serves a read-only JSON API: `/api/status`, `/api/sets`,
`/api/rules`, `/api/objects`, `/api/drops`, `/api/lookup`, `/api/geo`,
`/api/alerts`, `/api/top-ips`, `/api/rule-stats`.

---

## Safety

### Validation before load

Every apply runs the engine's render pipeline, which validates the generated
nftables file with `nft -c` before loading it. If validation fails, the
previous ruleset stays in place — the tool fails safe.

### Atomic nftables replacement

The table is replaced atomically: the generated file recreates the
`inet/nftgeo` table in a single `nft -f` load, so there is no moment in which
the rules are missing.

### Whitelist always wins

The whitelist (`WHITELIST` in config, or `/etc/nftgeo/whitelist.conf`) is
evaluated **before** any of your rules and before the abuse blocklist.
Whitelisted IPs can reach any port, even when they are outside an allowed geo
or appear on the AbuseIPDB blacklist. This is the recommended way to protect
your admin IP from accidental lockout.

### Established/related always allowed

Each chain accepts `ct state established,related` first, so replies to
connections you initiated are always allowed. Inbound traffic is permitted only
as a response unless an `allow in` rule explicitly opens the port.

### Deadman (auto-rollback)

When a change might lock you out, apply it with the deadman:

```sh
sudo nftgeo apply --confirm        # apply, auto-roll-back in 120s
# ... verify you still have access ...
sudo nftgeo apply --commit         # keep it (cancels the rollback)
```

If you lose access, do nothing — the previous ruleset is restored
automatically after the timeout. `nftgeo rollback` restores the previous
generation at any time. Generations are kept under `/var/lib/nftgeo/generations/`.

### Dynamic blocks (survive reloads)

`nftgeo block <ip> [ttl]` cuts off an attacker immediately without editing
`rules.conf` or reloading. The block lives in a separate `nftgeo_dyn` table
that the update engine never rebuilds, so it survives refreshes and reboots
(restored by the service on boot). It refuses a whitelisted address or your
own SSH source unless you pass `--force`.

### Fail-safe geo resolution

If a country used in an `allow` rule resolves to no addresses (zone download
fails and no cache exists), the update **aborts** and leaves the previous
ruleset in place — rather than risk closing a port with an empty allow set. A
country used only in `deny` rules is skipped instead (an empty deny set drops
nothing).

### Avoid locking yourself out

Before geo-fencing the port you use for SSH:

1. Put your current IP in `WHITELIST` (or a hostname in `WHITELIST_HOSTS`) in
   `/etc/nftgeo/config` — the whitelist is checked before any rule.
2. Deploy behind the deadman: `nftgeo apply --confirm`.
3. Keep your VPS provider's emergency console as a recovery plan.

---

## Limitations & compatibility

- **Hairpin NAT / NAT reflection is not emitted.** A `dnat` port-forward works
  for traffic arriving from the WAN, but LAN clients reaching the server via the
  *public* IP are not hairpinned. Access internal servers by their internal IP
  from inside the LAN, or add a hairpin SNAT rule to your own nftables.
- **Docker / Podman coexistence.** Docker manages its own NAT (`ip` family,
  prerouting/postrouting). nftgeo's NAT lives in the `inet` family at the
  standard `dstnat`/`srcnat` priorities, so on a box that also runs Docker the
  relative order of the two NAT hooks is not defined — if you port-forward with
  both, test the result. Filtering (input/forward) coexists fine.
- **Dynamic blocks run before the whitelist by design.** `nftgeo block` drops in
  a separate table at priority `-150`, ahead of the main table (`-100`) and its
  whitelist, so an explicit manual block wins even over a whitelisted address
  (which is why `block` refuses a whitelisted IP unless you pass `--force`).
- **Reboot during a pending `apply --confirm`.** Dashboard deploys are
  reboot-safe: a boot-time reconcile (`nftgeo-ui reconcile-boot`, wired as an
  `ExecStartPre` of `nftgeo.service`) restores the pre-apply config from backup
  before the engine loads, so an unconfirmed change that a reboot interrupted is
  rolled back, not committed. A CLI `apply --confirm` (where you edited
  `rules.conf` yourself) has no such backup — the live process deadman still
  doesn't survive a reboot there, so keep the emergency console handy and confirm
  promptly.

---

## Operator CLI

```sh
nftgeo check 203.0.113.7      # what does the firewall do to this address?
nftgeo status                 # version, last run, set sizes, drop counters, next run
nftgeo validate               # check config renders/loads, without applying
nftgeo plan                   # show how the rendered ruleset differs from loaded
nftgeo block 203.0.113.7 1h   # drop an address now (no reload, survives updates)
nftgeo unblock 203.0.113.7    # remove a dynamic block
nftgeo blocklist              # list current dynamic blocks and their TTL
nftgeo apply                  # rebuild and load now (same as the update engine)
nftgeo apply --confirm        # apply with deadman auto-rollback
nftgeo apply --commit         # keep a --confirm apply
nftgeo rollback               # restore the previous ruleset generation
nftgeo version                # print the nftgeo version
```

For a one-page reference of every command, see
[CHEATSHEET.md](CHEATSHEET.md). The commands, rule grammar and config keys are
also in the `nftgeo(8)` man page (`man nftgeo`).

---

## Update schedule

The `systemd` timer runs the update:

- 2 minutes after system boot
- Twice a day (03:00 and 15:00)
- With a randomized delay of up to 30 minutes

`ZONE_CACHE_HOURS` (default 20) keeps the second daily run from re-downloading
what the first one already fetched. To change the cadence, edit `OnCalendar=`
in `/etc/systemd/system/nftgeo.timer` and run `systemctl daemon-reload`.

---

## Troubleshooting

```sh
# Is the table loaded?
nft list table inet nftgeo

# One-screen summary
nftgeo status

# Check what happens to a specific IP
nftgeo check 203.0.113.7

# Run health / warnings
journalctl -u nftgeo.service -n 100 --no-pager

# Dropped packets (needs LOG_DROPS=1)
journalctl -k | grep nftgeo-drop

# Per-rule counters
nft list chain inet nftgeo input

# When does the next refresh run?
systemctl list-timers nftgeo.timer

# Is an IP on the blocklist?
nft get element inet nftgeo abuse4 { 1.2.3.4 }

# Table not loaded?
sudo systemctl start nftgeo.service
```

### Common issues

| Problem | Solution |
|---------|----------|
| Locked out of SSH | Use your VPS console. Always set `WHITELIST` before geo-fencing port 22, and deploy with `apply --confirm`. |
| Abuse sets empty | Set `ABUSEIPDB_API_KEY` and/or `ABUSE_FEEDS` in config. The `abuse` target only downloads when a rule uses it. |
| Country zone download fails | The engine uses the cached copy. If no cache exists and the country is in an `allow` rule, the update aborts safely. |
| Port still open after `allow` | An `allow` on its own doesn't close the port — add a catch-all `deny ... any` below it. `validate` warns about this. |
| Egress geo-fencing breaks updates | If you restrict outbound 80/443, make sure the allowed regions cover ipdeny.com and AbuseIPDB, or add their IPs to `WHITELIST`. |
| Service won't start on a fresh install | If `rules.conf` is still the empty example, the engine loads a permissive baseline and warns (with `DEFAULT_INPUT=accept`); it only aborts if `DEFAULT_INPUT=drop`, where an empty ruleset would lock you out. Add rules and re-apply. |
| Drop map/stats empty in a container | Since 1.69.0 the dashboard reads drops via **NFLOG** (`NFLOG_GROUP`, default 5), which works inside LXC/OpenVZ — enable logging (`LOG_DROPS="1"` or per-rule `log`) and the map populates. If NFLOG can't be opened (no `CAP_NET_ADMIN`, or `NFLOG_GROUP=0`) it falls back to the kernel log, which a container can't read; the banner says so. |
| `nft: Message too long` on load | The container's netlink buffer is too small and `net.core.wmem_max` is host-controlled. The engine retries the transient automatically; if it persists, ask the host to raise `net.core.wmem_max`. |

---

## Development / testing

CI (`.github/workflows/ci.yml`) runs on every push:

- `shellcheck` on all shell tools
- `gofmt` / `go vet` / `go test` / build for the dashboard
- Offline render tests + migrate-sequential tests
- Real `nft -c` over every render fixture

Run them locally:

```sh
sh tests/render/run.sh              # offline: render fixtures, assert on output
go test ./ui/                       # dashboard parser tests
sudo sh tests/render/nft-check.sh   # optional: real nft -c over every fixture
make test                           # go vet + go test + render tests
make lint                           # shellcheck + gofmt check
make build                          # cross-compile nftgeo-ui for amd64 + arm64
make package                        # build .deb + .rpm (needs nfpm)
```

Render tests live in `tests/render/cases/<name>/` — each has a `rules.conf`,
optional `config`, and an `assert` file (`+`/`-` for must/must-not-contain, `!`
for expected error, `~` for a warning). Add a case when you fix a bug or add a
rule form.

### Packaging / release

Releases follow [Semantic Versioning](https://semver.org/) and are tagged
`vMAJOR.MINOR.PATCH`. The release workflow (`.github/workflows/release.yml`,
triggered on tag push) builds binaries, tarballs, `.deb` and `.rpm` packages
for `amd64` and `arm64`, generates SHA256 checksums, and publishes a GitHub
release with auto-generated notes.

---

## Uninstall

```sh
# If installed from source:
cd /path/to/nftgeo
sudo ./uninstall.sh

# If installed via package:
sudo apt remove nftgeo      # or: sudo dnf remove nftgeo
```

Removes the active `nftables` table, the systemd units, the scripts, and
`/etc/nftables.d/nftgeo.nft`. Leaves `/etc/nftgeo` and `/var/lib/nftgeo` in
place (your config and state survive).

---

## Data sources

- Country IP prefixes: [ipdeny.com](https://www.ipdeny.com)
- AbuseIPDB blacklist API: `https://api.abuseipdb.com/api/v2/blacklist`
- Custom feeds: any plaintext IP/CIDR blocklist (FireHOL, Spamhaus DROP,
  blocklist.de, GreenSnow, …)

Bogon, private, and reserved ranges (RFC1918, loopback, link-local, CGNAT,
multicast, documentation) are stripped from abuse sets automatically.

---

## Notes

`nftgeo` only touches the ports listed in `rules.conf`. It does not set a
default `DROP` policy for the whole system and does not close other ports. The
chain policy is `accept` by default; set `DEFAULT_INPUT="drop"` for a
default-deny posture.

NAT and inter-zone rules need IP forwarding enabled
(`sysctl net.ipv4.ip_forward=1`). nftgeo warns if forwarding is off but does
not manage the sysctl.

## License

[MIT](LICENSE) — Copyright (c) 2026 dzaczek
