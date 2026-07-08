# nftgeo

`nftgeo` is a small declarative geo firewall for `nftables` on Debian and
Ubuntu. You describe, per port and direction, which countries or regions are
allowed, and the tool builds and maintains the `nftables` rules for you:

- per-direction allow/deny rules from a simple `rules.conf`: inbound, outbound,
  and forwarded (router/gateway/VPN) traffic,
- match by country, region, or a literal IPv4/IPv6 address or subnet,
- tcp, udp, sctp, icmp, icmpv6, esp, ah, and gre, with single ports or ranges,
- stateful: replies to your own requests are always allowed,
- blocks the AbuseIPDB blacklist where you ask it to, with the same
  direction/protocol/port granularity as any other rule,
- always allows a configurable whitelist of trusted IPs or hostnames (the latter
  re-resolved on each run),
- a counter on every rule, so `nft list` shows per-rule packet/byte totals,
- downloads only the country zones your rules actually use, with a local cache,
- refreshes the rules twice a day through a `systemd` timer,
- validates the `nftables` file before loading it and replaces it atomically.

## The model

You write rules like sentences in `/etc/nftgeo/rules.conf`:

```text
# action  dir      proto  port   target
allow      in       tcp    22     europe
allow      in       tcp    22     203.0.113.5
allow      in       icmp   -      any
deny       in       tcp    22     ru
deny       in       any    -      abuse
allow      in       all    5060   de
allow      out      udp    53     any
allow      fwd-in   esp    -      europe
deny       fwd-in   any    -      abuse
```

Two simple guarantees:

- A port that appears in any `allow` rule (for that direction) is **closed by
  default**: only the listed geos get through, everyone else is dropped.
- A port/direction you never mention is **left untouched**.

> **The `any` protocol is the exception to "left untouched".** An
> `allow <dir> any - <target>` rule matches *every* protocol and port in that
> direction, so its deny-by-default closes the whole direction: everything that
> is not established, not whitelisted, and not from `<target>` is dropped -
> including ports you never named. Use `any` in an `allow` only when you mean
> "default-deny this entire direction except `<target>`"; use per-port rules
> otherwise. (In a `deny` rule, `any` just scopes the drop to every port and is
> not affected by this.)

On top of every managed port, the whitelist always wins. The AbuseIPDB
blacklist is opt-in: it is dropped only where you write a `deny ... abuse`
rule, so you choose its exact scope (see below).

> **Avoid locking yourself out.** The moment you add an `allow in tcp 22 ...`
> rule, port 22 is closed to every source outside that target - including the
> machine you are connected from. Put your own admin IP in `WHITELIST` (in
> `config`) *before* you add such a rule; the whitelist is evaluated first and
> bypasses both the geo deny-by-default and the AbuseIPDB blacklist.

### Fields

- `action` - `allow` or `deny`. `deny` drops a geo without closing the port for
  everyone else, and is evaluated before `allow`.
- `dir` - one of:
  - `in` - incoming to this host (matches the source country),
  - `out` - outgoing from this host (matches the destination country),
  - `fwd-in` - routed/forwarded traffic, matched by source country,
  - `fwd-out` - routed/forwarded traffic, matched by destination country.
- `proto` - port-based: `tcp`, `udp`, `sctp`, or `all` (tcp and udp). Port-less:
  `icmp` (IPv4 only), `icmpv6` (IPv6 only), `esp`, `ah`, `gre`, or `any` (every
  protocol and port).
- `port` - a single port (`22`), a range (`5060-5070`), a comma list
  (`80,443`), or the name of a `SERVICE_<NAME>` (see below); use `-` for
  port-less protocols (including `any`).
- `target` - what the source/destination address is matched against: any mix of,
  comma-separated, country codes (`pl`), region names (`europe`), literal IPv4/
  IPv6 addresses (`203.0.113.5`, `2001:db8::1`), IPv4/IPv6 with a mask
  (`10.0.0.0/8`, `2001:db8::/32`), a named `GROUP_<NAME>` list or a `HOST_<NAME>`
  single-host label from the config (used by its lowercase name, e.g. `office` /
  `db1`), or one of the reserved words `any`
  (every address) and `abuse` (the AbuseIPDB blacklist, `deny` only). The mixable
  targets can be combined in one rule
  (`allow in tcp 80 198.51.100.0/24,de,office`); `any` and `abuse` stand alone.

A rule may end with an optional `on <iface>` to scope it to one interface -
`allow in tcp 22 europe on eth0`, `masquerade`-style edge rules, etc. `on` maps
to `iifname` on the source side (`in`/`fwd-in`) and `oifname` on the destination
side (`out`/`fwd-out`). Deny-by-default stays interface-agnostic: it closes the
port on every interface except where an allow admits it.

Define reusable address groups in `config` as `GROUP_<NAME>` variables;
a group may itself mix IPs, subnets, country codes, and region names:

```sh
GROUP_OFFICE="203.0.113.5 198.51.100.0/24 2001:db8:1::/48"
GROUP_PARTNERS="de fr 192.0.2.0/24"
```

Groups cannot reference other groups.

### Reactive throttle (brute-force auto-block)

A `throttle` rule rate-limits a port **per source** and auto-bans offenders — the
reactive counterpart to `nftgeo block`, done entirely in the kernel (no daemon):

```
throttle in tcp 22 5/minute            # >5 new SSH conns/min from one IP → ban
throttle in tcp 3389 3/minute ban 2h   # custom ban length
throttle fwd-in udp 5060 20/second on eth0
```

Form: `throttle <in|fwd-in> <tcp|udp> <port> <N/second|minute|hour> [ban <dur>]
[on <iface>]`. Under the rate nothing changes; over it, the source is added to a
dynamic timeout set and dropped for `THROTTLE_BAN` (default `1h`; override
per-rule with `ban <dur>`). It runs **after the whitelist**, so whitelisted
sources are never throttled. Bans live in the `throttle_block{4,6}` sets (visible
in the dashboard's live-sets panel); they expire automatically. You can add and
edit throttle rules in the dashboard (**+ Throttle** on the Policy tab) as well as
in `rules.conf`.

### SYN-flood protection (`synproxy`)

Offload the TCP handshake to the kernel's `synproxy` for a public port, so
spoofed SYNs that never complete the handshake never reach the service:

```
synproxy in     tcp 22          # protect inbound SSH from SYN floods
synproxy in     tcp 80,443      # a port list works too
synproxy fwd-in tcp 443 on eth0 # a forwarded port, scoped to an interface
```

Form: `synproxy <in|fwd-in> tcp <port> [on <iface>]`. It runs before the allow
rules, so only completed connections proceed. (Pair it with a `throttle` rule for
rate-limiting on top.)

### Anti-spoofing (`ANTISPOOF`, reverse-path filter)

Drop packets whose source address is not routable back through the interface
they arrived on (strict uRPF, like `rp_filter` but in the firewall) — e.g. a
packet claiming a LAN source that shows up on the WAN. Set in `config` a
space-separated list of interfaces to protect:

```sh
ANTISPOOF="eth0"        # protect the WAN from spoofed source IPs
```

Applied to the `input` and `forward` chains for those interfaces. IPv4 only
(`meta nfproto ipv4 fib saddr . iif oif`); needs a kernel with the nftables `fib`
expression (≥ 4.1). Strict uRPF can drop legitimate traffic on asymmetric-routing
setups — enable it per-interface where the routing is symmetric.

Define reusable **service objects** as `SERVICE_<NAME>` variables — named ports
and port groups you use in a rule's port field by name. A service may contain
ports, ranges, and other service names (nested), and resolves to a
`tcp dport { … }` set:

```sh
SERVICE_WEB="80 443"
SERVICE_STACK="web 8080-8090"     # services can nest other services
SERVICE_DNS="53/tcp 53/udp"       # a member may carry a /tcp or /udp protocol
```
```
allow in tcp web   any            # -> tcp dport { 80, 443 }
allow in tcp stack any            # -> tcp dport { 80, 443, 8080-8090 }
allow in any dns   any            # -> tcp dport 53 ; udp dport 53
```

A **bare** port takes the rule's protocol (`all`/`any` expand it to both TCP and
UDP); a **`/proto`-tagged** port is fixed to that protocol. A tag that conflicts
with a specific rule protocol (a `/udp` member under `proto tcp`) is an error —
use `any` or `all` to emit every protocol the service defines.

Every generated rule carries a `counter`, so `nft list table inet nftgeo`
reports per-rule packet and byte totals.

`in`/`out` build the `input`/`output` chains; `fwd-in`/`fwd-out` build the
`forward` chain and are what you use when the host is a router, gateway, or VPN
endpoint passing traffic between networks.

### Egress NAT (gateway)

Act as a gateway that NATs an internal network out to the world:

```text
masquerade on eth0                  # masquerade everything leaving via the WAN
snat out on eth0 to 203.0.113.7     # or a static source NAT to a fixed IP
masquerade on eth0 in eth1          # ...only NAT what arrives on the LAN eth1
```

Only the **WAN (outbound) interface** is required — `masquerade on <wan>` already
NATs everything routed out that interface, so you do not need to name the LAN.
The optional `in <lan>` just restricts the NAT to traffic that arrived on a
specific inbound interface (handy on a multi-LAN router). These emit a `nat`
postrouting chain (only when a NAT rule exists, so a filter-only setup is
unchanged). Enable IP forwarding yourself (`sysctl net.ipv4.ip_forward=1`) —
nftgeo warns if a NAT/forward rule is present while forwarding is off, but does
not manage the sysctl.

### Ingress NAT / port-forward (gateway)

Redirect a port arriving on the WAN to an internal host:

```text
dnat tcp 8080 to 10.0.0.5:80 on eth0        # WAN :8080 -> 10.0.0.5:80
dnat udp 51820 to 10.0.0.9                   # forward with no port remap
dnat tcp 443 to [2001:db8::1]:8443           # IPv6 target
dnat tcp 2222 to 10.0.0.5:22 from europe     # only reachable from Europe
```

`dnat <proto> <port> to <ip>[:<port>] [from <geo>] [on <iface>]` emits a `nat`
prerouting (dstnat) chain. The `:port` remap, `from <geo>` source restriction,
and `on <iface>` scope are all optional (and `from`/`on` may appear in either
order). With `from <geo>` the forward is only opened for clients in that
country/region/group (an `ip saddr @g_<geo>` match, same family as the target).
The forward chain policy is accept, so the redirected packet passes through.

> Hairpin/reflexive NAT (reaching the service via the public IP from *inside*
> the LAN) is not auto-emitted — it needs the public IP and LAN subnet. Use
> split-horizon DNS, or add a manual rule pair (a prerouting `ip daddr <pub-ip>`
> DNAT plus a postrouting `ip saddr <lan-subnet> ip daddr <internal> masquerade`).

### Internal firewall: zones & segmentation

Name network segments by interface (in `config` or a `groups.d/*.conf`) and
write forward-chain rules between them:

```text
# config
ZONE_LAN="eth1"
ZONE_DMZ="eth2"
ZONE_GUEST="eth0.100"                  # a VLAN subinterface is just an interface
SEGMENT_DEFAULT="deny"                 # micro-segmentation: default-deny between zones

# rules.conf
allow lan -> dmz  tcp 80               # LAN reaches the DMZ web server
allow wan -> dmz  tcp 443 from europe  # world -> DMZ HTTPS, geo-filtered
deny  dmz -> lan  any -                # the DMZ can never open into the LAN
```

`allow|deny <zone> -> <zone> <proto> <port> [from <geo>]` builds forward-chain
rules matching the source zone's interfaces (`iifname`) against the destination
zone's (`oifname`). The port field accepts `SERVICE_<NAME>` names; `from <geo>`
layers a source-geo set on top. Deny is emitted before allow, so an explicit
deny wins. With `SEGMENT_DEFAULT="deny"`, any forwarded traffic between zone
interfaces that no rule allows is dropped (established/related still passes).
VLANs are handled by using their subinterfaces (`eth0.100`) as zone members.
Enable IP forwarding (`sysctl net.ipv4.ip_forward=1`) for any of this to route.

### Replies and "inbound only as a response"

Each chain accepts `established,related` connections first, so a reply to a
request you made is always allowed. That means inbound traffic is permitted only
as a response to a request *unless* an `allow in` rule explicitly opens the port
for new connections. To run a client that may talk out and receive answers back,
write only an `allow out` rule; the return packets flow automatically.

### Built-in regions

`europe`, `north_america`, `caribbean`, `south_america`, `middle_east`, `asia`,
`africa`, `oceania`. Override any of them or add your own `REGION_<NAME>` in
`config`.

## Examples

The [`examples/`](examples/) directory has ready-to-adapt `rules.d` fragments for
common services - SSH, a public web server, mail, a Prometheus exporter, a
WireGuard endpoint, a gateway, egress control, and a global abuse blocklist. Each
file explains every line; copy the ones you need into `/etc/nftgeo/rules.d/` and
edit the countries/IPs. See [`examples/README.md`](examples/README.md).

## Requirements

- Debian or Ubuntu
- `systemd`, `nftables`, `curl`
- root access
- an AbuseIPDB API key, if you want to use the AbuseIPDB blacklist

Without an AbuseIPDB key the script still works; the AbuseIPDB sets stay empty.

## Installation

### Package (.deb / .rpm)

Grab the package for your arch from the [latest
release](https://github.com/dzaczek/nftgeo/releases/latest):

```sh
sudo apt install ./nftgeo_<version>_amd64.deb     # Debian/Ubuntu
sudo dnf install ./nftgeo-<version>-1.x86_64.rpm   # Fedora/RHEL
```

Packages install to FHS paths (`/usr/sbin`, `/etc/nftgeo`,
`/usr/lib/systemd/system`), seed `config`/`rules.conf` on first install, and
enable **nothing** automatically. Then:

```sh
sudoedit /etc/nftgeo/config /etc/nftgeo/rules.conf
sudo systemctl enable --now nftgeo.timer          # scheduled refresh
sudo systemctl start nftgeo.service               # build & load now
sudo systemctl enable --now nftgeo-ui.service      # optional dashboard :8787
```

### From source

```sh
cd /root/nftgeo
sudo ./install.sh
```

The installer installs `curl`/`nftables`/`ca-certificates`, copies the engine and
CLI to `/usr/local/sbin`, creates `/etc/nftgeo/{config,rules.conf}` plus empty
`rules.d/` and `groups.d/`, installs `nftgeo.service` + `nftgeo.timer`, and enables
the service at boot and the twice-daily timer. Build the dashboard binary with
`make build` (or `go build -o /usr/local/sbin/nftgeo-ui ./ui`).

### Web dashboard (optional)

nftgeo includes a local web UI — a world map of drops, live stats, and a
visual policy editor with a safe Draft → Commit pipeline (validate → plan →
apply with deadman). It binds to `127.0.0.1:8787`; use a reverse proxy for
remote access.

```sh
# If installed via package: the binary is already at /usr/sbin/nftgeo-ui
sudo systemctl enable --now nftgeo-ui.service

# If installed from source: build and install
make build
sudo install -m 0755 dist/nftgeo-ui-linux-amd64 /usr/local/sbin/nftgeo-ui
sudo install -m 0644 systemd/nftgeo-ui.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now nftgeo-ui

# Get a login link (one-time read-write, or long-lived read-only):
sudo nftgeo-ui token
sudo nftgeo-ui token --ro
```

See `CHEATSHEET.md` → Dashboard section for details.

## Configuration

Everything lives in `/etc/nftgeo`:

```text
/etc/nftgeo/
  config            # settings: AbuseIPDB key, WHITELIST, WHITELIST_HOSTS, ZONE_CACHE_HOURS, regions, groups
  rules.conf        # rules (optional if you only use rules.d)
  rules.d/*.conf    # rule fragments, included in sorted filename order
  groups.d/*.conf   # GROUP_*/REGION_* definitions, sourced after config
```

`rules.conf` is read first, then every `rules.d/*.conf` in `LC_ALL=C` sorted
filename order - use numeric prefixes (`10-ssh.conf`, `20-web.conf`,
`90-default.conf`) to make the order obvious. Likewise `groups.d/*.conf` is
sourced after `config`, in sorted order, so a later file can override a variable
set by an earlier one (or by `config`).

On file priority: within a chain the engine always evaluates in a fixed order -
`whitelist -> deny -> allow -> deny-by-default` - regardless of which file a rule
came from (`deny ... abuse` rules are part of the `deny` step). So `deny` always
beats `allow`, and two `allow` rules never conflict; the file order only affects
how the rules read in `nft list`, not the filtering decision.

After editing any file, apply the changes:

```sh
sudo systemctl start nftgeo.service
```

### AbuseIPDB

```sh
ABUSEIPDB_API_KEY="your-api-key"
ABUSEIPDB_CONFIDENCE_MINIMUM="90"
ABUSEIPDB_LIMIT="10000"
ABUSEIPDB_DAYS="30"
ABUSEIPDB_RETENTION_DAYS="30"
```

- `ABUSEIPDB_API_KEY` - AbuseIPDB API key.
- `ABUSEIPDB_CONFIDENCE_MINIMUM` - minimum abuse confidence score.
- `ABUSEIPDB_LIMIT` - maximum number of entries to download.
- `ABUSEIPDB_DAYS` - how many days of AbuseIPDB history to consider.
- `ABUSEIPDB_RETENTION_DAYS` - how many days to keep locally retained
  AbuseIPDB addresses after they were last seen in a successful API response.
  For example, set it to `30` or `60` to carry older downloaded addresses into
  later firewall sets and automatically drop entries older than that.

Retained AbuseIPDB state is stored in `/var/lib/nftgeo/abuseipdb.tsv`.
When an AbuseIPDB download fails, `nftgeo` uses the retained state instead of
loading empty `abuse` sets.

The blacklist is applied through the reserved `abuse` target in `rules.conf`,
and only downloaded when at least one rule uses it. You decide its scope exactly
like any other rule:

```text
deny in  any -       abuse   # block every protocol/port inbound from abuse IPs
deny in  tcp 22      abuse   # block abuse IPs only on inbound SSH
deny in  all 1-65535 abuse   # block abuse IPs on every tcp+udp port inbound
deny out tcp 443     abuse   # block outbound HTTPS to abuse IPs
```

`abuse` is `deny`-only and stands alone (it cannot be combined with countries or
IPs in the same rule). It is dropped after the whitelist, so whitelisted
addresses are never blocked by it.

#### Extra blocklist feeds

The `abuse` sets are not limited to AbuseIPDB. Point `ABUSE_FEEDS` at any
plaintext IP/CIDR blocklists and they are merged into the same `abuse4`/`abuse6`
sets, so every `deny ... abuse` rule covers them too:

```sh
ABUSE_FEEDS="https://iplists.firehol.org/files/firehol_level1.netset
https://www.spamhaus.org/drop/drop.txt"
```

Space- or newline-separated URLs, fetched only when a rule targets `abuse`.
Comment markers (`#`, `;`) and any text after the address are stripped, which
covers the common feed formats (FireHOL, Spamhaus DROP, blocklist.de, GreenSnow).
Each feed's last good copy is cached under `/var/lib/nftgeo/feeds` and reused if a
later download fails, so a feed outage never shrinks the blocklist. Feeds work
with or without an AbuseIPDB key.

Mind feed quality: conservative lists (FireHOL level1, Spamhaus DROP) have few
false positives, while broader ones (blocklist.de, GreenSnow) block more but can
catch legitimate traffic. The `WHITELIST` always wins over `abuse`, so keep your
own networks there.

Bogon, private, and reserved ranges (RFC1918, loopback, link-local, CGNAT,
multicast, documentation) are stripped from the abuse sets automatically - some
feeds include them, and with a `deny out ... abuse` rule they would otherwise
drop traffic to your own LAN, VPN, or local resolver. The abuse sets only ever
hold public, routable addresses.

### Whitelist (always-allow IPs)

`WHITELIST` keeps trusted addresses connected no matter what. Whitelisted IPs
can reach any port, even when they are outside an allowed geo or appear on the
AbuseIPDB blacklist:

```sh
WHITELIST="203.0.113.10 198.51.100.0/24 2001:db8::/48"
```

Space-separated, IPv4 and IPv6, single addresses or CIDR ranges. This is the
recommended way to protect your own admin IP from accidental lockout.

`WHITELIST` only accepts literal addresses. To whitelist something by name -
typically a dynamic-DNS admin endpoint such as a WireGuard box - list it in
`WHITELIST_HOSTS` instead:

```sh
WHITELIST_HOSTS="wireguard.example.ch vpn.example.net"
WHITELIST_HOSTS_RETENTION_DAYS="7"
```

Each hostname is resolved on every run and the resulting IPs are merged into the
whitelist. By default resolution uses the system resolver (`getent`, honouring
`/etc/hosts` and `resolv.conf`). Set `RESOLVERS` to a list tried in order - the
first that answers wins - where `local` is the system resolver and an IP queries
that DNS server directly (via `dig`/`host`/`nslookup`):

```sh
RESOLVERS="1.1.1.1 8.8.8.8 local"
```

Listing public servers before `local` keeps hostname whitelisting working even
when the local (e.g. VPN) resolver is down, and returns the public-facing address
- usually the source the box actually sees. `RESOLVE_TIMEOUT` (default 5s) bounds
each lookup so a hung resolver cannot stall the update.
Because the `systemd` timer runs the update, the names are re-resolved
periodically; if the address changes, the next successful lookup replaces the
old one. A host's last successfully resolved addresses are retained in
`/var/lib/nftgeo/whitelist_hosts.tsv` for `WHITELIST_HOSTS_RETENTION_DAYS`, so a
transient DNS failure cannot drop your access, and addresses that stop resolving
age out after that window. IPv4-mapped IPv6 results (`::ffff:...`) are ignored.

### Regions

Regions are macros that expand to a list of country codes. The following are
built in and need no configuration: `europe`, `north_america`, `caribbean`,
`south_america`, `middle_east`, `asia`, `africa`, `oceania`.

Override a built-in or add your own by defining a `REGION_<NAME>` variable in
`config`; the name used in `rules.conf` is the lowercased part after
`REGION_`:

```sh
REGION_EUROPE="ad al at ... ua va xk"   # e.g. a trimmed Europe without ru/by
REGION_NORDICS="dk fi is no se"          # custom region, usable as "nordics"
```

### Zone cache

```sh
ZONE_CACHE_HOURS="20"
```

Downloaded country zones are reused for this many hours before being refreshed.

### Logging dropped packets

```sh
LOG_DROPS="1"
```

With `LOG_DROPS` set, a rate-limited `log prefix "nftgeo-drop "` is emitted before
every drop rule, so dropped packets show up in the kernel log:

```sh
journalctl -k | grep nftgeo-drop
```

Off by default. `LOG_PREFIX` and `LOG_LIMIT` (default `limit rate 10/second`)
tune the label and rate. Because per-rule counters reset on reload, this is the
way to keep a durable record of what is being blocked.

### Hardening

```sh
HARDEN="1"
```

Adds a baseline every firewall should have to each managed chain: accept
loopback traffic (`iifname lo` / `oifname lo`), drop `ct state invalid` packets,
and always permit the essential ICMPv6 types (Neighbor Discovery, packet-too-big,
echo, errors) so fencing IPv6 can't break it. Off by default; the ICMPv6 type
list is overridable via `ICMPV6_ESSENTIAL`.

## Manual run

```sh
sudo /usr/local/sbin/nftgeo-update
```

Runs are serialized by a lock (`/var/lib/nftgeo/.lock`), so a manual run and the
scheduled one cannot overlap; a run that cannot take the lock within
`LOCK_WAIT` seconds (default 60) exits without touching the ruleset.

## Operator CLI

For a one-page reference of every command grouped by task (enabling, blocking,
analysis, disabling), see [CHEATSHEET.md](CHEATSHEET.md). The commands, rule
grammar and config keys are also documented in the `nftgeo(8)` man page
(`man nftgeo`), installed by both the packages and `install.sh`.

The `nftgeo` command wraps the common day-to-day checks:

```sh
nftgeo check 203.0.113.7   # what does the firewall do to this address?
nftgeo status              # version, last run, set sizes, drop counters, next run
nftgeo validate            # check the current config renders/loads, without applying
nftgeo plan                # show how the rendered ruleset differs from what is loaded
nftgeo block 203.0.113.7 1h # drop an address now for a while (no reload)
nftgeo unblock 203.0.113.7 # remove a dynamic block
nftgeo blocklist           # list current dynamic blocks and their TTL
nftgeo apply               # rebuild and load now (same as the update engine)
```

`nftgeo block <ip> [ttl]` is for cutting off an attacker immediately without
editing `rules.conf` or reloading. The block lives in a separate `nftgeo_dyn`
table that the update engine never rebuilds, so it survives refreshes; it carries
an in-kernel timeout (default `1h`; use `30m`, `2d`, ...) and is restored after a
reboot. `block` refuses a whitelisted address or your own SSH source unless you
pass `--force`, so you cannot lock yourself out by mistake.

`nftgeo validate` and `nftgeo plan` let you check an edit before applying it:
`validate` exits non-zero if the config is invalid, and `plan` prints a policy
diff (set contents such as abuse/geo addresses are elided, so only your rule
changes show). Both need root and neither touches the live ruleset.

When a change might lock you out, apply it with a deadman:

```sh
nftgeo apply --confirm      # apply, then auto-roll-back in 120s unless confirmed
# ... verify you still have access ...
nftgeo apply --commit       # keep it (cancels the rollback); or 'nftgeo confirm'
```

If you lose access, do nothing and the previous ruleset is restored after the
timeout (default 120s; `nftgeo apply --confirm 300` for longer). `nftgeo rollback`
restores the previous generation at any time. Generations are kept under
`/var/lib/nftgeo/generations/`.

`nftgeo check <ip>` reports whether the address is whitelisted, on the abuse
list, or in any geo set, prints the rules that match it, and gives a plain verdict
(allowed / dropped / where). `nftgeo status` is a one-screen summary pulled from
the live table, the journal, and the feed cache.

## Status checks

The raw commands behind `nftgeo status`, if you want them directly:

```sh
nftgeo-update --version                       # installed version
systemctl status nftgeo.timer
systemctl list-timers --all nftgeo.timer
systemctl status nftgeo.service
journalctl -u nftgeo.service -n 100 --no-pager
```

Each run logs its version in the `Loaded` line, e.g.
`nftgeo 1.0.0 loaded inet/nftgeo: rules=3 ...`.

Active rules with per-rule counters, and cached data:

```sh
nft list table inet nftgeo
nft list chain inet nftgeo input    # or output / forward
ls /var/lib/nftgeo/zones
ls /var/lib/nftgeo/abuseipdb.tsv
```

Each run also persists the sets it loaded under `/var/lib/nftgeo`
(`whitelist4.set`, `whitelist6.set`, `abuse4.set`, `abuse6.set`) alongside the
retained `abuseipdb.tsv`.

## How the rules are built

For the example `rules.conf` above, the generated chains look like this
(IPv6 lines omitted for brevity):

```text
chain input {
    type filter hook input priority -100; policy accept;
    ct state established,related counter accept            # replies always allowed

    ip saddr @whitelist4 counter accept                    # whitelist wins first

    tcp dport 22 ip saddr @g_ru4 counter drop              # explicit deny
    ip saddr @abuse4 counter drop                          # deny in any - abuse

    tcp dport 22 ip saddr @g_europe4 counter accept        # geo allow (source)
    meta l4proto icmp counter accept                       # icmp "any"
    tcp dport 22 counter drop                              # deny-by-default
}

chain forward {
    type filter hook forward priority -100; policy accept;
    ct state established,related counter accept

    ip saddr @whitelist4 counter accept
    ip daddr @whitelist4 counter accept                    # both sides for routed traffic

    ip saddr @abuse4 counter drop                          # deny fwd-in any - abuse

    meta l4proto esp ip saddr @g_europe4 counter accept    # geo allow (source)
    meta l4proto esp counter drop                          # deny-by-default
}
```

The `allow in all 5060 de` and `allow out udp 53 any` rules add the rest (a udp
output chain and tcp+udp entries for 5060); they are left out above for brevity.
Note the per-rule `counter` and that deny-by-default emits one rule per protocol
and port (so an overlapping single port and range never collide).

Only chains for the directions you actually use are emitted. The table is
replaced atomically: the generated file recreates the table in a single `nft -f`
load, so there is no moment in which the rules are missing. The chain policy is
`accept`, so only the ports you manage are affected; nothing else is touched.

The tool fails safe: if a country used in an `allow` rule resolves to no
addresses (its zone cannot be downloaded and there is no cached copy), the update
aborts and leaves the previous ruleset in place rather than risk closing a port
with an empty allow set. A country used only in `deny` rules is skipped instead -
an empty deny set drops nothing - so one unresolvable code cannot freeze the
whole update.

> **Egress note:** if you geo-fence outbound `tcp 443` (or `80`), make sure the
> allowed regions cover the AbuseIPDB and ipdeny.com servers, or add their IPs to
> `WHITELIST` - otherwise the next update cannot download its data.

## Access safety

Before geo-fencing the port you use for SSH, make sure your current IP is inside
an allowed geo, or add it to `WHITELIST`. If you have access through your VPS
provider's emergency console, keep it as a recovery plan.

### Default-deny (`DEFAULT_INPUT="drop"`)

By default nftgeo is a *selective blocklist* (`policy accept`): it drops geo /
abuse / throttle matches and lets everything else through. Set
`DEFAULT_INPUT="drop"` in `config` to flip the input chain to **default-deny** —
only established/related traffic, loopback, `WHITELIST`, and your explicit
`allow in` rules get in; every other new inbound connection is dropped. This is
the stronger posture for a host whose open ports you can enumerate. **Before
enabling it:** ensure an `allow in tcp 22 <source>` (or `WHITELIST`) admits your
SSH, keep any services you rely on covered by `allow in` rules, and always deploy
behind the deadman (`nftgeo apply --confirm`, or Commit in the panel). `validate`
warns when nothing admits inbound traffic. Loopback is auto-accepted.

Recommended SSH configuration:

```text
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
```

## Update schedule

The timer runs the update:

- 2 minutes after system boot,
- twice a day (03:00 and 15:00),
- with a randomized delay of up to 30 minutes.

The upstream `ipdeny.com` country zones are regenerated once a day, so refreshing
more often than daily does not return fresher data. The twice-a-day schedule
shortens the staleness window (so IP allocations that migrate between countries
are picked up faster) and means a single failed run does not leave you a full day
out of date. The `ZONE_CACHE_HOURS` setting keeps the second daily run from
re-downloading what the first one already fetched. To change the cadence, edit
`OnCalendar=` in `/etc/systemd/system/nftgeo.timer` and run
`systemctl daemon-reload`.

## Uninstall

```sh
cd /root/nftgeo
sudo ./uninstall.sh
```

Removes the active `nftables` table, the systemd units, the script, and
`/etc/nftables.d/nftgeo.nft`. Leaves `/etc/nftgeo` and
`/var/lib/nftgeo` in place.

## Versioning

Releases follow [Semantic Versioning](https://semver.org/) and are tagged
`vMAJOR.MINOR.PATCH`. `nftgeo-update --version` reports the installed version and
each run logs it. See [CHANGELOG.md](CHANGELOG.md) for what changed between
releases.

## Development / tests

CI (`.github/workflows/ci.yml`) runs on every push: `shellcheck` on the shell
tools, `gofmt` / `go vet` / `go test` / build for the dashboard, and two render
harnesses. Run them locally:

```sh
sh tests/render/run.sh          # offline: render fixtures, assert on the output
go test ./ui/                   # dashboard parser tests
sudo sh tests/render/nft-check.sh   # optional: real `nft -c` over every fixture
```

Render tests live in `tests/render/cases/<name>/` (a `rules.conf`, optional
`config`, and an `assert` file: `+`/`-` for must/must-not-contain, `!` for an
expected error). Add a case when you fix a bug or add a rule form.

## Dashboard (nftgeo-ui)

`nftgeo-ui` is an optional, **read-only** local web dashboard (roadmap P6,
Phase A): a world map of where drops come from, live drop counters, set sizes,
and a recent-drops feed where you can click any IP to look it up (reverse DNS +
whois via RDAP). It only reads (`nft`, `journalctl`, `nftgeo-update`); the
firewall's source of truth stays in `/etc/nftgeo` and the CLI.

Build the single static binary (needs Go; no runtime dependencies) and run it:

```sh
go build -o /usr/local/sbin/nftgeo-ui ./ui
install -m 0644 systemd/nftgeo-ui.service /etc/systemd/system/
systemctl enable --now nftgeo-ui.service      # serves http://127.0.0.1:8787
```

The map and drop stats are fed by kernel drop logs, so set `LOG_DROPS="1"` in
`/etc/nftgeo/config` (and apply) to populate them. It binds to localhost; to view
it over SSH: `ssh -L 8787:127.0.0.1:8787 <host>`, then open
`http://127.0.0.1:8787`.

### Access & authentication

The panel is gated by a **per-session token you mint as root** — opening the URL
directly shows a lock screen, not the dashboard. On the host:

```sh
sudo nftgeo-ui token            # short-lived read-write session link
sudo nftgeo-ui token --ro       # long-lived read-only session link
```

Each prints a `http://127.0.0.1:8787/?auth=<token>` link. Open it (over the SSH
tunnel): the page exchanges the token for a `HttpOnly` session cookie, strips the
token from the URL, and loads. A read-write session **expires after 15 minutes of
inactivity** (`UI_SESSION_TTL`) and its token is **single-use**; a `--ro` token is
valid for 90 days and yields a read-only panel that cannot change the firewall
(all non-`GET` requests return 403 — the dashboard is read-only today regardless,
this future-proofs the Phase B editor). The signing secret lives root-only at
`/var/lib/nftgeo/ui-secret` (`0600`, auto-created on first start;
`UI_SECRET_FILE` to relocate). Run with `-noauth` only on a fully trusted
localhost. For remote access still front it with a reverse proxy for TLS.

Geolocation reuses the local ipdeny zones, which nftgeo only downloads for the
countries your rules reference. So the world map currently colours the countries
you filter on; the recent-drops feed, counters, and set sizes are always
complete. Set `GEO_FULL=1` (env, e.g. a `nftgeo-ui.service` drop-in) to have
the UI fetch every ipdeny country zone into `GEO_CACHE_DIR` on startup and daily,
making the map global (~240 outbound requests; off by default).

The read-only JSON API it serves: `/api/status`, `/api/sets`, `/api/rules`,
`/api/objects`, `/api/drops`, `/api/lookup`, `/api/geo`.

### Editing rules from the panel (draft → commit)

A **read-write** session (a `nftgeo-ui token` link, not `--ro`) can change rules
without ever risking a lock-out. The **Rules (edit)** tab edits a *draft* of
`rules.conf` held server-side (`UI_DRAFT_FILE`, default
`/var/lib/nftgeo/ui-draft.rules`) — **the live firewall is untouched** until you
press **Commit / Deploy** on the top bar. Commit runs the engine's own safe
pipeline: `validate → plan` (shown as a diff) `→ apply --confirm`, guarded by the
deadman. An in-page countdown then lets you **Keep** the change or **Roll back**;
if you do neither, the deadman reverts the kernel ruleset *and* the panel restores
`rules.conf` from its backup, so a broken or lock-out deploy can never persist.
Read-only sessions never see the editor and are refused (403) on any write.

The **Objects** tab is likewise editable: create/edit/delete **address groups**
(`GROUP_*`), **custom regions** (`REGION_*`), **services** (`SERVICE_*`, named
ports / port groups), **hosts** (`HOST_*`, single-IP labels) and **zones**
(`ZONE_*`, named interface lists incl. VLAN subinterfaces, with a click-to-add
interface picker) in a slide-out drawer. These are
saved to a UI-owned drop-in (`groups.d/ui-objects.conf`) and deployed through the
*same* Commit pipeline as rules, so one Deploy carries rules and objects together.
The **Policy** tab is a visual editor over the draft rules — columns for
Source / Destination / Service / Action with object chips, colour-coded verdicts
and live hit counts, **drag-and-drop reordering** (top-down precedence) and a
per-rule **enable/disable toggle**. Above the table a small **baseline** readout
shows the implicit accepts that run before your rules — *established/related* and
*whitelist* — with their live counters; this is where existing and whitelisted
connections (including your own SSH) are counted, which is why an `allow` rule's
own Hits stay low (it only counts new, non-whitelisted connections). Rules render as one flat list (engine order);
**sections** (`## …`) group them, and a small **File** badge shows which file each
rule lives in (`rules.conf` or a `rules.d/*.conf` drop-in) — the badge column only
appears when you have more than one file. Each edit applies to the rule's file, and
**Add rule** lets you pick the target file; Commit deploys all changed files
together. **+ Add rule** or clicking a row opens a
slide-out drawer to edit the rule's fields (action, direction, protocol, port,
target with group/region autocomplete, interface — picked from the host's live
interface list with a ⟳ refresh, name) or delete it; clicking a
target chip does an inline quick-edit, and **+ Section** adds a titled divider
(`## Title`) to group rules in large policies. **NAT** (`masquerade` / `snat` /
`dnat`) and **inter-zone** (`<zone> -> <zone>`) rules render as their own row
kinds — a verbatim **NAT** badge and source→destination **zone** chips — and
have dedicated **+ NAT** and **+ Zone** drawers (validated fields, zone-name
autocomplete) to add or edit them. The **Templates** drawer imports
built-in blocks (*Block abuse feeds*, *Safe Web Server*, *Basic Geo-Drop*) to the
top of the policy and can save the current policy as a reusable template. Every
change writes to the draft and deploys via Commit.

## Roadmap / TODO

nftgeo is growing from a geo/abuse edge filter into a single-tool declarative
firewall — so you don't need a second firewall manager beside it. See
[ROADMAP.md](ROADMAP.md) for the full plan with milestones. In short:

- ✅ **Done** — geo/abuse filtering, operator CLI (`check`/`status`/`validate`/
  `plan`/`block`/`apply --confirm`/`rollback`), `HARDEN`, per-interface `on <iface>`,
  reactive throttle, default-deny input, `SERVICE_*`/`HOST_*` objects, `man nftgeo`.
- ✅ **P3** — egress NAT (`masquerade` / `snat`) for gateways.
- ✅ **P4** — port forwarding (`dnat` inbound). *(Geo-restricted DNAT and hairpin
  NAT are still open — see ROADMAP M4.3/M4.5.)*
- ✅ **P5** — internal firewall / segmentation: interface zones, inter-zone rules,
  `SEGMENT_DEFAULT` default-deny, VLANs via subinterfaces.
- 🔜 **P6** — `nftgeo-ui`: local web dashboard (world map of drops, live stats,
  blocklist browser) + visual policy editor — shipped and evolving; the in-panel
  **Commit/deploy** pipeline (M6B.6) and full NAT/zone editor drawers are open.

## Data sources

- AbuseIPDB blacklist API: `https://api.abuseipdb.com/api/v2/blacklist`
- Country IP prefixes: `https://www.ipdeny.com`

The source URLs (`ABUSEIPDB_URL`, `IPDENY_V4_URL`, `IPDENY_V6_URL`) and all paths,
state-file, cache, and table names (`CONFIG_FILE`, `RULES_FILE`, `RULES_DIR`,
`GROUPS_DIR`, `STATE_DIR`, `ZONE_DIR`, `NFT_FILE`, `TABLE_FAMILY`, `TABLE_NAME`,
`LOCK_WAIT`, ...) are environment-variable overrides on `nftgeo-update`, mainly
for testing; the defaults are what a normal install uses.

## Notes

`nftgeo` only touches the ports listed in `rules.conf`. It does not set a
default `DROP` policy for the whole system and does not close other ports.

