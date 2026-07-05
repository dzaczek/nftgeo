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
- always allows a configurable whitelist of trusted IPs,
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
- `port` - a single port (`22`) or a range (`5060-5070`); use `-` for port-less
  protocols (including `any`).
- `target` - what the source/destination address is matched against: any mix of,
  comma-separated, country codes (`pl`), region names (`europe`), literal IPv4/
  IPv6 addresses (`203.0.113.5`, `2001:db8::1`), IPv4/IPv6 with a mask
  (`10.0.0.0/8`, `2001:db8::/32`), a named `GROUP_<NAME>` list from the config
  (used by its lowercase name, e.g. `office`), or one of the reserved words `any`
  (every address) and `abuse` (the AbuseIPDB blacklist, `deny` only). The mixable
  targets can be combined in one rule
  (`allow in tcp 80 198.51.100.0/24,de,office`); `any` and `abuse` stand alone.

Define reusable address groups in `config` as `GROUP_<NAME>` variables;
a group may itself mix IPs, subnets, country codes, and region names:

```sh
GROUP_OFFICE="203.0.113.5 198.51.100.0/24 2001:db8:1::/48"
GROUP_PARTNERS="de fr 192.0.2.0/24"
```

Groups cannot reference other groups.

Every generated rule carries a `counter`, so `nft list table inet nftgeo`
reports per-rule packet and byte totals.

`in`/`out` build the `input`/`output` chains; `fwd-in`/`fwd-out` build the
`forward` chain and are what you use when the host is a router, gateway, or VPN
endpoint passing traffic between networks.

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

## Requirements

- Debian or Ubuntu
- `systemd`, `nftables`, `curl`
- root access
- an AbuseIPDB API key, if you want to use the AbuseIPDB blacklist

Without an AbuseIPDB key the script still works; the AbuseIPDB sets stay empty.

## Installation

```sh
cd /root/nftgeo
sudo ./install.sh
```

The installer:

- installs `curl`, `nftables`, and `ca-certificates`,
- copies the script to `/usr/local/sbin/nftgeo-update`,
- creates `/etc/nftgeo/config` and `/etc/nftgeo/rules.conf`, plus empty
  `rules.d/` and `groups.d/` directories for drop-in files,
- installs `nftgeo.service` and `nftgeo.timer`,
- enables the service at boot and the twice-daily timer.

## Configuration

Everything lives in `/etc/nftgeo`:

```text
/etc/nftgeo/
  config            # settings: AbuseIPDB key, WHITELIST, ZONE_CACHE_HOURS, regions, groups
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

Each hostname is resolved (via `getent`, honouring `/etc/hosts` and
`resolv.conf`) on every run and the resulting IPs are merged into the whitelist.
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

## Manual run

```sh
sudo /usr/local/sbin/nftgeo-update
```

## Status checks

```sh
systemctl status nftgeo.timer
systemctl list-timers --all nftgeo.timer
systemctl status nftgeo.service
journalctl -u nftgeo.service -n 100 --no-pager
```

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

The tool fails safe: if a required country zone cannot be downloaded and there is
no cached copy, the update aborts and leaves the previous ruleset in place rather
than risk closing a port with an empty allow set.

> **Egress note:** if you geo-fence outbound `tcp 443` (or `80`), make sure the
> allowed regions cover the AbuseIPDB and ipdeny.com servers, or add their IPs to
> `WHITELIST` - otherwise the next update cannot download its data.

## Access safety

Before geo-fencing the port you use for SSH, make sure your current IP is inside
an allowed geo, or add it to `WHITELIST`. If you have access through your VPS
provider's emergency console, keep it as a recovery plan.

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

## Data sources

- AbuseIPDB blacklist API: `https://api.abuseipdb.com/api/v2/blacklist`
- Country IP prefixes: `https://www.ipdeny.com`

## Notes

`nftgeo` only touches the ports listed in `rules.conf`. It does not set a
default `DROP` policy for the whole system and does not close other ports.
