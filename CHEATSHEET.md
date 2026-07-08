# nftgeo cheat sheet

Quick reference for every command. Rules live in `/etc/nftgeo/rules.conf` (or
`rules.d/*.conf`); settings in `/etc/nftgeo/config`. After editing files, apply
with `sudo systemctl start nftgeo.service` (or `sudo nftgeo apply`).

Rule line: `<action> <dir> <proto> <port> <target> [on <iface>]`
- **action** `allow` | `deny`
- **dir** `in` | `out` | `fwd-in` | `fwd-out`
- **proto** `tcp` `udp` `sctp` `all` | `any` `icmp` `icmpv6` `esp` `ah` `gre`
- **port** `22` | `5060-5070` | `80,443` | service name `web` | `-` (port-less protos)
- **target** country `pl` · region `europe` · IP `203.0.113.5` · CIDR `10.0.0.0/8`
  · group `office` · host label `db1` · `any` · `abuse` (deny-only)
- **on `<iface>`** (optional) scope to one interface: `iifname` for the source
  side (`in`/`fwd-in`), `oifname` for the destination (`out`/`fwd-out`). Any real
  name works (`eth0`, `eth0.100`, `br-lan`, `wg0`, `home-Client-10`).

Reactive throttle (auto-ban brute force):
`throttle <in|fwd-in> <tcp|udp> <port> <N/second|minute|hour> [ban <dur>] [on <iface>]`
```
throttle in tcp 22   5/minute          # ban IPs doing >5 new SSH conns/min
throttle in tcp 3389 3/minute ban 2h   # custom ban length (default THROTTLE_BAN=1h)
```
Whitelisted sources are never throttled. Bans live in `throttle_block{4,6}` and expire.

SYN-flood protection (kernel synproxy) and anti-spoofing (reverse-path filter):
```
synproxy in tcp 22            # offload the SSH handshake; drop spoofed SYNs
synproxy fwd-in tcp 443 on eth0
ANTISPOOF="eth0"              # (in config) strict uRPF on the WAN; IPv4 only
```

Egress NAT (gateway; needs `net.ipv4.ip_forward=1`):
```
masquerade on eth0                 # NAT the LAN out via the WAN (WAN iface only)
masquerade on eth0 in eth1         # ...optionally restrict to inbound LAN eth1
snat out on eth0 to 203.0.113.7    # or a static source IP
```
Ingress NAT / port-forward (gateway):
```
dnat tcp 8080 to 10.0.0.5:80 on eth0   # forward WAN :8080 to an internal host
dnat udp 51820 to 10.0.0.9             # forward with no port remap
dnat tcp 2222 to 10.0.0.5:22 from europe   # ...only reachable from Europe
```
Inter-zone rules (internal firewall; `ZONE_*` in config, forward chain):
```
ZONE_LAN="eth1"  ZONE_DMZ="eth2"       # (in config) name segments by interface
allow lan  -> dmz  tcp 80              # LAN reaches DMZ web
allow wan  -> dmz  tcp 443 from europe # geo-filtered inter-zone allow
deny  dmz  -> lan  any -               # DMZ never opens into the LAN
# SEGMENT_DEFAULT="deny" in config -> drop all inter-zone traffic not allowed
```

---

## Install / update

```sh
sudo ./install.sh                     # install engine + CLI + service/timer
sudo systemctl start nftgeo.service   # build & load now
nftgeo-update --version               # installed version
```

---

## Enabling access — `allow` (edit rules.conf, then apply)

```sh
allow in  tcp 22   pl                  # SSH only from Poland
allow in  tcp 22   203.0.113.10        # + one fixed admin IP
allow in  tcp 22   office              # + a GROUP_OFFICE list from config
allow in  tcp web  any                 # named ports: SERVICE_WEB="80 443"
allow in  tcp 443  any                 # public HTTPS (whole world)
allow in  tcp 443  europe              # HTTPS from Europe only
allow in  tcp 25   any                 # inbound mail (any MTA)
allow in  all 5060-5070 de             # SIP tcp+udp range from Germany
allow in  udp 51820 any                # WireGuard endpoint
allow in  icmp -   any                 # allow ping (v4); icmpv6 for v6
allow out udp 53   any                 # outbound DNS (client; replies auto-allowed)
allow fwd-in  tcp 443 europe           # gateway: forward inbound 443 from EU
allow fwd-out tcp 80  any              # gateway: let the LAN browse out
allow in  tcp 22   europe on eth0      # SSH from EU only on the WAN interface
allow in  tcp 22   any    on wg0       # ...and freely over a trusted VPN tunnel
```

A pure client needs no rule — replies to its own connections are always allowed.
See `examples/` for ready-to-copy per-service fragments.

---

## Blocking

### Static, in `rules.conf` (persistent)
```sh
deny in  tcp 22  ru,cn                 # block countries on SSH
deny in  tcp 22  192.0.2.7             # block one IP
deny in  any -   abuse                 # drop known-bad inbound (needs key/feed)
deny out any -   abuse                 # never talk to known-bad outbound
```

### Dynamic, right now — no reload, survives updates
```sh
sudo nftgeo block 203.0.113.7          # block for 1h (default)
sudo nftgeo block 203.0.113.7 2d       # block for 2 days (30m, 1h, 2d, 3600s...)
sudo nftgeo block --force 10.0.0.5 1h  # override whitelist/own-SSH-source guard
sudo nftgeo unblock 203.0.113.7        # remove a dynamic block
sudo nftgeo blocklist                  # list dynamic blocks + remaining TTL
```

### Blocklist sources (config → apply)
```sh
ABUSEIPDB_API_KEY="your-key"
ABUSE_FEEDS="https://iplists.firehol.org/files/firehol_level1.netset
https://www.spamhaus.org/drop/drop.txt"
```
Bogon/private/reserved ranges are stripped automatically, so feeds can't block
your own LAN/VPN/DNS.

### Whitelist (never blocked — protect your admin access)
```sh
WHITELIST="203.0.113.10 198.51.100.0/24"
WHITELIST_HOSTS="vpn.example.ch"       # by name, re-resolved each run
RESOLVERS="1.1.1.1 8.8.8.8 local"      # resolve via public DNS first
```

---

## Analysis / inspection

```sh
nftgeo status                          # one screen: version, sets, drop counters, next run
nftgeo check 203.0.113.7               # what happens to this IP (whitelist/abuse/geo + verdict)
nftgeo blocklist                       # current dynamic blocks

nft list table inet nftgeo             # full ruleset with per-rule counters
nft list chain inet nftgeo input       # one chain (or output / forward)
nft reset counters table inet nftgeo   # zero counters, wait, re-list = live activity
nft get element inet nftgeo abuse4 { 1.2.3.4 }   # is an IP on the blocklist?

journalctl -u nftgeo.service -n 50     # run health / warnings
journalctl -k | grep nftgeo-drop       # dropped packets (needs LOG_DROPS=1)
systemctl list-timers nftgeo.timer     # when the next refresh runs
cat /var/lib/nftgeo/whitelist_hosts.tsv  # what hostnames resolved to
```

### Trace one source live (non-disruptive)
```sh
nft insert rule inet nftgeo input ip saddr 1.2.3.4 meta nftrace set 1
nft monitor trace                      # generate traffic from that IP in another shell
nft -a list chain inet nftgeo input    # find the trace rule's handle, then:
nft delete rule inet nftgeo input handle <N>
```

---

## Safe changes (deadman — guard against lock-out)

```sh
sudo nftgeo validate                   # does the current config produce a valid ruleset?
sudo nftgeo plan                       # show what would change vs what is loaded
sudo nftgeo apply --confirm            # apply, auto-roll-back in 120s unless confirmed
sudo nftgeo apply --confirm 300        # ...with a 5-minute window
#   ... check you still have access ...
sudo nftgeo apply --commit             # keep it (cancels the rollback); alias: nftgeo confirm
sudo nftgeo rollback                   # restore the previous generation
```

---

## Enabling features (config → apply)

```sh
HARDEN="1"                             # baseline: accept lo, drop invalid, ICMPv6
LOG_DROPS="1"                          # log dropped packets to journald/dmesg
ABUSE_FEEDS="https://..."              # extra blocklists
WHITELIST_HOSTS="vpn.example.ch"       # hostname whitelist
RESOLVERS="1.1.1.1 8.8.8.8 local"      # resolve whitelist hosts via public DNS first
# then:
sudo systemctl start nftgeo.service
```

---

## Disabling / turning off

```sh
# A rule: comment it out in rules.conf, then apply
sudo systemctl start nftgeo.service

# A feature: blank it in config (LOG_DROPS="", ABUSE_FEEDS="", ...), then apply

# A dynamic block:
sudo nftgeo unblock 203.0.113.7

# Pause / resume the scheduled refresh:
sudo systemctl disable --now nftgeo.timer
sudo systemctl enable  --now nftgeo.timer

# Drop the whole firewall now (keeps config on disk):
sudo nft delete table inet nftgeo
sudo nft delete table inet nftgeo_dyn     # if you used dynamic blocks

# Full uninstall (removes table, units, scripts; keeps /etc/nftgeo + /var/lib/nftgeo):
sudo ./uninstall.sh
```

---

## Dashboard (nftgeo-ui)

Local read-only web panel + visual policy editor (world map of drops, live stats,
Objects/Policy editor). Binds to `127.0.0.1:8787`; front it with a proxy for TLS.

```sh
sudo systemctl enable --now nftgeo-ui        # start the panel
sudo nftgeo-ui token                          # mint a one-time read-write login link
sudo nftgeo-ui token -ro                      # long-lived read-only link
```
Policy tab shows every rule kind: `allow`/`deny` filters, `throttle`, **NAT**
(`masquerade`/`snat`/`dnat`) and **inter-zone** (`<z> -> <z>`) rules — each with
its own add/edit drawer (**+ Rule**, **+ Throttle**, **+ Zone**, **+ NAT**), plus
**Raw** for bulk text edits. Interface fields pick from the host's live NICs
(with a ⟳ refresh). Objects has tabs for address groups, regions, services,
hosts and **zones** (named interface lists, incl. VLANs, with a click-to-add
interface picker). Edits stage to a draft and deploy via **Commit**
(validate → plan diff → apply with a deadman countdown + one-click rollback).

---

## Files

```text
/etc/nftgeo/config          settings (whitelist, abuse, feeds, resolvers, logging)
/etc/nftgeo/rules.conf       rules
/etc/nftgeo/rules.d/*.conf   rule fragments (sorted order)
/etc/nftgeo/groups.d/*.conf  GROUP_* / REGION_* definitions
/var/lib/nftgeo/             state: zones, feeds, abuseipdb.tsv, dynblock.tsv, generations/
/etc/nftables.d/nftgeo.nft   the generated, loaded ruleset
```
