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
  · group `office` · `any` · `abuse` (deny-only)
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

## Files

```text
/etc/nftgeo/config          settings (whitelist, abuse, feeds, resolvers, logging)
/etc/nftgeo/rules.conf       rules
/etc/nftgeo/rules.d/*.conf   rule fragments (sorted order)
/etc/nftgeo/groups.d/*.conf  GROUP_* / REGION_* definitions
/var/lib/nftgeo/             state: zones, feeds, abuseipdb.tsv, dynblock.tsv, generations/
/etc/nftables.d/nftgeo.nft   the generated, loaded ruleset
```
