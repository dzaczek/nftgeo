# nftgeo rule examples

Ready-to-adapt rule fragments for common services. Each file is a `rules.d`
drop-in: copy the ones you need into `/etc/nftgeo/rules.d/`, edit the country
codes / IPs, then apply.

```sh
cp examples/40-prometheus-node-exporter.conf /etc/nftgeo/rules.d/
$EDITOR /etc/nftgeo/rules.d/40-prometheus-node-exporter.conf
systemctl start nftgeo.service
```

The numeric prefix is also the load order (files are read in sorted name order).

Two things to remember before you apply anything:

- **Whitelist yourself first.** The moment a port has an `allow in` rule it is
  closed to every other source - including you. Put your admin/VPN IP in
  `WHITELIST` (or a hostname in `WHITELIST_HOSTS`) in `/etc/nftgeo/config` so you
  cannot lock yourself out.
- **`deny ... abuse` needs a source.** It only drops anything if you set an
  `ABUSEIPDB_API_KEY` and/or `ABUSE_FEEDS` in `config`; otherwise it is a no-op.

Rule format: `<action> <dir> <proto> <port> <target>`. See the top-level
[README](../README.md) for the full field reference.

| File | Scenario |
|------|----------|
| `10-ssh.conf` | Admin SSH, locked to a country + your IP, abuse-filtered |
| `20-web-server.conf` | Public HTTP/HTTPS, reachable worldwide but abuse-filtered |
| `30-mail-server.conf` | SMTP / submission / IMAP / POP |
| `40-prometheus-node-exporter.conf` | Metrics locked to your monitoring host |
| `50-egress-control.conf` | Restrict what the box is allowed to talk to |
| `60-wireguard.conf` | WireGuard VPN endpoint |
| `70-gateway-forward.conf` | Router/gateway forwarded traffic |
| `80-ping-icmp.conf` | Allow ping / IPv6 Neighbor Discovery |
| `90-abuse-blocklist.conf` | Drop known-bad IPs everywhere |

One rule of thumb that explains most of these: **inbound is closed only where you
open it, outbound is open unless you restrict it, and replies to connections you
started are always allowed.** So a pure client (it only makes outbound requests)
usually needs no rules at all.
