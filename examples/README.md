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

Three things to remember before you apply anything:

- **Whitelist yourself first.** Put your admin/VPN IP in `WHITELIST` (or a
  hostname in `WHITELIST_HOSTS`) in `/etc/nftgeo/config` before restricting SSH.
- **An `allow` does not close a port.** With the default
  `DEFAULT_INPUT="accept"`, add a matching `deny ... any` below a restricted
  allow. Rules are evaluated top-to-bottom, first match wins.
- **`deny ... abuse` needs a source.** It only drops anything if you set an
  `ABUSEIPDB_API_KEY` and/or `ABUSE_FEEDS` in `config`; otherwise it is a no-op.

Rule format: `<action> <dir> <proto> <port> <target>`. See the
[full reference](../docs/REFERENCE.md) for all fields and safety details.

| File | Scenario |
|------|----------|
| `10-ssh.conf` | Admin SSH, locked to a country + your IP, abuse-filtered |
| `20-web-server.conf` | Public HTTP/HTTPS, reachable worldwide but abuse-filtered |
| `30-mail-server.conf` | SMTP / submission / IMAP / POP |
| `40-prometheus-node-exporter.conf` | Metrics locked to your monitoring host |
| `50-egress-control.conf` | Restrict what the box is allowed to talk to |
| `60-wireguard.conf` | WireGuard VPN endpoint |
| `70-gateway-forward.conf` | Router/gateway forwarded traffic |
| `71-nat-gateway.conf` | NAT gateway: masquerade / SNAT / DNAT port-forward |
| `75-internal-zones.conf` | Internal firewall: zones + micro-segmentation |
| `80-ping-icmp.conf` | Allow ping / IPv6 Neighbor Discovery |
| `90-abuse-blocklist.conf` | Drop known-bad IPs everywhere |
| `95-ingress.conf` | Optional stateless early drops before conntrack |

One rule of thumb that explains most of these: **traffic is accepted by default,
restricted allows need a following catch-all deny, and replies to connections
you started are always allowed.** So a pure client (it only makes outbound
requests) usually needs no rules at all.

Two extras that apply across all of these:

- **Scope any rule to an interface** by ending it with `on <iface>`, e.g.
  `allow in tcp 22 europe on eth0`. `on` maps to `iifname` on the source side
  (`in`/`fwd-in`) and `oifname` on the destination side (`out`/`fwd-out`); any
  real interface name works (`eth0.100`, `br-lan`, `wg0`, ...).
- **Baseline hardening** is a config toggle, not a rule fragment: set `HARDEN="1"`
  in `/etc/nftgeo/config` to accept loopback, drop invalid packets, and always
  permit essential ICMPv6.

NAT / port-forwarding (`71-nat-gateway.conf`) and internal (inter-VLAN)
segmentation (`75-internal-zones.conf`) both need IP forwarding
(`sysctl net.ipv4.ip_forward=1`). See [ROADMAP.md](../ROADMAP.md) for status.
