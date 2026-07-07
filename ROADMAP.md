# nftgeo roadmap / TODO

nftgeo today is a stateful **geo/abuse edge filter** with an operator CLI. This
roadmap tracks its growth into a single tool that covers the whole job — edge
**and** internal firewall — so you never have to run a second firewall manager
next to it.

Legend: ✅ shipped · 🔜 next · 📋 planned

Cross-cutting principles for everything below: declarative rules, `nftgeo
validate` / `plan` before applying, the safe-apply **deadman** guards every
change, fail-safe loads, and thorough Docker tests. NAT is IPv4-first;
nftgeo warns about (but does not flip) `ip_forward`/`forwarding` sysctls.

---

## ✅ Shipped

- Per-direction geo/region/IP/CIDR/group filtering (`in`/`out`/`fwd-in`/`fwd-out`).
- AbuseIPDB + `ABUSE_FEEDS` blocklists, bogon-scrubbed; `WHITELIST` + re-resolved
  `WHITELIST_HOSTS` with `RESOLVERS`.
- Operator CLI: `check`, `status`, `validate`, `plan`, `block/unblock/blocklist`,
  `apply --confirm/--commit`, `rollback`; no-op reloads; `LOG_DROPS`.
- **P1 — HARDEN**: loopback accept, `ct state invalid` drop, essential ICMPv6.
- **P2 — Interfaces**: `on <iface>` on any rule, arbitrary interface names
  (VLANs, tunnels, bridges) with an unknown-interface warning.

---

## 🔜 P3 — Egress NAT (masquerade / SNAT)

**Goal:** act as a gateway that NATs an internal network out to the world.

```text
masquerade on eth0                  # masquerade everything leaving via the WAN
snat out on eth0 to 203.0.113.7     # or a static source NAT
```

Milestones:
- [ ] **M3.1** `nat` table + `postrouting` chain scaffolding (emitted only when a
  NAT rule exists; coexists with the filter table).
- [ ] **M3.2** `masquerade on <iface>` → `oifname <iface> masquerade`.
- [ ] **M3.3** `snat out on <iface> to <ip>` (static source NAT).
- [ ] **M3.4** warn when IP forwarding is disabled (document; sysctl not managed).
- [ ] **M3.5** `validate`/`plan`/deadman aware; fail-safe.
- [ ] **M3.6** docs, examples, Docker (privileged netns) tests.

---

## 🔜 P4 — Ingress NAT (port forwarding / DNAT)

**Goal:** expose an internal service on the box's public interface — the headline
"I don't need another firewall" feature. Geo and interface qualifiers reused.

```text
dnat in tcp 443  to 10.0.0.5:8443                 # WAN:443 -> internal:8443
dnat in tcp 2222 europe to 10.0.0.5:22 on eth0    # geo-restricted, on the WAN
```

Milestones:
- [ ] **M4.1** `prerouting` NAT chain scaffolding.
- [ ] **M4.2** `dnat <dir> <proto> <port> to <ip[:port]>` parse + emit.
- [ ] **M4.3** reuse the geo target and `on <iface>` qualifier.
- [ ] **M4.4** auto-emit the matching `fwd-in` accept so the forwarded packet
  passes the filter (make it "just work").
- [ ] **M4.5** optional hairpin/reflexive NAT (reach the service via the public IP
  from inside the LAN).
- [ ] **M4.6** warn on disabled forwarding; IPv4-first.
- [ ] **M4.7** docs, examples, tests.

---

## 📋 P5 — Internal firewall / segmentation (VLANs & zones)

**Goal:** a real internal firewall. Filter traffic **between segments**
(VLANs / subnets), not only world↔host — micro-segmentation with rules that read
like sentences. This is where nftgeo becomes an internal firewall in its own
right, and it needs a few new primitives first.

### New primitives (config)

```text
# Service names: built-in (ssh=22, https=443, postgres=5432, ...) plus your groups
SERVICE_WEB="http https"
SERVICE_DB="postgres mysql"

# IP / host labels: name single hosts, use the name in rules
HOST_DB1="10.0.20.5"
HOST_LB="10.0.10.7"

# Zones: a segment = interfaces and/or subnets grouped under one name
ZONE_WEB="eth0.10 10.0.10.0/24"
ZONE_DB="eth0.20 10.0.20.0/24"
ZONE_MGMT="eth0.99 10.0.99.0/24"
```

### Inter-zone rules (forward chain)

```text
allow web  -> db    db                 # web tier reaches the DB service group
allow mgmt -> any   ssh                 # mgmt may SSH into any internal zone
allow any  -> web   web from europe     # world -> web (http/https), geo-filtered
allow web  -> db1   postgres            # ...or a single labelled host
deny  db   -> any   any                 # the DB initiates nothing (egress lockdown)
```

`<zone> -> <zone>` matches the source segment (iifname + saddr subnets) against
the destination segment (oifname + daddr subnets); services expand to ports;
`from <geo>` layers geo on top; per zone-pair deny-by-default applies.

Milestones:
- [ ] **M5.1** Service names + `SERVICE_<NAME>` groups (usable in the port field,
  e.g. `allow in tcp ssh ...` / `allow web -> db db`).
- [ ] **M5.2** Host/IP labels (`HOST_<NAME>` / `LABEL_<NAME>`) — single-IP names,
  usable as any target.
- [ ] **M5.3** Zones (`ZONE_<NAME>` = interfaces + subnets) as source/destination.
- [ ] **M5.4** Inter-zone rule form `allow <zone> -> <zone> <service> [from <geo>]`
  emitted into the forward chain, with per zone-pair deny-by-default.
- [ ] **M5.5** 802.1Q VLAN-tag matching (`vlan id <N>`) for trunk ports, on top of
  VLAN sub-interfaces (`eth0.10`) which already work via `on`.
- [ ] **M5.6** Optional default-deny between zones (true micro-segmentation
  posture) — a `SEGMENT_DEFAULT="deny"` switch.
- [ ] **M5.7** docs, examples, tests; interplay with geo/abuse/HARDEN and P3/P4 NAT.

---

## 📋 P6 — nftgeo-ui (local web dashboard & visual editor)

**Goal:** a small, dependency-light local web UI — a single Go binary serving
`127.0.0.1` — that makes a geo firewall *visual*: a world map of what's being
dropped, live stats, blocklist browsing, and (later) drag-and-drop group/template
building. **Principle:** the UI is a *view + editor* over `rules.conf`/`config`
and the CLI verbs (`status`/`plan`/`validate`/`apply --confirm`) — never a second
source of truth. Localhost-only by default.

### Phase A — read-only dashboard 🚧 (mostly shipped in 1.11.0)
- [x] **M6A.1** Go single binary `nftgeo-ui`, embedded assets, serves
  `127.0.0.1:<port>`; systemd unit; no runtime dependencies.
- [x] **M6A.2** `/api/status` — version, table loaded, per-chain rule counters.
- [x] **M6A.3** `/api/sets` — whitelist / abuse / geo / dynamic-block sizes.
- [x] **M6A.4** drop-event stream — parse journald `nftgeo-drop` (needs
  `LOG_DROPS`): source IP, port, direction (ingress/egress), time.
- [x] **M6A.5** geolocation from the local ipdeny zones (IP → country), no
  external GeoIP dependency.
- [x] **M6A.5b** full offline geo dataset: fetch all ipdeny country zones into a
  UI-owned cache so the map covers every source, not only rule-referenced
  countries (today it only geolocates cached zones).
- [x] **M6A.6** world map of drops by country (jsVectorMap), ingress focus.
- [x] **M6A.7** live stats — top source countries, top blocked ports; auto-refresh.
- [ ] **M6A.7b** drops-over-time chart (time series).
- [~] **M6A.8** offline map assets (bundle jsVectorMap), prebuilt release binaries,
  hardened service (drop root/caps), tests. *(Map assets vendored & served from
  `/vendor/` in 1.17.1 — no CDN; release binaries / hardening still open.)*

### Phase B — visual editor (writes) 📋

An **enterprise-grade, object-oriented policy editor** (Palo Alto / Fortinet
ergonomics) that stays faithful to nftgeo's model: the UI is a *view + editor*
over `rules.conf`/`config`, and every change flows through **Draft → Commit**
(`validate → plan → apply --confirm`, deadman-guarded). Writes require a
read-write session token; `--ro` sessions never leave read-only. Guiding rule:
**you never lose your context and you never deploy by accident.**

**Layout (M6B.0)** — three-pane shell: left sidebar (Dashboard / Objects /
Firewall Rules / Templates / Logs), central work area (data tables), and a
right **slide-out drawer** for editing (no pop-ups — the table stays visible
behind). A persistent **Commit/Deploy bar** across the top shows pending-change
count.

- [x] **M6B.1 Draft engine (backend).** *(Shipped 1.18.0.)* Server-side draft of
  `rules.conf` (read-write sessions only); all edits mutate the draft, never the
  live file. `GET/PUT /api/draft`, `/api/draft/discard`, and the commit pipeline
  `/api/commit/preview|apply|keep|rollback|status` — `validate → plan →
  apply --confirm` with the deadman, plus UI-side `rules.conf` backup/restore so
  a timed-out or interrupted deploy can never persist. Foundation raw editor +
  top Commit bar included; the visual editor (M6B.2–M6B.5) builds on this.
- [x] **M6B.2 Objects module.** *(Shipped 1.19.0.)* Editable tabs for **Address
  groups** (`GROUP_*`) and **Custom regions** (`REGION_*`) with a right slide-out
  drawer and member chips, stored in a UI-owned `groups.d/ui-objects.conf` drop-in
  and staged through the same Commit pipeline (input sanitised against shell
  metacharacters). Services/host-label objects (`SERVICE_*`/`HOST_*`) follow with
  the internal firewall (P5).
- [x] **M6B.3 Policy table (Palo-Alto style).** *(Shipped 1.20.0.)* Columns
  **№ · On · Name · Source · Destination · Service · Action · Hits**; object
  references render as chips with member tooltips; Action colour-coded
  (DROP red / ACCEPT green); Hits from the live counters. Row **drag-drop
  reorder** (top-down precedence), an **enable/disable toggle** (disabled = stored
  commented-out), and a live filter — all writing to the draft. Lossless parse
  keeps each rule's trivia + verbatim body.
- [x] **M6B.4 Rule editor drawer + inline edit.** *(Shipped 1.21.0.)* Add / edit /
  delete rules in the right drawer (action, direction, protocol, port, target with
  group/region autocomplete, `on <iface>`, name); click a target chip for an
  **inline quick-edit**. Fields validated server-side; the engine's `validate` is
  the final gate. Writes to the draft, deploys via Commit.
- [x] **M6B.5 Sections / rule groups.** *(Shipped 1.22.0.)* Titled section headers
  ("Perimeter", "DMZ", "Egress") group rules for readability; add / rename / delete
  / drag them. Stored as `## Title` comment lines in `rules.conf` (round-trip
  lossless, ignored by the engine).
- [ ] **M6B.6 Commit / Deploy pipeline.** Top-bar **Commit** button → change
  summary ("+1 rule, ~1 object") → `validate` → `plan` visual diff → on confirm
  `apply --confirm` with the in-page deadman countdown / one-click rollback.
  Pending edits are highlighted (yellow) until committed. Nothing touches the
  live firewall before this step.
- [ ] **M6B.7 Templates / building blocks.** Predefined rule blocks ("Basic
  Geo-Drop", "Safe Web Server") importable at the top of the policy; save / load
  reusable sets. Import inserts into the draft (still needs a Commit).
- [~] **M6B.8** auth + TLS for non-localhost use; minimal RBAC. *(Auth shipped in
  1.17.0: root-minted per-session tokens, single-use read-write with inactivity
  TTL, long-lived read-only; TLS still expected via a front proxy.)*

### Phase C — polish 📋
- [ ] **M6C.1** template library / presets.
- [ ] **M6C.2** saved dashboard layouts.
- [ ] **M6C.3** alerts (drop spikes, stale feeds, failed runs).

## Backlog (unscheduled ideas)

- Auto-throttle brute-force: kernel-native `limit rate ... add @dyn_block` (the
  reactive half of `nftgeo block`).
- Conntrack limits: per-source connection caps (`ct count`), SYN-flood / synproxy.
- Anti-spoofing / rpfilter, MSS clamping (VPN/PPPoE gateways), flowtable offload.
- Prometheus metrics export; fail2ban as an actuator; userspace log listener.
- Declarative config schema / API; multi-host (fleet) mode.
