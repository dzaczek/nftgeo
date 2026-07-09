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
- Per-rule connection logging: `log` keyword on any filter rule (`nftgeo-accept:`
  / `nftgeo-drop:<name>` prefix), toggleable per rule from the dashboard *(1.60.0)*.
- `LOG_WHITELIST` — log whitelist hits as `nftgeo-accept:whitelist` *(1.61.0)*.
- Built-in well-known service catalog (name → port, e.g. `https`), overridable by
  `SERVICE_<NAME>`; empty/`-` port = every port of a proto (`tcp -`, `meta l4proto`);
  create `rules.d/*.conf` files from the dashboard *(1.62.0)*.
- Ingress hook — early stateless drop via `ingress.conf`/`ingress.d/` (`<accept|drop>
  <target> [proto] [port] [log]`), whitelist auto-first; opt-in *(1.64.0)*.
- **P1 — HARDEN**: loopback accept, `ct state invalid` drop, essential ICMPv6.
- **P2 — Interfaces**: `on <iface>` on any rule, arbitrary interface names
  (VLANs, tunnels, bridges) with an unknown-interface warning.

---

## ✅ P3 — Egress NAT (masquerade / SNAT) *(shipped 1.36.0)*

**Goal:** act as a gateway that NATs an internal network out to the world.

```text
masquerade on eth0                  # masquerade everything leaving via the WAN
snat out on eth0 to 203.0.113.7     # or a static source NAT
```

Milestones:
- [x] **M3.1** `nat` table + `postrouting` chain scaffolding (emitted only when a
  NAT rule exists; coexists with the filter table).
- [x] **M3.2** `masquerade on <iface>` → `oifname <iface> masquerade`.
- [x] **M3.3** `snat out on <iface> to <ip>` (static source NAT).
- [x] **M3.4** warn when IP forwarding is disabled (document; sysctl not managed).
- [x] **M3.5** `validate`/`plan`/deadman aware; fail-safe.
- [x] **M3.6** docs, examples, Docker (privileged netns) tests.

---

## ✅ P4 — Ingress NAT / port-forward *(shipped 1.37.0)*

**Goal:** expose an internal service on the box's public interface — the headline
"I don't need another firewall" feature. Geo and interface qualifiers reused.

```text
dnat tcp 443  to 10.0.0.5:8443              # WAN:443 -> internal 10.0.0.5:8443
dnat tcp 2222 to 10.0.0.5:22 on eth0        # scope the redirect to the WAN iface
dnat tcp 2222 to 10.0.0.5:22 from europe    # only reachable from Europe
```

Shipped grammar: `dnat <proto> <port> to <ip>[:<port>] [from <geo>] [on <iface>]`
(IPv4/IPv6; `from`/`on` in either order).

Milestones:
- [x] **M4.1** `prerouting` NAT chain scaffolding.
- [x] **M4.2** `dnat <proto> <port> to <ip[:port]>` parse + emit (v4 + v6).
- [x] **M4.3** `on <iface>` qualifier and geo-restricted DNAT (`from <geo>`,
  same-family `ip saddr @g_<geo>` match) *(shipped 1.41.0)*.
- [x] **M4.4** forwarded DNAT traffic passes the filter — achieved via the
  accept-policy forward chain rather than an explicit auto-emitted `fwd-in` rule
  (same "just works" outcome).
- [ ] **M4.5** hairpin/reflexive NAT (reach the service via the public IP from
  inside the LAN) — **not auto-emitted**; needs a public-IP + LAN-subnet input.
  Documented manual recipe (split-DNS or a prerouting-DNAT + postrouting-masq
  pair) in the README until a first-class form is designed.
- [x] **M4.6** warn on disabled forwarding; IPv4-first.
- [x] **M4.7** docs, examples, tests *(render fixtures + `examples/71-nat-gateway.conf`)*.

---

## ✅ P5 — Internal firewall / segmentation (VLANs & zones) *(shipped 1.38.0)*

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

# Zones: a segment = a list of interfaces (incl. VLAN subinterfaces)
ZONE_WEB="eth0.10"
ZONE_DB="eth0.20"
ZONE_MGMT="eth0.99"
```

### Inter-zone rules (forward chain)

```text
allow web  -> db   tcp postgres         # web tier reaches the DB service
allow mgmt -> any  tcp 22               # mgmt may SSH into any internal zone
allow any  -> web  tcp web from europe  # world -> web (http/https), geo-filtered
deny  db   -> any  any -                # the DB initiates nothing (egress lockdown)
```

`allow|deny <zone> -> <zone> <proto> <port> [from <geo>]` matches the source
zone's interfaces (iifname) against the destination zone's (oifname); the port
field accepts `SERVICE_<NAME>` names; `from <geo>` layers a source-geo set on
top. `SEGMENT_DEFAULT="deny"` drops all forwarded traffic between zone
interfaces that no rule allows.

Milestones:
- [x] **M5.1** Service names + `SERVICE_<NAME>` groups *(shipped 1.24.0)* — named
  ports and port groups usable in a rule's port field (`allow in tcp web any`),
  nestable, resolved to `dport { … }`. Editable in the nftgeo-ui Objects tab.
- [x] **M5.2** Host/IP labels (`HOST_<NAME>`) *(shipped 1.35.0)* — named single
  IP/CIDR usable as any rule target; editable in the nftgeo-ui Objects > Hosts tab.
- [x] **M5.3** Zones (`ZONE_<NAME>` = interface list, incl. VLAN subinterfaces)
  as source/destination *(shipped 1.38.0; editable in the nftgeo-ui Objects >
  Zones tab with an interface picker since 1.44.0)*. Subnet members remain a future add.
- [x] **M5.4** Inter-zone rule form `allow|deny <zone> -> <zone> <proto> <port>
  [from <geo>]` emitted into the forward chain *(shipped 1.38.0)*; deny wins over
  allow, and `SEGMENT_DEFAULT="deny"` gives per zone-pair deny-by-default.
- [x] **M5.5** VLANs handled via subinterfaces (`eth0.10`) used directly as zone
  members *(shipped 1.38.0)*. Explicit 802.1Q `vlan id <N>` matching (trunk ports,
  before tag strip) is a netdev/bridge concern and stays out of the inet filter.
- [x] **M5.6** Optional default-deny between zones (`SEGMENT_DEFAULT="deny"`)
  *(shipped 1.38.0)*.
- [x] **M5.7** docs, examples, tests; interplay with geo/abuse/HARDEN and P3/P4 NAT
  *(shipped 1.38.0)*.

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
- [x] **M6A.7b** drops-over-time chart (time series).
- [~] **M6A.8** offline map assets (bundle jsVectorMap), prebuilt release binaries,
  hardened service (drop root/caps), tests. *(Map assets vendored & served from
  `/vendor/` in 1.17.1 — no CDN; release binaries / hardening still open.)*

### Phase B — visual editor (writes) 🚧 (core shipped in 1.18.0–1.23.0)

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
- [x] **M6B.2 Objects module.** *(Shipped 1.19.0; +services/hosts, +zones with an
  interface picker in 1.44.0.)* Editable tabs for **Address
  groups** (`GROUP_*`) and **Custom regions** (`REGION_*`) with a right slide-out
  drawer and member chips, stored in a UI-owned `groups.d/ui-objects.conf` drop-in
  and staged through the same Commit pipeline (input sanitised against shell
  metacharacters). Services/host-label objects (`SERVICE_*`/`HOST_*`) follow with
  the internal firewall (P5).
- [x] **M6B.3 Policy table (Palo-Alto style).** *(Shipped 1.20.0.)* Columns
  **№ · On · Name · Source · Destination · Service · Action · Hits**; object
  references render as chips with member tooltips; Action colour-coded
  (DROP red / ACCEPT green); Hits from the live counters, with a baseline strip (1.45.0) showing the implicit established/related + whitelist accepts so low allow-rule hits make sense. Row **drag-drop
  reorder** (top-down precedence), an **enable/disable toggle** (disabled = stored
  commented-out), and a live filter — all writing to the draft. Lossless parse
  keeps each rule's trivia + verbatim body. *(1.40.0: also renders NAT
  (masquerade/snat/dnat) and inter-zone (`<z> -> <z>`) rules as their own row
  kinds — verbatim NAT badge, zone src→dst chips — instead of mis-columning
  them. 1.42.0: dedicated **+ Zone**, **+ NAT** and **+ Synproxy** drawers author/edit
  them with validated fields and zone-name autocomplete.)*
- [x] **M6B.4 Rule editor drawer + inline edit.** *(Shipped 1.21.0.)* Add / edit /
  delete rules in the right drawer (action, direction, protocol, port, target with
  group/region autocomplete, `on <iface>`, name); click a target chip for an
  **inline quick-edit**. Fields validated server-side; the engine's `validate` is
  the final gate. Writes to the draft, deploys via Commit.
- [x] **M6B.5 Sections / rule groups.** *(Shipped 1.22.0.)* Titled section headers
  ("Perimeter", "DMZ", "Egress") group rules for readability; add / rename / delete
  / drag them. Stored as `## Title` comment lines in `rules.conf` (round-trip
  lossless, ignored by the engine).
- [x] **M6B.6 Commit / Deploy pipeline.** *(Shipped; verified 1.42.0.)* Top-bar
  **Commit** bar with a live pending-change summary (per-file counts) →
  `validate` → `plan` visual diff (`/api/commit/preview`) → on confirm
  `apply --confirm` with an in-page deadman countdown and a one-click
  **Keep** / **Roll back**. The bar is highlighted until committed; nothing
  touches the live firewall before this step.
- [x] **M6B.7 Templates / building blocks.** *(Shipped 1.23.0.)* Built-in blocks
  (*Block abuse feeds*, *Safe Web Server*, *Basic Geo-Drop*) import to the top of
  the policy as their own section; save the current policy as a reusable template
  and delete saved ones. Import stages into the draft (still needs a Commit).
- [~] **M6B.8** auth + TLS for non-localhost use; minimal RBAC. *(Auth shipped in
  1.17.0: root-minted per-session tokens, single-use read-write with inactivity
  TTL, long-lived read-only; TLS still expected via a front proxy.)*

### Phase C — polish ✅
- [x] **M6C.1** template library / presets (6 built-in presets: `mail-server`,
  `wireguard`, `ssh-lockdown`, plus the original 3).
- [~] **M6C.2** saved dashboard layouts — **skipped** (not worth the complexity;
  focus on template presets instead).
- [x] **M6C.3** alerts (drop spikes, stale feeds, failed runs) — `/api/alerts`
  endpoint, `detectSpike`, `buildAlerts`, banner in dashboard UI.
- [x] **M6C.4** in-memory stats store + Top-IP stats — `/api/top-ips` endpoint
  with time-range filtering, 50 MB cap, periodic disk dump.

## Backlog (unscheduled ideas)

- ✅ Auto-throttle brute-force *(shipped 1.27.0)*: kernel-native `throttle` rules
  (`limit rate over ... add @throttle_block`) — the reactive half of `nftgeo block`.
- [x] SYN-flood / synproxy *(shipped)*; per-source connection caps (`ct count`) still open.
- [x] Anti-spoofing / rpfilter (`ANTISPOOF`) *(shipped)*; MSS clamping, flowtable offload still open.
- Prometheus metrics export; fail2ban as an actuator; userspace log listener.
- Declarative config schema / API; multi-host (fleet) mode.
