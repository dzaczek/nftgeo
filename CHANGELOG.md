# Changelog

All notable changes to `nftgeo` are documented here. Versions follow
[Semantic Versioning](https://semver.org/). The running version is reported by
`nftgeo-update --version` and in the `Loaded` log line of each run.

## [Unreleased]

Remaining ideas are tracked in [ROADMAP.md](ROADMAP.md).

## [1.57.0] - 2026-07-09

First step of the sequential-rule-model epic (#46). Engine only — do **not**
release/deploy on its own; the migration (#43) and docs (#44) must land first.

### Changed — ⚠️ BREAKING: rule evaluation is now sequential (file order)

- **`allow`/`deny` rules are evaluated top-to-bottom in the order they appear**
  in `rules.conf`/`rules.d`, first match wins — like a classic firewall. The
  previous model emitted all `deny` before all `allow`, so order in the file did
  not matter; now it does. (#41)
- **Automatic deny-by-default is removed.** Previously a port with any geo-fenced
  `allow` was implicitly closed to every other source. Now a port is closed only
  by an explicit `deny <dir> <proto> <port> any` **or** by `DEFAULT_INPUT="drop"`.
- **Migration required.** Existing configs that relied on deny-by-default will
  leave those ports open under this version until an explicit trailing `deny` is
  added — see #43 for the automated migration. The baseline still runs first and
  is unchanged (loopback, `ct invalid`, `established,related`, whitelist,
  synproxy, throttle), so this cannot bypass the whitelist or open established
  state; it only affects ports you geo-fenced with `allow`.

Idiom going forward:

```
allow in tcp 22 pl
deny  in tcp 22 any     # close the port to everyone else
```

## [1.56.0] - 2026-07-09

Integrates PR #40 (chain-grouped Policy view) after fixing its correctness bugs.

### Added
- **Chain-grouped Policy view.** Rules are now grouped into per-chain cards
  (INPUT / FORWARD / OUTPUT / NAT), each with a flow bar that shows the **actual
  evaluation order** the engine emits — `invalid ✗ → ct est ✓ → @wl ✓ → deny →
  allow → deny-by-default → policy` (with live baseline counters) — making it
  clear that order is fixed by the engine, not by row order. A whitelist summary
  card sits at the top of the view with a bulk editor that writes to the
  whitelist draft (deployed via Commit under the deadman).

### Fixed
- Corrected the PR's flow diagram, which showed `established → whitelist →
  invalid` — the real order is `invalid → established → whitelist`, with your
  `deny` rules before `allow` and a per-port deny-by-default.
- Renamed the drawer's save function to avoid a collision with the existing
  `saveWhitelistDraft` (the whitelist editor from 1.55.0), which silently saved
  the wrong data.
- NAT rules now render in their own NAT group instead of being lumped into
  FORWARD, and the flow uses the real theme CSS variables (the PR referenced
  several undefined ones, leaving chips unstyled).

## [1.55.0] - 2026-07-09

Integrates PR #39 and closes the two follow-ups from the PR #35 review.

### Added
- **Whitelist as dedicated files with the deadman (closes #37).** The whitelist
  now lives in `/etc/nftgeo/whitelist.conf` (IPs/CIDRs) and
  `/etc/nftgeo/whitelist-hosts.conf` (hostnames), edited from the dashboard
  through the same **draft → commit → deadman** pipeline as rules and objects —
  no more direct writes to the live config, and a whitelist change that would cut
  your access auto-rolls-back. The engine reads each file when it has any entry
  and otherwise falls back to the legacy `WHITELIST=` / `WHITELIST_HOSTS=` config
  variables, so existing setups keep working and an entry removed in the UI stays
  removed. New `/api/whitelist/draft` endpoint; `WHITELIST_FILE` /
  `WHITELIST_HOSTS_FILE` engine variables.
- **Template group-target validation (closes #38).** Importing a service template
  that references an undefined group (e.g. `ADMINS`, `APPS`, `MONITORING`) now
  returns a warning telling you to create the `GROUP_*` object first, instead of
  failing silently at commit time.

### Removed
- The v1.54.0 direct-config-write whitelist endpoint (`/api/whitelist`
  POST/DELETE) is superseded by the draft pipeline above.

## [1.54.0] - 2026-07-09

Integrates PR #35 (service templates, rule-stats, whitelist editor, docs).

### Added
- **15 new service templates.** `nginx`, `kamailio`, `redis`, `postgres`,
  `mysql`, `gitlab`, `docker-registry`, `elasticsearch`, `grafana`,
  `dns-server`, `openvpn`, `minecraft`, `mosh`, `prometheus-stack` —
  bringing the total built-in template count from 6 to 21. Each includes
  abuse filtering and uses placeholder group names (`ADMINS`, `APPS`,
  `MONITORING`) for easy adaptation.
- **Rule statistics API (`/api/rule-stats`).** Returns a breakdown of all
  rules by action (allow/deny/throttle/synproxy/nat/zone), counts of
  deny-abuse and allow-any rules, whitelist IP/host counts, and live
  whitelist hit counters from the kernel baseline.
- **Whitelist management API (`/api/whitelist`).** GET, POST (add), and
  DELETE (remove) endpoints for `WHITELIST` and `WHITELIST_HOSTS` entries.
  Entries are validated (IP/CIDR via `net.ParseCIDR`/`net.ParseIP`, hostnames
  rejected if they contain shell metacharacters). The config file is updated
  in place, preserving its existing permissions (it holds the AbuseIPDB key)
  and written atomically; the change takes effect on the next `nftgeo apply`.
- **Dashboard whitelist editor.** The Objects → Reference tab now shows
  a **+ Add** button (with IP/CIDR or hostname selector) and a **🗑**
  button per entry for removing whitelist items with confirmation.
- **README diagrams.** A "How it works" and a "Rule evaluation order" ASCII
  diagram, plus the expanded template list.

## [1.53.1] - 2026-07-08

### Added
- **"Shadowed by whitelist" hint in Policy.** An allow rule that is loaded but has
  0 hits now shows a small `*` when the traffic is actually being accepted ahead
  of it by the established/related or whitelist baseline rules (e.g. your own
  whitelisted SSH). Hovering explains why the rule's own counter stays at 0, so a
  0 no longer looks like a broken counter.

## [1.53.0] - 2026-07-08

### Added
- **Deduplicated abuse total.** The dashboard now shows how many unique IPs/ranges
  are actually loaded into the abuse sets — read from the engine's on-disk,
  merged, scrubbed and CIDR-aggregated set — instead of only summing the
  per-source feed counts. The same IP on several feeds is counted once, so the
  headline "abuse IPs" tile and the Abuse sources card now show the real total
  next to the (larger) sum of sources, making feed overlap obvious.

## [1.52.1] - 2026-07-08

### Fixed
- **IPv6 drop lookups showed `Range <nil>/29`.** The RDAP whois panel read the
  block prefix only from the cidr0 `v4prefix` field, which is absent for IPv6
  (those blocks use `v6prefix`), so every IPv6 drop rendered a nil range. It now
  uses whichever prefix the block carries and omits the row when neither exists.
- **Abuse sources mislabeled custom feeds as "blocklist".** The dashboard guessed
  a feed's name by substring-matching its URL, and the generic token "blocklist"
  shadowed the real provider (e.g. a feed on `blocklist.greensnow.co` showed as
  "blocklist" instead of "greensnow"). UI-added feeds now display the label the
  operator gave them, and unlabeled feeds resolve to the actual provider name.

## [1.52.0] - 2026-07-08

### Added
- **CIDR aggregation for abuse feeds.** Before loading, abuse IPs are collapsed
  into CIDR ranges (`ABUSE_FEEDS_AGGREGATE`, default on) so adjacent addresses
  become a single prefix — a smaller nftables set that loads and matches faster.
  Uses `iprange` (IPv4) / `aggregate6` (IPv6) when installed and falls back to
  the kernel's set auto-merge otherwise. `install.sh` now pulls in `iprange`
  best-effort. The run log reports `Aggregated abuse IPv4: X -> Y CIDRs`.
- **Paced (batched) loading for very large blocklists.** When the abuse set has
  more than `ABUSE_FEEDS_BATCH` entries (default 0 = off), the ruleset loads
  with an empty abuse set and the engine fills it in chunks of that size,
  pausing `ABUSE_FEEDS_BATCH_SLEEP` seconds between chunks, so a multi-million-IP
  feed can't spike load average on a small box. Protection ramps up over the
  load window; a warning is logged when batching starts.
- **Abuse-load progress in the dashboard.** A new `/api/abuse-load` endpoint and
  a warning banner with a progress bar show a batched load filling in real time
  ("Loading a large abuse blocklist … loaded / total"), then clear when done.

## [1.51.0] - 2026-07-08

### Fixed
- **Dashboard could melt the box with a large abuse set.** The UI ran
  `nft list table` (which also serialises every set element) on `tableLoaded`,
  `baselineCounters`, and `ruleCounters` — on every refresh. With a multi-million
  IP abuse set each call took minutes and they piled up (load 15+). These now
  query per **chain** (`nft list chain …`), which never dumps set elements, so the
  dashboard is immune to set size.

### Added
- **`ABUSE_FEEDS_MAX`** (default 200000): caps the entries kept from a single
  abuse feed, so a runaway blocklist (e.g. a 57 MB list) can't build a huge,
  slow nftables set. 0 disables it.
- **Custom abuse feeds are now labeled objects.** Manage them in **Objects →
  Reference → + New feed** as `FEED_<LABEL>` objects (a label + one or more URLs),
  edited/deleted like any other object and deployed via Commit. The engine reads
  a derived `ABUSE_FEEDS_UI` (it doesn't enumerate `FEED_*`). Supersedes the flat
  URL textarea from 1.50.0. URLs validated (http(s), no shell metacharacters).

## [1.50.0] - 2026-07-08

### Added
- **Custom abuse feeds from the panel.** A new **Objects → Reference → Custom
  abuse feeds** editor lets you add your own blocklist URLs. Stored as
  `ABUSE_FEEDS_UI` in the UI-managed drop-in and appended to any `ABUSE_FEEDS`
  from `config` (the engine fetches/parses them identically), so a `deny … abuse`
  rule covers them. URLs are validated (http(s) only, no whitespace or shell
  metacharacters) before being written to the sourced file; deployed via Commit.

### Changed
- **Top-IP stats store: lower memory/disk churn.** Cap by entry count
  (`maxStatsEntries`) with a single-slice eviction instead of a per-entry byte
  estimate, and only write `ui-stats.json` when new drops were actually ingested
  (no periodic 50 MB rewrite when idle).

## [1.49.1] - 2026-07-08

### Fixed
- **Top source IPs were over-counted ~12×.** The stats ingester polled the last
  hour of drops every few minutes but never deduplicated, so each drop was
  re-counted on every tick until it aged out of the window. Ingest now tracks a
  high-water-mark timestamp and only records drops newer than the last one seen
  (`filterNewDrops`), and `loadStats` resumes that mark from disk so a restart
  doesn't re-count the overlap. Regression test added.

## [1.49.0] - 2026-07-08

### Added
- **Custom IP lists (`LIST_<NAME>`).** Named IP/CIDR lists you manage from the
  panel's **Objects > IP Lists** tab and use as a rule target — e.g. a personal
  blocklist referenced by `deny in any - mylist`. Resolves like a `GROUP_` (v4/v6
  split into address sets); threaded through the objects draft/commit pipeline.

## [1.48.0] - 2026-07-08

### Added
- **Alerts (M6C.3).** New `/api/alerts` endpoint with `detectSpike` (drop-spike
  detection) and `buildAlerts` (not-loaded / feed-stale / drop-spike). A banner
  in the dashboard UI surfaces current alerts.
- **Template presets (M6C.1).** 3 new built-in template presets —
  `mail-server`, `wireguard`, `ssh-lockdown` — bringing the total to 6.
  Importable from the Templates drawer.
- **Top-IP stats (M6C.4).** New `/api/top-ips` endpoint with time-range
  filtering, backed by an in-memory stats store (50 MB cap, periodic disk dump).
- **Drops-over-time chart (M6A.7b).** Time-series sparkline in the dashboard,
  showing drop event volume over the last N minutes.

## [1.47.0] - 2026-07-08

### Added
- **nftgeo-ui: synproxy rules in the policy editor.** `synproxy` (SYN-flood
  protection) rules now render as their own policy-table row (SYN-guard chip +
  SYNPROXY badge) instead of being invisible trivia, and get a dedicated
  **+ Synproxy** drawer (direction / port / interface, validated server-side via
  `buildSynproxyBody`). Classified in the draft parser and `/api/policy`; excluded
  from counter annotation (synproxy rules carry no `nftgeo:` comment). Round-trip
  verified end-to-end.

## [1.46.0] - 2026-07-08

### Added
- **SYN-flood protection (`synproxy`).** `synproxy <in|fwd-in> tcp <port>
  [on <iface>]` offloads the TCP handshake to the kernel so spoofed SYNs never
  reach the service (issue #14).
- **Anti-spoofing (`ANTISPOOF`).** A config list of interfaces to protect with a
  strict reverse-path filter (uRPF); drops IPv4 packets whose source is not
  routable back through the arrival interface (issue #15).
- **IPv6 geolocation in the dashboard** (issue #13) and a **FortiGate theme**
  (3-way theme switcher) for nftgeo-ui.
- Hardening/robustness fixes from the audit backlog (issues #1–#22): clear a
  stale deadman sentinel after reboot, verify the deadman PID before killing,
  validate the IP in `nftgeo block`, tighten the IPv6 regex, prune the auth
  nonce map, add an HTTP `User-Agent`, URL-fragment auth tokens, and installer/
  uninstaller UI handling.

### Fixed
- **`synproxy` was non-functional as merged.** The `on <iface>` form failed to
  parse (the interface token was mis-read into the geo field) and the
  no-interface form emitted an invalid `iifname ""`. Re-tokenized the rule tail
  and now store only `<hook> <port> <iface>`. Verified with `nft -c` (fixture
  `synproxy`).
- **`ANTISPOOF` was non-functional and inverted as merged.** It emitted `ip fib …`
  — a syntax error, so the ruleset never loaded — and used `oif != 0`, which is
  backwards (drops legitimate traffic, passes spoofed). Corrected to
  `meta nfproto ipv4 fib saddr . iif oif 0` (valid, IPv4-scoped, strict uRPF).
  Verified with `nft -c` (fixture `antispoof`).

## [1.45.0] - 2026-07-08

### Added
- **nftgeo-ui: baseline-counter readout in the Policy view.** A strip above the
  policy table shows the implicit accepts the engine runs before your rules —
  *established/related* and *whitelist* (and any *invalid* drop) — with their live
  packet counters (`/api/baseline`). This explains a common surprise: an `allow`
  rule's own **Hits** stay near zero while only drops climb, because existing and
  whitelisted connections — including your own SSH — are accepted at the baseline,
  not at the geo `allow` rule. Nothing about the ruleset changed; the traffic was
  always counted there, just not surfaced.

## [1.44.0] - 2026-07-08

### Added
- **nftgeo-ui: Zones editor.** A new **Objects > Zones** tab defines `ZONE_*`
  segments as named interface lists — including VLAN subinterfaces
  (`eth0.100`) — with a click-to-add interface picker (and a ⟳ refresh) plus
  free-text entry. Draft-defined zones immediately feed the inter-zone rule
  drawer's zone autocomplete. Interface members are validated (shell-metachars
  rejected) and deployed through the Commit pipeline.
- **NAT masquerade/snat: optional inbound (LAN) interface.** Grammar is now
  `masquerade on <wan> [in <lan>]` and `snat out on <wan> to <ip> [in <lan>]`.
  The WAN (outbound) interface alone is sufficient — masquerade already NATs
  everything routed out it — so the LAN interface is optional and only restricts
  which inbound interface is NAT'd (multi-LAN routers). The NAT drawer gains a
  "LAN interface (inbound, optional)" field. Verified via render fixture + real
  `nft -c` on hermes.

### Fixed
- **Dashboard omitted AbuseIPDB from "Abuse feeds".** The status/health widget
  only listed the netset feeds; it now uses the same source list as the Reference
  tab, so **AbuseIPDB** appears (with its IP count and age) whenever its state
  file is present — even when the blocklist is retained without a live API key.

## [1.43.0] - 2026-07-08

### Added
- **nftgeo-ui: interface picker in the rule drawers.** Every interface field
  (Rule / Throttle / NAT) is now backed by a live datalist of the host's network
  interfaces (`/api/interfaces` via `net.Interfaces()`), with a ⟳ **refresh**
  button for when interfaces change (a VPN/tunnel coming up, etc.). Free text is
  still accepted so you can scope a rule to an interface that is not up yet.

## [1.42.0] - 2026-07-08

### Added
- **nftgeo-ui: dedicated NAT and inter-zone rule drawers.** The panel can now
  author and edit NAT (`masquerade` / `snat` / `dnat`) and inter-zone
  (`<zone> -> <zone>`) rules with proper validated fields — no more Raw-only.
  New **+ NAT** and **+ Zone** toolbar buttons; clicking a NAT/zone row opens
  its drawer pre-filled. The NAT drawer switches fields by type (masquerade =
  interface; snat = interface + source IP; dnat = proto/port/target/`from <geo>`/
  interface). The zone drawer offers **zone-name autocomplete** sourced from the
  `ZONE_*` definitions in config + `groups.d` (via `/api/objects`). Bodies are
  built and validated server-side (`buildZoneBody` / `buildNatBody`) and the
  engine's `validate` remains the final gate; edits stage to the draft and deploy
  through the existing Commit pipeline.

### Notes
- Verified the **Commit / Deploy pipeline** (roadmap M6B.6) is complete —
  pending-change summary, `validate` + `plan` diff preview, `apply --confirm`
  with the in-page deadman countdown, and Keep / Roll-back — and marked it
  shipped in the roadmap (the checkbox was stale).

## [1.41.0] - 2026-07-08

### Added
- **Geo-restricted port-forwarding (roadmap M4.3).** `dnat` now takes an optional
  `from <geo>`, so a forward is only opened for clients in a country/region/group:
  ```
  dnat tcp 2222 to 10.0.0.5:22 from europe     # SSH forward, EU sources only
  dnat tcp 443  to [2001:db8::1]:8443 from pl   # IPv6 target, PL only
  ```
  Full grammar: `dnat <proto> <port> to <ip>[:<port>] [from <geo>] [on <iface>]`
  (`from`/`on` in either order). The geo reuses the existing set machinery and
  matches the client with a same-family `ip saddr @g_<geo>` in the prerouting
  chain. Filter-only and geo-less DNAT configs render identically. Verified via
  render fixtures + real `nft -c` on hermes.

### Notes
- Hairpin/reflexive NAT (M4.5) is intentionally **not** auto-emitted: a correct
  form needs the public IP and LAN subnet. The README/example document the manual
  recipe (split-DNS, or a prerouting-DNAT + postrouting-masquerade pair).

## [1.40.1] - 2026-07-08

### Changed
- Docs completion for the 1.40.0 UI change (finish-a-module doc sweep): CHEATSHEET
  gains a **Dashboard (nftgeo-ui)** section; the README panel section documents the
  NAT/zone row kinds + Raw-edit behaviour; the README roadmap summary now reflects
  P3/P4/P5 as shipped (and flags the open M4.3/M4.5 and M6B.6 items).

## [1.40.0] - 2026-07-08

### Fixed
- **nftgeo-ui: NAT and inter-zone rules are now first-class in the policy table.**
  Previously the panel mis-parsed a zone rule (`allow lan -> dmz tcp 80`) into the
  filter columns (`Dir=lan, Proto=->`) and hid NAT rules (masquerade/snat/dnat)
  entirely. The draft/policy parser now classifies these into `nat` and `zone`
  row kinds: NAT renders as a verbatim badge, zone as source→destination zone
  chips with service/verdict/geo. They round-trip losslessly and — because the
  classic rule drawer would corrupt their grammar — clicking one opens the Raw
  editor. `/api/policy` classifies them too. (Full inline NAT/zone editor drawers
  are still to come; author them via Raw or the config for now.)

## [1.39.1] - 2026-07-08

### Fixed
- CI: the real `nft -c` fixture pass (`tests/render/nft-check.sh`) now copies
  each case's `groups.d/*.conf`, so the zone fixtures resolve their `ZONE_*`
  definitions instead of failing with "unknown source zone". No engine change.

## [1.39.0] - 2026-07-08

### Added
- **`nftgeo(8)` man page.** A full Linux man page covering the operator CLI
  commands, the rules.conf grammar (filter / throttle / NAT / inter-zone rules),
  configuration keys, files and examples. Installed to
  `/usr/local/share/man/man8/` by `install.sh` and to `/usr/share/man/man8/` by
  the `.deb`/`.rpm` packages (`man nftgeo`).
- **Example fragments for NAT and zones.** `examples/71-nat-gateway.conf`
  (masquerade / SNAT / DNAT port-forward) and `examples/75-internal-zones.conf`
  (interface zones + `SEGMENT_DEFAULT` micro-segmentation).

### Changed
- Docs sweep for the P3–P5 features: README (egress/ingress NAT, zones),
  CHEATSHEET, `config.example`, `rules.conf.example`, ROADMAP (P3/P4/P5 marked
  shipped), and the examples index. `make tarball` now ships `man/` and
  `examples/`.

## [1.38.0] - 2026-07-07

### Added
- **Internal firewall: zones & segmentation (roadmap P5).** Name network
  segments by interface and write forward-chain rules between them:
  ```
  # config:
  ZONE_LAN="eth1"   ZONE_DMZ="eth2"   ZONE_GUEST="eth0.100"
  SEGMENT_DEFAULT="deny"
  # rules.conf:
  allow lan -> dmz  tcp 80
  allow wan -> dmz  tcp 443 from europe
  deny  dmz -> lan  any -
  ```
  `allow|deny <zone> -> <zone> <proto> <port> [from <geo>]` emits into the
  forward chain (iifname = source zone, oifname = destination zone); the port
  field accepts `SERVICE_<NAME>` names and `from <geo>` layers a source-geo set
  on top. Deny is emitted before allow, so an explicit deny wins.
  `SEGMENT_DEFAULT="deny"` drops all forwarded traffic between zone interfaces
  that no rule allows (established/related still passes). VLANs are handled via
  subinterfaces (`eth0.100`) used directly as zone members. Zone drops log with a
  `nftgeo-drop:zone` / `nftgeo-drop:segment` prefix under `LOG_DROPS`. Verified
  via real `nft -c` in CI/on hermes; not enabled on any host.

## [1.37.0] - 2026-07-07

### Added
- **Ingress NAT / port-forward (roadmap P4).** Redirect a WAN port to an
  internal host:
  ```
  dnat tcp 8080 to 10.0.0.5:80 on eth0   # forward WAN :8080 to 10.0.0.5:80
  dnat udp 51820 to 10.0.0.9             # forward, no port remap
  dnat tcp 443 to [2001:db8::1]:8443     # IPv6 target
  ```
  Emits a `nat` prerouting (dstnat) chain, only when a `dnat` rule exists.
  Supports optional `:port` remap and `on <iface>` scoping; `dnat` spells out
  the family (`dnat ip`/`dnat ip6`) for the inet table and uses `[addr]:port`
  for IPv6 targets. The forward chain policy is accept, so the redirected packet
  passes without an extra rule. Verified via real `nft -c` in CI/on hermes.

## [1.36.0] - 2026-07-08

### Added
- **Egress NAT (roadmap P3).** Turn nftgeo into a NAT gateway:
  ```
  masquerade on eth0                  # masquerade the LAN out via the WAN
  snat out on eth0 to 203.0.113.7     # or a static source NAT
  ```
  Emits a `nat` postrouting chain in the `nftgeo` table, only when a NAT rule
  exists (filter-only setups are byte-identical). `snat` disambiguates the family
  (`snat ip`/`snat ip6`) for the inet table. `validate` warns when a NAT/forward
  rule is present but `net.ipv4.ip_forward=0` (the sysctl is not managed).
  Verified via real `nft -c` in CI/on hermes; not enabled on any host by default.

## [1.35.0] - 2026-07-08

### Added
- **Host labels (`HOST_<NAME>`).** Name a single IP/CIDR (or a few) and use the
  name as a rule target, like a one-address group: `HOST_DB1="10.0.20.5"` then
  `deny out any - db1`. Editable in the nftgeo-ui Objects > **Hosts** tab; usable
  in the rule target autocomplete. (Roadmap P5 M5.2; completes the object types
  alongside groups/regions/services.)

### Fixed
- The objects draft (Objects tab) failed to save when no rules draft existed yet
  (`ui-drafts/` was never created) - it now creates the dir, like the rules draft.

## [1.34.0] - 2026-07-08

### Changed
- **Drop logs show the rule's name, not just a category.** If a rule has a
  trailing `# comment` (a name), the drop's log prefix now uses it
  (`nftgeo-drop:block others`) so the Logs "policy" column shows exactly which
  rule dropped a packet. Unnamed and synthesized drops (deny-by-default,
  default-deny) still show the category (abuse/geo/deny/default-deny). The
  per-rule counter comment is unchanged (still the full rule line).

## [1.33.0] - 2026-07-07

### Changed
- **Exact per-rule hit counts.** The dashboard used a best-effort signature match
  to map a rule to its live counters, which missed rules using a `SERVICE_` name
  in the port, a multi-port set, or an interface qualifier (they showed 0/unmatched
  even when the kernel counter wasn't). The engine now stamps every generated rule
  with a `comment "nftgeo:<the rules.conf line>"`, and the UI reads exact counters
  via `nft -j`, summing per comment (v4+v6, proto buckets). Hit counts are now
  correct for every rule form, and `nft list table inet nftgeo` is self-documenting
  (each line shows its source rule). Allow-rule counts still reflect *new*
  connections (the stateful `established,related accept` handles the rest), so they
  are naturally lower than deny counts.

## [1.32.0] - 2026-07-07

### Added
- **Drops show which policy dropped them.** The engine now tags each drop's log
  prefix with a reason — `nftgeo-drop:abuse` / `:geo` / `:deny` / `:default-deny`
  — and the dashboard's Logs table gains a **policy** column showing it. (Needs
  `LOG_DROPS`; existing logs from before this release show "—".)
- **Abuse sources in the Objects reference.** The old "Abuse feeds" panel is now
  **Abuse sources**: it lists what actually fills the `abuse` blocklist —
  AbuseIPDB and each cached feed — with the **entry count** and age per source.

### Changed
- **Removed the "Rules (edit)" tab; the Policy tab is the editor.** The raw
  textarea (the M6B.1 foundation) was redundant now that the visual editor covers
  the whole grammar. A discreet **Raw** button on the Policy toolbar still opens a
  per-file raw text editor for power users / bulk edits (`GET/PUT /api/draft` kept).

## [1.31.0] - 2026-07-07

### Added
- **Default-deny input policy (`DEFAULT_INPUT="drop"`).** Flip the input chain
  from the default selective-blocklist (`policy accept`) to **default-deny**: only
  established/related, loopback, `WHITELIST` and explicit `allow in` rules pass;
  everything else is dropped. Loopback is auto-accepted even without `HARDEN`, and
  `validate` warns when nothing admits inbound traffic (anti-lockout). Invalid
  values are rejected. Pairs with the deadman; the render is verified but not
  enabled anywhere by default. (Edge-chain counterpart to the planned per-zone
  `SEGMENT_DEFAULT`.)

## [1.30.1] - 2026-07-07

### Fixed
- **Panel deploy was broken since 1.26.0.** The multi-file refactor moved commit
  backups to `ui-backups/<file>`, but `backupLive` never created that directory,
  so every Deploy failed at the backup step ("cannot back up live files"). It now
  creates the backup dir. Added a regression test. *(Reported: a reorder + Deploy
  returned an error.)*
- **Deploy error messages are honest now.** The panel showed "Deploy blocked:
  invalid draft" for *any* apply failure (a deploy already pending, a backup/stage
  error, …). It now surfaces the real error and, for an invalid draft, opens the
  preview with the engine's validation output.

## [1.30.0] - 2026-07-07

### Added
- **Throttle rules in the panel.** The visual policy editor now understands
  `throttle` rules: they render as their own row (a rate chip, `THROTTLE` badge
  with the ban in the tooltip) and a **+ Throttle** button / row-click opens a
  dedicated drawer (direction, protocol, port, rate = number + per second/minute/
  hour, optional ban and interface). They toggle, reorder, delete and deploy
  through the same draft→Commit pipeline as every other rule; input is validated
  server-side and by the engine at preview. Previously throttle rules were only
  editable in `rules.conf` / the raw editor. New tests cover `buildThrottleBody`
  and throttle parsing.

## [1.29.0] - 2026-07-07

### Added
- **Releases & packaging (track B).** nftgeo now ships prebuilt artifacts:
  - `.deb` and `.rpm` packages (amd64 + arm64, built with nfpm) that install the
    engine, CLI, dashboard binary, systemd units and example configs to FHS paths
    (`/usr/sbin`, `/etc/nftgeo`, `/usr/lib/systemd/system`), seed config on first
    install, and never auto-enable anything.
  - Prebuilt `nftgeo-ui` binaries (linux amd64 + arm64) and a source tarball.
  - A `Makefile` (`build` / `test` / `lint` / `package` / `tarball`) and a
    `release` GitHub workflow that tests, builds and publishes all of the above to
    a GitHub Release on every `v*` tag.

### Changed
- **Hardened the `nftgeo-ui` service** and corrected its description (it is a
  dashboard *and* editor now, not read-only): `PrivateTmp`, `ProtectSystem=full`
  (keeps `/etc` writable for commits), on top of the existing `NoNewPrivileges` /
  `ProtectHome`.

## [1.28.0] - 2026-07-07

### Added
- **Test suite + CI.** First automated tests for a firewall that had none:
  - `tests/render/` — golden/snippet render tests: each fixture renders offline
    and asserts on the generated ruleset (must/must-not contain) or on the
    expected error. Covers regressions and features: `deny … any` (must not emit
    a phantom geo set), service→`dport { … }` buckets, mixed `all` proto, throttle
    sets/rules, HARDEN, interfaces, groups, and invalid-input rejection.
  - `tests/render/nft-check.sh` — renders every fixture through a real `nft -c`.
  - `ui/main_test.go` — table-driven Go tests for the parsers (`buildRuleBody`
    incl. injection rejection, `parseDraftRules`/`serializeDraftRules` round-trip,
    objects round-trip, `sanitizeObjects`).
  - `.github/workflows/ci.yml` — shellcheck, `gofmt`/`go vet`/`go test`/build, and
    both render harnesses on every push.

### Fixed
- **Draft round-trip no longer accumulates blank lines.** `parseDraftRules`
  treated a file's trailing newline as a blank line, so each save-through added an
  empty line at EOF; it now drops the terminator. (Caught by the new Go tests.)

### Changed
- **Render-only runs are unprivileged and side-effect-free.** `validate` / `plan`
  and the test harness no longer require root and no longer create `STATE_DIR` or
  touch the live `nft` path; the kernel check is skipped when `nft` is absent or
  `NFTGEO_SKIP_NFT_CHECK=1` (a real load still requires both).

## [1.27.0] - 2026-07-07

### Added
- **Reactive auto-block: `throttle` rules (brute-force protection).** Rate-limit a
  port per source and auto-ban offenders, entirely in the kernel (no daemon):
  ```
  throttle in tcp 22 5/minute            # >5 new SSH conns/min from one IP -> ban
  throttle in tcp 3389 3/minute ban 2h   # custom ban duration
  throttle fwd-in udp 5060 20/second on eth0
  ```
  Under the rate, traffic is untouched; over it, the source is added to a dynamic
  timeout set and dropped for `THROTTLE_BAN` (default `1h`, per-rule `ban <dur>`).
  Implemented with the nftables meter→blackhole idiom (a per-port meter set holds
  the per-source `limit rate over`, a shared `throttle_block{4,6}` set holds the
  bans). Runs after the whitelist, so **whitelisted sources are never throttled**.
  Supports `in` / `fwd-in`, `tcp` / `udp`, ports / ranges / lists, and `on <iface>`.
  This is the reactive half of `nftgeo block`. The block-set sizes show up in the
  dashboard's live-sets view; the visual editor preserves throttle lines untouched
  (configure them in `rules.conf` / the raw editor for now).

## [1.26.1] - 2026-07-07

### Changed
- **nftgeo-ui: sections group, files are just a badge.** Following on from the
  multi-file editor, the Policy table no longer draws big per-file group headers
  (which double-grouped alongside sections). Rules render as one flat list in
  engine order; **sections** (`## …`) remain the grouping mechanism, and the
  source file shows as a small **File** badge per rule (column hidden entirely
  when everything lives in `rules.conf`). Editing, the file picker on Add rule,
  and within-file reordering are unchanged.

## [1.26.0] - 2026-07-07

### Changed
- **nftgeo-ui editor now spans `rules.d/*.conf`, not just `rules.conf`.** The
  visual policy editor previously only read/edited `rules.conf`, so rules kept in
  `rules.d` drop-ins were invisible in the panel (a regression vs the original
  read-only view, which listed them). The Policy table now groups rules by file
  (`rules.conf` first, then each `rules.d/*.conf` in engine order); toggle /
  reorder / edit / delete / add-section operate within a rule's file; **Add rule**,
  **+ Section** and **template import** let you choose the target file; and the
  Commit pipeline stages every changed rule file (each drafted under
  `ui-drafts/<path>`, deployed together through the deadman). Preview renders the
  drafts of all files via a temp `RULES_DIR`, so validate/plan reflect the whole
  policy. Reordering is scoped within a file (the engine's cross-file order is set
  by filename).

## [1.25.0] - 2026-07-07

### Added
- **Per-protocol service members (`port/proto`).** A `SERVICE_*` member may now
  carry a protocol tag, so one service can span TCP and UDP:
  ```sh
  SERVICE_DNS="53/tcp 53/udp"
  SERVICE_APP="443/tcp 3478/udp"
  ```
  ```
  allow in any dns any     # -> tcp dport 53 ; udp dport 53
  allow in tcp web any      # bare ports still take the rule's protocol
  ```
  A **bare** port takes the rule's protocol (`all`/`any` → both TCP and UDP); a
  **tagged** port is fixed to its protocol. A tag that conflicts with a specific
  rule protocol (e.g. a `/udp` member under `proto tcp`) is a clear error — use
  `any`/`all` to emit every protocol the service defines. Fully backward
  compatible: existing bare-port services are unchanged. The engine expands a
  rule into one normalized line per resolved protocol. In nftgeo-ui the rule
  editor now offers `all`/`sctp` protocols and keeps the port field editable for
  `any` (blank = every port, or a service).

## [1.24.0] - 2026-07-07

### Added
- **Service objects (`SERVICE_*`) — named ports & port groups (roadmap P5, M5.1).**
  Define a service in the config or a `groups.d` drop-in and use its name in a
  rule's port field:
  ```
  SERVICE_WEB="80 443"
  SERVICE_STACK="web 8080-8090"     # services can nest other services
  allow in tcp web any
  allow in tcp stack any
  ```
  The engine resolves a port token that is a number, a range (`N-M`), a
  comma/space list, or a `SERVICE_` name (recursively, with a cycle guard) into a
  normalized set and emits `tcp dport { … }`. In **nftgeo-ui** the Objects tab now
  has a **Services** section to create/edit/delete these, and the rule editor's
  port field autocompletes service names. Input is sanitised before it reaches the
  shell-sourced config.

### Fixed
- **`deny <dir> <proto> <port> any` now works.** The deny path always emitted an
  address-set match, so a deny rule with the `any` target referenced a
  non-existent `@g_any` set and failed to load; it now drops on the protocol/port
  alone (both families, honouring `LOG_DROPS`), mirroring the allow path. Surfaced
  while adding service objects (`deny in tcp <service> any`).

## [1.23.0] - 2026-07-07

### Added
- **nftgeo-ui templates / building blocks (roadmap Phase B, M6B.7).** A
  **Templates** drawer on the Policy tab offers built-in blocks — *Block abuse
  feeds*, *Safe Web Server*, *Basic Geo-Drop* — that **import to the top** of the
  policy (into the draft, each as its own section) for review and Commit. You can
  also **save the current policy as a reusable template** and delete your saved
  ones (built-ins are protected). Saved templates live in a UI-owned
  `ui-templates.json`. New endpoints: `GET/POST /api/templates`,
  `POST /api/templates/delete`, `POST /api/rules/draft/import`.
  This rounds out the Phase B visual editor.

## [1.22.0] - 2026-07-07

### Added
- **nftgeo-ui rule sections (roadmap Phase B, M6B.5).** Group rules under titled
  section headers ("Perimeter", "DMZ", "Egress"…) for readability in large
  policies. **+ Section** adds a divider; click one to rename or delete it; drag
  it like any row to position it. Sections are stored as `## Title` comment lines
  in rules.conf, so they round-trip losslessly and the engine ignores them
  (validated on hermes: adding/moving a section keeps the ruleset byte-identical).
  New endpoint: `POST /api/rules/draft/section` (add/rename); delete reuses the
  rule-delete endpoint. Next: templates / building blocks (M6B.7).

## [1.21.0] - 2026-07-07

### Added
- **nftgeo-ui rule editor (roadmap Phase B, M6B.4).** The policy table is now
  fully editable. **+ Add rule** and clicking a row open a right slide-out drawer
  to set action, direction, protocol, port, target (with an autocomplete of your
  groups / regions / `any` / `abuse`) and interface, plus a name; **Delete**
  removes a rule. Clicking a target chip does an **inline quick-edit** of just
  that target. All edits write to the draft and deploy via the same Commit
  pipeline. Fields are validated server-side (enum action/direction/protocol,
  numeric port, safe target/interface) — the engine's `validate` remains the
  final gate at preview/deploy. New endpoints: `POST /api/rules/draft/save`
  (add/edit) and `POST /api/rules/draft/delete`. Read-only sessions cannot edit.
  This completes the core visual editor; sections and templates (M6B.5, M6B.7)
  are next.

## [1.20.0] - 2026-07-07

### Added
- **nftgeo-ui visual policy table (roadmap Phase B, M6B.3).** The Policy tab is
  now an enterprise-style editor over the draft rules: columns **№ · On · Name ·
  Source · Destination · Service · Action · Hits**, with Source/Destination
  derived from the rule direction, object references shown as **chips** (group /
  region tooltips resolve their members), colour-coded actions (ACCEPT green /
  DROP red) and live hit counts. Rows support **drag-and-drop reorder**
  (top-down precedence) and an **enable/disable toggle** — both write to the
  draft (a disabled rule is stored commented-out) and deploy via the same Commit
  pipeline. Parsing is lossless: each rule keeps its leading comments/blank lines
  and verbatim body, so reorder/toggle round-trip cleanly. Read-only sessions get
  the view without drag or toggle. New endpoints: `GET /api/rules/draft`,
  `POST /api/rules/draft/reorder`, `POST /api/rules/draft/toggle`. Adding/editing
  rule fields (drawer + inline) is next (M6B.4).

## [1.19.0] - 2026-07-07

### Added
- **nftgeo-ui Objects editor (roadmap Phase B, M6B.2).** The Objects tab is now
  editable (read-write sessions): create/edit/delete **address groups**
  (`GROUP_*`) and **custom regions** (`REGION_*`) in a right slide-out drawer,
  with member chips. Objects are stored in a UI-owned drop-in
  `groups.d/ui-objects.conf` and staged through the *same* Commit pipeline as
  rules — validate → plan → `apply --confirm` deadman — so a deploy now carries
  rules and objects together, and the Commit bar shows a per-stage change count.
  Member/name input is strictly sanitised (rejects shell metacharacters) before
  it reaches the shell-sourced config. Read-only sessions see the objects but
  cannot edit them. `SERVICE_*`/`HOST_*` objects await the internal firewall
  (P5). New endpoint: `GET/PUT /api/objects/draft`; the commit endpoints now
  stage every draft file.

## [1.18.0] - 2026-07-07

### Added
- **nftgeo-ui draft + commit pipeline (roadmap Phase B, M6B.1).** The dashboard
  can now change rules — safely, and only from a read-write session. Edits go to
  a **server-side draft** of `rules.conf`; the live file is never touched until
  you press **Commit / Deploy**, which runs the engine's own pipeline:
  `validate → plan` (shown as a visual diff) `→ apply --confirm` guarded by the
  deadman. An in-page countdown lets you **Keep** the change or **Roll back**;
  if you do neither, the deadman auto-reverts the kernel ruleset *and* the UI
  restores `rules.conf` from its backup — so a bad deploy can never persist. A
  top **Commit bar** shows the pending-change count; a new **Rules (edit)** tab
  hosts the (foundation) raw draft editor. New endpoints (all read-write only):
  `PUT /api/draft`, `POST /api/draft/discard`, `/api/commit/preview|apply|keep|
  rollback|status`. Read-only sessions never see the editor and are refused
  (403) on every write. The visual, object-oriented policy editor builds on this
  foundation next.

## [1.17.1] - 2026-07-07

### Fixed
- **Offline world map.** nftgeo-ui loaded jsVectorMap from a CDN, so over an SSH
  tunnel (or any box without outbound internet in the browser) the map failed and
  the panel showed "Map library unavailable — see the country list." The library
  (`jsvectormap.min.js/.css`) and the world geometry (`world.js`) are now vendored
  into the embedded assets and served from `/vendor/`, so the map renders with no
  external requests. (Roadmap M6A.8, offline map assets.)

## [1.17.0] - 2026-07-07

### Added
- **nftgeo-ui authentication.** The dashboard is now gated by a per-session token
  minted as root — opening the URL directly shows a lock screen instead of the
  panel. `nftgeo-ui token` prints a short-lived read-write session link
  (`/?auth=<token>`); `nftgeo-ui token --ro` prints a long-lived (90-day)
  read-only link. The page exchanges the token for an `HttpOnly`, `SameSite=Strict`
  session cookie and strips it from the URL. Read-write sessions are single-use
  and expire after 15 minutes of inactivity (`UI_SESSION_TTL`); read-only sessions
  reject every non-`GET` request (403), future-proofing the Phase B editor.
  Tokens are HMAC-SHA256 signed with a root-only `0600` secret
  (`/var/lib/nftgeo/ui-secret`, `UI_SECRET_FILE` to relocate), auto-created on
  first start. `-noauth` disables the gate for a trusted localhost. Still
  read-only; no firewall mutation.

## [1.16.1] - 2026-07-06

### Changed
- Housekeeping (from the final audit): `gofmt` the nftgeo-ui source, and list the
  `/api/*` endpoints in the README dashboard section. No behaviour change.

## [1.16.0] - 2026-07-06

### Added
- nftgeo-ui full offline geo dataset (roadmap M6A.5b): `GEO_FULL=1` makes the UI
  fetch every ipdeny country zone into `GEO_CACHE_DIR` (default
  `/var/lib/nftgeo/ui-geo`) in the background on startup and daily, so the world
  map geolocates all sources - not just the countries your rules reference (238
  countries / ~177k prefixes on a live host). Low concurrency + retries (ipdeny
  throttles bursts); a `/api/geo` endpoint reports coverage, shown on the map.
  Off by default (~240 outbound requests to ipdeny.com).

## [1.15.0] - 2026-07-06

### Added
- nftgeo-ui Objects & theme polish: address groups and custom regions expand to
  their members as chips (IP/CIDR chips and whitelist IPs are click-to-lookup);
  a light/dark theme toggle (persisted in localStorage, keeping the dark
  FortiGate-style sidebar); a responsive layout that collapses the sidebar on
  narrow screens; and tooltips.

## [1.14.0] - 2026-07-06

### Added
- nftgeo-ui Dashboard widgets: a System card (next scheduled run, established
  connections, abuse-feed freshness pills, last load), top destination countries
  for egress drops alongside sources, and a drops-over-time sparkline (24h
  hourly), backed by `health` in /api/status and a `timeline` in /api/drops.

## [1.13.0] - 2026-07-06

### Added
- nftgeo-ui Policy view: live hit counts per rule (each `rules.conf` rule is
  joined to the chain rules that implement it - by hook, verdict, port, address
  side, and the target's set name - and their counters summed), sortable columns,
  and a click-through rule drawer showing the generated nft lines with counters.
  The side match cleanly separates ingress vs egress rules that share a set (e.g.
  `deny in ... abuse` vs `deny out ... abuse`).

## [1.12.0] - 2026-07-06

### Added
- nftgeo-ui: a FortiGate-style navigation shell for ergonomics - a left sidebar
  with Dashboard / Policy / Logs & Drops / Objects views:
  - **Policy** — your `rules.conf` (+ `rules.d`) as a readable policy table
    (action/dir/service/target/interface/file/comment), from `/api/rules`.
  - **Logs & Drops** — the drop feed as a filterable table (direction, country,
    port, IP search) with click-to-lookup.
  - **Objects** — address groups, custom regions, whitelist/hosts, abuse feeds,
    and live set sizes, from `/api/objects`.
  Still read-only; editing is roadmap P6 phase B.

## [1.11.1] - 2026-07-06

### Added
- nftgeo-ui: click any IP in the recent-drops feed to look it up - reverse DNS
  (PTR) plus whois via RDAP (network, org, country, range), served by a new
  `/api/lookup` endpoint (no `whois` CLI dependency). RDAP also fills in the
  country when an IP isn't in a cached geo zone.

## [1.11.0] - 2026-07-06

### Added
- `nftgeo-ui` (roadmap P6, Phase A): an optional, read-only local web dashboard -
  a single dependency-free Go binary that serves `127.0.0.1:8787` with a world
  map of where drops come from (geolocated from the local ipdeny zones, no
  external GeoIP), live drop-rule counters, set sizes, top source countries and
  ports, and a recent-drops feed. It only reads `nft`/`journalctl`/`nftgeo-update`
  and never writes; feed the map by enabling `LOG_DROPS`. Built from `./ui` with a
  `nftgeo-ui.service` unit.

## [1.10.1] - 2026-07-06

### Added
- `on <iface>` works with arbitrary interface names (VPN tunnels, VLANs, bridges,
  predictable names - e.g. `home-Client-10`, `eth0.100`, `br-lan`, `enp3s0`,
  `wg0`), preserved verbatim. If a referenced interface is not currently present,
  the update prints a non-fatal warning (visible in `nftgeo validate`) so a typo
  can't silently break a rule - while a legitimately-down tunnel still works once
  it appears.

## [1.10.0] - 2026-07-06

### Added
- Per-interface rules: an optional `on <iface>` qualifier on any rule, e.g.
  `allow in tcp 22 europe on eth0` or `deny fwd-out any - abuse on wan0`. It maps
  to `iifname` on the source side (`in`/`fwd-in`) and `oifname` on the
  destination side (`out`/`fwd-out`), so you can scope a rule to one interface.
  Deny-by-default stays interface-agnostic (it closes the port on all interfaces
  except where an allow admits it). Foundation for NAT (P3/P4).

## [1.9.0] - 2026-07-06

### Added
- `HARDEN=1` — baseline firewall hardening on every managed chain: accept
  loopback (`iifname lo` / `oifname lo`), drop `ct state invalid`, and always
  permit the essential ICMPv6 types (NDP, PTB, echo, errors) so locking down IPv6
  cannot break it. Off by default; `ICMPV6_ESSENTIAL` is configurable. First step
  of growing nftgeo from a geo overlay toward a complete edge firewall.

## [1.8.2] - 2026-07-06

### Fixed
- Deadman cleanup: the 1.8.1 `setsid` group-kill did not reliably reap the
  waiter on all hosts, leaving a stray `sleep` behind. The deadman now polls the
  sentinel once a second and self-exits within ~1s of it being removed, so
  `--commit`/`rollback` leave nothing behind regardless of the platform. (It was
  always functionally correct - cancellation is sentinel-based - this only tidies
  the leftover process.)

## [1.8.1] - 2026-07-06

### Changed
- Polish: match the dynamic-block state file by exact field (awk) instead of a
  regex, run the deadman in its own session (`setsid`) and group-kill it on
  confirm/rollback so no stray `sleep` is left behind, and drop the undocumented
  `blocks` alias. Added a command cheat sheet ([CHEATSHEET.md](CHEATSHEET.md)).
  (The deadman cleanup here was superseded by 1.8.2.)

## [1.8.0] - 2026-07-06

### Added
- Safe-apply deadman and rollback. `nftgeo apply --confirm [T]` snapshots the
  loaded ruleset, applies the new one, and auto-rolls-back after T seconds
  (default 120) unless you run `nftgeo apply --commit` (alias `nftgeo confirm`) -
  a guard against a rule change that locks you out. `nftgeo rollback` restores the
  previous generation. Ruleset generations are kept under
  `/var/lib/nftgeo/generations/` (last 10) with a `previous` pointer; the deadman
  is a detached process that survives the CLI exiting and cleans up after itself.

## [1.7.0] - 2026-07-06

### Added
- Optional drop logging: set `LOG_DROPS=1` to emit a rate-limited
  `log prefix "nftgeo-drop "` before every drop rule, so dropped packets appear
  in the kernel log / journald (`journalctl -k | grep nftgeo-drop`). Off by
  default; `LOG_PREFIX` and `LOG_LIMIT` are configurable.

## [1.6.0] - 2026-07-06

### Added
- `nftgeo block <ip> [ttl]` / `unblock <ip>` / `blocklist` - drop an address right
  now for a TTL (default 1h) without editing rules or reloading. Blocks live in a
  separate `nftgeo_dyn` table that `nftgeo-update` never rebuilds, so they survive
  ruleset reloads; entries carry an in-kernel timeout and are restored after a
  reboot from `/var/lib/nftgeo/dynblock.tsv` (via the service's ExecStartPost).
  `block` refuses a whitelisted address or your current SSH source unless
  `--force`, to prevent self-lockout.

## [1.5.1] - 2026-07-06

### Fixed
- `nftgeo status` reported `1` for an empty set instead of `0`. Document the
  engine's URL / path / table environment overrides in the README.

## [1.5.0] - 2026-07-06

### Added
- No-op detection: when a run renders a ruleset byte-identical to the one already
  loaded, the reload is skipped so per-rule counters are preserved instead of
  being zeroed twice a day. A live-table check keeps a fresh boot loading
  normally.

## [1.4.1] - 2026-07-06

### Fixed
- Strip bogon / private / reserved ranges (RFC1918, loopback, link-local, CGNAT,
  multicast, documentation) from the abuse sets. Feeds such as FireHOL level1
  include these, and with a `deny ... abuse` egress rule they dropped traffic to
  the local resolver `127.0.0.53`, the LAN, and a VPN resolver - breaking DNS on
  the host. The abuse sets now only ever hold public, routable addresses.

## [1.4.0] - 2026-07-06

### Added
- `RESOLVERS` for `WHITELIST_HOSTS`: a list of resolvers tried in order (the first
  that answers wins). `local` uses the system resolver (getent); an IP queries
  that DNS server directly via dig/host/nslookup. Listing public servers before
  `local` (e.g. `RESOLVERS="1.1.1.1 8.8.8.8 local"`) keeps hostname whitelisting
  working when the local/VPN resolver is down and yields the public-facing
  address. `RESOLVE_TIMEOUT` (default 5s) bounds each lookup. Default `local`
  keeps prior behaviour.

## [1.3.1] - 2026-07-06

### Fixed
- Bound each `WHITELIST_HOSTS` lookup with `RESOLVE_TIMEOUT` (default 5s) so a
  hung resolver can no longer stall the whole update, including the scheduled
  timer run; a timed-out lookup just falls back to the retained address.
- `nftgeo validate`/`plan` (RENDER_ONLY) no longer re-resolve hostnames or mutate
  state - they reuse the last resolved addresses, staying fast and side-effect
  free even when DNS is down.

## [1.3.0] - 2026-07-06

### Added
- `nftgeo validate` - render the ruleset from the current config and check it
  with `nft -c` without loading it; exits non-zero on an invalid config.
- `nftgeo plan` - show how the rendered ruleset differs from what is loaded, as a
  policy diff with set contents (abuse/geo addresses) elided so only rule changes
  show. Backed by a new `RENDER_ONLY` mode in the engine that skips the lock, the
  network fetches, and the live load.

## [1.2.0] - 2026-07-06

### Added
- `nftgeo` operator CLI (installed alongside `nftgeo-update`):
  - `nftgeo check <ip>` - show whether an address is whitelisted, on the abuse
    list, or in a geo set, the rules that match it, and the resulting verdict.
  - `nftgeo status` - one-screen summary: version, last run, set sizes, live drop
    counters, abuse-feed cache freshness, and the next scheduled run.
  - `nftgeo apply` / `nftgeo version` wrap the update engine.

## [1.1.1] - 2026-07-05

### Fixed
- Add `auto-merge` to the address sets so overlapping/adjacent entries no longer
  fail to load with "conflicting intervals" - which happened once `ABUSE_FEEDS`
  CIDRs were merged with AbuseIPDB single IPs, and could also affect a whitelist
  or geo target that mixed an address with a subnet containing it.

## [1.1.0] - 2026-07-05

### Added
- `ABUSE_FEEDS`: extra plaintext IP/CIDR blocklists (e.g. FireHOL level1,
  Spamhaus DROP, blocklist.de, GreenSnow) merged into the same `abuse` sets, so
  existing `deny ... abuse` rules cover them. Feeds are fetched only when a rule
  targets `abuse`, and each feed's last good copy is cached per URL and reused on
  a download failure so an outage never shrinks the blocklist.

## [1.0.0] - 2026-07-05

First tagged release. Captures the current feature set and recent hardening.

### Features
- Declarative per-direction geo firewall for `nftables` (`in`/`out`/`fwd-in`/`fwd-out`).
- Match by country, region, literal IPv4/IPv6, CIDR, named groups, `any`, and the
  AbuseIPDB blacklist (`abuse`), with tcp/udp/sctp/icmp/icmpv6/esp/ah/gre.
- Opt-in AbuseIPDB blocking with retained state across download failures.
- `WHITELIST` of always-allowed addresses, plus `WHITELIST_HOSTS` for
  hostname-based whitelisting that is re-resolved on every run (fail-safe, with
  retention through DNS failures).
- Twice-daily refresh via a `systemd` timer; atomic, validated ruleset loads.

### Fixed / hardened
- Ship `rules.conf.example` without an active rule so a fresh install cannot
  lock out SSH.
- A single unresolvable country no longer aborts the whole update; deny-only
  empty geo groups are skipped, allow-backed ones still fail safe.
- Serialize runs with a lock so the timer and a manual run cannot race.

### Notes
- Documented that `allow <dir> any - <target>` closes the entire direction.
- Refreshed stale `systemd` unit descriptions.

[1.45.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.45.0
[1.44.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.44.0
[1.43.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.43.0
[1.42.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.42.0
[1.41.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.41.0
[1.40.1]: https://github.com/dzaczek/nftgeo/releases/tag/v1.40.1
[1.40.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.40.0
[1.39.1]: https://github.com/dzaczek/nftgeo/releases/tag/v1.39.1
[1.39.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.39.0
[1.38.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.38.0
[1.37.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.37.0
[1.36.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.36.0
[1.35.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.35.0
[1.34.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.34.0
[1.33.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.33.0
[1.32.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.32.0
[1.31.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.31.0
[1.30.1]: https://github.com/dzaczek/nftgeo/releases/tag/v1.30.1
[1.30.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.30.0
[1.29.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.29.0
[1.28.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.28.0
[1.27.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.27.0
[1.26.1]: https://github.com/dzaczek/nftgeo/releases/tag/v1.26.1
[1.26.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.26.0
[1.25.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.25.0
[1.24.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.24.0
[1.23.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.23.0
[1.22.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.22.0
[1.21.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.21.0
[1.20.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.20.0
[1.19.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.19.0
[1.18.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.18.0
[1.17.1]: https://github.com/dzaczek/nftgeo/releases/tag/v1.17.1
[1.17.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.17.0
[1.16.1]: https://github.com/dzaczek/nftgeo/releases/tag/v1.16.1
[1.16.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.16.0
[1.15.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.15.0
[1.14.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.14.0
[1.13.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.13.0
[1.12.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.12.0
[1.11.1]: https://github.com/dzaczek/nftgeo/releases/tag/v1.11.1
[1.11.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.11.0
[1.10.1]: https://github.com/dzaczek/nftgeo/releases/tag/v1.10.1
[1.10.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.10.0
[1.9.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.9.0
[1.8.2]: https://github.com/dzaczek/nftgeo/releases/tag/v1.8.2
[1.8.1]: https://github.com/dzaczek/nftgeo/releases/tag/v1.8.1
[1.8.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.8.0
[1.7.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.7.0
[1.6.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.6.0
[1.5.1]: https://github.com/dzaczek/nftgeo/releases/tag/v1.5.1
[1.5.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.5.0
[1.4.1]: https://github.com/dzaczek/nftgeo/releases/tag/v1.4.1
[1.4.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.4.0
[1.3.1]: https://github.com/dzaczek/nftgeo/releases/tag/v1.3.1
[1.3.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.3.0
[1.2.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.2.0
[1.1.1]: https://github.com/dzaczek/nftgeo/releases/tag/v1.1.1
[1.1.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.1.0
[1.0.0]: https://github.com/dzaczek/nftgeo/releases/tag/v1.0.0
