# nftgeo firewall concept audit

## Executive summary
nftgeo is a highly capable and well-designed declarative firewall manager that successfully abstracts nftables complexity into a human-readable format. It is promising and handles atomic reloads, rollback safety, and geo/abuse sets effectively. However, it requires a few high-priority fixes before it can be considered a safely production-ready system/gateway firewall, particularly regarding IPv6 ICMP handling under default-deny, missing Hairpin NAT support, potential reboot inconsistencies during unconfirmed deployments, and subtle table priority issues that could allow dynamic blocks to bypass whitelists. The core architecture is very strong, but it is currently somewhat risky for complex deployments without addressing these gaps.

## Critical missing pieces
1. **IPv6 ND / SLAAC breakage on default-deny:** If `DEFAULT_INPUT="drop"` is configured without `HARDEN=1`, essential ICMPv6 traffic (Neighbor Discovery, Router Solicitation) is dropped. This breaks IPv6 connectivity completely. `HARDEN` should not be optional for essential ICMPv6.
2. **Reboot inconsistency during pending confirm:** If the system reboots while an `apply --confirm` is pending (before `--commit`), the `nftgeo.service` (which runs `nftgeo-update` on boot) may start *before* `nftgeo-ui.service` (which runs `reconcileCommit()` to restore backups). This would cause the firewall to boot up with the unconfirmed, potentially broken ruleset, defeating the deadman switch for reboots.
3. **Missing Hairpin NAT (NAT Reflection):** For a gateway firewall, forwarding WAN ports to an internal LAN server requires Hairpin NAT so other LAN clients can reach the server via the public IP. `nftgeo` does not support emitting the necessary SNAT rules for this, breaking internal access to public services.
4. **Abuse blocklist precedence bypass:** The documentation claims the abuse blocklist is evaluated before any allow rules. However, user rules are evaluated strictly in file order. If a user writes `allow in tcp 22 any` before `deny in tcp 22 abuse`, the `allow` rule will be matched first, completely bypassing the abuse blocklist for that port.

## High priority improvements
1. **Container network (Docker/Podman) conflicts:** `nftgeo` operates in the `inet` family at `prerouting` priority `-100` for DNAT. Docker operates in the `ip` family at `prerouting` priority `-100`. This creates a race condition where the execution order of NAT hooks is undefined, potentially breaking container port forwarding. A warning should be added, or priorities adjusted.
2. **Global Output/Forward default policy control:** The `output` and `forward` chain policies are hardcoded to `accept`. `DEFAULT_OUTPUT` and `DEFAULT_FORWARD` should be added to allow for strict default-deny egress and routing setups, which are critical for high-security environments.
3. **Dynamic block priority flaw:** The `nftgeo_dyn` table (used for immediate CLI blocks) runs at priority `-150`, which executes *before* the main `nftgeo` table (priority `-100`). This means a dynamic block will drop traffic before the whitelist has a chance to accept it, bypassing the safety of the whitelist.

## Medium priority improvements
1. **ICMP rate limiting:** ICMP/ICMPv6 traffic is not rate-limited by default (even with `HARDEN`), leaving the host vulnerable to ping floods.
2. **AbuseIPDB empty cache edge case:** If the AbuseIPDB API fails on the first run and there is no state file, the abuse sets are left empty but the script proceeds. While this is a reasonable fail-safe, a warning should be logged prominently.
3. **UI: Large zone set loading:** `geoFetchAll()` fetches all country zones concurrently on a background ticker, but storing and parsing massive zone files (if `GEO_FULL=1`) can consume significant RAM in the UI process.

## Confirmed strengths
- **Deadman rollback architecture:** The sentinel-based auto-rollback works reliably and detaches correctly using `nohup`, ensuring safety if SSH is lost.
- **Fail-safe validation:** `nft -c` is used before every reload, preventing syntax errors from flushing a working ruleset.
- **Atomic set operations:** `auto-merge` is used correctly with CIDR aggregation to load massive abuse blocklists without kernel errors.
- **Whitelist supremacy (in main table):** Whitelist files are processed robustly and placed at the top of chains in the `nftgeo` table, overriding geo or abuse sets.
- **Security-first UI:** The dashboard uses robust token-to-cookie exchange, `HttpOnly`/`SameSite=Strict` cookies, and enforces a strict read-only boundary for untrusted sessions.

## Host firewall checklist

| requirement | implemented | evidence | recommendation |
| :--- | :--- | :--- | :--- |
| loopback handling | partial | `bin/nftgeo-update`: `emit_chain()` | Handled via `HARDEN` or `DEFAULT_INPUT=drop`. Make it unconditional for all chains to prevent local service breakage. |
| established/related handling | yes | `bin/nftgeo-update`: `emit_chain()` | Handled first in all configured chains. |
| invalid packet drop | partial | `bin/nftgeo-update`: `emit_chain()` | Only applied if `HARDEN` is set. Should be default. |
| ICMP and ICMPv6 handling | partial | `bin/nftgeo-update`: `emit_chain()` | Essential ICMPv6 relies on `HARDEN`. Should be unconditional to prevent IPv6 breakage. |
| IPv6 neighbor discovery safety | partial | `bin/nftgeo-update`: `emit_chain()` | Same as above; fails under `DEFAULT_INPUT=drop` without `HARDEN`. |
| DHCP/DNS/VPN edge cases | partial | `bin/nftgeo-update`: `scrub_abuse()` | Bogons stripped from abuse lists, preventing local DNS breakage. No built-in DHCP templates. |
| default input/output/forward policies | yes | `bin/nftgeo-update`: `emit_chain()` | Input configurable, output/forward hardcoded to `accept`. Add `DEFAULT_FORWARD` and `DEFAULT_OUTPUT`. |
| difference between default-accept and default-deny | yes | `bin/nftgeo-update`: sequential model warning | Warnings reliably detect geo-allows lacking catch-all denys. |
| safe ordering of whitelist, abuse rules, user rules, dynamic blocks | no | `bin/nftgeo`: `ensure_dyn()`, `bin/nftgeo-update`: `emit_chain()` | Whitelist is safe internally, but dynamic blocks (-150) bypass whitelist (-100). User rules (including abuse) are strictly file-order, allowing accidental bypasses. |
| "allow geo then deny any" behavior is clearly enforced | yes | `bin/nftgeo-update`: `awk` validation script | Prints a warning if a geo-allow lacks a catch-all deny. |
| accidental open ports are detected reliably | yes | `bin/nftgeo-update`: sequential warning logic | Works as intended. |

## Gateway/NAT/VLAN checklist

| requirement | implemented | evidence | recommendation |
| :--- | :--- | :--- | :--- |
| multiple LANs | yes | `bin/nftgeo-update`: `parse_rules_file()` | Supported via `ZONE_*` and interfaces. |
| WAN + LAN | yes | `examples/71-nat-gateway.conf` | Working correctly. |
| VLAN subinterfaces | yes | `bin/nftgeo-update`: `zoneMemberRe` | `eth0.100` supported in syntax and parsing. |
| routed traffic between zones | yes | `bin/nftgeo-update`: `ZONE_NORM` parsing | Inter-zone `allow <z> -> <z>` correctly uses `iifname`/`oifname`. |
| default-deny between zones | yes | `SEGMENT_DEFAULT="deny"` in config | Emits default drop between zone interfaces. |
| allow/deny zone-to-zone rules | yes | `bin/nftgeo-update`: `ZONE_NORM` | Denies are correctly emitted before allows. |
| asymmetric routing risks | yes | `ANTISPOOF` config | Implements Strict uRPF (`fib saddr . iif oif 0`). |
| IP forwarding requirements | partial | `bin/nftgeo-update`: ip_forward check | Warns if disabled, but does not manage the sysctl. |
| rp_filter / uRPF / anti-spoofing behavior | yes | `bin/nftgeo-update`: `emit_chain()` | Correctly uses `fib`. |
| hairpin NAT / NAT reflection | no | `bin/nftgeo-update`: DNAT logic | No SNAT rules emitted for DNAT hair-pinning. Should be documented as a limitation. |
| port forwarding from WAN to LAN/DMZ | yes | `bin/nftgeo-update`: DNAT logic | Works for standard ingress. |
| outbound NAT only for selected internal interfaces | yes | `masquerade on eth0 in eth1` | Restricts SNAT via `iifname`. |
| dual-stack IPv4/IPv6 gateway behavior | yes | `bin/nftgeo-update`: NAT generation | Uses correct `ip` / `ip6` families in `inet` tables. |

## Safety/rollback checklist

| requirement | implemented | evidence | recommendation |
| :--- | :--- | :--- | :--- |
| deadman rollback reliability | yes | `bin/nftgeo`: `cmd_apply()` | Sentinel and `nohup` sleep mechanism is robust. |
| rollback after failed apply | yes | `bin/nftgeo-update`: validation step | `nft -c` catches errors before `nft -f` commit. |
| rollback after SSH lockout | yes | `bin/nftgeo`: `cmd_apply()` | Handled by deadman switch. |
| dynamic blocks survive reloads | yes | `bin/nftgeo`: `ensure_dyn()` | `nftgeo_dyn` table is isolated from `nftgeo-update` flushes. |
| whitelisted IPs protected from abuse/dynamic blocks | no | `bin/nftgeo`: `ensure_dyn()` | CLI prevents manual blocking, but `nftgeo_dyn` runs at priority `-150` (before whitelist at `-100`). Dynamic blocks will bypass the whitelist. |
| current SSH source detection | yes | `bin/nftgeo`: `cmd_block()` | Checks `$SSH_CLIENT` to prevent self-blocking. |
| apply --confirm / --commit flow robust | partial | `ui/main.go`: `reconcileCommit()` | Robust in normal operation, but rebooting during a pending commit may load unconfirmed rules. |
| what happens on reboot during pending rollback | risky | `systemd/nftgeo.service` | Service starts `nftgeo-update` reading the unconfirmed `rules.conf` before `nftgeo-ui` can restore backups, effectively committing the broken ruleset. |
| generations stored and restored safely | yes | `bin/nftgeo`: `snapshot_current()` | Safely keeps last 10 generations. |

## Test gaps
1. **IPv6 ICMP dropping:** Add a test case `tests/render/cases/ipv6-icmp/` with `DEFAULT_INPUT=drop` without `HARDEN` to assert that `icmpv6` is explicitly dropped (or allowed, if the implementation is fixed).
2. **Hairpin NAT validation:** Add a test ensuring that if Hairpin NAT syntax is attempted, it throws an error (if unsupported), or test that proper SNAT rules are generated if implemented.
3. **Abuse rule ordering bypass:** Create a test case `tests/render/cases/abuse-order-bypass/` showing `allow in tcp 22 any` before `deny in tcp 22 abuse` to highlight the evaluation order issue.
4. **Dynamic block vs Whitelist precedence:** Write a test validating that the `nftgeo_dyn` table operates at a priority that respects the `nftgeo` whitelist (currently it does not).
5. **Config parsing empty edge cases:** Test behavior when `rules.conf` exists but is completely empty.

## Suggested README changes
- **Limitations:** Explicitly state that **Hairpin NAT (NAT Reflection)** is not supported. Users must access internal servers via internal IPs when inside the LAN.
- **Rule Ordering:** Clarify that the `abuse` blocklist is evaluated strictly in the order it appears in the file, NOT automatically before all allow rules. Recommend always placing `deny ... abuse` at the top of the rules file.
- **Compatibility Warnings:** Add a section explicitly warning about Docker and Podman. Docker operates in the `ip` family at the same priority hooks (`prerouting -100`), causing undefined behavior for port forwarding.
- **IPv6 and Default-Deny:** Warn users that if they use `DEFAULT_INPUT="drop"`, they *must* set `HARDEN=1` to prevent breaking IPv6 connectivity.

## Suggested implementation changes
- **File:** `bin/nftgeo-update`
  - **Function:** `emit_chain()`
  - **Change:** Move the `icmpv6 type { ... } counter accept` and `iifname "lo" counter accept` logic *outside* the `if [ -n "$HARDEN" ]; then` block, so they are unconditional. Breaking IPv6 ND and local loopback by default is too dangerous.
- **File:** `bin/nftgeo-update`
  - **Function:** `generate()` -> `emit_chain()`
  - **Change:** Introduce `DEFAULT_OUTPUT` and `DEFAULT_FORWARD` configuration variables in `config` to allow strict default-deny policies on output and forward chains, rather than hardcoding `accept`.
- **File:** `systemd/nftgeo.service`
  - **Change:** Add `ExecStartPre=/usr/local/bin/nftgeo-reconcile-commit` (or similar script logic) to check for `.pending-confirm` and restore backups *before* `nftgeo-update` runs on boot.
- **File:** `bin/nftgeo`
  - **Function:** `ensure_dyn()`
  - **Change:** Change the priority of `nftgeo_dyn` from `-150` to `-50` (or similar) so that it runs *after* the `nftgeo` filter chains (`-100`), ensuring that the Whitelist can protect IPs from dynamic blocks.