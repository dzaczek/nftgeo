# Milestone 3 — editable Objects tab (console TUI)

Part of epic #91 (nftgeo-ui console / Bubble Tea TUI). Builds on M1 (read-only
views + charts) and M2 (safe policy editing). Target branch: `future`.

## Goal

Make the **Objects** tab in `ui/cli.go` editable, covering every object
category: **groups, regions, services, hosts, zones, lists, feeds**. Read the
current state with the existing `objects()` function — each category is
`[]objEntry{ Name string, Members []string }`.

## Safety — reuse the M2 pipeline, do NOT reinvent it

- Write edits to the **objects draft file** by reusing the existing serializer:
  `serializeObjects(groups, regions, services, hosts, zones, lists, feeds)` →
  `os.WriteFile(objDraftFile, …)`, mirroring the `http.MethodPut` branch of
  `handleObjectsDraft`. **Never** write `objLiveFile` directly.
- The `"objects"` stage is already part of `stages()` / `activeStages()`, so the
  **existing M2 commit flow already deploys the objects draft**: `c` (deploy) →
  `validateDraft` → `backupLive` → `copyFile` stage → `apply --confirm 90`,
  then `y` keep (`apply --commit`) / `n`/`r` rollback (`rollback` +
  `restoreBackups`), plus `reconcileCommit` recovery. **Reuse it — add no new
  deploy/keep/rollback code.**

## Editing UX

Keep keybindings consistent with M2. Navigate category → entry → members;
support **add** (`a`), **edit** (`e` / `enter`), **delete** (`d`) for both
entries and their members. Show the unsaved-draft indicator. The `c`/`y`/`n`/`r`
confirm flow is unchanged.

## Validation before writing the draft

- host / list members and any IP-bearing members: valid **IP or CIDR** via
  `net.ParseIP` / `net.ParseCIDR`;
- feed URLs: run through the existing `sanitizeFeedURL`;
- reject empty names and duplicate names within a category.

## Constraints

- Base the PR on the latest `origin/future`; single-purpose diff (`ui/cli.go`,
  plus `ui/main.go` only if a small helper is needed).
- **Add tests**: a `serializeObjects` round-trip for an edited object set, and
  rejection of invalid IP/CIDR and empty names.
- CI green; **no new dependencies**.
