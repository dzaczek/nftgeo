#!/bin/sh
# Real `nft -c` validation of the render fixtures (needs nft; intended for CI
# under sudo). Renders each non-expect-fail case through the engine WITHOUT
# skipping the kernel check, asserting the ruleset is accepted.
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
engine="${NFTGEO_ENGINE:-$here/../../bin/nftgeo-update}"
command -v nft >/dev/null 2>&1 || { echo "nft not found" >&2; exit 2; }

fail=0
for case_dir in "$here"/cases/*/; do
	[ -f "$case_dir/rules.conf" ] || continue
	grep -q '^!' "$case_dir/assert" 2>/dev/null && continue # skip expect-fail cases
	name="$(basename "$case_dir")"
	cfg="/dev/null"
	[ -f "$case_dir/config" ] && cfg="$case_dir/config"
	tmp="$(mktemp -d)"
	mkdir -p "$tmp/zones" "$tmp/rules.d" "$tmp/groups.d" "$tmp/state"
	if RENDER_ONLY=1 CONFIG_FILE="$cfg" RULES_FILE="$case_dir/rules.conf" RULES_DIR="$tmp/rules.d" \
		GROUPS_DIR="$tmp/groups.d" ZONE_DIR="$tmp/zones" STATE_DIR="$tmp/state" \
		"$engine" >/dev/null 2>"$tmp/err"; then
		echo "  OK   $name"
	else
		echo "  FAIL $name: $(head -1 "$tmp/err")"
		fail=$((fail + 1))
	fi
	rm -rf "$tmp"
done
[ "$fail" = 0 ] || { echo "nft -c rejected $fail case(s)" >&2; exit 1; }
echo "nft -c: all fixtures accepted"
