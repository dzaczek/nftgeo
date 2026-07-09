#!/bin/sh
# Golden/snippet render tests for the nftgeo engine. Each case dir under cases/
# holds a rules.conf (required), an optional config, and an assert file:
#   + <substr>   generated ruleset MUST contain <substr>
#   - <substr>   generated ruleset MUST NOT contain <substr>
#   ! <substr>   render is expected to FAIL, with <substr> in stderr
# A case with any '!' line expects failure; otherwise it must render cleanly.
#
# Runs offline (NFTGEO_SKIP_NFT_CHECK=1), so no nft/kernel needed. For a real
# `nft -c` pass over the same fixtures, see nft-check.sh.
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
engine="${NFTGEO_ENGINE:-$here/../../bin/nftgeo-update}"
[ -x "$engine" ] || { echo "engine not found/executable: $engine" >&2; exit 2; }

pass=0
fail=0
failed_cases=""

for case_dir in "$here"/cases/*/; do
	[ -f "$case_dir/rules.conf" ] || continue
	name="$(basename "$case_dir")"
	cfg="/dev/null"
	[ -f "$case_dir/config" ] && cfg="$case_dir/config"

	tmp="$(mktemp -d)"
	mkdir -p "$tmp/zones" "$tmp/rules.d" "$tmp/groups.d" "$tmp/state"
	# a case may ship extra groups.d drop-ins
	[ -d "$case_dir/groups.d" ] && cp "$case_dir"/groups.d/*.conf "$tmp/groups.d/" 2>/dev/null || true
	# a case may ship a whitelist.conf / whitelist-hosts.conf
	[ -f "$case_dir/whitelist.conf" ] && cp "$case_dir/whitelist.conf" "$tmp/whitelist.conf"
	[ -f "$case_dir/whitelist-hosts.conf" ] && cp "$case_dir/whitelist-hosts.conf" "$tmp/whitelist-hosts.conf"

	out="$tmp/out.nft"
	err="$tmp/err.txt"
	set +e
	NFTGEO_SKIP_NFT_CHECK=1 RENDER_ONLY=1 RENDER_OUT="$out" \
		CONFIG_FILE="$cfg" RULES_FILE="$case_dir/rules.conf" RULES_DIR="$tmp/rules.d" \
		GROUPS_DIR="$tmp/groups.d" ZONE_DIR="$tmp/zones" STATE_DIR="$tmp/state" \
		WHITELIST_FILE="$tmp/whitelist.conf" WHITELIST_HOSTS_FILE="$tmp/whitelist-hosts.conf" \
		"$engine" >/dev/null 2>"$err"
	rc=$?
	set -e

	expect_fail=0
	grep -q '^!' "$case_dir/assert" 2>/dev/null && expect_fail=1
	ok=1
	msg=""

	if [ "$expect_fail" = 1 ]; then
		if [ "$rc" = 0 ]; then ok=0; msg="expected failure but render succeeded"; fi
	else
		if [ "$rc" != 0 ]; then ok=0; msg="render failed (rc=$rc): $(head -1 "$err")"; fi
	fi

	if [ "$ok" = 1 ] && [ -f "$case_dir/assert" ]; then
		while IFS= read -r line; do
			[ -n "$line" ] || continue
			op="$(printf '%s' "$line" | cut -c1)"
			sub="$(printf '%s' "$line" | cut -c2- | sed 's/^[[:space:]]*//')"
			case "$op" in
				'#') : ;;
				'+') grep -qF -- "$sub" "$out" || { ok=0; msg="missing: $sub"; break; } ;;
				'-') grep -qF -- "$sub" "$out" && { ok=0; msg="unexpected: $sub"; break; } || true ;;
				'!') grep -qF -- "$sub" "$err" || { ok=0; msg="error lacked: $sub (got: $(head -1 "$err"))"; break; } ;;
				*) : ;;
			esac
		done < "$case_dir/assert"
	fi

	if [ "$ok" = 1 ]; then
		pass=$((pass + 1)); printf '  PASS %s\n' "$name"
	else
		fail=$((fail + 1)); failed_cases="$failed_cases $name"; printf '  FAIL %s — %s\n' "$name" "$msg"
	fi
	rm -rf "$tmp"
done

printf '\nrender tests: %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" = 0 ] || { printf 'failed:%s\n' "$failed_cases"; exit 1; }
