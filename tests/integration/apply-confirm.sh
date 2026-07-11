#!/bin/sh
# Exercise the live apply/confirm/rollback path in its own network namespace.
# This never changes the runner's network namespace or its nftables ruleset.
set -eu

here="$(cd "$(dirname "$0")/../.." && pwd)"
name="nftgeo-ci-$$"
tmp="$(mktemp -d)"

cleanup() {
	sudo ip netns del "$name" 2>/dev/null || true
	rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

mkdir -p "$tmp/rules.d" "$tmp/groups.d" "$tmp/zones" "$tmp/state"
cat > "$tmp/config" <<'EOF'
DEFAULT_INPUT="accept"
DEFAULT_OUTPUT="accept"
DEFAULT_FORWARD="accept"
LOG_DROPS="0"
EOF
cat > "$tmp/rules.conf" <<'EOF'
allow in tcp 22 any
EOF

sudo ip netns add "$name"
run_cli() {
	sudo ip netns exec "$name" env \
		TABLE_FAMILY=inet TABLE_NAME=nftgeo_ci \
		STATE_DIR="$tmp/state" NFT_FILE="$tmp/nftgeo.nft" \
		CONFIG_FILE="$tmp/config" RULES_FILE="$tmp/rules.conf" RULES_DIR="$tmp/rules.d" \
		GROUPS_DIR="$tmp/groups.d" ZONE_DIR="$tmp/zones" \
		NFTGEO_UPDATE="$here/bin/nftgeo-update" sh "$here/bin/nftgeo" "$@"
}

run_nft() { sudo ip netns exec "$name" nft "$@"; }

run_cli apply --confirm 2 >/dev/null
run_nft list table inet nftgeo_ci >/dev/null
sleep 3
if run_nft list table inet nftgeo_ci >/dev/null 2>&1; then
	echo "deadman did not roll back the unconfirmed ruleset" >&2
	exit 1
fi

run_cli apply --confirm 10 >/dev/null
run_cli apply --commit >/dev/null
sleep 1
run_nft list table inet nftgeo_ci >/dev/null

echo "apply-confirm integration: PASS"
