#!/bin/sh
# Keep every shipped rule fragment valid against the current parser and renderer.
set -eu

here="$(cd "$(dirname "$0")/../.." && pwd)"
engine="${NFTGEO_ENGINE:-$here/bin/nftgeo-update}"
[ -x "$engine" ] || { echo "engine not found/executable: $engine" >&2; exit 2; }

pass=0
for example in "$here"/examples/*.conf; do
	name="$(basename "$example")"
	tmp="$(mktemp -d)"
	trap 'rm -rf "$tmp"' EXIT INT TERM
	mkdir -p "$tmp/rules.d" "$tmp/groups.d" "$tmp/zones" "$tmp/state" "$tmp/ingress.d"
	cat > "$tmp/config" <<'EOF'
DEFAULT_INPUT="accept"
DEFAULT_OUTPUT="accept"
DEFAULT_FORWARD="accept"
INGRESS_DEV="eth0"
EOF
	: > "$tmp/rules.conf"

	case "$name" in
		75-internal-zones.conf)
			cat >> "$tmp/config" <<'EOF'
ZONE_LAN="eth1"
ZONE_DMZ="eth2"
ZONE_GUEST="eth0.100"
ZONE_WAN="eth0"
EOF
			cp "$example" "$tmp/rules.d/$name"
			;;
		95-ingress.conf) cp "$example" "$tmp/ingress.conf" ;;
		*) cp "$example" "$tmp/rules.d/$name" ;;
	esac

	if RENDER_ONLY=1 CONFIG_FILE="$tmp/config" RULES_FILE="$tmp/rules.conf" \
		RULES_DIR="$tmp/rules.d" GROUPS_DIR="$tmp/groups.d" ZONE_DIR="$tmp/zones" \
		STATE_DIR="$tmp/state" INGRESS_FILE="$tmp/ingress.conf" INGRESS_DIR="$tmp/ingress.d" \
		"$engine" >/dev/null; then
		printf '  PASS %s\n' "$name"
		pass=$((pass + 1))
	else
		echo "  FAIL $name" >&2
		exit 1
	fi
	rm -rf "$tmp"
	trap - EXIT INT TERM
done

printf 'example render tests: %d passed\n' "$pass"
