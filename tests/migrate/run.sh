#!/bin/sh
# Regression test for `nftgeo migrate-sequential`: a geo-restricted allow gets a
# catch-all deny, an allow that already has one (or targets "any") does not.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
cli="${NFTGEO_CLI:-$here/../../bin/nftgeo}"
d="$(mktemp -d)"
trap 'rm -rf "$d"' EXIT
mkdir -p "$d/rules.d"
cat > "$d/rules.conf" <<'EOF'
allow in tcp 22 pl
allow in tcp 443 europe
deny in tcp 443 any
allow in tcp 80 any
allow out tcp 53 de
EOF
printf 'allow in tcp 8080 office\n' > "$d/rules.d/10-x.conf"

out="$(RULES_FILE="$d/rules.conf" RULES_DIR="$d/rules.d" sh "$cli" migrate-sequential --dry-run)"

fail=0
check_has()  { echo "$out" | grep -qF "$1" || { echo "FAIL: expected '$1'"; fail=1; }; }
check_lacks(){ echo "$out" | grep -qF "$1" && { echo "FAIL: unexpected '$1'"; fail=1; } || true; }
check_has  "deny in tcp 22 any"
check_has  "deny in tcp 8080 any"
check_has  "deny out tcp 53 any"
check_lacks "deny in tcp 443 any"   # already had a catch-all deny
check_lacks "deny in tcp 80 any"    # allow target is "any" (intentionally open)

if [ "$fail" = 0 ]; then echo "migrate tests: PASS"; else echo "migrate tests: FAILED"; exit 1; fi
