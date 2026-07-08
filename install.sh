#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
	echo "Run as root: sudo ./install.sh" >&2
	exit 1
fi

# shellcheck disable=SC1007  # "CDPATH= cd" is an intentional env-var prefix
BASE_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

if ! command -v apt-get >/dev/null 2>&1; then
	echo "This installer supports Debian/Ubuntu systems with apt-get." >&2
	exit 1
fi

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y curl nftables ca-certificates

install -d -m 0755 /etc/nftgeo /etc/nftgeo/rules.d /etc/nftgeo/groups.d \
	/etc/nftables.d /var/lib/nftgeo /var/lib/nftgeo/zones /usr/local/sbin
install -m 0755 "${BASE_DIR}/bin/nftgeo-update" /usr/local/sbin/nftgeo-update
install -m 0755 "${BASE_DIR}/bin/nftgeo" /usr/local/sbin/nftgeo

if [ -f "${BASE_DIR}/man/nftgeo.8" ]; then
	install -d -m 0755 /usr/local/share/man/man8
	install -m 0644 "${BASE_DIR}/man/nftgeo.8" /usr/local/share/man/man8/nftgeo.8
	command -v mandb >/dev/null 2>&1 && mandb -q >/dev/null 2>&1 || true
fi

if [ ! -f /etc/nftgeo/config ]; then
	install -m 0600 "${BASE_DIR}/etc/config.example" /etc/nftgeo/config
else
	echo "Keeping existing /etc/nftgeo/config"
fi

if [ ! -f /etc/nftgeo/rules.conf ]; then
	install -m 0644 "${BASE_DIR}/etc/rules.conf.example" /etc/nftgeo/rules.conf
else
	echo "Keeping existing /etc/nftgeo/rules.conf"
fi

install -m 0644 "${BASE_DIR}/systemd/nftgeo.service" /etc/systemd/system/nftgeo.service
install -m 0644 "${BASE_DIR}/systemd/nftgeo.timer" /etc/systemd/system/nftgeo.timer

systemctl daemon-reload
systemctl enable nftgeo.service
systemctl enable --now nftgeo.timer

echo "Installed nftgeo."
echo "Edit /etc/nftgeo/config (ABUSEIPDB_API_KEY, WHITELIST, regions, groups)"
echo "and /etc/nftgeo/rules.conf or /etc/nftgeo/rules.d/*.conf, then run:"
echo "  systemctl start nftgeo.service"
