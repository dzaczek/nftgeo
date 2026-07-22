#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
	echo "Run as root: sudo ./uninstall.sh" >&2
	exit 1
fi

systemctl disable --now nftgeo.timer >/dev/null 2>&1 || true
systemctl disable --now nftgeo.service >/dev/null 2>&1 || true
systemctl disable --now nftgeo-ui >/dev/null 2>&1 || true
systemctl disable --now nftgeo-qos >/dev/null 2>&1 || true

if command -v nft >/dev/null 2>&1 && nft list table inet nftgeo >/dev/null 2>&1; then
	nft delete table inet nftgeo
fi
if command -v nft >/dev/null 2>&1 && nft list table inet nftgeo_dyn >/dev/null 2>&1; then
	nft delete table inet nftgeo_dyn
fi
rm -f /usr/sbin/nftgeo
rm -f /usr/sbin/nftgeo-update
rm -f /usr/sbin/nftgeo-ui
rm -f /usr/sbin/nftgeo-qos
# also clean up the pre-packaging /usr/local/sbin layout, if present
rm -f /usr/local/sbin/nftgeo /usr/local/sbin/nftgeo-update /usr/local/sbin/nftgeo-ui
rm -f /usr/local/sbin/nftgeo-qos
rm -f /usr/local/share/man/man5/nftgeo.conf.5
rm -f /usr/local/share/man/man8/nftgeo.8
rm -f /usr/local/share/man/man8/nftgeo-update.8
rm -f /usr/local/share/man/man8/nftgeo-ui.8
rm -f /usr/local/share/man/man8/nftgeo-qos.8

rm -f /etc/systemd/system/nftgeo.service
rm -f /etc/systemd/system/nftgeo.timer
rm -f /etc/systemd/system/nftgeo-ui.service
rm -f /etc/systemd/system/nftgeo-qos.service
rm -f /etc/nftables.d/nftgeo.nft
systemctl daemon-reload

command -v mandb >/dev/null 2>&1 && mandb -q >/dev/null 2>&1 || true

echo "Removed nftgeo service, timer, scripts, UI, manual pages, and active nftables table."
echo "Left in place: /etc/nftgeo and /var/lib/nftgeo"
