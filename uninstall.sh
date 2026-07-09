#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
	echo "Run as root: sudo ./uninstall.sh" >&2
	exit 1
fi

systemctl disable --now nftgeo.timer >/dev/null 2>&1 || true
systemctl disable --now nftgeo.service >/dev/null 2>&1 || true
systemctl disable --now nftgeo-ui >/dev/null 2>&1 || true

if command -v nft >/dev/null 2>&1 && nft list table inet nftgeo >/dev/null 2>&1; then
	nft delete table inet nftgeo
fi
if command -v nft >/dev/null 2>&1 && nft list table inet nftgeo_dyn >/dev/null 2>&1; then
	nft delete table inet nftgeo_dyn
fi
rm -f /usr/sbin/nftgeo
rm -f /usr/sbin/nftgeo-update
rm -f /usr/sbin/nftgeo-ui

rm -f /etc/systemd/system/nftgeo.service
rm -f /etc/systemd/system/nftgeo.timer
rm -f /etc/systemd/system/nftgeo-ui.service
rm -f /etc/nftables.d/nftgeo.nft
systemctl daemon-reload

echo "Removed nftgeo service, timer, scripts, UI, and active nftables table."
echo "Left in place: /etc/nftgeo and /var/lib/nftgeo"
