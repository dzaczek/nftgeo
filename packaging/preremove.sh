#!/bin/sh
set -e

# On a real removal (not an upgrade), stop and disable the units. dpkg passes
# "remove"; rpm passes "0" as the last transaction for the package.
case "${1:-}" in
	remove | 0)
		systemctl disable --now nftgeo-ui.service nftgeo-qos.service nftgeo.timer nftgeo.service 2>/dev/null || true
		;;
esac
