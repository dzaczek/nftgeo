#!/bin/sh
# Install the just-built packages in clean distro containers. Reinstalling after
# modifying config/rules proves the postinstall hook preserves operator files.
set -eu

dist="${1:-dist}"
dist="$(cd "$dist" && pwd)"
version="$(sed -n 's/^NFTGEO_VERSION="\(.*\)"/\1/p' bin/nftgeo-update)"
deb="$(find "$dist" -maxdepth 1 -name "nftgeo_${version}_amd64.deb" -print -quit)"
rpm="$(find "$dist" -maxdepth 1 -name "nftgeo-${version}-1.x86_64.rpm" -print -quit)"

[ -n "$deb" ] || { echo "amd64 DEB not found in $dist" >&2; exit 1; }
[ -n "$rpm" ] || { echo "x86_64 RPM not found in $dist" >&2; exit 1; }

docker run --rm \
	-e PACKAGE_FILE="$(basename "$deb")" -e PACKAGE_VERSION="$version" \
	-v "$dist:/packages:ro" debian:13-slim sh -ec '
	export DEBIAN_FRONTEND=noninteractive
	apt-get update
	apt-get install -y "/packages/$PACKAGE_FILE"
	test "$(dpkg-query -W -f="${Version}" nftgeo)" = "$PACKAGE_VERSION"
	test -x /usr/sbin/nftgeo && test -x /usr/sbin/nftgeo-update && test -x /usr/sbin/nftgeo-ui
	test -f /usr/share/man/man8/nftgeo.8.gz && test -f /usr/share/man/man5/nftgeo.conf.5.gz
	printf "TEST_PRESERVE=1\n" >/etc/nftgeo/config
	printf "allow in tcp 12345 any\n" >/etc/nftgeo/rules.conf
	dpkg -i "/packages/$PACKAGE_FILE"
	grep -qx "TEST_PRESERVE=1" /etc/nftgeo/config
	grep -qx "allow in tcp 12345 any" /etc/nftgeo/rules.conf
	/usr/sbin/nftgeo-ui -h >/dev/null
'

docker run --rm \
	-e PACKAGE_FILE="$(basename "$rpm")" -e PACKAGE_VERSION="$version" \
	-v "$dist:/packages:ro" fedora:latest sh -ec '
	dnf -y install "/packages/$PACKAGE_FILE"
	test "$(rpm -q --qf "%{VERSION}" nftgeo)" = "$PACKAGE_VERSION"
	test -x /usr/sbin/nftgeo && test -x /usr/sbin/nftgeo-update && test -x /usr/sbin/nftgeo-ui
	test -f /usr/share/man/man8/nftgeo.8.gz && test -f /usr/share/man/man5/nftgeo.conf.5.gz
	printf "TEST_PRESERVE=1\n" >/etc/nftgeo/config
	printf "allow in tcp 12345 any\n" >/etc/nftgeo/rules.conf
	dnf -y reinstall "/packages/$PACKAGE_FILE"
	grep -qx "TEST_PRESERVE=1" /etc/nftgeo/config
	grep -qx "allow in tcp 12345 any" /etc/nftgeo/rules.conf
	/usr/sbin/nftgeo-ui -h >/dev/null
'

echo "package install tests: PASS"
