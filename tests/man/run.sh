#!/bin/sh
set -eu

command -v mandoc >/dev/null 2>&1 || {
	echo "mandoc is required to validate manual pages" >&2
	exit 1
}

expected='nftgeo-qos.8:8
nftgeo-ui.8:8
nftgeo-update.8:8
nftgeo.8:8
nftgeo.conf.5:5'
actual="$(for page in man/*.[1-9]; do
	section="${page##*.}"
	name="$(basename "$page")"
	header_section="$(awk '$1 == ".TH" { print $3; exit }' "$page")"
	[ "$section" = "$header_section" ] || {
		echo "$page: filename section $section differs from .TH section $header_section" >&2
		exit 1
	}
	printf '%s:%s\n' "$name" "$section"
done | LC_ALL=C sort)"

[ "$actual" = "$expected" ] || {
	echo "unexpected manual page set:" >&2
	printf '%s\n' "$actual" >&2
	exit 1
}

for page in man/*.[1-9]; do
	mandoc -T lint "$page"
	for heading in NAME SYNOPSIS DESCRIPTION EXAMPLES 'SEE ALSO'; do
		grep -Fq ".SH $heading" "$page" || {
			echo "$page: missing $heading section" >&2
			exit 1
		}
	done
done

echo "manual pages: OK"
