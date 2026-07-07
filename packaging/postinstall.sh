#!/bin/sh
set -e

# State + generated-ruleset dirs.
install -d -m 0755 /var/lib/nftgeo /var/lib/nftgeo/zones /etc/nftables.d

# Seed config/rules on first install only (never clobber an admin's files).
if [ ! -f /etc/nftgeo/config ]; then
	cp /etc/nftgeo/config.example /etc/nftgeo/config
	chmod 0600 /etc/nftgeo/config
fi
if [ ! -f /etc/nftgeo/rules.conf ]; then
	cp /etc/nftgeo/rules.conf.example /etc/nftgeo/rules.conf
fi

systemctl daemon-reload 2>/dev/null || true

cat <<'EOF'
nftgeo installed. Next:
  sudoedit /etc/nftgeo/config        # ABUSEIPDB_API_KEY, WHITELIST, regions, groups
  sudoedit /etc/nftgeo/rules.conf    # your allow/deny/throttle rules
  systemctl enable --now nftgeo.timer      # scheduled refresh (feeds + resolve)
  systemctl start nftgeo.service           # build & load the ruleset now
  systemctl enable --now nftgeo-ui.service # optional dashboard on 127.0.0.1:8787
Nothing is enabled automatically. See: nftgeo help
EOF
