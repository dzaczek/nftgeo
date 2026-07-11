# nftgeo Quick Start

Use the packaged release if you want the shortest path to a working install.
Download the latest DEB or RPM from the
[latest release](https://github.com/dzaczek/nftgeo/releases/latest).

## Debian / Ubuntu

```sh
sudo apt install ./nftgeo_<version>_amd64.deb
```

## Fedora / RHEL / compatible RPM systems

```sh
sudo dnf install ./nftgeo-<version>-1.x86_64.rpm
```

## First run

```sh
sudoedit /etc/nftgeo/config
# WHITELIST="YOUR.PUBLIC.IP"

sudoedit /etc/nftgeo/rules.conf
# allow in tcp 22 YOUR.PUBLIC.IP
# deny  in tcp 22 any
# allow out udp 53 any

sudo nftgeo validate
sudo nftgeo apply --confirm
sudo nftgeo apply --commit
sudo systemctl enable --now nftgeo.timer
```

## Notes

- Package installs seed `/etc/nftgeo/config` and `/etc/nftgeo/rules.conf` on
  first install.
- Packages do not enable the firewall policy automatically.
- If you need the full install matrix, see [docs/REFERENCE.md](docs/REFERENCE.md).
