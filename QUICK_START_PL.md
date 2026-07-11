# nftgeo Szybki Start

Jeśli chcesz najszybciej uruchomić instalację z gotowej paczki, pobierz
najnowszy DEB albo RPM ze strony
[najnowszego wydania](https://github.com/dzaczek/nftgeo/releases/latest).

## Debian / Ubuntu

```sh
sudo apt install ./nftgeo_<version>_amd64.deb
```

## Fedora / RHEL / zgodne systemy RPM

```sh
sudo dnf install ./nftgeo-<version>-1.x86_64.rpm
```

## Pierwsze uruchomienie

```sh
sudoedit /etc/nftgeo/config
# WHITELIST="TWOJE.PUBLICZNE.IP"

sudoedit /etc/nftgeo/rules.conf
# allow in tcp 22 TWOJE.PUBLICZNE.IP
# deny  in tcp 22 any
# allow out udp 53 any

sudo nftgeo validate
sudo nftgeo apply --confirm
sudo nftgeo apply --commit
sudo systemctl enable --now nftgeo.timer
```

## Uwagi

- Paczki przy pierwszej instalacji tworzą `config` i `rules.conf` w
  `/etc/nftgeo`.
- Paczki nie włączają polityki zapory automatycznie.
- Pełny opis instalacji znajdziesz w [docs/REFERENCE.md](docs/REFERENCE.md).
