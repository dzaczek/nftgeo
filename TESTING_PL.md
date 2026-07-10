# Testowanie nftgeo

Dziękuję za testowanie nftgeo. Najbardziej przydatne są konkretne informacje:
co było testowane, na jakim systemie, jakie komendy zostały uruchomione, jaki
był oczekiwany wynik i co faktycznie się stało.

Nie publikuj prawdziwych kluczy API, list prywatnych adresów IP, nazw hostów
produkcyjnych, danych SSH ani danych dostępowych do serwerów.

## Co warto testować

Dobre obszary testów:

- Świeża instalacja z paczki albo przez `install.sh`.
- `nftgeo validate`, `nftgeo plan` oraz `nftgeo apply --confirm` / `--commit`.
- Ograniczenie SSH według kraju albo IP, z wpisem na białej liście.
- AbuseIPDB albo własne źródła z listami blokowanych adresów IP.
- Dashboard: uruchomienie usługi, logowanie tokenem, token tylko do odczytu,
  edytor polityki i zatwierdzanie zmian.
- NAT, forwarding, strefy, reguły ingress, throttling i SYN proxy, jeżeli
  używasz tych funkcji.
- Aktualizacja albo odinstalowanie na maszynie niekrytycznej.

Najlepiej testować na jednorazowym VPS, maszynie wirtualnej albo hoście
laboratoryjnym. Jeżeli testujesz przez SSH, pozostaw otwartą konsolę awaryjną
dostawcy i dodaj swoje aktualne publiczne IP do białej listy przed zmianą reguł
przychodzących.

## Bezpieczny smoke test na hoście testowym

```sh
git clone https://github.com/dzaczek/nftgeo.git
cd nftgeo
sudo ./install.sh

sudoedit /etc/nftgeo/config
# Ustaw:
#   WHITELIST="TWOJE.PUBLICZNE.IP"

cat <<'EOF' | sudo tee /etc/nftgeo/rules.conf
allow in tcp 22 TWOJE.PUBLICZNE.IP
deny  in tcp 22 any
allow out udp 53 any
EOF

sudo nftgeo validate
sudo nftgeo plan
sudo nftgeo apply --confirm
# Otwórz drugą sesję SSH albo inaczej potwierdź, że dostęp działa.
sudo nftgeo apply --commit
sudo nftgeo status
```

Wycofanie zmian w oknie potwierdzenia:

```sh
sudo nftgeo rollback
```

## Lokalne testy deweloperskie

Te testy nie zmieniają aktywnej zapory:

```sh
go test ./ui/
sh tests/render/run.sh
sh tests/migrate/run.sh
make test
```

Opcjonalna walidacja przez prawdziwe nftables:

```sh
sudo sh tests/render/nft-check.sh
```

`nft-check.sh` używa `nft -c` dla wygenerowanych fixture'ów. Uruchamiaj go
tylko na Linuksie z dostępnym nftables.

## Dodanie przypadku testowego renderowania

Utwórz `tests/render/cases/<nazwa-przypadku>/` z plikami:

- `rules.conf` - testowana polityka.
- `assert` - oczekiwane fragmenty.
- `config` - opcjonalna konfiguracja testowa.
- `groups.d/*.conf`, `whitelist.conf`, `ingress.conf` - opcjonalne fixture'y.

Prefiksy w `assert`:

```text
+ tekst   wygenerowany ruleset musi zawierać tekst
- tekst   wygenerowany ruleset nie może zawierać tekstu
! tekst   render musi się nie udać, a stderr musi zawierać tekst
~ tekst   render musi się udać, a stderr musi zawierać ostrzeżenie
```

Uruchom:

```sh
sh tests/render/run.sh
```

## Szablon zgłoszenia

Najwygodniej użyć formularza
[Raport z testów](https://github.com/dzaczek/nftgeo/issues/new?template=test_report_PL.yml).

```text
Wersja:
Sposób instalacji:
System / kernel:
Środowisko: VPS / VM / bare metal / kontener
Testowana funkcja:
Uruchomione komendy:
Oczekiwany wynik:
Rzeczywisty wynik:
Istotna konfiguracja, bez sekretów:
Istotne logi:
```

Przydatne komendy:

```sh
nftgeo version
uname -a
sudo nftgeo validate
sudo nftgeo status
journalctl -u nftgeo.service -n 100 --no-pager
journalctl -u nftgeo-ui.service -n 100 --no-pager
```

Jeżeli sprawa dotyczy bezpieczeństwa, użyj [SECURITY.md](SECURITY.md) zamiast
publicznego zgłoszenia.
