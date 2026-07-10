# Jak współtworzyć nftgeo

Mile widziane są przede wszystkim konkretne zgłoszenia błędów, przypadki
testowe, poprawki dokumentacji i małe pull requesty, które łatwo przejrzeć.

## Zasady

- Nie dodawaj do commitów, zgłoszeń, logów, zrzutów ekranu ani fixture'ów
  sekretów produkcyjnych, prywatnych nazw serwerów, danych SSH ani kluczy API.
- Problemy dotyczące bezpieczeństwa zgłaszaj według [SECURITY.md](SECURITY.md),
  nie jako publiczne zgłoszenie.
- Preferuj małe PR-y z jedną czytelną zmianą zachowania.
- Trzymaj się istniejącego stylu shella i Go.
- Dodaj albo zaktualizuj testy, jeżeli zmienia się zachowanie.

## Środowisko deweloperskie

Wymagania:

- Go w wersji z `go.mod` albo nowszej.
- Narzędzia POSIX shell.
- `nftables` do opcjonalnej walidacji przez prawdziwe `nft -c`.
- `shellcheck` do lintowania skryptów shell.
- `nfpm` tylko do budowania paczek.

Podstawowy workflow:

```sh
git clone https://github.com/dzaczek/nftgeo.git
cd nftgeo
make test
make lint
```

## Komendy testowe

```sh
go test ./ui/
sh tests/render/run.sh
sh tests/migrate/run.sh
make test
make lint
```

Opcjonalne sprawdzenia:

```sh
sudo sh tests/render/nft-check.sh
make build
make package
```

`nft-check.sh` wymaga Linuksa z dostępnym `nft`. `make package` wymaga `nfpm`.

## Fixture'y testów renderowania

Większość zachowania silnika jest pokryta fixture'ami w
`tests/render/cases/`.

Każdy przypadek może zawierać:

- `rules.conf` - wymagana polityka wejściowa.
- `assert` - wymagane asercje.
- `config` - opcjonalne nadpisania konfiguracji.
- `groups.d/*.conf` - opcjonalne definicje obiektów.
- `whitelist.conf`, `whitelist-hosts.conf`, `ingress.conf`, `ingress.d/*.conf`
  - opcjonalne powiązane dane wejściowe.

Prefiksy asercji:

```text
+ tekst   wygenerowany wynik musi zawierać tekst
- tekst   wygenerowany wynik nie może zawierać tekstu
! tekst   render ma się nie udać, a stderr musi zawierać tekst
~ tekst   render musi się udać, a stderr musi zawierać ostrzeżenie
```

Uruchom fixture'y:

```sh
sh tests/render/run.sh
```

## Checklista pull requesta

Przed otwarciem PR:

- Uruchom `make test`.
- Uruchom `make lint`, jeżeli zmieniasz shell albo Go.
- Dodaj fixture renderowania albo test Go dla zmiany zachowania.
- Zaktualizuj dokumentację, jeżeli zmienia się składnia, konfiguracja, output
  CLI albo zachowanie związane z bezpieczeństwem.
- Usuń lokalne nazwy hostów, adresy IP, tokeny i pliki debugowe.

W opisie PR podaj:

- Co się zmieniło.
- Dlaczego się zmieniło.
- Jak zostało przetestowane.
- Uwagi o kompatybilności albo migracji, jeżeli są potrzebne.

## Dokumentacja

`README.md` powinien pozostać krótkim wprowadzeniem. Szczegółowe zachowanie
trzymaj w `docs/REFERENCE.md`, szybkie komendy w `CHEATSHEET.md`, instrukcje
testowania w `TESTING_PL.md`, a przykłady usług w `examples/`.
