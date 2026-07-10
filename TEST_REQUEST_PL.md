# Prośba o testy

Cześć,

szukam testerów nftgeo, czyli deklaratywnego menedżera zapory sieciowej
wykorzystującego nftables i reguły geograficzne.

Repozytorium: https://github.com/dzaczek/nftgeo

Najbardziej przydatne testy:

- Świeża instalacja na jednorazowym VPS z Debianem lub Ubuntu, maszynie
  wirtualnej albo hoście laboratoryjnym.
- `nftgeo validate`, `nftgeo plan` i bezpieczne zastosowanie zmian przez
  `nftgeo apply --confirm` / `--commit`.
- Ograniczenie SSH z wpisem na białej liście.
- AbuseIPDB albo własne źródła z listami blokowanych adresów IP.
- Opcjonalnie dashboard: uruchomienie usługi i logowanie tokenem.
- NAT, forwarding, strefy, ingress, throttling albo SYN proxy, jeżeli masz dla
  nich środowisko testowe.

Nie zaczynaj testów na krytycznym serwerze produkcyjnym. Jeżeli testujesz przez
SSH, zachowaj dostęp do konsoli awaryjnej i dodaj swoje aktualne publiczne IP
do białej listy przed zastosowaniem reguł przychodzących.

Instrukcja testowania: TESTING_PL.md
Zasady współtworzenia: CONTRIBUTING_PL.md
Raport z testów: https://github.com/dzaczek/nftgeo/issues/new?template=test_report_PL.yml
Problemy dotyczące bezpieczeństwa: SECURITY.md

Przydatny format informacji zwrotnej:

```text
Wersja:
Sposób instalacji:
System / kernel:
Środowisko:
Testowana funkcja:
Uruchomione komendy:
Oczekiwany wynik:
Rzeczywisty wynik:
Istotna konfiguracja, bez sekretów:
Istotne logi:
```

Przed publikacją logów albo konfiguracji usuń klucze API, prywatne nazwy
hostów, listy prywatnych adresów IP, dane SSH i hasła.
