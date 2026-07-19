# Instalacja Algen PAM

`install.sh` instaluje backend FastAPI i statyczny frontend, tworzy Python
virtualenv, bezpieczny plik `.env`, launcher oraz opcjonalną usługę systemd.
Backend wymaga Pythona 3.12, startuje jako `uvicorn app.main:app`, czyta `.env` z
katalogu głównego aplikacji i udostępnia health check `GET /api/health`.

## Wymagania systemowe

- Linux: Debian/Ubuntu, RHEL/Rocky/Alma/Fedora, Arch albo openSUSE/SUSE.
- Python 3.12 z modułami `venv` i `pip` (wersja starsza jest błędem).
- `tar`, `openssl` oraz `curl` lub `wget`.
- biblioteka PAM dla domyślnego `PAM_LOCAL_AUTH_MODE=os`.
- Git wyłącznie dla repozytorium podanego adresem SSH.
- systemd tylko wtedy, gdy użyto `--service`.

Instalator wykrywa brakujące narzędzia i używa odpowiednio `apt`, `dnf`,
`pacman` albo `zypper`. Operacje systemowe wymagają procesu root lub `sudo`.
Aplikacja nigdy nie jest uruchamiana jako root: przy bezpośrednim uruchomieniu
instalatora przez root tworzony jest systemowy użytkownik `algen-pam`, a przy
`sudo` używane jest konto z `SUDO_USER`.

`sudo ./install.sh --user` jest celowo odrzucane. Instalację użytkownika należy
uruchomić bez sudo, aby nie pomylić katalogu domowego z `/root`.

## Tryby działania

Każde uruchomienie ma jeden tryb:

- `--install` — świeża instalacja;
- `--update` — bezpieczna aktualizacja istniejącej instalacji;
- `--reinstall` — wymiana aplikacji z zachowaniem konfiguracji i danych;
- `--backup` — kopia `.env` i danych;
- `--remove-app` — usunięcie kodu i integracji, zachowanie stanu;
- `--uninstall` — pełna deinstalacja.

Bez jawnego trybu instalator wybiera `install`, gdy nie ma znacznika, albo
`update`, gdy instalacja istnieje. Sprzeczne opcje, np. `--update --uninstall`,
kończą się błędem.

## Instalacja interaktywna

```bash
./install.sh
```

Przy istniejącej instalacji instalator pokazuje jednokrotnie tekstowe menu
operacji odczytywane bezpiecznie z `/dev/tty`:

1. aktualizacja aplikacji;
2. reinstalacja;
3. backup konfiguracji;
4. usunięcie aplikacji z zachowaniem danych;
5. pełna deinstalacja;
6. anulowanie.

Domyślnym wyborem jest aktualizacja. Pusty Enter wybiera ją natychmiast, a brak
odpowiedzi przez 5 sekund uruchamia bezpieczną aktualizację automatycznie, bez
drugiego potwierdzenia. Konfiguracja, dane i logi są zachowywane. Jawny tryb CLI
ma zawsze pierwszeństwo i wyłącza menu. `whiptail` i `dialog` pozostają dostępne
w kreatorze pierwszej instalacji.

Pełna deinstalacja wybrana z menu wymaga wpisania `USUN`. Jawne
`--uninstall --yes` może pominąć to potwierdzenie w trybie bezobsługowym.

## Instalacja silent

Tryb silent nigdy nie wykonuje `read` ani nie otwiera TUI:

```bash
./install.sh --silent --yes --user --no-service
sudo ./install.sh --silent --yes --system --service
```

Brak wymaganej wartości albo konflikt portu kończy się błędem. Automatyczny wybór
wolnego portu jest możliwy tylko po dodaniu `--auto-port`:

```bash
./install.sh --silent --yes --user --port 8080 --gateway-port 2222 --auto-port
```

## Źródło, branch i tag

Domyślne źródło to branch `main` repozytorium projektu. Przykłady:

```bash
./install.sh --install --branch main
./install.sh --install --tag v1.2.0
./install.sh --install --repo https://github.com/example/fork
./install.sh --install --repo /srv/src/algen-pam
```

Dla HTTPS pobierane jest archiwum konkretnego brancha/taga, sprawdzane przez
`tar -t` i walidowane pod kątem niebezpiecznych ścieżek oraz wymaganej struktury.
Dla SSH wykonywane są jawne `fetch` oraz checkout wybranej rewizji. Branch i tag
nie mogą być podane jednocześnie. `.git`, lokalny `.env`, `data` i istniejący
virtualenv nie są kopiowane.

## Administrator i sekrety

```bash
./install.sh --install --admin-user jan --admin-email jan@example.org
PAM_LOCAL_AUTH_MODE=database ./install.sh --install --generate-admin-password
```

Bootstrap korzysta z `python -m app.bootstrap_admin`. Hasło jest generowane albo
pobierane z argumentu, przekazywane tylko do bootstrapu, usuwane z `.env`, a
zmienna powłoki jest czyszczona przez `unset`. Wygenerowane hasło jest pokazane
raz. Hasła, tokeny, klucze prywatne i zawartość `.env` nie trafiają do logu ani
do outputu `--verbose`/`--dry-run`.

Domyślne `change-me` i `change-this-32-byte-key` z `.env.example` są zastępowane
losowymi sekretami. Zapis `.env` jest atomowy i obsługuje spacje, `#` i znaki
specjalne; nowe linie i niepoprawne nazwy kluczy są odrzucane.

## Lokalizacje i uprawnienia

| Zakres | Aplikacja | Konfiguracja | Log | Launcher |
|---|---|---|---|---|
| system | `/opt/algen-pam` | `/etc/algen-pam/.env` | `/var/log/algen-pam/install.log` | `/usr/local/bin/algen-pam` |
| user | `~/.local/share/algen-pam` | `~/.config/algen-pam/.env` | `~/.local/state/algen-pam/logs/install.log` | `~/.local/bin/algen-pam` |

Dane SQLite i klucz hosta gateway są w `<app>/data`. Katalogi konfiguracji,
danych i logów mają `0700`, `.env` i znacznik `0600`, a `UMask=0077` chroni nowe
pliki usługi. Klucze prywatne powinny mieć `0600`.

## Aktualizacja, walidacja i rollback

```bash
sudo ./install.sh --update --system --yes
./install.sh --update --user --yes
./install.sh --reinstall --user --yes
```

Aktualizacja:

1. pobiera kod do katalogu tymczasowego;
2. waliduje strukturę;
3. tworzy virtualenv i instaluje zależności;
4. sprawdza importy backendu;
5. zapamiętuje stan `active` i `enabled` usługi;
6. tworzy backup konfiguracji i danych;
7. zatrzymuje aktywną usługę;
8. przełącza kompletne wydanie i zachowuje `data` oraz `.env`;
9. przywraca tylko wcześniejszy stan uruchomienia;
10. sprawdza `/api/health` i w razie błędu automatycznie przywraca poprzednie
    wydanie.

Usługa wcześniej nieaktywna nie jest uruchamiana, a wyłączona nie jest włączana.
Usunięte z repozytorium pliki znikają, bo wdrażany jest kompletny staging, nie
kopiowanie in-place. W razie błędu przed przełączeniem staging pozostaje w
lokalizacji wskazanej w komunikacie diagnostycznym.

## systemd

```bash
sudo ./install.sh --install --system --service --yes
./install.sh --install --user --service --yes
```

Jednostka ustawia `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`,
`ProtectHome`, `ReadWritePaths` dla danych i logów oraz `UMask=0077`. Dla zakresu
user używane jest wyłącznie `systemctl --user`. Jeśli usługa ma działać bez
aktywnej sesji, administrator może jawnie włączyć linger:

```bash
sudo loginctl enable-linger USER
```

## Backup i deinstalacja

```bash
./install.sh --backup --user --yes
./install.sh --remove-app --user --yes
./install.sh --uninstall --user --yes
./install.sh --uninstall --user --yes --keep-config --keep-data --keep-logs
```

Backup trafia do `<config>/backups/TIMESTAMP/`. Usuwanie wymaga absolutnej,
niesymbolicznej ścieżki, poprawnego znacznika z nazwą aplikacji i zgodnym
katalogiem oraz braku nieoczekiwanych symlinków wychodzących poza instalację.
Znacznik zawiera nazwę aplikacji, wersję instalatora, zakres, katalog i datę.
Końcowy komunikat pełnej deinstalacji nie zapisuje do usuniętego katalogu logów.

## Diagnostyka i odzyskiwanie

```bash
curl -i http://127.0.0.1:8080/api/health
systemctl status algen-pam
systemctl --user status algen-pam
```

Log instalatora znajduje się w tabeli lokalizacji powyżej. Błąd podaje etap,
lokalizację logu i zachowanego stagingu. Rollback po nieudanym health checku jest
automatyczny. Backup ręczny można rozpakować przez `tar -xzf data.tar.gz -C
<app>/data`, po uprzednim zatrzymaniu usługi i zachowaniu bieżących danych.

## Testy instalatora

```bash
bash -n install.sh
shellcheck -S warning install.sh
bash tests/install_menu.sh
bash tests/install_smoke.sh
bash tests/install_integration.sh
```

CI wykonuje kontrolę składni, ShellCheck oraz pełny cykl instalacja–update–health
check–deinstalacja na Ubuntu z Pythonem 3.12.
