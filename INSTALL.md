# Instalacja Algen-PAM / Linux PAM Lite

Ten projekt jest aplikacja webowa PAM Lite:

- backend: Python FastAPI, SQLAlchemy, APScheduler, Paramiko/AsyncSSH,
- frontend: statyczny HTML/CSS/JavaScript serwowany przez FastAPI,
- start lokalny: `uvicorn app.main:app --host 0.0.0.0 --port 8080`,
- dane domyslne: SQLite,
- usluga systemd: opcjonalna, przydatna gdy aplikacja ma dzialac stale w tle.

Instalator znajduje sie w pliku `install.sh`. Pobiera kod z repozytorium
`https://github.com/chmajster/Algen-PAM`, tworzy virtualenv, instaluje zaleznosci
Pythona, przygotowuje konfiguracje, wrapper `algen-pam` oraz opcjonalna usluge
systemd i skrot `.desktop`.

Podczas instalacji tworzony jest lokalny administrator aplikacji. To konto ma
role `admin` i dostep do panelu administracyjnego, zarzadzania uzytkownikami,
policy, policy engine, sekretami, tozsamoscia, alertami, ustawieniami runtime i
audit logami.

## Wymagania

Obslugiwane sa dystrybucje z menedzerem pakietow:

- Debian/Ubuntu: `apt`
- Fedora: `dnf`
- Arch Linux: `pacman`

Wymagane narzedzia systemowe:

- Linux,
- Python 3.12 zalecany,
- `python3-venv` / modul `venv`,
- `pip`,
- `curl` albo `wget`,
- `tar`,
- `git` opcjonalnie, ale preferowany.

Gdy `git` nie jest dostepny, instalator probuje pobrac archiwum `tar.gz` z GitHuba.

## Instalacja UI

Uruchom:

```bash
./install.sh
```

Instalator przeprowadzi przez:

- ekran powitalny,
- sprawdzenie systemu i zaleznosci,
- wybor instalacji uzytkownika albo systemowej,
- wybor katalogu instalacji,
- opcjonalne utworzenie uslugi systemd,
- opcjonalne utworzenie skrotu `.desktop`,
- utworzenie konta admina aplikacji,
- podsumowanie,
- instalacje i walidacje.

Jezeli dostepny jest `whiptail` albo `dialog`, zostanie uzyty prosty TUI.
W przeciwnym razie instalator przejdzie do tekstowych pytan w terminalu.

## Cicha instalacja CLI

Instalacja bez pytan:

```bash
./install.sh --silent --yes
```

Instalacja z jawnym kontem admina:

```bash
./install.sh --silent --yes --admin-user admin --admin-email admin@example.local --admin-password 'zmien-to-haslo'
```

Instalacja z wygenerowanym haslem admina:

```bash
./install.sh --silent --yes --generate-admin-password
```

Instalacja systemowa z usluga:

```bash
./install.sh --silent --install-dir /opt/algen-pam --system --service --yes
```

Instalacja uzytkownika bez uslugi:

```bash
./install.sh --silent --user --no-service --install-dir ~/.local/share/algen-pam --yes
```

Instalacja z wybranego brancha:

```bash
./install.sh --silent --yes --branch main
```

Instalacja z taga:

```bash
./install.sh --silent --yes --tag v1.0.0
```

Nadpisanie repozytorium:

```bash
./install.sh --silent --yes --repo https://github.com/chmajster/Algen-PAM
```

## Sciezki

Instalacja systemowa:

```text
/opt/algen-pam
/usr/local/bin/algen-pam
/etc/algen-pam/.env
/var/log/algen-pam/install.log
```

Instalacja uzytkownika:

```text
~/.local/share/algen-pam
~/.local/bin/algen-pam
~/.config/algen-pam/.env
~/.local/state/algen-pam/logs/install.log
```

Instalator tworzy rowniez katalog `data` w katalogu instalacji. Domyslna baza
SQLite jest zapisywana jako:

```text
<install-dir>/data/pam_lite.db
```

## Konfiguracja

Konfiguracja jest tworzona na podstawie `.env.example` i zapisywana w:

- `/etc/algen-pam/.env` dla instalacji systemowej,
- `~/.config/algen-pam/.env` dla instalacji uzytkownika.

W katalogu aplikacji powstaje symlink `.env` wskazujacy na ten plik, poniewaz
aplikacja FastAPI czyta konfiguracje z katalogu glownego repozytorium.

Przed uzyciem produkcyjnym sprawdz co najmniej:

- `SECRET_KEY`,
- `PAM_DEFAULT_ADMIN_USER`,
- `PAM_DEFAULT_ADMIN_EMAIL`,
- `PAM_DEFAULT_ADMIN_PASSWORD`,
- `PAM_EXECUTOR_MODE`,
- `PAM_EXECUTOR_SSH_KEY_PATH`,
- ustawienia LDAP/OIDC/MFA, jezeli sa uzywane.

## Uruchamianie

Po instalacji uzytkownika:

```bash
~/.local/bin/algen-pam
```

Po instalacji systemowej:

```bash
algen-pam
```

Nastepnie otworz:

```text
http://127.0.0.1:8080/
```

Domyslne konta demo:

```text
admin / admin123
approver / approver123
user / user123
```

Instalator tworzy lub aktualizuje lokalne konto admina przez:

```bash
cd <install-dir>/backend
./.venv/bin/python -m app.bootstrap_admin --username admin --email admin@example.local --password 'nowe-haslo' --update-password
```

Przy ponownym uruchomieniu instalatora haslo istniejacego admina nie jest
resetowane, chyba ze podasz `--admin-password` albo `--generate-admin-password`.

## systemd

Usluga systemd jest opcjonalna. Aplikacja moze dzialac jako proces webowy w tle,
wiec `--service` ma sens na serwerze.

Instalacja systemowa:

```bash
./install.sh --silent --system --service --yes
sudo systemctl status algen-pam
sudo systemctl stop algen-pam
sudo systemctl start algen-pam
```

Instalacja uzytkownika:

```bash
./install.sh --silent --user --service --yes
systemctl --user status algen-pam
systemctl --user stop algen-pam
systemctl --user start algen-pam
```

## Skrot desktop

Skrot `.desktop` otwiera interfejs webowy:

```bash
./install.sh --silent --user --desktop --yes
```

Skrot zaklada, ze aplikacja slucha na `http://127.0.0.1:8080/`.

## Aktualizacja

Aktualizacja zachowuje konfiguracje i dane:

```bash
./install.sh --update --user --yes
```

Dla instalacji systemowej:

```bash
./install.sh --update --system --yes
```

Jezeli usluga byla aktywna, instalator zatrzymuje ja przed aktualizacja i probuje
uruchomic ponownie po zakonczeniu.

Aktualizacja nie zmienia hasla admina, o ile nie podasz jawnie nowego hasla:

```bash
./install.sh --update --user --yes --admin-password 'nowe-haslo'
```

## Deinstalacja

Usuniecie instalacji uzytkownika:

```bash
./install.sh --uninstall --user --yes
```

Usuniecie instalacji systemowej:

```bash
./install.sh --uninstall --system --yes
```

Zachowanie konfiguracji:

```bash
./install.sh --uninstall --user --keep-config --yes
```

Zachowanie logow:

```bash
./install.sh --uninstall --user --keep-logs --yes
```

Deinstalator:

- zatrzymuje usluge systemd, jezeli dziala,
- wylacza usluge,
- usuwa plik uslugi,
- usuwa wrapper `algen-pam`,
- usuwa katalog aplikacji,
- opcjonalnie usuwa konfiguracje i logi.

Dla bezpieczenstwa deinstalator odmawia usuwania katalogow, ktore nie wygladaja
jak katalogi tej aplikacji.

## Dry run i walidacja

Pomoc:

```bash
./install.sh --help
```

Plan bez zapisu:

```bash
./install.sh --dry-run
```

Cicha walidacja parsera i planu:

```bash
./install.sh --silent --yes --user --no-service --dry-run
```

Instalator po instalacji sprawdza:

- czy wrapper startowy istnieje,
- czy `algen-pam --version` odpowiada,
- status systemd, jezeli utworzono usluge.

## Argumenty

```text
--silent              uruchamia instalacje bez UI i bez pytan
--yes, -y             automatycznie akceptuje operacje
--install-dir PATH    katalog instalacji
--user                instalacja dla biezacego uzytkownika
--system              instalacja systemowa
--service             utworz i wlacz usluge systemd
--no-service          nie tworz uslugi systemd
--desktop             utworz skrot aplikacji
--no-desktop          nie tworz skrotu aplikacji
--admin-user NAME     lokalny administrator aplikacji
--admin-email EMAIL   email lokalnego administratora
--admin-password PASS haslo lokalnego administratora
--generate-admin-password
                     generuje losowe haslo administratora
--branch NAME         pobierz wskazany branch repozytorium
--tag NAME            pobierz wskazany tag/release
--repo URL            nadpisuje URL repozytorium
--update              aktualizuje istniejaca instalacje
--uninstall           usuwa program
--keep-config         zostawia konfiguracje przy deinstalacji
--keep-logs           zostawia logi przy deinstalacji
--dry-run             pokazuje co zostanie wykonane
--verbose             pokazuje dokladniejsze logi
--help, -h            pomoc
```

## Troubleshooting

### Brak sudo

Instalacja systemowa wymaga `sudo`. Uzyj instalacji uzytkownika:

```bash
./install.sh --silent --user --yes
```

### Brak internetu albo GitHub niedostepny

Instalator przerwie prace z komunikatem bledu pobierania. Sprawdz DNS, proxy,
firewall albo uzyj `--repo` z lokalnym mirror URL.

### Brak `git`

Instalator uzyje archiwum z GitHuba, jezeli ma `curl` albo `wget` oraz `tar`.
Mozesz tez zainstalowac `git` i uruchomic instalator ponownie.

### Python starszy niz 3.12

Instalator ostrzega, jezeli wykryje starsza wersje. Projekt dokumentuje Python
3.12 jako zalecany runtime. Na starszej dystrybucji zainstaluj Python 3.12 z
pakietow dystrybucji, pyenv albo backports.

### Port 8080 jest zajety

Wrapper przyjmuje zmienne srodowiskowe:

```bash
ALGEN_PAM_PORT=8081 algen-pam
```

Dla systemd zmien `ExecStart` w pliku uslugi albo uruchom aplikacje bez uslugi z
innym portem.

### Usluga uzytkownika nie startuje po restarcie

Dla uslug `systemctl --user` moze byc potrzebne linger:

```bash
loginctl enable-linger "$USER"
```

### Aplikacja startuje, ale nie widac frontendu

Sprawdz, czy katalog `frontend` istnieje w katalogu instalacji oraz czy aplikacja
jest uruchamiana z wrappera `algen-pam`. Backend zaklada strukture repozytorium:

```text
backend/app/main.py
frontend/index.html
```
