# Instalacja Algen-PAM / Linux PAM Lite

Ten projekt jest aplikacja webowa PAM Lite:

- backend: Python FastAPI, SQLAlchemy, APScheduler, Paramiko/AsyncSSH,
- frontend: statyczny HTML/CSS/JavaScript serwowany przez FastAPI,
- start lokalny: `uvicorn app.main:app --host 0.0.0.0 --port 8080`,
- dane domyslne: SQLite,
- usluga systemd: opcjonalna, przydatna gdy aplikacja ma dzialac stale w tle.

Instalator znajduje sie w pliku `install.sh`. Pobiera kod z repozytorium
`https://github.com/chmajster/Algen-Privileged-Access-Management`, tworzy virtualenv, instaluje zaleznosci
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
- `tar`.

Instalator nie wykonuje `git clone`, `git fetch` ani `git pull`. Przy kazdej
instalacji i aktualizacji pobiera swieze archiwum `tar.gz` najnowszego stanu
brancha `main` (albo brancha/taga wskazanego argumentem).

## Bezposrednia instalacja z sieci

Instalator mozna uruchomic bez klonowania repozytorium
[chmajster/Algen-Privileged-Access-Management](https://github.com/chmajster/Algen-Privileged-Access-Management):

```bash
curl -fsSL https://raw.githubusercontent.com/chmajster/Algen-Privileged-Access-Management/main/install.sh | bash
```

Mimo ze standardowe wejscie Bash jest zajete przez potok, instalator automatycznie
podlacza pytania do terminala `/dev/tty`. Dzieki temu powyzsze polecenie uruchamia
pelny kreator interaktywny oraz menu wykrytej instalacji.

Wariant bez pytan:

```bash
curl -fsSL https://raw.githubusercontent.com/chmajster/Algen-Privileged-Access-Management/main/install.sh | bash -s -- --silent --yes
```

Bez wskazania zakresu instalator domyslnie instaluje aplikacje systemowo w
`/opt/algen-pam`. Uzyj `--user`, aby wybrac instalacje w katalogu biezacego
uzytkownika.

Argumenty po `bash -s --` sa przekazywane do instalatora, na przyklad:

```bash
curl -fsSL https://raw.githubusercontent.com/chmajster/Algen-Privileged-Access-Management/main/install.sh | bash -s -- --silent --yes --system --service --port 8081
```

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
- przypisanie roli admin istniejacemu kontu systemu Linux,
- podsumowanie,
- instalacje i walidacje.

Jezeli dostepny jest `whiptail` albo `dialog`, zostanie uzyty prosty TUI.
W przeciwnym razie instalator przejdzie do tekstowych pytan w terminalu.

## Cicha instalacja CLI

Instalacja bez pytan:

```bash
./install.sh --silent --yes
```

Instalacja z jawnym kontem Linux, ktore otrzyma role admina:

```bash
./install.sh --silent --yes --admin-user "$(id -un)" --admin-email "$(id -un)@localhost.localdomain"
```

Tryb zgodnosci wstecznej z haslem w bazie aplikacji:

```bash
PAM_LOCAL_AUTH_MODE=database ./install.sh --silent --yes --generate-admin-password
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
./install.sh --silent --yes --repo https://github.com/chmajster/Algen-Privileged-Access-Management
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
http://ADRES_IP_SERWERA:8080/
```

Instalator ustawia `ALGEN_PAM_HOST=0.0.0.0`, wiec aplikacja nasluchuje na
wszystkich interfejsach sieciowych. Dostep z innych komputerow wymaga zezwolenia
na wybrany port TCP w firewallu hosta i ewentualnym firewallu sieciowym.

Domyslne konta demo ponizej dzialaja tylko w jawnym trybie
`PAM_LOCAL_AUTH_MODE=database`:

```text
admin / admin123
approver / approver123
user / user123
```

W domyslnym trybie `os` instalator wymaga istniejacego konta Linux i przypisuje
mu role administratora w bazie aplikacji. Nie tworzy konta systemowego i nie
zmienia jego hasla. Rekord roli aplikacyjnej mozna odtworzyc przez:

```bash
cd <install-dir>/backend
./.venv/bin/python -m app.bootstrap_admin --username "$(id -un)" --email "$(id -un)@localhost.localdomain" --password "$(openssl rand -hex 24)"
```

Haslem logowania pozostaje haslo konta systemu operacyjnego. Argumenty
`--admin-password` i `--generate-admin-password` maja znaczenie tylko w trybie
zgodnosci `PAM_LOCAL_AUTH_MODE=database`.

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

## Wykrywanie istniejacej instalacji

Przy zwyklym uruchomieniu `./install.sh` instalator wykrywa istniejaca instalacje
uzytkownika albo systemowa i wyswietla menu:

```text
Choose action (automatic update starts after 5 seconds):
  1) Update application (backup and keep config)
  2) Reinstall application (clean app files; keep config, data, and logs)
  3) Backup config only
  4) Remove app (keep config, data, and logs)
  5) Remove app and all files
  6) Abort
Action [1] (auto update in 5s):
```

Brak wyboru przez 5 sekund uruchamia opcje `1`. Aktualizacja wykonuje kopie
konfiguracji w podkatalogu `backups` katalogu konfiguracji. Reinstalacja usuwa
tylko pliki aplikacji i zachowuje konfiguracje, katalog `data` oraz logi. Opcja
`4` usuwa program i integracje systemd/desktop, ale pozostawia te same dane.

W trybie `--silent --yes` wykryta instalacja jest aktualizowana automatycznie bez
oczekiwania na menu.

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

Istniejacy plik uslugi jest automatycznie wykrywany i zachowywany podczas
aktualizacji, nawet gdy ponowne uruchomienie instalatora nie zawiera opcji
`--service`. Po update instalator wymaga, aby `algen-pam.service` byla wlaczona
(`is-enabled`), aktywna (`is-active`) i odpowiadala na `/api/health`. Niespelnienie
ktoregokolwiek warunku konczy aktualizacje bledem i wskazuje log instalatora oraz
journal systemd.

Aktualizacja nie zmienia hasla konta systemu Linux. W trybie zgodnosci database
haslo aplikacyjne mozna zmienic jawnie:

```bash
PAM_LOCAL_AUTH_MODE=database ./install.sh --update --user --yes --admin-password 'nowe-haslo'
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
- status systemd, jezeli utworzono usluge,
- czy aplikacja odpowiada na endpointzie `/api/health`.

Bez uslugi systemd instalator uruchamia aplikacje tymczasowo na potrzeby testu i
zatrzymuje ja po poprawnej odpowiedzi. Z usluga systemd sprawdza dzialajacy proces
uslugi. Brak poprawnej odpowiedzi konczy instalacje bledem i wskazuje logi.

Pelny test cyklu instalacji i aktualizacji na Linuxie:

```bash
bash tests/install_integration.sh
```

Test korzysta z katalogu tymczasowego i izolowanej implementacji `systemctl`.
Sprawdza swieza instalacje, aktywny proces uslugi, odpowiedz `/api/health`, restart
po automatycznym update, kopie konfiguracji, zachowanie danych, poprawnosc unit
file oraz zatrzymanie i usuniecie uslugi podczas deinstalacji.

## Argumenty

```text
--silent              uruchamia instalacje bez UI i bez pytan
--yes, -y             automatycznie akceptuje operacje
--install-dir PATH    katalog instalacji
--user                instalacja dla biezacego uzytkownika
--system              instalacja systemowa (domyslnie /opt/algen-pam)
--port PORT           port HTTP aplikacji (domyslnie 8080)
--gateway-port PORT   port bramy SSH (domyslnie 2222)
--service             utworz i wlacz usluge systemd
--no-service          nie tworz uslugi systemd
--desktop             utworz skrot aplikacji
--no-desktop          nie tworz skrotu aplikacji
--admin-user NAME     istniejace konto Linux z rola administratora aplikacji
--admin-email EMAIL   email lokalnego administratora
--admin-password PASS haslo tylko dla trybu zgodnosci database
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

### Pobieranie najnowszej wersji

Instalator zawsze pobiera archiwum z GitHuba i nie wymaga `git`. Archiwum jest
najpierw pobierane, sprawdzane przez `tar` i rozpakowywane w katalogu tymczasowym.
Dopiero po poprawnej weryfikacji instalator wymienia pliki aplikacji, zachowujac
konfiguracje, dane i logi.

### Python starszy niz 3.12

Instalator ostrzega, jezeli wykryje starsza wersje. Projekt dokumentuje Python
3.12 jako zalecany runtime. Na starszej dystrybucji zainstaluj Python 3.12 z
pakietow dystrybucji, pyenv albo backports.

### Port aplikacji albo bramy SSH jest zajety

Instalator sprawdza port HTTP (domyslnie `8080`) oraz port bramy SSH (domyslnie
`2222`) przed zapisaniem konfiguracji. W trybie interaktywnym proponuje najblizszy
wolny port i pozwala wpisac inny. W trybie cichym z `--yes` automatycznie wybiera
zaproponowany wolny port. Porty mozna tez wskazac jawnie:

```bash
./install.sh --port 8081 --gateway-port 2223
```

Wybrane wartosci sa zapisywane w konfiguracji i uzywane przez wrapper, usluge
systemd oraz skrot pulpitu. Przy recznym uruchamianiu nadal mozna jednorazowo
nadpisac port HTTP: `ALGEN_PAM_PORT=8081 algen-pam`.

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
