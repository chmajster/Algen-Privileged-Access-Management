# Linux PAM Lite

Linux PAM Lite is a small Privileged Access Management web app for time-boxed SSH and sudo access to Linux servers. It includes JWT login, roles, server inventory, access requests, approvals, active grants, automatic expiry, audit logs, session history, command history, CSV export, and a working mock executor for local demos.

## Architecture

- Backend: Python FastAPI, SQLAlchemy, SQLite by default.
- Frontend: Bootstrap 5 and plain JavaScript, served by FastAPI.
- Auth: JWT plus bcrypt password hashing.
- Executor: `mock` for demos and `ssh` with Paramiko for Linux hosts.
- Scheduler: APScheduler job every `SCHEDULER_INTERVAL_SECONDS`.
- Monitoring: minimal bash history/PROMPT_COMMAND JSONL hooks, with documented limitations.

## Instalacja

### Szybki instalator Linux

Bezposrednia instalacja z repozytorium
[chmajster/Algen-Privileged-Access-Management](https://github.com/chmajster/Algen-Privileged-Access-Management):

```bash
curl -fsSL https://raw.githubusercontent.com/chmajster/Algen-Privileged-Access-Management/main/install.sh | bash
```

Instalator automatycznie korzysta z `/dev/tty`, dlatego kreator interaktywny
dziala rowniez wtedy, gdy skrypt jest przekazywany do Bash przez potok. Instalacja
bez pytan nadal jest dostepna przez `bash -s -- --silent --yes`.
Domyslnie wykonywana jest instalacja systemowa w `/opt/algen-pam`; wariant lokalny
dla biezacego uzytkownika wymaga opcji `--user`.

Po sklonowaniu repozytorium mozesz tez uzyc instalatora z trybem UI albo cichej
instalacji CLI:

```bash
./install.sh
./install.sh --silent --yes --user --no-service --admin-user admin --admin-password 'zmien-to-haslo'
./install.sh --silent --yes --system --service --install-dir /opt/algen-pam
```

Instalator sprawdza, czy port HTTP `8080` i port bramy SSH `2222` sa wolne. Przy
konflikcie proponuje inne porty (albo wybiera je automatycznie w trybie
`--silent --yes`). Wlasne wartosci ustawisz przez `--port` i `--gateway-port`.
Po instalacji uruchamia test `/api/health`. Aplikacja nasluchuje domyslnie na
`0.0.0.0`, dlatego jest dostepna przez wszystkie adresy IP serwera, na przyklad
`http://192.168.1.10:8080/` (o ile pozwala na to firewall).

Ponowne uruchomienie instalatora wykrywa istniejaca instalacje i pokazuje menu
aktualizacji, reinstalacji, kopii konfiguracji oraz usuwania. Bez wyboru po
5 sekundach automatycznie rozpoczyna sie aktualizacja z kopia konfiguracji.

Pelna dokumentacja instalacji, aktualizacji i deinstalacji znajduje sie w [INSTALL.md](INSTALL.md).

Instalator tworzy lokalne konto admina aplikacji. Po zalogowaniu admin ma dostep do panelu zarzadzania uzytkownikami, policy, policy engine, sekretami, alertami, tozsamoscia, ustawieniami i audit logami.

### Wymagania

- Python 3.12 do uruchomienia lokalnego.
- Docker Desktop albo Docker Engine z Docker Compose, jeśli chcesz uruchomić aplikację w kontenerze.
- Git, jeśli klonujesz projekt z repozytorium.

Sklonuj repozytorium i przejdź do katalogu projektu:

```powershell
git clone https://github.com/chmajster/Algen-Privileged-Access-Management.git
cd Algen-Privileged-Access-Management
```

Utwórz plik konfiguracyjny środowiska w katalogu głównym projektu:

```powershell
copy .env.example .env
```

Przed użyciem poza lokalnym demo edytuj `.env` i zmień `SECRET_KEY`. Do testów lokalnych wystarczy domyślne `PAM_EXECUTOR_MODE=mock`, które nie wymaga dostępu SSH do serwera Linux.

### Opcja 1: Docker Compose

W katalogu głównym projektu uruchom:

```powershell
docker compose up --build
```

Otwórz http://127.0.0.1:8080.

Dane SQLite są przechowywane w wolumenie Dockera `pam_lite_data`. Aby zatrzymać aplikację, naciśnij `Ctrl+C`, a następnie uruchom:

```powershell
docker compose down
```

### Opcja 2: Lokalny Python

W katalogu głównym projektu utwórz i aktywuj środowisko wirtualne w katalogu `backend`:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8080 --reload
```

Otwórz http://127.0.0.1:8080.

Domyślne dane logowania:

- `admin` / `admin123`
- `approver` / `approver123`
- `user` / `user123`

Aby uruchomić testy lokalnie:

```powershell
pytest
```

## Configuration

Use `.env` based on `.env.example`:

- `DATABASE_URL`: SQLite now, PostgreSQL-compatible SQLAlchemy URL later.
- `SECRET_KEY`: change before any real use.
- `PAM_EXECUTOR_MODE`: `mock` or `ssh`.
- `PAM_EXECUTOR_SSH_KEY_PATH`: private key path for SSH executor.
- `SCHEDULER_INTERVAL_SECONDS`: expiry/import interval.
- `PAM_SESSION_LOG_IMPORT_ENABLED`: enables active grant import pass.
- `PAM_SESSION_LOG_DIR`: Linux-side log directory.

## Changelog

Release notes and upcoming changes are tracked in [CHANGELOG.md](CHANGELOG.md). Add every user-facing change under `[Unreleased]` before cutting a release.

## Workflow

1. User logs in and adds an SSH public key.
2. User requests access to a server for 15, 30, 60, 120, 240, or 480 minutes.
3. Backend checks role, environment, access type, duration, logging, and recording policy.
4. If approval is not required, an access grant is created immediately.
5. If approval is required, approver or admin approves or rejects it.
6. Granting creates a sanitized Linux username such as `pam_user`.
7. Executor grants SSH access and optional sudo.
8. Session monitoring is configured.
9. Scheduler imports logs and expires overdue grants.
10. All administrative and workflow actions are written to `audit_logs`.

## Linux Server Requirements

For SSH mode, the target server needs:

- SSH access for `ssh_admin_user`.
- A private key available to the backend by path, not stored in the database.
- Permission to run `useradd`, `usermod`, `mkdir`, `chmod`, `chown`, `visudo`, and sudoers changes.
- `/var/log/pam-lite/` writable by the configured monitoring approach.

## Executor Modes

`mock` mode never opens SSH connections. It simulates executor actions, creates an example session, and inserts command history so the full request -> approve -> grant -> session logging -> command history -> expire/revoke workflow can be tested locally.

`ssh` mode uses Paramiko to connect as `ssh_admin_user` with `ssh_private_key_path`. It creates or unlocks the `pam_<username>` account, manages `authorized_keys`, writes sudoers rules for `limited_sudo` or `full_sudo`, validates sudoers with `visudo -cf`, and removes access during revoke/expiry.

## Access Revocation

Revocation imports final logs, removes the SSH public key, removes `/etc/sudoers.d/pam_username`, disables the Linux user if no other active grant uses it, marks the grant as `revoked` or `expired`, and writes audit records.

## Session Monitoring

The minimal implementation configures:

- `HISTTIMEFORMAT`
- `histappend`
- `PROMPT_COMMAND`
- `/home/pam_username/.pam_lite_profile`
- `/var/log/pam-lite/pam_username_commands.log`

Command log lines are intended to be JSONL with timestamp, grant ID, Linux username, working directory, command, SSH connection, and session ID.

This approach is useful for lightweight visibility but is not tamper-proof. A user with full sudo can bypass or modify shell-level logging. For full sudo or production use, prefer tlog, auditd `execve` rules, sudo I/O logging, or an SSH gateway/bastion that records sessions outside the target account.

## Monitoring sesji i import logow

Linux PAM Lite zapisuje osobna historie aktywnosci uzytkownikow na serwerach Linux. Nie jest to zwykly audit log aplikacji: dane sesji trafiaja do tabel `sessions`, a komendy do `session_commands`.

Po utworzeniu grantu workflow wyglada tak:

1. Aplikacja nadaje dostep SSH i opcjonalne sudo.
2. Konfiguruje hook monitoringu dla konta `pam_username`.
3. Tworzy albo importuje aktywna sesje.
4. Scheduler co `SCHEDULER_INTERVAL_SECONDS` importuje nowe wpisy z logow.
5. Administrator widzi sesje i komendy w UI.
6. Przy revoke albo expire aplikacja najpierw robi finalny import logow, a dopiero potem usuwa dostep.

Na hoscie Linux uzywane sa pliki:

- `/var/log/pam-lite/pam_username_commands.log`
- `/var/log/pam-lite/pam_username_sessions.log`
- `/home/pam_username/.pam_lite_profile`

Blok w `.bashrc` jest oznaczony komentarzami `BEGIN PAM-LITE MONITORING` i `END PAM-LITE MONITORING`, dzieki czemu mozna go bezpiecznie odswiezyc albo usunac przy cofnieciu dostepu. Hook zachowuje istniejacy `PROMPT_COMMAND` i wykonuje go po wlasnym logowaniu.

Import logow czyta tylko nowe dane na podstawie `log_import_offsets`. Parser obsluguje JSONL dla `session_started`, `session_finished` oraz `command`, wykrywa komendy sudo, usuwa duplikaty i zapisuje bledy importu jako `session_log_import_failed`.

### Tryb mock

W `PAM_EXECUTOR_MODE=mock` aplikacja nie laczy sie po SSH. Po nadaniu dostepu tworzy przykladowa aktywna sesje oraz komendy:

- `whoami`
- `hostname`
- `df -h`
- `sudo systemctl status nginx`
- `journalctl -xe`

Szybki test:

```powershell
copy .env.example .env
docker compose up --build
```

Zaloguj sie jako `user` / `user123`, utworz request dla `demo-linux`, a nastepnie sprawdz widoki Sessions i Commands.

### Tryb ssh

W `PAM_EXECUTOR_MODE=ssh` backend uzywa Paramiko i konta administracyjnego serwera. Wymagane sa:

- `ssh_admin_user` z uprawnieniami do zarzadzania kontami i sudoers.
- prywatny klucz pod sciezka `PAM_EXECUTOR_SSH_KEY_PATH` albo `ssh_private_key_path` serwera.
- mozliwosc tworzenia `/var/log/pam-lite/` i edycji `/home/pam_username/.bashrc`.

Przykladowy test:

1. Ustaw `PAM_EXECUTOR_MODE=ssh` w `.env`.
2. Dodaj serwer z poprawnym IP, portem, adminem SSH i sciezka do klucza.
3. Utworz request i zatwierdz grant.
4. Zaloguj sie na host jako `pam_username` z kluczem uzytkownika.
5. Wykonaj kilka komend, potem kliknij Import logs przy grancie albo poczekaj na scheduler.

### Ograniczenia i produkcja

Bash history i `PROMPT_COMMAND` sa lekkim mechanizmem widocznosci, ale nie sa pelnym zabezpieczeniem. Uzytkownik z `full_sudo` moze je obejsc albo zmodyfikowac. Dla wysokiego poziomu audytu zalecane sa:

- sudo I/O logging do zapisu wejscia/wyjscia komend sudo,
- auditd z regulami `execve` dla systemowego audytu procesow,
- tlog do nagrywania sesji terminalowych,
- SSH gateway albo bastion, ktory rejestruje sesje poza kontem docelowym.

Rekomendacja produkcyjna: traktuj bash/PROMPT_COMMAND jako warstwe pomocnicza, a dla `full_sudo` wlacz tlog, auditd, sudo I/O logging albo bramke SSH. Nie przechowuj prywatnych kluczy w bazie danych i regularnie eksportuj historie sesji oraz komend do zewnetrznego systemu audytu.

## Gateway SSH Mode

Linux PAM Lite obsluguje dwa modele dostepu:

- Direct SSH Mode: aplikacja nadaje konto i klucz na serwerze docelowym, a uzytkownik laczy sie bezposrednio z hostem. Monitoring pochodzi z hookow i logow na serwerze.
- Gateway SSH Mode: uzytkownik laczy sie do PAM Gateway, gateway sprawdza aktywny grant i dopiero potem otwiera polaczenie do serwera docelowego. Uzytkownik nie dostaje prywatnego klucza do target server, a sesja jest centralnie audytowana.

Konfiguracja `.env`:

```env
PAM_ACCESS_MODE=gateway
PAM_GATEWAY_ENABLED=true
PAM_GATEWAY_HOST=0.0.0.0
PAM_GATEWAY_PORT=2222
PAM_GATEWAY_HOST_KEY_PATH=/data/gateway_host_key
PAM_GATEWAY_SESSION_RECORDING=true
PAM_GATEWAY_COMMAND_LOGGING=true
PAM_GATEWAY_IDLE_TIMEOUT_SECONDS=900
PAM_GATEWAY_MAX_SESSION_SECONDS=28800
```

Host key gateway mozesz wygenerowac tak:

```powershell
ssh-keygen -t ed25519 -f gateway_host_key -N ""
```

W kontenerze lub na serwerze produkcyjnym umiesc klucz pod sciezka z `PAM_GATEWAY_HOST_KEY_PATH`. Live proxy jest wydzielony w `backend/app/gateway/` i preferuje `asyncssh`; w trybie `PAM_EXECUTOR_MODE=mock` aplikacja tworzy symulowane gateway connections, events, komendy i nagrania, zeby UI oraz API byly testowalne bez prawdziwego SSH proxy.

Gateway worker uruchamiaj jako osobny proces:

```powershell
cd backend
python -m app.gateway.server
```

Uzytkownik laczy sie przez gateway:

```powershell
ssh pam_username@pam-gateway-host -p 2222
```

Jesli ma kilka aktywnych grantow, gateway moze pokazac liste serwerow do wyboru. Obslugiwany jest tez wybor serwera w loginie:

```powershell
ssh pam_username+12@pam-gateway-host -p 2222
```

Gateway mapuje `pam_username` na uzytkownika aplikacji albo `access_grants.gateway_username`, sprawdza publiczny klucz zapisany przy uzytkowniku i dopuszcza tylko aktywne, niewygasle granty dla wlaczonego serwera. Polaczenie do target server odbywa sie jako `servers.gateway_target_user` albo `ssh_admin_user`, z kluczem `servers.gateway_private_key_path` albo `PAM_EXECUTOR_SSH_KEY_PATH`. Prywatny klucz uzytkownika nie jest przekazywany dalej.

Nagrywanie gateway zapisuje terminal jako JSONL w `/data/recordings/session_<session_id>.log`:

```json
{"timestamp":"...","stream":"stdin","data":"...","session_id":"...","sequence":1}
```

Dla kazdego nagrania aplikacja zapisuje metadane w `gateway_recordings`, rozmiar i SHA256. Endpointy pobierania nagran zabezpieczaja dostep rolami: user widzi tylko swoje nagrania, approver sesje zatwierdzone przez siebie, admin wszystko.

Gateway command detection dziala na strumieniu wejscia terminala: buforuje znaki do Enter, obsluguje Backspace, ignoruje proste sekwencje sterujace i zapisuje komendy z `source=gateway`. To jest praktyczny detektor typowych komend wpisywanych recznie, ale nie pelny parser terminala. Programy pelnoekranowe, paste mode, zlozone sekwencje TTY albo komendy generowane przez powloke moga wymagac tlog/auditd/sudo I/O logging.

Sesje gateway koncza sie automatycznie, gdy:

- nie ma aktywnosci dluzej niz `PAM_GATEWAY_IDLE_TIMEOUT_SECONDS`,
- przekroczono `PAM_GATEWAY_MAX_SESSION_SECONDS`,
- grant wygasl lub zostal cofniety.

Wtedy `termination_reason` dostaje wartosc `idle_timeout`, `max_session_time`, `grant_expired` albo `grant_revoked`, a zdarzenie trafia do `gateway_events` i `audit_logs`.

Rekomendacje produkcyjne:

- uruchamiaj gateway jako osobny proces/worker z ograniczonymi uprawnieniami,
- trzymaj host key i klucze target server poza repozytorium,
- nie pozwalaj na direct access dla serwerow wymagajacych centralnego audytu,
- wysylaj `gateway_events`, `gateway_recordings` i `session_commands` do zewnetrznego systemu SIEM,
- dla wysokiego poziomu audytu lacz gateway z tlog, auditd albo sudo I/O logging na target server.

## Secrets Vault

Secrets Vault to centralny magazyn sekretow uzywanych przez PAM Lite. Zamiast polegac wylacznie na statycznych sciezkach typu `ssh_private_key_path`, serwery moga wskazywac:

- `ssh_auth_secret_id` dla klucza uzywanego przez executor,
- `gateway_secret_ref_id` dla klucza gateway do target server,
- `secret_ref_id` jako ogolny fallback.

API i UI nigdy nie zwracaja plaintextu sekretu ani `encrypted_value`. Widoczne sa tylko metadane: nazwa, typ, backend, fingerprint, public key, wersja, status i daty rotacji.

Tryby vault:

- `local_encrypted`: wartosc sekretu jest szyfrowana aplikacyjnie i zapisana w DB jako ciphertext.
- `file_reference`: baza trzyma tylko referencje do pliku, np. `/run/secrets/pam_ssh_key`; backend czyta plik dopiero przy uzyciu sekretu.
- `external_vault`: szkielet/mock integracji pod HashiCorp Vault lub inny backend. Pelna integracja produkcyjna wymaga konfiguracji zewnetrznego systemu.

Konfiguracja:

```env
PAM_VAULT_MODE=local_encrypted
PAM_VAULT_MASTER_KEY=change-this-32-byte-key
PAM_SECRET_ROTATION_ENABLED=true
PAM_SECRET_ROTATION_INTERVAL_HOURS=24
PAM_SSH_KEY_ROTATION_ENABLED=true
PAM_SECRET_ACCESS_AUDIT_ENABLED=true
```

Dla `local_encrypted` ustaw mocny `PAM_VAULT_MASTER_KEY` z sekretow srodowiska, a nie z repozytorium. W produkcji preferuj KMS albo zewnetrzny Vault, poniewaz lokalny master key i ciphertext sa zarzadzane przez ta sama aplikacje.

Dodawanie sekretu:

1. Zaloguj sie jako admin.
2. Otworz widok Secrets.
3. Dodaj sekret jako `local_encrypted`, `file_reference` albo `external_vault`.
4. Przypisz sekret do serwera w polach SSH auth secret lub Gateway secret.

Audyt sekretow:

- kazde utworzenie, odczyt wewnetrzny, uzycie przez executor/gateway, rotacja, disable i revoke wersji trafia do `secret_access_logs`,
- audit log nie zawiera wartosci sekretu,
- bledy rotacji zapisuja komunikat bez ujawniania klucza.

Rotacja SSH key:

1. Tworzona jest nowa wersja sekretu.
2. Zapisywany jest public key i fingerprint.
3. Dla live SSH proces powinien dodac public key do `authorized_keys`, przetestowac nowe polaczenie i dopiero wtedy aktywowac wersje.
4. Przy sukcesie stara wersja jest oznaczona jako revoked.
5. Przy bledzie job dostaje `failed`, a stary sekret pozostaje aktywny.

W trybie mock rotacja jest symulowana: powstaje `secret_rotation_job`, nowa wersja, fingerprint i wpisy access log. Nie sa wykonywane realne polaczenia SSH.

Migracja ze starego `ssh_private_key_path`:

1. Utworz sekret `file_reference` wskazujacy obecna sciezke klucza.
2. Przypisz go jako `ssh_auth_secret_id` na serwerze.
3. Zostaw `ssh_private_key_path` jako fallback legacy do czasu potwierdzenia, ze executor uzywa vault.
4. Po migracji przenies klucze do zewnetrznego Vault/KMS lub bezpiecznego mechanizmu sekretow platformy.

## Policy Engine, Risk Engine i Alerts

Ta iteracja dodaje warstwe polityk bezpieczenstwa oraz ocene ryzyka dla kluczowych przeplywow PAM:

- access request,
- approval,
- utworzenie grantu,
- start i aktywnosc sesji,
- komendy z logow direct SSH oraz gateway,
- logowanie przez gateway,
- uzycie sekretu i bledy rotacji,
- revoke i expire grantu.

Konfiguracja `.env`:

```env
PAM_POLICY_ENGINE_ENABLED=true
PAM_RISK_ENGINE_ENABLED=true
PAM_ALERTS_ENABLED=true
PAM_AUTO_REVOKE_ON_CRITICAL_RISK=false
PAM_REQUIRE_REASON_FOR_PROD=true
PAM_REQUIRE_APPROVAL_FOR_PROD=true
PAM_REQUIRE_SESSION_RECORDING_FOR_PROD=true
PAM_REQUIRE_MFA_FOR_PROD=false
PAM_MAX_RISK_SCORE=100
PAM_CRITICAL_RISK_SCORE=80
PAM_HIGH_RISK_SCORE=60
PAM_MEDIUM_RISK_SCORE=30
```

Reguly polityk sa przechowywane w tabeli `policy_rules`. Kazda regula ma typ, priorytet, opcjonalne filtry (`environment`, `user_role`, `server_group`, `access_type`), JSON warunku oraz JSON akcji.

Przyklady akcji:

```json
{"deny": true}
```

```json
{"require_approval": true, "require_session_recording": true}
```

```json
{"requires_gateway": true}
```

Przyklady warunkow:

```json
{"command_regex": "rm\\s+-rf\\s+/"}
```

```json
{"server_group": "production-core"}
```

W UI admin ma widoki:

- Policy Engine: zarzadzanie regulami,
- Policy Test: testowanie decyzji dla uzytkownika, serwera, typu dostepu i komendy,
- Server Groups: grupowanie serwerow,
- Risk Events: os czasu zdarzen ryzyka,
- Alerts: obsluga alertow przez acknowledge, resolve i dismiss.

Zdarzenia ryzyka trafiaja do `risk_events`, a alerty wysokiego i krytycznego poziomu do `alerts`. Komendy maja zapisany `risk_score`, `risk_severity`, dopasowana regule oraz flage `blocked_by_policy`. Jesli wlaczysz `PAM_AUTO_REVOKE_ON_CRITICAL_RISK=true`, aktywny grant moze zostac automatycznie cofniety po krytycznej komendzie.

## MFA i Identity Providers

Linux PAM Lite obsluguje lokalne konta oraz przygotowane integracje LDAP/Active Directory i OIDC/Keycloak. Dostepne providery sa konfigurowane przez:

```env
PAM_AUTH_PROVIDERS=local,ldap,oidc
PAM_DEFAULT_AUTH_PROVIDER=local
PAM_MFA_ENABLED=true
PAM_MFA_ISSUER=Linux PAM Lite
PAM_MFA_REQUIRED_FOR_ADMIN=true
PAM_MFA_REQUIRED_FOR_PROD=true
PAM_MFA_REQUIRED_FOR_FULL_SUDO=true
PAM_MFA_REQUIRED_FOR_GATEWAY=true
PAM_MFA_REQUIRED_FOR_SECRET_ROTATION=true
PAM_MFA_TOKEN_TTL_SECONDS=300
PAM_STEP_UP_TTL_SECONDS=900
```

### Local auth

Local auth sprawdza `users.password_hash`. Jesli konto ma wlaczone MFA, backend po poprawnym hasle tworzy `mfa_challenges`, zwraca `mfa_required=true` oraz krotkotrwaly `mfa_token`. Pelny JWT jest wydawany dopiero po poprawnym TOTP albo jednorazowym recovery code.

Konto moze zostac czasowo zablokowane po kilku nieudanych logowaniach (`locked_until`). Logi uwierzytelniania trafiaja do `auth_events` i nie zawieraja hasel, tokenow, sekretow TOTP ani kodow recovery.

### LDAP / Active Directory

LDAP jest konfigurowany przez:

```env
PAM_LDAP_ENABLED=false
PAM_LDAP_URL=ldap://ldap.example.local:389
PAM_LDAP_BASE_DN=dc=example,dc=local
PAM_LDAP_USER_FILTER=(sAMAccountName={username})
PAM_LDAP_ROLE_ADMIN_GROUP=Linux-PAM-Admins
PAM_LDAP_ROLE_APPROVER_GROUP=Linux-PAM-Approvers
PAM_LDAP_ROLE_USER_GROUP=Linux-PAM-Users
```

Po udanym bind backend tworzy albo aktualizuje `users`, `user_identities` oraz `user_groups`. Haslo LDAP nigdy nie jest zapisywane w bazie. Mapowanie rol:

- `Linux-PAM-Admins` -> `admin`
- `Linux-PAM-Approvers` -> `approver`
- `Linux-PAM-Users` -> `user`

Gdy LDAP jest wylaczony, mock user `ldap_user` pozwala testowac UI i synchronizacje bez prawdziwego AD.

### OIDC / Keycloak

OIDC jest konfigurowany przez:

```env
PAM_OIDC_ENABLED=false
PAM_OIDC_ISSUER_URL=
PAM_OIDC_CLIENT_ID=
PAM_OIDC_CLIENT_SECRET=
PAM_OIDC_REDIRECT_URI=http://localhost:8080/auth/oidc/callback
PAM_OIDC_ROLE_CLAIM=roles
PAM_OIDC_USERNAME_CLAIM=preferred_username
PAM_OIDC_EMAIL_CLAIM=email
```

Callback mapuje claims na `users` oraz `user_identities`. Role sa mapowane z claimu `roles`:

- `pam_admin` -> `admin`
- `pam_approver` -> `approver`
- `pam_user` -> `user`

W trybie mock endpoint OIDC tworzy `oidc_user`, dzieki czemu UI dziala bez Keycloak.

### TOTP i recovery codes

MFA uzywa TOTP zgodnego z aplikacjami typu Microsoft Authenticator, Google Authenticator, 1Password albo FreeOTP. Sekret TOTP jest szyfrowany tym samym mechanizmem co lokalny Vault (`PAM_VAULT_MASTER_KEY`) i nie jest zwracany po zakonczeniu enrollmentu.

Recovery codes sa generowane jednorazowo, zapisywane tylko jako hash i oznaczane `used_at` po uzyciu. Kod recovery moze zostac wykorzystany tylko raz.

### Step-up MFA

Step-up MFA pozwala byc zalogowanym, ale wymaga dodatkowej weryfikacji przed operacjami wysokiego ryzyka. Po poprawnym kodzie powstaje `step_up_sessions` wazny przez `PAM_STEP_UP_TTL_SECONDS`.

Uzywane contexty:

- `approve_high_risk_request`
- `prod_access_request`
- `prod_full_sudo_request`
- `full_sudo_request`
- `gateway_login`
- `rotate_secret`
- `view_recording`
- `export_audit_logs`
- `export_session_logs`
- `export_risk_logs`
- `manual_revoke`
- `edit_policy`

Policy Engine wymusza MFA dla produkcji, `full_sudo`, gateway oraz rotacji sekretow zgodnie z konfiguracja. Gateway MVP nie pyta o TOTP w protokole SSH: przed polaczeniem uzytkownik musi kliknac w panelu `Verify MFA for Gateway`. Bez aktywnego step-up gateway odrzuca login komunikatem o wymaganym MFA.

### Test lokalny MFA

1. Zaloguj sie jako `admin` / `admin123`.
2. Otworz `MFA Settings`.
3. Kliknij `Enroll`, dodaj provisioning URI do aplikacji TOTP albo wpisz sekret recznie.
4. Zweryfikuj kod.
5. Wygeneruj recovery codes i zachowaj je poza aplikacja.
6. Sprobuj eksportu audit log albo edycji policy rule: backend powinien wymagac step-up.

Rekomendacje produkcyjne:

- wymuszaj MFA dla adminow, produkcji, gateway i `full_sudo`,
- dla Keycloak uzyj Authorization Code Flow z PKCE i krotkich sesji,
- dla AD/LDAP uzyj LDAPS albo StartTLS,
- ogranicz grupy mapujace role PAM do dedykowanych grup,
- nie loguj haseł LDAP, tokenow OIDC, sekretow TOTP ani recovery codes,
- wysylaj `auth_events`, `risk_events` i `audit_logs` do SIEM.

## Security Notes

- Change `SECRET_KEY` before real deployment.
- Do not store private SSH keys in the database.
- Keep executor errors sanitized before showing users.
- Regular users cannot approve their own requests or delete history.
- Server and user deletes deactivate records when linked workflow data exists.
- Treat this project as PAM Lite: a learning/demo foundation, not a complete enterprise PAM appliance.

## Tests

```powershell
cd backend
pytest
```

The test suite covers login, role access control, request creation, approvals, automatic grants, self-approval blocking, scheduler expiry, audit logging, Linux username validation, mock executor behavior, session creation, command import, CSV export, and history deletion protection.

## Development Roadmap

- PostgreSQL migrations with Alembic.
- Thread-level approval ownership and approver scopes.
- Real offset tracking for remote log imports.
- tlog/auditd/sudo I/O log collectors.
- SSH gateway mode with terminal recording.
- Secret manager integration for SSH keys.
- More granular sudo policies and command risk scoring.
