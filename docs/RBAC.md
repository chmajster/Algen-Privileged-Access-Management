# RBAC i grupy serwerów

## Model bezpieczeństwa

`ServerGroup` i `ServerGroupMember` są źródłem prawdy dla lokalnego zakresu PAM. Tabele `user_groups` nadal przechowują wyłącznie deklaracje pochodzące z LDAP, AD i OIDC i nie są używane do lokalnej autoryzacji.

Nowy model składa się z:

- `server_groups` — zakres bezpieczeństwa oraz reguły dostępu, MFA, zatwierdzania, gateway i nagrywania;
- `server_group_members` — relacja wiele-do-wielu serwerów z grupami;
- `server_group_user_memberships` — aktywne i ograniczone czasowo członkostwa z rolą `group_admin`, `operator`, `user` lub `custom`;
- `permissions` — centralny katalog kodów uprawnień;
- `role_permissions` — uprawnienia domyślne ról;
- `group_permissions` — jawne ustawienia grupy;
- `user_group_permissions` — indywidualne wyjątki użytkownika w jednej grupie.

Stare `access_groups*` są tylko wejściem migracji danych. Endpointy `/api/access-groups` są aliasem zgodności nad `ServerGroup` i nie tworzą drugiego systemu. `servers.server_group_id` jest polem legacy: aktualizacja kopiuje jego wartość do `server_group_members`, a wszystkie nowe decyzje korzystają wyłącznie z relacji wiele-do-wielu.

## Role i decyzja

- `admin` ma pełny dostęp globalny i nie wymaga członkostwa;
- `operator` działa w przypisanych grupach i otrzymuje domyślnie obsługę requestów, grantów, sesji, komend i nagrań grupy;
- `user` otrzymuje widok przypisanych serwerów, własne requesty i sesje oraz połączenie przez gateway;
- stara rola `approver` jest akceptowana jako alias, lecz przy inicjalizacji zostaje trwale zmigrowana do `operator`.

Algorytm centralnego modułu `app.authorization`/`app.rbac`:

1. Globalny administrator otrzymuje `allow`.
2. Nieaktywny użytkownik, wyłączona grupa, wyłączone członkostwo albo członkostwo poza `valid_from`/`valid_to` nie daje praw.
3. Dla wskazanego serwera brane są wyłącznie aktywne grupy zawierające serwer.
4. Łączone są wpisy `RolePermission`, `GroupPermission` i `UserGroupPermission`.
5. Dowolny jawny `deny` ma pierwszeństwo przed każdym `allow`.
6. Brak `allow` oznacza `default_deny`.
7. Policy Engine może decyzję ograniczyć, ale nigdy nie może nadać prawa, którego RBAC nie przyznał.

Policy Engine otrzymuje `user_role`, role grupowe, identyfikatory i nazwy grup serwera, efektywne uprawnienia, najbliższą datę wygaśnięcia członkostwa, środowisko i krytyczność serwera. Może wymusić MFA, zatwierdzenie, gateway lub nagrywanie, zabronić Direct SSH i ograniczyć typ albo czas dostępu.

`PAM_GROUP_SCOPED_ACCESS=true` włącza obowiązkowe filtrowanie zasobów grupowych. Listy serwerów, requestów, grantów, sesji, komend, nagrań, sekretów i audytu są ograniczane w SQL. Bezpośrednie odwołanie do obcego identyfikatora zwraca zazwyczaj `404`, by nie ujawniać istnienia zasobu; niedozwolona operacja na znanym zasobie zwraca `403`.

## Domyślna macierz

| Kategoria | Administrator | Operator (w grupie) | User (w grupie) |
|---|---|---|---|
| Serwery | wszystkie operacje | widok, edycja/test jeśli jawnie nadane | widok |
| Requesty i granty | pełna obsługa | approve, reject, revoke, extend | własny request i dozwolony typ dostępu |
| Połączenia | direct i gateway | gateway | gateway |
| Sesje/komendy/nagrania | wszystkie | zakres grupy | własne |
| Członkowie grupy | pełne zarządzanie | domyślnie tylko widok | brak |
| Sekrety i konfiguracja | pełne zarządzanie | brak domyślny | brak |

Tabela `role_permissions` zawiera dokładne kody. Uprawnienia grupowe i użytkownika mogą zawęzić powyższe wartości; deny zawsze wygrywa.

## API

Podstawowe endpointy:

- `GET/POST /api/server-groups`, `GET/PUT/DELETE /api/server-groups/{id}`;
- `GET/POST/DELETE /api/server-groups/{id}/servers[...]` oraz `bulk-add`/`bulk-remove`;
- `GET/POST /api/server-groups/{id}/users`, `PUT/DELETE /api/server-groups/{id}/users/{user_id}`;
- `GET/PUT /api/server-groups/{id}/permissions`;
- `GET/PUT /api/server-groups/{id}/users/{user_id}/permissions`;
- `GET /api/server-groups/{id}/users/{user_id}/effective-permissions`;
- `GET /api/permissions`, `GET /api/role-permissions`;
- `GET /api/users/{id}/groups`, `GET /api/users/{id}/effective-permissions`;
- `PUT /api/users/{id}/role`, `PUT /api/users/{id}/status`;
- `GET/POST /api/servers`, `GET/PUT/DELETE /api/servers/{id}`, `POST /api/servers/{id}/test-connection`.

Listy grup i serwerów obsługują `search`, `environment`, `skip` i `limit`; serwery dodatkowo `group_id`. Stare ścieżki `/api/access-groups` pozostają aliasami zgodności.

## Serwery i sekrety

Formularz ręcznego serwera obsługuje nazwę, display name, IP/FQDN, port, środowisko, właściciela, krytyczność, ustawienia Direct/Gateway SSH, MFA, zatwierdzanie, nagrywanie i wiele grup. Host i port są walidowane, a duplikaty hostname lub adres+port odrzucane.

Klucz prywatny ani hasło nie są przyjmowane w formularzu. Konfiguracja wskazuje rekord Secrets Vault przez `ssh_auth_secret_id`, `secret_ref_id` lub `gateway_secret_ref_id`. Legacy ścieżki kluczy mogą pozostać w starej bazie, ale nie są serializowane przez API. Serwer z aktywnym grantem nie może być usunięty ani zarchiwizowany.

## Migracja

`init_db()` wykonuje idempotentny, niedestrukcyjny upgrade dla SQLite i PostgreSQL:

1. tworzy brakujące tabele;
2. dodaje wyłącznie brakujące, bezpiecznie domyślne kolumny;
3. kopiuje `servers.server_group_id` do `server_group_members`;
4. migruje wcześniejsze `access_groups*` do istniejących lub nowych `ServerGroup`;
5. migruje `approver` do `operator`;
6. uzupełnia katalog i domyślne wpisy ról;
7. na starej, nieskopowanej instalacji tworzy systemową grupę `Legacy compatibility` bez automatycznego dodawania późniejszych kont.

Migracja nie usuwa użytkowników, serwerów, requestów, grantów, sesji ani audytu. Przed wdrożeniem produkcyjnym wykonaj kopię bazy i przejrzyj członkostwa w `Legacy compatibility`. Dla rozbudowanych instalacji nadal zalecany jest kontrolowany proces migracji Alembic oraz test na kopii danych.

## Audit

Zmiany RBAC i serwerów zapisują wykonawcę, akcję, typ i identyfikator obiektu, stare i nowe wartości, IP, User-Agent, wynik i czas. Odrzucone decyzje mają `result=denied`. Metadane są serializowane bez haseł, tokenów, plaintextu sekretów i materiału klucza.
