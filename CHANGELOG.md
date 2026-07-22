# Changelog

All notable changes to this project will be documented in this file.

The format follows Keep a Changelog, and this project uses semantic versioning when releases are tagged.

## [Unreleased]

### Added

- Added a request-to-connect flow and a persistent column chooser to the Access view. Its default columns are Host, Safe, Username, and Actions.
- Installation instructions in `README.md`.
- Initial changelog with an `Unreleased` section for future updates.
- Full session monitoring import flow with sessions, command history, log offsets, CSV export, manual grant log import, and UI audit views.
- Documentation for session monitoring, SSH log locations, mock testing, SSH testing, and production audit recommendations.
- Gateway SSH mode foundation with gateway models, API, mock connections, command detection, recordings, scheduler termination, UI views, and documentation.
- Secrets Vault with encrypted/file/external backends, secret metadata API, versions, access logs, rotation jobs, executor/gateway lookup integration, UI views, and documentation.
- Policy Engine, Risk Engine, Alerts, Server Groups, policy test UI, risk scoring for access requests/grants/commands/gateway logins/secrets, and CSV exports for risk events and alerts.
- MFA and Identity foundation with local/LDAP/OIDC providers, TOTP enrollment, recovery codes, step-up sessions, auth events, MFA-protected high-risk operations, and identity admin UI.
- Internal PAM access groups with many-to-many user/server membership, per-group roles, permission templates, explicit allow/deny overrides, policy constraints, and effective-permission explanations.
- Group-scoped server, request, grant, session, command, alert, secret and audit APIs, including bulk membership changes, session termination and automatic grant revocation.
- Access-group administration UI, permission matrix, multi-select server/user assignment, searchable paginated tables, server connection reports, and expanded user access views.
- Idempotent migration from legacy server groups plus a compatibility group for existing installations.
- Backend coverage for RBAC isolation, IDOR attempts, expiration, deny precedence, MFA/gateway limits, operator approval, revocation, server validation and migration.
- Central `Permission`, `RolePermission`, `GroupPermission`, `UserGroupPermission` catalog and time-bound `ServerGroupUserMembership` model, with `/api/server-groups` REST management and compatibility aliases.
- `PAM_GROUP_SCOPED_ACCESS`, role/effective-permission APIs, per-user group overrides, RBAC audit context, demo Production/Development groups, and Secrets-Vault-only manual server form.

### Changed

- MFA and seeded policy rules are disabled by default for new installations; existing explicitly configured policy records are preserved during updates.
- Updates now compare a stored source fingerprint and skip virtualenv, pip, Playwright browser installation, backup, deployment, and service restart when no new application version is available.
- Translated installation instructions in `README.md` to Polish.
- Access request, approval, gateway, command logging, and secret-use flows now persist policy decisions and risk metadata.
- Login, gateway access, secret rotation, manual revoke, recording access, exports, and security policy changes can require MFA step-up according to configuration.
- The legacy `approver` role is persisted as `operator` during idempotent startup migration and remains accepted as a compatibility alias.
- `ServerGroupMember` is now the authoritative many-to-many server scope; `servers.server_group_id` is migrated and treated as legacy input only.

### Security

- Explicit deny overrides all allows, inactive/expired memberships fail closed, foreign IDs are concealed, gateway rechecks membership and permissions, server key paths are excluded from API output, and active grants block server archival.
- OIDC synchronization now follows a changed authoritative `preferred_username` when it does not collide with another account.

### Fixed

- MFA login failures are counted until the complete authentication flow succeeds.
- Session duration calculation handles SQLite timestamps that lost timezone metadata.

## How To Update

When making a change, add it under `[Unreleased]` using one of these sections:

- `Added` for new features.
- `Changed` for changes in existing functionality.
- `Deprecated` for soon-to-be removed features.
- `Removed` for removed features.
- `Fixed` for bug fixes.
- `Security` for vulnerability fixes.

When creating a release, rename `[Unreleased]` to the released version and date, then add a fresh empty `[Unreleased]` section above it.

Example:

```markdown
## [Unreleased]

## [1.1.0] - 2026-07-02

### Added

- New access request filter.
```
# Multi-protocol PAM

- Added extensible SSH, web, and VNC access providers while retaining the SSH gateway.
- Added isolated Playwright/CDP browser sessions, server-side authentication modes,
  SSRF and DNS-rebinding controls, lifecycle enforcement, generic events, artifacts,
  authenticated replay/download APIs, and replay/live-session UI.
- Added additive SQLite initialization and PostgreSQL migration 003, configuration
  examples, architecture/security documentation, and targeted security tests.
