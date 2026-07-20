# Multi-protocol PAM architecture

## Provider boundary

`AccessProvider` is the protocol boundary. A provider receives a `ProviderContext`
containing the existing `Server`, `AccessGrant`, and `Session`; it never receives a
frontend object. The registry currently maps `ssh`, `web`, and `vnc`. RDP,
database, and Kubernetes implementations can implement the same validate, test,
launch, input, terminate, and cleanup contract without changing authorization.

SSH remains on the existing gateway. The SSH provider is an adapter and does not
replace command capture, sudo detection, host-key policy, recording, or gateway
lifecycle.

## Web transport

Web sessions use Playwright Chromium with one incognito browser context per PAM
session. A temporary profile directory is allocated per session and removed during
idempotent cleanup. Browser state, credentials, cookies, HTTP authentication, and
headers remain inside the backend worker. Chromium's CDP screencast emits JPEG
frames through a FastAPI WebSocket. Mouse, key, wheel, and text input travel back
over that channel. No Chromium, CDP, VNC, worker, or internal TCP port is bound for
users, and the UI does not use `window.open`.

The WebSocket token expires after 60 seconds by default and contains both user ID
and session ID. It only establishes the stream; the PAM JWT, grant, and session
lifecycle continue to govern the session.

## VNC transport

VNC targets are connected by the backend. The worker completes RFB 3.8 VNC
password authentication with a vault secret, then presents an authentication-free
RFB handshake only inside the already authenticated, session-bound PAM WebSocket.
The target TCP port and password are never disclosed. TLS/VeNCrypt is deliberately
fail-closed until implemented; VNC is disabled by default and non-TLS VNC must be
limited to an isolated target network. The current web distribution loads a
pinned noVNC ES module; air-gapped and high-assurance deployments should vendor
that module with the PAM static assets and enforce a matching Content Security
Policy.

## Lifecycle and storage

The lifecycle monitor handles logout, JWT expiry, grant expiry/revocation, idle and
absolute timeout, worker loss, and administrative termination. Termination closes
contexts/connections before setting the final database state, is idempotent, and
removes temporary files. Startup shutdown also closes all browser contexts.

Generic ordered `SessionEvent` rows cover all protocols. Metadata is recursively
redacted before persistence. Text input records selector, field type, and
`value_changed`, never the value. `SessionArtifact` stores an absolute non-public
path, MIME type, byte count, and SHA-256. Playback and download validate the path
under `PAM_ARTIFACT_DIR`, enforce recording RBAC and privileged MFA step-up, and
write an audit record.

Credentialed browser sessions record video and normalized events. Playwright
traces are only enabled for `none` and `manual` authentication because traces can
capture request headers, cookies, DOM values, and storage. This intentional
trade-off honors credential non-disclosure over trace completeness.
