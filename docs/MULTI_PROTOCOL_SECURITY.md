# Multi-protocol PAM security model

## Trust boundaries and threats

The browser/VNC worker and artifact directory are privileged backend components.
The browser frame is untrusted visual data; all input and navigation remain subject
to server policy. Target sites, DNS, downloads, uploads, popups, and browser content
are hostile. Users may be authorized for a target but not for its credentials or
recordings.

Controls:

- Only normalized HTTP/HTTPS URLs are accepted. `file`, `data`, `javascript`,
  `chrome`, `about`, FTP, embedded URL credentials, and malformed IDNs are blocked.
- Every request, redirect, frame navigation, and popup is intercepted. DNS is
  resolved and repeatedly validated; a changed answer is treated as rebinding.
- Loopback, link-local, multicast, unspecified, reserved, and cloud-metadata
  addresses are always blocked. Private addresses require an explicit resource
  policy. Domain allow/block lists use label-aware suffix matching.
- Upload, download, clipboard, and popup behavior defaults to deny/restrict. Size
  caps apply before a user file reaches browser input and before a download becomes
  an artifact.
- Secrets are fetched directly from the existing vault in the worker. API and
  event schemas only contain secret references. Validation errors are covered by
  the application's secret-redaction handler.
- Browser contexts are isolated, use no shared storage state, and are closed at
  termination. The worker does not expose remote-debugging ports.
- Recording authorization is concealed as 404 when absent. Admin/operator
  recording access forces an MFA step-up. All play/download actions are audited.

## Operational limits

Chromium must run under a dedicated, non-root container account with its sandbox
enabled and current security patches. Egress firewalling should mirror allowed
domains because application-level SSRF controls are defense in depth, not a
replacement for network segmentation. Multi-node deployments need worker affinity
and a shared private artifact store; the included runtime registry is process-local.
Artifact encryption at rest and retention/deletion scheduling depend on deployment
storage controls and are not implemented here. Playwright video does not include
audio. VNC currently supports RFB 3.8 password or no-auth targets only and fails
closed for TLS/VeNCrypt. RDP, databases, and Kubernetes have extension points but
no provider implementation yet.
