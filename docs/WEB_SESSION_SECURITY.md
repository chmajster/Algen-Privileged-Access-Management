# Controlled web-session transport

Algen PAM uses Playwright/CDP screencasting. Chromium and CDP remain inside the API container; neither a debugging port nor a browser credential is exposed. A short-lived JWT bound to one PAM session authorizes the frame WebSocket and constrained input endpoint. The client receives JPEG frames and can submit mouse, key and wheel events only.

Each session gets an incognito browser context, isolated cookies/storage/cache, a temporary worker directory, trace capture and video recording. Termination closes the context, finalizes SHA-256 metadata, and removes the temporary directory. The lifecycle monitor terminates sessions after logout, JWT/grant expiry, revocation, idle/absolute timeout, administrative action or worker shutdown.

## Navigation protection

Every browser request is intercepted, including redirects and popup requests. Only HTTP(S) is accepted. DNS answers are validated against loopback, link-local, metadata, reserved and (unless resource-enabled) private ranges. A host whose answer set changes during a session is rejected as DNS rebinding. Resources may further limit exact domains and subdomains.

## Trade-offs

Screencasting avoids exposing VNC/CDP ports and gives the PAM policy engine a narrow input vocabulary. It has higher CPU use and somewhat more latency than direct browser delivery. JPEG frames are visual output, so highly sensitive pages should additionally use display-watermark and retention controls at deployment level. Chromium sandboxing remains defense in depth; the container also runs as a non-root user with no host browser socket.
