import re

with open("frontend/app.js", "r", encoding="utf-8") as f:
    content = f.read()

# Remove the exact lines from navItems array
content = re.sub(r'^\s*\["settings", "Settings", "bi-gear", "Runtime settings", \["user", "approver", "admin"\]\],\n', '', content, flags=re.MULTILINE)
content = re.sub(r'^\s*\["mfaSettings", "MFA Settings", "bi-shield-lock", "TOTP and recovery codes", \["user", "approver", "admin"\]\],\n', '', content, flags=re.MULTILINE)

# Remove "Runtime Settings" from sections array in renderAdminPanel
content = re.sub(r'^\s*\["Runtime Settings", "settings", "bi-gear", ""\],\n', '', content, flags=re.MULTILINE)

with open("frontend/app.js", "w", encoding="utf-8") as f:
    f.write(content)
