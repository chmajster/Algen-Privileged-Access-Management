import re
from datetime import datetime, timezone

from app.config import settings


DANGEROUS_PATTERNS = [
    r"rm\s+-rf\s+/",
    r"rm\s+-rf\s+\*",
    r"chmod\s+777",
    r"chown\s+-R",
    r"\buseradd\b",
    r"\buserdel\b",
    r"\bpasswd\b",
    r"\bvisudo\b",
    r"\biptables\b",
    r"\bnft\b",
    r"systemctl\s+stop",
    r"systemctl\s+disable",
    r"\bmkfs\b",
    r"\bdd\s+if=",
    r"curl\b.*\|\s*sh",
    r"wget\b.*\|\s*sh",
    r"history\s+-c",
    r"unset\s+HISTFILE",
    r"export\s+HISTFILE=/dev/null",
    r"kill\s+-9",
    r"\breboot\b",
    r"\bshutdown\b",
]


CRITICAL_PATTERNS = [
    r"history\s+-c",
    r"unset\s+HISTFILE",
    r"export\s+HISTFILE=/dev/null",
    r"rm\s+-rf\s+/",
    r"\bmkfs\b",
]


def clamp_score(score: int) -> int:
    return max(0, min(settings.pam_max_risk_score, int(score)))


def severity_for_score(score: int) -> str:
    score = clamp_score(score)
    if score >= settings.pam_critical_risk_score:
        return "critical"
    if score >= settings.pam_high_risk_score:
        return "high"
    if score >= settings.pam_medium_risk_score:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def outside_business_hours(now: datetime | None = None) -> bool:
    now = now or datetime.now(timezone.utc)
    return now.hour < 8 or now.hour >= 18


def is_dangerous_command(command: str) -> bool:
    return any(re.search(pattern, command or "", re.IGNORECASE) for pattern in DANGEROUS_PATTERNS)


def is_critical_command(command: str) -> bool:
    return any(re.search(pattern, command or "", re.IGNORECASE) for pattern in CRITICAL_PATTERNS)
