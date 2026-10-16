"""Detector: hardcoded secrets / credentials embedded in the artifact."""
from __future__ import annotations

import math
import re

from ..formats import Artifact
from ..model import Finding, Evidence, PASS, FAIL

NAME = "secrets"

_PATTERNS = [
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("PEM private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}")),
    ("GitHub token", re.compile(r"\bghp_[0-9A-Za-z]{30,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Credential assignment",
     re.compile(r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|token)\b"
                r"\s*[=:]\s*[\"']?[^\s\"';,]{6,}")),
]

# High-entropy base64-ish tokens that look like keys/secrets.
_TOKEN_RE = re.compile(r"[A-Za-z0-9+/]{32,}")


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _looks_like_secret(token: str) -> bool:
    has_upper = any(c.isupper() for c in token)
    has_lower = any(c.islower() for c in token)
    has_digit = any(c.isdigit() for c in token)
    return has_upper and has_lower and has_digit and _shannon(token) > 4.0


def run(art: Artifact) -> list[Finding]:
    ev: list[Evidence] = []
    seen: set[str] = set()

    for offset, text in art.strings:
        for label, rx in _PATTERNS:
            for m in rx.finditer(text):
                hit = m.group(0)
                key = f"{label}:{hit}"
                if key in seen:
                    continue
                seen.add(key)
                ev.append(Evidence(kind="string", excerpt=hit[:120], offset=offset, note=label))
        for m in _TOKEN_RE.finditer(text):
            tok = m.group(0)
            if 32 <= len(tok) <= 100 and _looks_like_secret(tok):
                key = f"entropy:{tok}"
                if key in seen:
                    continue
                seen.add(key)
                ev.append(Evidence(kind="string", excerpt=tok[:120], offset=offset,
                                   note=f"high-entropy token (H={_shannon(tok):.2f})"))

    if ev:
        return [Finding(
            type="hardcoded-secret",
            title="Hardcoded credential, API key or token embedded in the binary",
            severity="High", result=FAIL, detector=NAME,
            detail=f"{len(ev)} embedded secret(s) / credential-like token(s) found.",
            evidence=ev[:25],
        )]
    return [Finding(
        type="hardcoded-secret",
        title="No embedded credentials detected",
        severity="Info", result=PASS, detector=NAME,
        detail="No embedded secrets or credential-like tokens found.",
    )]
