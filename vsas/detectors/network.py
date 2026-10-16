"""Detector: embedded endpoints -> plaintext transport + data-egress inventory."""
from __future__ import annotations

import re

from ..formats import Artifact
from ..model import Finding, Evidence, PASS, FAIL, MANUAL

NAME = "network"

_URL_RE = re.compile(r"\b(?:https?|ftp|telnet)://[^\s\"'<>\\)]+", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_CLEARTEXT = ("http://", "ftp://", "telnet://")
_SKIP_IPS = {"0.0.0.0", "127.0.0.1", "255.255.255.255"}


def _valid_ip(ip: str) -> bool:
    try:
        return all(0 <= int(o) <= 255 for o in ip.split(".")) and ip not in _SKIP_IPS
    except ValueError:
        return False


def run(art: Artifact) -> list[Finding]:
    urls: list[tuple[int, str]] = []
    for offset, text in art.strings:
        for m in _URL_RE.finditer(text):
            urls.append((offset, m.group(0)))

    cleartext = [(o, u) for o, u in urls if u.lower().startswith(_CLEARTEXT)]
    hosts: set[str] = set()
    for _, u in urls:
        m = re.match(r"[a-z]+://([^/:]+)", u, re.IGNORECASE)
        if m:
            hosts.add(m.group(1))
    for offset, text in art.strings:
        for m in _IP_RE.finditer(text):
            if _valid_ip(m.group(0)):
                hosts.add(m.group(0))

    findings: list[Finding] = []

    # 1) plaintext-transport
    if cleartext:
        findings.append(Finding(
            type="plaintext-transport",
            title="Data transmitted over a non-TLS (cleartext) channel",
            severity="High", result=FAIL, detector=NAME,
            detail=f"{len(cleartext)} cleartext endpoint(s) embedded.",
            evidence=[Evidence(kind="url", excerpt=u[:120], offset=o) for o, u in cleartext[:25]],
        ))
    else:
        findings.append(Finding(
            type="plaintext-transport",
            title="No cleartext transport endpoints detected",
            severity="Info", result=PASS, detector=NAME,
            detail="All embedded endpoints use TLS, or none are present.",
        ))

    # 2) data-egress-endpoint (inventory for data-flow / transfer review)
    if hosts:
        findings.append(Finding(
            type="data-egress-endpoint",
            title="Embedded external endpoints (data-flow / transfer review required)",
            severity="Medium", result=MANUAL, detector=NAME,
            detail=f"{len(hosts)} endpoint host(s) found; confirm purpose and data-transfer basis.",
            evidence=[Evidence(kind="url", excerpt=h[:120]) for h in sorted(hosts)[:30]],
        ))
    else:
        findings.append(Finding(
            type="data-egress-endpoint",
            title="No embedded external endpoints detected",
            severity="Info", result=PASS, detector=NAME,
            detail="No outbound hosts/URLs embedded in the artifact.",
        ))

    return findings
