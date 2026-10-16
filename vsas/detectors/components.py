"""Detector: third-party component inventory (SBOM) + outdated/EOL components."""
from __future__ import annotations

import re

from ..formats import Artifact
from ..model import Finding, Evidence, PASS, FAIL

NAME = "components"

_LIB_RE = [
    ("OpenSSL", re.compile(r"OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)")),
    ("zlib", re.compile(r"\bzlib\s+(\d+\.\d+\.\d+)")),
    ("libcurl", re.compile(r"libcurl[/ ]?(\d+\.\d+\.\d+)")),
    ("nginx", re.compile(r"nginx/(\d+\.\d+\.\d+)")),
    ("OpenSSH", re.compile(r"OpenSSH[_ ](\d+\.\d+(?:\.\d+)?)")),
    ("Log4j", re.compile(r"log4j[-:/ ]?(\d+\.\d+\.\d+)", re.IGNORECASE)),
]


def _ver_tuple(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v))


def _eol_reason(name: str, ver: str) -> str | None:
    t = _ver_tuple(ver)
    if name == "OpenSSL" and t < (3, 0, 0):
        return "OpenSSL < 3.0 is end-of-life (1.0.x/1.1.x no longer receive security fixes)"
    if name == "zlib" and t < (1, 2, 12):
        return "zlib < 1.2.12 is affected by CVE-2018-25032"
    if name == "Log4j" and (2, 0, 0) <= t <= (2, 14, 1):
        return "Log4j 2.0-2.14.1 is vulnerable to Log4Shell (CVE-2021-44228)"
    if name == "OpenSSH" and t < (8, 5):
        return "OpenSSH < 8.5 is outdated"
    return None


def run(art: Artifact) -> list[Finding]:
    components: list[dict] = []
    ev: list[Evidence] = []
    seen: set[str] = set()

    for offset, text in art.strings:
        for name, rx in _LIB_RE:
            m = rx.search(text)
            if not m:
                continue
            ver = m.group(1)
            key = f"{name}:{ver}"
            if key in seen:
                continue
            seen.add(key)
            reason = _eol_reason(name, ver)
            components.append({"name": name, "version": ver,
                               "eol": bool(reason), "reason": reason or ""})
            if reason:
                ev.append(Evidence(kind="string", excerpt=f"{name} {ver}", offset=offset, note=reason))

    # Expose the inventory for the SBOM report regardless of pass/fail.
    art.metadata["sbom_components"] = components

    if ev:
        return [Finding(
            type="outdated-component",
            title="Bundled third-party component is outdated / end-of-life",
            severity="High", result=FAIL, detector=NAME,
            detail=f"{len(ev)} outdated/EOL component(s) identified.",
            evidence=ev[:25],
        )]
    if components:
        return [Finding(
            type="outdated-component",
            title="Third-party components identified; all within support",
            severity="Info", result=PASS, detector=NAME,
            detail=f"{len(components)} component(s) inventoried; none flagged EOL.",
        )]
    return [Finding(
        type="outdated-component",
        title="No third-party component versions identified",
        severity="Info", result=PASS, detector=NAME,
        detail="No recognizable component version strings found (SBOM may be incomplete).",
    )]
