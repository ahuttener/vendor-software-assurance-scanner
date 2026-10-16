"""Detector: weak / deprecated cryptography references."""
from __future__ import annotations

import re

from ..formats import Artifact
from ..model import Finding, Evidence, PASS, FAIL

NAME = "crypto"

# Case-sensitive uppercase tokens (how they appear in binaries/symbols) to limit noise.
_WEAK_STRINGS = [
    ("MD5", re.compile(r"\bMD5\b"), "MD5 is collision-broken; unfit for integrity/signatures"),
    ("MD4", re.compile(r"\bMD4\b"), "MD4 is broken"),
    ("SHA-1", re.compile(r"\bSHA-?1\b"), "SHA-1 is unsafe for signatures (collisions)"),
    ("DES/3DES", re.compile(r"\b(?:3DES|TripleDES|DES-?CBC|DES-?EDE)\b"), "DES/3DES deprecated"),
    ("RC4", re.compile(r"\b(?:RC4|ARC4|ARCFOUR)\b"), "RC4 is an insecure stream cipher"),
    ("ECB mode", re.compile(r"\bECB\b"), "ECB mode leaks plaintext structure"),
]

# Known weak-primitive symbol/import names (OpenSSL/wincrypt style).
_WEAK_SYMBOLS = {
    "MD5_Init": "MD5", "MD5_Update": "MD5", "MD5_Final": "MD5", "MD5": "MD5",
    "SHA1_Init": "SHA-1", "SHA1_Update": "SHA-1", "SHA1": "SHA-1",
    "DES_set_key": "DES", "DES_ecb_encrypt": "DES/ECB", "DES_ncbc_encrypt": "DES",
    "RC4": "RC4", "RC4_set_key": "RC4",
}


def run(art: Artifact) -> list[Finding]:
    ev: list[Evidence] = []
    seen: set[str] = set()

    for offset, text in art.strings:
        for label, rx, why in _WEAK_STRINGS:
            if rx.search(text) and label not in seen:
                seen.add(label)
                m = rx.search(text)
                ev.append(Evidence(kind="string", excerpt=text[:120], offset=offset, note=f"{label}: {why}"))

    for sym in art.symbols:
        if sym in _WEAK_SYMBOLS:
            label = _WEAK_SYMBOLS[sym]
            key = f"sym:{sym}"
            if key not in seen:
                seen.add(key)
                ev.append(Evidence(kind="symbol", excerpt=sym, note=f"weak primitive: {label}"))

    if ev:
        return [Finding(
            type="weak-crypto",
            title="Reference to weak or deprecated cryptographic algorithm",
            severity="High", result=FAIL, detector=NAME,
            detail="Deprecated cryptographic primitive(s) referenced.",
            evidence=ev[:25],
        )]
    return [Finding(
        type="weak-crypto",
        title="No weak cryptography detected",
        severity="Info", result=PASS, detector=NAME,
        detail="Only modern or no cryptographic primitives referenced.",
    )]
