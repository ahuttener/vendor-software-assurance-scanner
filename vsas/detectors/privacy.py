"""Detector: personal / special-category data markers (privacy review trigger)."""
from __future__ import annotations

import re

from ..formats import Artifact
from ..model import Finding, Evidence, PASS, MANUAL

NAME = "privacy"

# (marker regex, label, is_special_category)
_MARKERS = [
    (re.compile(r"(?i)\bssn\b"), "SSN (US Social Security Number)", False),
    (re.compile(r"(?i)social[ _]security"), "Social Security", False),
    (re.compile(r"(?i)\bdob\b|date[ _]of[ _]birth"), "Date of birth", False),
    (re.compile(r"(?i)passport"), "Passport number", False),
    (re.compile(r"(?i)\bemail\b"), "Email address", False),
    (re.compile(r"(?i)\biban\b|credit[ _]?card|\bpan\b"), "Financial account / card", False),
    (re.compile(r"(?i)patient"), "Patient identifier (health)", True),
    (re.compile(r"(?i)diagnos(is|es|tic)"), "Diagnosis (health)", True),
    (re.compile(r"(?i)\bphi\b|protected[ _]health"), "Protected Health Information", True),
    (re.compile(r"(?i)\bmedical\b|health[ _]record"), "Medical / health record", True),
]


def run(art: Artifact) -> list[Finding]:
    ev: list[Evidence] = []
    special = False
    seen: set[str] = set()

    for offset, text in art.strings:
        for rx, label, is_special in _MARKERS:
            if rx.search(text) and label not in seen:
                seen.add(label)
                special = special or is_special
                ev.append(Evidence(kind="string", excerpt=text[:120], offset=offset, note=label))

    if ev:
        note = ("Includes SPECIAL-CATEGORY (health) markers: GDPR Art. 9 and HIPAA apply."
                if special else "Personal-data markers present; confirm lawful basis and minimisation.")
        return [Finding(
            type="personal-data-marker",
            title="Markers suggesting personal / special-category data handling",
            severity="High" if special else "Medium",
            result=MANUAL, detector=NAME,
            detail=note,
            evidence=ev[:25],
        )]
    return [Finding(
        type="personal-data-marker",
        title="No personal-data markers detected",
        severity="Info", result=PASS, detector=NAME,
        detail="No personal/special-category field markers found in strings.",
    )]
