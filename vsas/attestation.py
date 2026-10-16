"""Reconcile a vendor's self-attestation against the scanner's evidence.

A due-diligence red flag is raised whenever the vendor's questionnaire answer is
contradicted by what the binary actually contains (control: attestation-gap).
"""
from __future__ import annotations

from typing import Any

import yaml

from .model import Finding, Evidence, PASS, FAIL, MANUAL

# (claim key, claimed value that should hold, finding type that would contradict it, message)
_CHECKS = [
    ("encryption_in_transit", True, "plaintext-transport",
     "Vendor attests encryption in transit, but a cleartext (non-TLS) endpoint was found."),
    ("no_hardcoded_secrets", True, "hardcoded-secret",
     "Vendor attests no hardcoded secrets, but embedded credentials were found."),
    ("strong_cryptography_only", True, "weak-crypto",
     "Vendor attests strong cryptography only, but a deprecated algorithm was referenced."),
    ("code_signed", True, "unsigned-binary",
     "Vendor attests the release is code-signed, but no signature could be verified."),
    ("processes_personal_data", False, "personal-data-marker",
     "Vendor attests no personal data is processed, but personal/health markers were found."),
]


def load_attestation(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def reconcile(attestation: dict[str, Any], findings: list[Finding]) -> list[Finding]:
    claims = (attestation or {}).get("claims", {})
    # Which finding types came back with evidence (FAIL or MANUAL)?
    triggered = {f.type for f in findings if f.result in (FAIL, MANUAL)}

    gaps: list[Finding] = []
    for claim_key, expected, ftype, msg in _CHECKS:
        if claim_key in claims and claims[claim_key] == expected and ftype in triggered:
            gaps.append(Finding(
                type="attestation-gap",
                title="Vendor attestation contradicted by evidence",
                severity="High", result=FAIL, detector="attestation",
                detail=msg,
                evidence=[Evidence(kind="attestation",
                                   excerpt=f"{claim_key} = {claims[claim_key]}",
                                   note="self-attested; contradicted")],
            ))

    if gaps:
        return gaps
    return [Finding(
        type="attestation-gap",
        title="No contradictions between attestation and evidence",
        severity="Info", result=PASS, detector="attestation",
        detail="Every checked attestation is consistent with the evidence gathered.",
    )]
