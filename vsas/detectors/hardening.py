"""Detector: exploit-mitigation hardening + code-signing / integrity."""
from __future__ import annotations

from ..formats import Artifact
from ..model import Finding, Evidence, PASS, FAIL, MANUAL

NAME = "hardening"


def run(art: Artifact) -> list[Finding]:
    h = art.hardening or {}
    plat = h.get("platform")
    findings: list[Finding] = []
    missing: list[str] = []

    if plat == "elf":
        if not h.get("pie"):
            missing.append("PIE/ASLR (binary is a non-PIE executable)")
        if h.get("relro") != "full":
            missing.append(f"full RELRO (current: {h.get('relro', 'unknown')})")
        if not h.get("stack_canary"):
            missing.append("stack canary (-fstack-protector)")
        if not h.get("nx"):
            missing.append("NX/DEP (stack is executable)")
    elif plat == "pe":
        if not h.get("aslr"):
            missing.append("ASLR (/DYNAMICBASE)")
        if not h.get("dep_nx"):
            missing.append("DEP/NX (/NXCOMPAT)")
        if not h.get("cfg"):
            missing.append("Control Flow Guard (/GUARD:CF)")

    if plat in ("elf", "pe"):
        if missing:
            findings.append(Finding(
                type="missing-hardening",
                title="Binary built without exploit-mitigation hardening",
                severity="Medium", result=FAIL, detector=NAME,
                detail="Missing mitigations: " + "; ".join(missing),
                evidence=[Evidence(kind="metadata", excerpt=m) for m in missing],
            ))
        else:
            findings.append(Finding(
                type="missing-hardening",
                title="Standard exploit mitigations are enabled",
                severity="Info", result=PASS, detector=NAME,
                detail="All expected platform mitigations are present.",
            ))
    else:
        findings.append(Finding(
            type="missing-hardening",
            title="Hardening not assessed for this artifact type",
            severity="Info", result=MANUAL, detector=NAME,
            detail=f"Hardening checks not available for format '{plat}'.",
        ))

    # Code signing / integrity
    signed = h.get("signed")
    if signed:
        findings.append(Finding(
            type="unsigned-binary",
            title="Artifact carries a code signature / integrity mechanism",
            severity="Info", result=PASS, detector=NAME,
            detail="A signature was detected; verify the signer and chain.",
        ))
    else:
        note = h.get("signed_note", "No embedded code signature detected.")
        findings.append(Finding(
            type="unsigned-binary",
            title="Artifact is not code-signed / integrity cannot be verified",
            severity="Medium", result=FAIL, detector=NAME,
            detail=note + " Request a signed release and published checksums.",
            evidence=[Evidence(kind="metadata", excerpt="no signature present")],
        ))

    return findings
