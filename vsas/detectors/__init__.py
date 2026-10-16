"""Detector registry.

Each detector module exposes `run(artifact) -> list[Finding]` and corresponds to
one or more control tests in controls.yaml. A detector is an automated test
procedure: it reads evidence from the artifact and returns PASS / FAIL / MANUAL.
"""
from __future__ import annotations

from ..formats import Artifact
from ..model import Finding
from . import secrets, crypto, network, privacy, components, hardening

DETECTORS = [secrets, crypto, network, privacy, components, hardening]


def run_all(artifact: Artifact) -> list[Finding]:
    findings: list[Finding] = []
    for det in DETECTORS:
        findings.extend(det.run(artifact))
    return findings
