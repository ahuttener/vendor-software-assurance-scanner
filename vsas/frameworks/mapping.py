"""Attach control mappings and risk scores to findings.

Loads controls.yaml once and, for each finding, fills in:
  - the control identifiers it maps to across every framework,
  - remediation guidance,
  - likelihood / impact / overall risk (NIST SP 800-30), for non-PASS results.
"""
from __future__ import annotations

import os
from typing import Any

import yaml

from ..model import Finding
from ..risk import overall

_CFG: dict[str, Any] | None = None
_DEFAULT_PATH = os.path.join(os.path.dirname(__file__), "controls.yaml")


def load_config(path: str | None = None) -> dict[str, Any]:
    global _CFG
    if _CFG is None or path is not None:
        with open(path or _DEFAULT_PATH, "r", encoding="utf-8") as fh:
            _CFG = yaml.safe_load(fh)
    return _CFG


def enrich(findings: list[Finding], path: str | None = None) -> tuple[list[Finding], dict]:
    cfg = load_config(path)
    fdefs = cfg.get("findings", {})
    scales = cfg.get("risk_scales", {})
    matrix = scales.get("matrix", {})
    levels = scales.get("levels", [])

    for f in findings:
        d = fdefs.get(f.type, {})
        f.controls = d.get("controls", {})
        f.remediation = d.get("remediation", "")
        if f.result == "PASS":
            f.likelihood = f.impact = f.risk = "N/A"
        else:
            f.likelihood = d.get("default_likelihood", "Moderate")
            f.impact = d.get("default_impact", "Moderate")
            f.risk = overall(f.likelihood, f.impact, matrix, levels)
    return findings, cfg
