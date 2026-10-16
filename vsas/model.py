"""Core data types shared across the scanner."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

# Severity ranking used only for sorting/colouring the report.
SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}

# Three-state result of a control test.
PASS = "PASS"
FAIL = "FAIL"
MANUAL = "MANUAL"  # evidence found but a human must decide (e.g. personal-data markers)


@dataclass
class Evidence:
    """A single, reproducible piece of evidence for a finding."""
    kind: str                 # 'string' | 'symbol' | 'metadata' | 'url' | 'entry' | 'attestation'
    excerpt: str              # the exact text/value found (truncated for display)
    offset: int = -1          # byte offset in the artifact when known, else -1
    note: str = ""            # optional qualifier (e.g. which algorithm, which claim)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    """One control-test result. `type` matches a key in controls.yaml -> findings."""
    type: str
    title: str
    severity: str = "Medium"
    result: str = FAIL        # PASS / FAIL / MANUAL
    detail: str = ""
    detector: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    # Filled in by the mapping/risk stage:
    likelihood: str = ""
    impact: str = ""
    risk: str = ""
    controls: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["evidence"] = [e.to_dict() for e in self.evidence]
        return d
