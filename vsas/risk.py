"""Risk scoring per NIST SP 800-30 Rev. 1.

Overall risk is the combination of assessed likelihood and impact, read from the
5x5 matrix in controls.yaml (Appendix I style).
"""
from __future__ import annotations


def overall(likelihood: str, impact: str, matrix: dict, levels: list[str]) -> str:
    """Return the overall risk level for a (likelihood, impact) pair."""
    try:
        return matrix[likelihood][levels.index(impact)]
    except (KeyError, ValueError, IndexError):
        return "Moderate"
