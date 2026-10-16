"""Vendor Software Assurance Scanner (VSAS).

Static, read-only assurance testing of third-party / vendor software as part of a
Third-Party Risk Management (TPRM) programme. The scanner reads a compiled artifact,
gathers evidence, runs control tests, maps each result to multiple compliance
frameworks and produces an audit-style compliance report.

It never executes, modifies or attacks the artifact under test.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
