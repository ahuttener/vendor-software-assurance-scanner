"""Command-line entry point: scan an artifact and write the compliance reports."""
from __future__ import annotations

import argparse
import datetime
import hashlib
import os
import sys

from . import __version__
from .formats import load
from .detectors import run_all
from .frameworks.mapping import enrich
from .attestation import load_attestation, reconcile
from .report import json_out, sbom, oscal, crosswalk_csv, html

_RISK_RANK = {"N/A": 0, "Very Low": 1, "Low": 2, "Moderate": 3, "High": 4, "Very High": 5}


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _recommendation(max_risk: str) -> tuple[str, str]:
    if _RISK_RANK.get(max_risk, 0) >= 4:          # High / Very High
        return "Reject", "Reject — remediate before approval"
    if max_risk == "Moderate":
        return "Conditional", "Approve with conditions (time-bound remediation)"
    return "Approve", "Approve"


def _summarize(findings: list) -> dict:
    counts = {"PASS": 0, "FAIL": 0, "MANUAL": 0}
    for f in findings:
        counts[f.result] = counts.get(f.result, 0) + 1
    open_f = [f for f in findings if f.result != "PASS"]
    max_risk = "N/A"
    for f in open_f:
        if _RISK_RANK.get(f.risk, 0) > _RISK_RANK.get(max_risk, 0):
            max_risk = f.risk
    rec_key, rec_text = _recommendation(max_risk)
    top = [f.title for f in sorted(open_f, key=lambda x: -_RISK_RANK.get(x.risk, 0))[:3]]
    narrative = (f"{counts['FAIL']} control test(s) failed and {counts['MANUAL']} require "
                 f"manual review; {counts['PASS']} passed. Highest open risk: {max_risk}. "
                 + (("Key issues: " + "; ".join(top) + ".") if top else "No open issues."))
    return {"counts": counts, "max_risk": max_risk, "recommendation_key": rec_key,
            "recommendation": rec_text, "narrative": narrative}


def scan(path: str, attestation_path: str | None = None) -> dict:
    art = load(path)
    findings = run_all(art)
    attestation = None
    if attestation_path:
        attestation = load_attestation(attestation_path)
        findings += reconcile(attestation, findings)
    findings, cfg = enrich(findings)

    return {
        "tool": "VSAS", "tool_version": __version__,
        "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "artifact": {
            "name": os.path.basename(path), "path": path, "size": art.size,
            "fmt": art.fmt, "sha256": _sha256(path),
            "metadata": art.metadata, "hardening": art.hardening,
        },
        "attestation": attestation,
        "findings": [f.to_dict() for f in findings],
        "summary": _summarize(findings),
        "frameworks": cfg.get("frameworks", {}),
        "_findings_obj": findings,   # kept for self-test; not serialized by json_out directly
    }


def _write_reports(result: dict, out_dir: str) -> list[str]:
    os.makedirs(out_dir, exist_ok=True)
    serializable = {k: v for k, v in result.items() if not k.startswith("_")}
    paths = {
        "report.html": html.write,
        "report.json": json_out.write,
        "sbom.cdx.json": sbom.write,
        "assessment-results.oscal.json": oscal.write,
        "crosswalk.csv": crosswalk_csv.write,
    }
    written = []
    for name, writer in paths.items():
        p = os.path.join(out_dir, name)
        writer(serializable, p)
        written.append(p)
    return written


def _print_summary(result: dict) -> None:
    s = result["summary"]
    print(f"\n  Artifact : {result['artifact']['name']}  ({result['artifact']['fmt']}, "
          f"{result['artifact']['size']} bytes)")
    print(f"  SHA-256  : {result['artifact']['sha256']}")
    print(f"  Verdict  : {s['recommendation']}   (highest open risk: {s['max_risk']})")
    print(f"  Results  : {s['counts']['FAIL']} FAIL · {s['counts']['MANUAL']} MANUAL · "
          f"{s['counts']['PASS']} PASS\n")
    print(f"  {'CONTROL TEST':<26}{'RESULT':<9}{'RISK':<11}SEVERITY")
    print("  " + "-" * 60)
    for f in result["_findings_obj"]:
        print(f"  {f.type:<26}{f.result:<9}{(f.risk or ''):<11}{f.severity}")
    print()


def _self_test(result: dict, answer_key_path: str) -> int:
    import yaml
    with open(answer_key_path, "r", encoding="utf-8") as fh:
        key = yaml.safe_load(fh)
    expected = key.get("expected", {})
    by_type: dict[str, set] = {}
    for f in result["_findings_obj"]:
        by_type.setdefault(f.type, set()).add(f.result)
    mismatches = []
    for ftype, want in expected.items():
        got = by_type.get(ftype, set())
        if want not in got:
            mismatches.append(f"{ftype}: expected {want}, got {sorted(got) or 'nothing'}")
    if mismatches:
        print("SELF-TEST: FAIL")
        for m in mismatches:
            print("  - " + m)
        return 1
    print(f"SELF-TEST: PASS ({len(expected)} expectations met)")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="vsas",
        description="Vendor Software Assurance Scanner — static, read-only compliance "
                    "testing of third-party software against NIST, GDPR, HIPAA, SOC 2, "
                    "CCPA/CPRA, PCI DSS, FedRAMP, CMMC, DORA and ISO 27001.")
    ap.add_argument("artifact", help="path to the binary/package to assess")
    ap.add_argument("-a", "--attestation", help="vendor attestation YAML to reconcile")
    ap.add_argument("-o", "--out", default="vsas-report", help="output directory")
    ap.add_argument("--answer-key", help="run as a self-test against this expected-results YAML")
    ap.add_argument("--version", action="version", version=f"VSAS {__version__}")
    args = ap.parse_args(argv)

    if not os.path.isfile(args.artifact):
        ap.error(f"artifact not found: {args.artifact}")

    result = scan(args.artifact, args.attestation)

    if args.answer_key:
        _print_summary(result)
        return _self_test(result, args.answer_key)

    written = _write_reports(result, args.out)
    _print_summary(result)
    print("  Reports written:")
    for p in written:
        print("   -", p)
    print()
    return 0
