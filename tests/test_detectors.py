"""Detector tests: scan the vulnerable fixture and assert the expected results."""
import os
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(ROOT, "samples", "bin", "demo_vendor_app")
ATTEST = os.path.join(ROOT, "samples", "vendor_attestation.yaml")

from vsas.cli import scan  # noqa: E402


def _ensure_fixture():
    if not os.path.exists(FIXTURE):
        subprocess.run(["bash", os.path.join(ROOT, "samples", "build.sh")], check=True)


@pytest.fixture(scope="module")
def result():
    _ensure_fixture()
    return scan(FIXTURE, ATTEST)


def _by_type(result):
    d = {}
    for f in result["findings"]:
        d.setdefault(f["type"], set()).add(f["result"])
    return d


@pytest.mark.parametrize("ftype", [
    "hardcoded-secret", "weak-crypto", "plaintext-transport",
    "outdated-component", "missing-hardening", "unsigned-binary",
])
def test_control_fails(result, ftype):
    assert "FAIL" in _by_type(result)[ftype]


@pytest.mark.parametrize("ftype", ["data-egress-endpoint", "personal-data-marker"])
def test_control_manual(result, ftype):
    assert "MANUAL" in _by_type(result)[ftype]


def test_attestation_gaps_detected(result):
    gaps = [f for f in result["findings"]
            if f["type"] == "attestation-gap" and f["result"] == "FAIL"]
    assert len(gaps) >= 4, "expected several attestation contradictions"


def test_sbom_flags_eol_component(result):
    comps = result["artifact"]["metadata"].get("sbom_components", [])
    assert any(c.get("eol") for c in comps), "expected an EOL component (OpenSSL 1.0.1)"


def test_each_finding_has_controls_and_risk(result):
    for f in result["findings"]:
        if f["result"] == "PASS":
            continue
        assert f["controls"], f"{f['type']} has no control mapping"
        assert f["risk"] in ("Very Low", "Low", "Moderate", "High", "Very High")


def test_verdict_is_reject(result):
    assert result["summary"]["recommendation_key"] == "Reject"
