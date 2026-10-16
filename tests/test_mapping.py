"""Crosswalk integrity tests."""
from vsas.frameworks.mapping import load_config
from vsas.risk import overall

# Frameworks that every control test must map to (core set).
_REQUIRED = {"nist_csf", "nist_80053", "gdpr", "hipaa", "soc2", "pci_dss", "iso_27001"}


def test_every_finding_covers_required_frameworks():
    cfg = load_config()
    for name, d in cfg["findings"].items():
        controls = set(d.get("controls", {}))
        missing = _REQUIRED - controls
        assert not missing, f"{name} is missing frameworks: {sorted(missing)}"


def test_every_finding_maps_to_at_least_eleven_frameworks():
    cfg = load_config()
    for name, d in cfg["findings"].items():
        assert len(d.get("controls", {})) >= 11, f"{name} maps to too few frameworks"


def test_risk_matrix_is_well_formed():
    cfg = load_config()
    scales = cfg["risk_scales"]
    levels, matrix = scales["levels"], scales["matrix"]
    for lk in levels:
        for im in levels:
            assert overall(lk, im, matrix, levels) in levels


def test_frameworks_have_sources():
    cfg = load_config()
    for key, meta in cfg["frameworks"].items():
        assert meta.get("source", "").startswith("http"), f"{key} has no source URL"
