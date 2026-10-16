"""OSCAL-style assessment-results (NIST OSCAL 1.1.2).

A compact, well-formed assessment-results document: each non-PASS finding becomes
an OSCAL finding with a linked observation. Good enough to import into OSCAL
tooling for demonstration; not a full SAR.
"""
from __future__ import annotations

import json
import uuid


def build(result: dict) -> dict:
    now = result.get("generated")
    observations = []
    findings_out = []
    for f in result["findings"]:
        if f["result"] == "PASS":
            continue
        obs_uuid = str(uuid.uuid4())
        observations.append({
            "uuid": obs_uuid,
            "description": f"{f['title']} - {f['detail']}",
            "methods": ["EXAMINE"],
            "collected": now,
            "relevant-evidence": [
                {"description": f"{e.get('kind')}: {e.get('excerpt')}"
                                + (f" (offset {e['offset']})" if e.get("offset", -1) >= 0 else "")}
                for e in f.get("evidence", [])[:10]
            ],
        })
        findings_out.append({
            "uuid": str(uuid.uuid4()),
            "title": f["title"],
            "description": f["detail"],
            "props": [
                {"name": "finding-type", "value": f["type"]},
                {"name": "result", "value": f["result"]},
                {"name": "risk", "value": f.get("risk", "")},
                {"name": "severity", "value": f.get("severity", "")},
            ],
            "related-observations": [{"observation-uuid": obs_uuid}],
        })

    return {
        "assessment-results": {
            "uuid": str(uuid.uuid4()),
            "metadata": {
                "title": f"VSAS assessment of {result['artifact'].get('name', 'artifact')}",
                "last-modified": now,
                "version": result.get("tool_version", "0.1.0"),
                "oscal-version": "1.1.2",
            },
            "import-ap": {"href": "#vsas-automated-assessment-plan"},
            "results": [{
                "uuid": str(uuid.uuid4()),
                "title": "VSAS automated static assessment",
                "description": "Automated, read-only static assurance testing of a vendor binary.",
                "start": now,
                "observations": observations,
                "findings": findings_out,
            }],
        }
    }


def write(result: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(build(result), fh, indent=2, ensure_ascii=False)
