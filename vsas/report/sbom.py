"""CycloneDX 1.5 Software Bill of Materials from the identified components."""
from __future__ import annotations

import json
import uuid


def build(result: dict) -> dict:
    art = result["artifact"]
    components = art.get("metadata", {}).get("sbom_components", []) or []
    cdx = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": result.get("generated"),
            "tools": [{"vendor": "VSAS", "name": "vendor-software-assurance-scanner",
                       "version": result.get("tool_version", "0.1.0")}],
            "component": {
                "type": "application",
                "name": art.get("name", "artifact"),
                "hashes": [{"alg": "SHA-256", "content": art.get("sha256", "")}],
            },
        },
        "components": [
            {
                "type": "library",
                "name": c["name"],
                "version": c["version"],
                "description": ("END-OF-LIFE / outdated: " + c["reason"]) if c.get("eol") else "",
            }
            for c in components
        ],
    }
    return cdx


def write(result: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(build(result), fh, indent=2, ensure_ascii=False)
