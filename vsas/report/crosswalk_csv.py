"""Flat CSV crosswalk: one row per (finding, framework) with the control IDs."""
from __future__ import annotations

import csv


def write(result: dict, path: str) -> None:
    frameworks = result.get("frameworks", {})
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["finding_type", "result", "risk", "severity",
                    "framework", "framework_version", "control_ids", "detail"])
        for f in result["findings"]:
            controls = f.get("controls", {})
            if not controls:
                w.writerow([f["type"], f["result"], f.get("risk", ""), f.get("severity", ""),
                            "", "", "", f.get("detail", "")])
                continue
            for fw_key, ids in controls.items():
                meta = frameworks.get(fw_key, {})
                w.writerow([
                    f["type"], f["result"], f.get("risk", ""), f.get("severity", ""),
                    meta.get("name", fw_key), meta.get("version", ""),
                    "; ".join(ids) if isinstance(ids, list) else str(ids),
                    f.get("detail", ""),
                ])
