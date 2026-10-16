"""Full machine-readable result as JSON."""
from __future__ import annotations

import json


def write(result: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, ensure_ascii=False)
