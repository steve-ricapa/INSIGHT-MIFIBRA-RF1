from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def persist_cycle_payloads(payload_dir: str, raw_payload: dict[str, Any], filtered_payload: dict[str, Any], run_meta: dict[str, Any]) -> dict[str, str]:
    base = Path(payload_dir)
    stamp = utc_stamp()
    raw_path = base / f"raw_{stamp}.json"
    filtered_path = base / f"filtered_{stamp}.json"
    meta_path = base / f"run_{stamp}.meta.json"
    write_json(raw_path, raw_payload)
    write_json(filtered_path, filtered_payload)
    write_json(meta_path, run_meta)
    return {
        "raw": str(raw_path),
        "filtered": str(filtered_path),
        "meta": str(meta_path),
    }

