from __future__ import annotations

from dataclasses import dataclass
from typing import Any

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info", "unknown"}


@dataclass(frozen=True)
class PullMetrics:
    total_assets: int
    total_findings: int
    filtered_findings: int
    cycle_seconds: float


def normalize_severity(value: Any) -> str:
    if value is None:
        return "unknown"
    if isinstance(value, str):
        v = value.strip().lower()
        mapping = {
            "informational": "info",
            "moderate": "medium",
            "severe": "high",
        }
        v = mapping.get(v, v)
        return v if v in VALID_SEVERITIES else "unknown"
    if isinstance(value, (int, float)):
        score = float(value)
        if score <= 0:
            return "info"
        if score < 4:
            return "low"
        if score < 7:
            return "medium"
        if score < 9:
            return "high"
        return "critical"
    return "unknown"

