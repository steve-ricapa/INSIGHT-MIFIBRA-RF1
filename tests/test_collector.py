from __future__ import annotations

from insightvm_pull.collector import filter_payload_by_severity


def test_filter_payload_by_severity():
    payload = {
        "assets": [{"id": 1}],
        "findings": [
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "medium"},
        ],
        "meta": {"assets_count": 1, "findings_count": 3},
    }
    out = filter_payload_by_severity(payload, ("critical", "high"))
    assert out["meta"]["findings_count"] == 2
    assert [f["severity"] for f in out["findings"]] == ["critical", "high"]

