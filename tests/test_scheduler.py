from __future__ import annotations

import json
from pathlib import Path

from insightvm_pull.client import InsightVMClient
from insightvm_pull.collector import InsightVMCollector
from insightvm_pull.config import Settings
from insightvm_pull.scheduler import run_service


def test_run_service_retries_and_persists_real_server(tmp_path: Path, insightvm_test_server):
    server = insightvm_test_server
    server["state"].fail_assets_times = 1
    settings = Settings(
        insightvm_base_url=server["base_url"],
        insightvm_user="u",
        insightvm_password="p",
        insightvm_timeout=5,
        insightvm_verify_ssl=False,
        page_size=1,
        interval_seconds=3600,
        max_retries=3,
        retry_backoff_seconds=0.0,
        severities=("critical", "high"),
        log_level="INFO",
        log_file=str(tmp_path / "logs" / "integration.log"),
        payload_dir=str(tmp_path / "payloads"),
    )
    collector = InsightVMCollector(client=InsightVMClient(settings=settings))
    run_service(settings=settings, collector=collector, once=True)

    payload_files = sorted((tmp_path / "payloads").glob("*.json"))
    assert len(payload_files) == 3
    raw_file = [p for p in payload_files if p.name.startswith("raw_")][0]
    filtered_file = [p for p in payload_files if p.name.startswith("filtered_")][0]
    meta_file = [p for p in payload_files if p.name.startswith("run_")][0]

    raw_data = json.loads(raw_file.read_text(encoding="utf-8"))
    filtered_data = json.loads(filtered_file.read_text(encoding="utf-8"))
    meta_data = json.loads(meta_file.read_text(encoding="utf-8"))

    assert raw_data["meta"]["findings_count"] == 2
    assert filtered_data["meta"]["findings_count"] == 1
    assert meta_data["success"] is True
    assert server["state"].assets_calls >= 2
