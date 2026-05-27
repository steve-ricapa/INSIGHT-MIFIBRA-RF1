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
        backend_enabled=False,
        backend_url="http://127.0.0.1:9999/txdxsecure/guarda_alarma.php",
        backend_local="Txdxsecure",
        backend_alarm_type="1 - Alarma de seguridad",
        backend_timeout=5,
        backend_verify_ssl=False,
        backend_payload_level="level1",
    )
    collector = InsightVMCollector(client=InsightVMClient(settings=settings))
    run_service(settings=settings, collector=collector, once=True)

    payload_files = sorted((tmp_path / "payloads").glob("*.json"))
    assert len(payload_files) == 3
    raw_api_file = [p for p in payload_files if p.name.startswith("raw_api_")][0]
    filtered_file = [p for p in payload_files if p.name.startswith("filtered_")][0]
    meta_file = [p for p in payload_files if p.name.startswith("run_")][0]

    raw_api_data = json.loads(raw_api_file.read_text(encoding="utf-8"))
    filtered_data = json.loads(filtered_file.read_text(encoding="utf-8"))
    meta_data = json.loads(meta_file.read_text(encoding="utf-8"))

    assert "assets_pages" in raw_api_data
    assert "asset_vulnerabilities" in raw_api_data
    assert "vulnerability_definitions" in raw_api_data
    assert filtered_data["meta"]["findings_count"] == 1
    assert meta_data["success"] is True
    assert server["state"].assets_calls >= 2


def test_run_service_aborts_on_auth_error(tmp_path: Path, insightvm_test_server):
    server = insightvm_test_server
    server["state"].fail_auth = True
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
        backend_enabled=False,
        backend_url="http://127.0.0.1:9999/txdxsecure/guarda_alarma.php",
        backend_local="Txdxsecure",
        backend_alarm_type="1 - Alarma de seguridad",
        backend_timeout=5,
        backend_verify_ssl=False,
        backend_payload_level="level1",
    )
    collector = InsightVMCollector(client=InsightVMClient(settings=settings))
    run_service(settings=settings, collector=collector, once=True)

    # Debe haber abortado en la primera llamada y no haber reintentado (llamadas == 1)
    assert server["state"].assets_calls == 1

    payload_files = sorted((tmp_path / "payloads").glob("*.json"))
    meta_file = [p for p in payload_files if p.name.startswith("run_")][0]
    meta_data = json.loads(meta_file.read_text(encoding="utf-8"))

    assert meta_data["success"] is False
    assert "InsightVM HTTP 401" in meta_data["error"]


def test_run_service_does_not_lose_vulnerabilities_if_paginated(tmp_path: Path, insightvm_test_server):
    server = insightvm_test_server
    # Forzar 2 vulnerabilidades en el active asset "a1"
    server["state"].asset_vulns = {"a1": [{"id": "v1"}, {"id": "v2"}]}
    server["state"].vuln_defs = {
        "v1": {"id": "v1", "title": "Critical vuln", "severity": "critical", "riskScore": 900},
        "v2": {"id": "v2", "title": "High vuln", "severity": "high", "riskScore": 800},
    }
    
    # Configuramos el page_size = 1 para que divida la consulta en varias páginas
    settings = Settings(
        insightvm_base_url=server["base_url"],
        insightvm_user="u",
        insightvm_password="p",
        insightvm_timeout=5,
        insightvm_verify_ssl=False,
        page_size=1,  # Tamaño de página = 1
        interval_seconds=3600,
        max_retries=1,
        retry_backoff_seconds=0.0,
        severities=("critical", "high"),
        log_level="INFO",
        log_file=str(tmp_path / "logs" / "integration.log"),
        payload_dir=str(tmp_path / "payloads"),
        backend_enabled=False,
        backend_url="http://127.0.0.1:9999/txdxsecure/guarda_alarma.php",
        backend_local="Txdxsecure",
        backend_alarm_type="1 - Alarma de seguridad",
        backend_timeout=5,
        backend_verify_ssl=False,
        backend_payload_level="level1",
    )
    collector = InsightVMCollector(client=InsightVMClient(settings=settings))
    run_service(settings=settings, collector=collector, once=True)

    payload_files = sorted((tmp_path / "payloads").glob("*.json"))
    filtered_file = [p for p in payload_files if p.name.startswith("filtered_")][0]
    filtered_data = json.loads(filtered_file.read_text(encoding="utf-8"))

    # Deben haberse descargado ambas vulnerabilidades (sin perder ninguna a pesar de la paginación)
    assert filtered_data["meta"]["findings_count"] == 2
    findings_ids = [f["vulnerability_id"] for f in filtered_data["findings"]]
    assert "v1" in findings_ids
    assert "v2" in findings_ids

    meta_file = [p for p in payload_files if p.name.startswith("run_")][0]
    meta_data = json.loads(meta_file.read_text(encoding="utf-8"))
    assert meta_data["success"] is True
