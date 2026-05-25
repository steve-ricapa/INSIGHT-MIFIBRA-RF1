from __future__ import annotations

from insightvm_pull.backend_client import BackendAlarmClient
from insightvm_pull.config import Settings


def _settings(url: str) -> Settings:
    return Settings(
        insightvm_base_url="https://example/api/3",
        insightvm_user="u",
        insightvm_password="p",
        insightvm_timeout=5,
        insightvm_verify_ssl=False,
        page_size=200,
        interval_seconds=3600,
        max_retries=1,
        retry_backoff_seconds=0.0,
        severities=("critical", "high"),
        log_level="INFO",
        log_file="logs/integration.log",
        payload_dir="payloads",
        backend_enabled=True,
        backend_url=url,
        backend_local="Txdxsecure",
        backend_alarm_type="1 - Alarma de seguridad",
        backend_timeout=5,
        backend_verify_ssl=False,
    )


def test_backend_send_success(backend_alarm_test_server):
    client = BackendAlarmClient(_settings(backend_alarm_test_server["url"]))
    payload = {
        "findings": [
            {"asset_hostname": "OLT-1", "asset_ip": "192.168.1.100", "severity": "critical", "title": "Test vuln"}
        ]
    }
    result = client.send_filtered_findings(payload)
    assert result["sent_ok"] == 1
    assert result["backend_errors"] == 0


def test_backend_send_conflict(backend_alarm_test_server):
    backend_alarm_test_server["state"].mode = "conflict"
    client = BackendAlarmClient(_settings(backend_alarm_test_server["url"]))
    payload = {
        "findings": [
            {"asset_hostname": "OLT-CENTRAL-01", "asset_ip": "192.168.1.100", "severity": "high", "title": "Conflict vuln"}
        ]
    }
    result = client.send_filtered_findings(payload)
    assert result["sent_ok"] == 0
    assert result["conflicts"] == 1


def test_backend_missing_required_fields(backend_alarm_test_server):
    client = BackendAlarmClient(_settings(backend_alarm_test_server["url"]))
    payload = {"findings": [{"severity": "critical", "title": "Missing host/ip"}]}
    result = client.send_filtered_findings(payload)
    assert result["validation_errors"] == 1
    assert result["sent_ok"] == 0

