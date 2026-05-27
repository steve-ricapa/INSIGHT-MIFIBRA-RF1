from __future__ import annotations

from insightvm_pull.backend_client import BackendAlarmClient
from insightvm_pull.config import Settings


def _settings(url: str, payload_level: str = "level1") -> Settings:
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
        backend_payload_level=payload_level,
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


def test_backend_payload_level_basic(backend_alarm_test_server):
    client = BackendAlarmClient(_settings(backend_alarm_test_server["url"], payload_level="basic"))
    finding = {
        "asset_id": "12345",
        "asset_hostname": "OLT-1",
        "asset_ip": "192.168.1.100",
        "vulnerability_id": "ssh-vuln",
        "vulnerability_title": "Test vuln",
        "title": "Test vuln",
        "severity": "critical",
        "cvss_score": 9.8,
        "cvss": 9.8,
        "source": "InsightVM",
        "solution": "Apply patch"
    }
    payload = {"findings": [finding]}
    result = client.send_filtered_findings(payload)
    
    assert result["sent_ok"] == 1
    sent_request = backend_alarm_test_server["state"].requests[-1]
    
    # Debe contener solo los 5 campos básicos
    expected_keys = {"servidor", "ip", "TipoAlarma", "Local", "fechaalarma"}
    assert set(sent_request.keys()) == expected_keys


def test_backend_payload_level_level1(backend_alarm_test_server):
    client = BackendAlarmClient(_settings(backend_alarm_test_server["url"], payload_level="level1"))
    finding = {
        "asset_id": "12345",
        "asset_hostname": "OLT-1",
        "asset_ip": "192.168.1.100",
        "vulnerability_id": "ssh-vuln",
        "vulnerability_title": "Test vuln",
        "title": "Test vuln",
        "severity": "critical",
        "cvss_score": 9.8,
        "cvss": 9.8,
        "source": "InsightVM"
    }
    payload = {"findings": [finding]}
    result = client.send_filtered_findings(payload)
    
    assert result["sent_ok"] == 1
    sent_request = backend_alarm_test_server["state"].requests[-1]
    
    # Debe contener todos los campos de Nivel 1
    assert sent_request["servidor"] == "OLT-1"
    assert sent_request["ip"] == "192.168.1.100"
    assert sent_request["estado"] == 0
    assert sent_request["asset_id"] == "12345"
    assert sent_request["vulnerability_id"] == "ssh-vuln"
    assert sent_request["vulnerability_title"] == "Test vuln"
    assert sent_request["severity"] == "critical"
    assert sent_request["cvss_score"] == 9.8
    assert sent_request["source"] == "InsightVM"


def test_backend_payload_level_level1_no_solution(backend_alarm_test_server):
    client = BackendAlarmClient(_settings(backend_alarm_test_server["url"], payload_level="level1"))
    finding = {
        "asset_id": "12345",
        "asset_hostname": "OLT-1",
        "asset_ip": "192.168.1.100",
        "vulnerability_id": "ssh-vuln",
        "vulnerability_title": "Test vuln",
        "title": "Test vuln",
        "severity": "critical",
        "cvss_score": 9.8,
        "cvss": 9.8,
        "source": "InsightVM",
        "solution": "Apply patch"  # pasamos solución explícitamente
    }
    payload = {"findings": [finding]}
    result = client.send_filtered_findings(payload)
    
    assert result["sent_ok"] == 1
    sent_request = backend_alarm_test_server["state"].requests[-1]
    
    # Confirmar que 'solution' NO existe en el payload enviado al backend
    assert "solution" not in sent_request

