from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

import requests

from insightvm_pull.config import Settings

log = logging.getLogger("insightvm_pull.backend")


class BackendAlarmClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.session = requests.Session()

    def send_filtered_findings(self, filtered_payload: dict[str, Any]) -> dict[str, Any]:
        findings = filtered_payload.get("findings", [])
        if not isinstance(findings, list):
            findings = []

        sent_ok = 0
        conflicts = 0
        validation_errors = 0
        backend_errors = 0
        details: list[dict[str, Any]] = []

        for finding in findings:
            if not isinstance(finding, dict):
                continue
            alarm = self._build_alarm_payload(finding)
            if alarm is None:
                validation_errors += 1
                details.append({"success": False, "message": "Missing required fields: servidor/ip", "finding": finding})
                continue

            result = self._post_alarm(alarm)
            details.append(result)
            if result.get("success") is True:
                sent_ok += 1
            elif "Ya existe un registro activo" in str(result.get("message", "")):
                conflicts += 1
            else:
                backend_errors += 1

        return {
            "enabled": True,
            "total_filtered_findings": len(findings),
            "sent_ok": sent_ok,
            "conflicts": conflicts,
            "validation_errors": validation_errors,
            "backend_errors": backend_errors,
            "details": details,
        }

    def _build_alarm_payload(self, finding: dict[str, Any]) -> dict[str, Any] | None:
        servidor = str(finding.get("asset_hostname") or "").strip()
        ip = str(finding.get("asset_ip") or "").strip()
        if not servidor:
            servidor = ip
        if not servidor or not ip:
            return None

        sev = str(finding.get("severity") or "").lower()
        title = str(finding.get("title") or "Alarma de seguridad")
        tipo = f"{self.settings.backend_alarm_type} [{sev}] - {title}"
        fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return {
            "servidor": servidor,
            "ip": ip,
            "TipoAlarma": tipo,
            "Local": self.settings.backend_local,
            "fechaalarma": fecha,
        }

    def _post_alarm(self, alarm_payload: dict[str, Any]) -> dict[str, Any]:
        try:
            response = self.session.post(
                self.settings.backend_url,
                json=alarm_payload,
                timeout=self.settings.backend_timeout,
                verify=self.settings.backend_verify_ssl,
                headers={"Content-Type": "application/json"},
            )
        except Exception as exc:
            log.error("Backend connection error: %s", exc)
            return {"success": False, "message": f"Connection error: {exc}", "alarm_payload": alarm_payload}

        try:
            data = response.json()
        except Exception:
            data = {"success": False, "message": f"Non-JSON backend response HTTP {response.status_code}"}

        if not isinstance(data, dict):
            data = {"success": False, "message": "Invalid backend response format"}

        data["http_status"] = response.status_code
        data["alarm_payload"] = alarm_payload
        return data

