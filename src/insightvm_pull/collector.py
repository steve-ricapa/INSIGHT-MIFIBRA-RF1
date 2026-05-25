from __future__ import annotations

import logging
from typing import Any

from insightvm_pull.client import InsightVMClient
from insightvm_pull.models import normalize_severity

log = logging.getLogger("insightvm_pull.collector")


class InsightVMCollector:
    def __init__(self, client: InsightVMClient) -> None:
        self.client = client

    def collect(self, page_size: int) -> dict[str, Any]:
        assets: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        vuln_cache: dict[str, dict[str, Any]] = {}

        for asset in self.client.get_paged("/assets", size=page_size):
            assets.append(asset)

        for asset in assets:
            asset_id = asset.get("id")
            if not asset_id:
                continue
            try:
                vuln_refs = self.client.get(f"/assets/{asset_id}/vulnerabilities").get("resources", [])
            except Exception as exc:
                log.warning("asset_id=%s vulnerabilities fetch failed: %s", asset_id, exc)
                continue

            if not isinstance(vuln_refs, list):
                continue

            for ref in vuln_refs:
                if not isinstance(ref, dict):
                    continue
                vuln_id = ref.get("id")
                if not vuln_id:
                    continue
                if vuln_id not in vuln_cache:
                    vuln_cache[vuln_id] = self.client.get(f"/vulnerabilities/{vuln_id}")

                vdef = vuln_cache[vuln_id]
                sev = normalize_severity(vdef.get("severity") or vdef.get("severityScore") or vdef.get("cvss_score"))
                findings.append(
                    {
                        "asset_id": asset_id,
                        "asset_ip": _extract_asset_ip(asset),
                        "asset_hostname": asset.get("hostName") or asset.get("hostname") or asset.get("name"),
                        "vulnerability_id": vuln_id,
                        "title": vdef.get("title") or vdef.get("name") or "Vulnerability",
                        "severity": sev,
                        "cvss": _extract_cvss(vdef),
                        "risk_score": vdef.get("riskScore"),
                        "cves": vdef.get("cves") or [],
                        "raw": vdef,
                    }
                )

        return {
            "assets": assets,
            "findings": findings,
            "meta": {
                "assets_count": len(assets),
                "findings_count": len(findings),
            },
        }


def filter_payload_by_severity(payload: dict[str, Any], allowed_severities: tuple[str, ...]) -> dict[str, Any]:
    findings = payload.get("findings", [])
    if not isinstance(findings, list):
        findings = []
    filtered_findings = [f for f in findings if isinstance(f, dict) and f.get("severity") in allowed_severities]
    return {
        "assets": payload.get("assets", []),
        "findings": filtered_findings,
        "meta": {
            "assets_count": payload.get("meta", {}).get("assets_count", 0),
            "findings_count": len(filtered_findings),
            "allowed_severities": list(allowed_severities),
        },
    }


def _extract_asset_ip(asset: dict[str, Any]) -> str | None:
    if isinstance(asset.get("ip"), str):
        return asset["ip"]
    addresses = asset.get("addresses")
    if isinstance(addresses, list):
        for item in addresses:
            if isinstance(item, str):
                return item
            if isinstance(item, dict):
                candidate = item.get("ip") or item.get("address")
                if isinstance(candidate, str):
                    return candidate
    return None


def _extract_cvss(vdef: dict[str, Any]) -> float | None:
    value = vdef.get("cvss_score")
    if isinstance(value, (int, float)):
        return float(value)
    cvss = vdef.get("cvss")
    if isinstance(cvss, dict):
        for version in ("v3", "v2"):
            sub = cvss.get(version)
            if isinstance(sub, dict) and isinstance(sub.get("score"), (int, float)):
                return float(sub["score"])
    if isinstance(vdef.get("severityScore"), (int, float)):
        return float(vdef["severityScore"])
    return None
