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
        assets_pages: list[dict[str, Any]] = []
        asset_vulns_raw: dict[str, dict[str, Any]] = {}
        vuln_defs_raw: dict[str, dict[str, Any]] = {}

        assets, assets_pages = self._fetch_assets_with_raw_pages(page_size=page_size)

        for asset in assets:
            asset_id = asset.get("id")
            if not asset_id:
                continue
            try:
                asset_vuln_resp = self.client.get(f"/assets/{asset_id}/vulnerabilities")
                asset_vulns_raw[str(asset_id)] = asset_vuln_resp
                vuln_refs = asset_vuln_resp.get("resources", [])
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
                    vuln_resp = self.client.get(f"/vulnerabilities/{vuln_id}")
                    vuln_cache[vuln_id] = vuln_resp
                    vuln_defs_raw[str(vuln_id)] = vuln_resp

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
            "raw_api": {
                "assets_pages": assets_pages,
                "asset_vulnerabilities": asset_vulns_raw,
                "vulnerability_definitions": vuln_defs_raw,
            },
        }

    def _fetch_assets_with_raw_pages(self, page_size: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        assets: list[dict[str, Any]] = []
        pages: list[dict[str, Any]] = []
        page = 0
        while True:
            response = self.client.get("/assets", params={"page": page, "size": page_size})
            if not isinstance(response, dict):
                raise RuntimeError("Unexpected non-dict response for /assets")
            pages.append(response)
            resources = response.get("resources")
            if not isinstance(resources, list):
                raise RuntimeError("Missing 'resources' list in /assets response")
            for item in resources:
                if isinstance(item, dict):
                    assets.append(item)
            if len(resources) < page_size:
                break
            page += 1
        return assets, pages


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
