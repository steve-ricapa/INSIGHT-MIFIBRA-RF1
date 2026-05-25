from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any

from insightvm_pull.collector import InsightVMCollector, filter_payload_by_severity
from insightvm_pull.config import Settings
from insightvm_pull.storage import persist_cycle_payloads

log = logging.getLogger("insightvm_pull.scheduler")


def run_service(settings: Settings, collector: InsightVMCollector, once: bool = False) -> None:
    cycle = 0
    while True:
        cycle += 1
        started = time.monotonic()
        cycle_time = datetime.now(timezone.utc).isoformat()
        log.info("cycle=%s started_at=%s", cycle, cycle_time)

        success = False
        last_error: str | None = None
        raw_payload: dict[str, Any] = {}
        filtered_payload: dict[str, Any] = {}

        for attempt in range(1, settings.max_retries + 1):
            try:
                raw_payload = collector.collect(page_size=settings.page_size)
                filtered_payload = filter_payload_by_severity(raw_payload, settings.severities)
                success = True
                log.info("cycle=%s attempt=%s status=success", cycle, attempt)
                break
            except Exception as exc:
                last_error = str(exc)
                log.exception("cycle=%s attempt=%s status=error error=%s", cycle, attempt, exc)
                if attempt < settings.max_retries:
                    sleep_seconds = settings.retry_backoff_seconds * (2 ** (attempt - 1))
                    log.warning("cycle=%s retrying_in=%.2fs", cycle, sleep_seconds)
                    time.sleep(sleep_seconds)

        elapsed = round(time.monotonic() - started, 3)
        run_meta = {
            "cycle": cycle,
            "started_at": cycle_time,
            "success": success,
            "error": last_error,
            "total_assets": raw_payload.get("meta", {}).get("assets_count", 0),
            "total_findings": raw_payload.get("meta", {}).get("findings_count", 0),
            "filtered_findings": filtered_payload.get("meta", {}).get("findings_count", 0),
            "allowed_severities": list(settings.severities),
            "duration_seconds": elapsed,
            "max_retries": settings.max_retries,
        }
        paths = persist_cycle_payloads(settings.payload_dir, raw_payload, filtered_payload, run_meta)
        log.info("cycle=%s persisted raw=%s filtered=%s meta=%s", cycle, paths["raw"], paths["filtered"], paths["meta"])

        if once:
            return

        log.info("cycle=%s sleeping interval_seconds=%s", cycle, settings.interval_seconds)
        time.sleep(settings.interval_seconds)
