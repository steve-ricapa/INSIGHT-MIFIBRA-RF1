from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

from insightvm_pull.models import VALID_SEVERITIES


def _truthy(v: str | None, default: bool) -> bool:
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "t", "yes", "y", "on"}


def _parse_severities(raw: str | None) -> tuple[str, ...]:
    if not raw:
        return ("critical", "high")
    parts = [p.strip().lower() for p in raw.split(",") if p.strip()]
    invalid = [p for p in parts if p not in VALID_SEVERITIES]
    if invalid:
        raise ValueError(f"Invalid severities: {', '.join(invalid)}")
    if not parts:
        raise ValueError("At least one severity must be configured.")
    return tuple(parts)


@dataclass(frozen=True)
class Settings:
    insightvm_base_url: str
    insightvm_user: str
    insightvm_password: str
    insightvm_timeout: int
    insightvm_verify_ssl: bool
    page_size: int
    interval_seconds: int
    max_retries: int
    retry_backoff_seconds: float
    severities: tuple[str, ...]
    log_level: str
    log_file: str
    payload_dir: str


def load_settings(env_file: str = ".env", overrides: dict | None = None) -> Settings:
    load_dotenv(dotenv_path=Path(env_file), override=True)
    ov = overrides or {}

    base_url = (ov.get("insightvm_base_url") or os.getenv("INSIGHTVM_BASE_URL") or "").strip()
    user = (ov.get("insightvm_user") or os.getenv("INSIGHTVM_USER") or "").strip()
    password = (ov.get("insightvm_password") or os.getenv("INSIGHTVM_PASSWORD") or "").strip()
    timeout = int(ov.get("insightvm_timeout") or os.getenv("INSIGHTVM_TIMEOUT", "30"))
    verify_ssl = _truthy(str(ov.get("insightvm_verify_ssl")) if ov.get("insightvm_verify_ssl") is not None else os.getenv("INSIGHTVM_VERIFY_SSL"), True)
    page_size = int(ov.get("page_size") or os.getenv("PAGE_SIZE", "200"))
    interval = int(ov.get("interval_seconds") or os.getenv("PULL_INTERVAL_SECONDS", "3600"))
    max_retries = int(ov.get("max_retries") or os.getenv("MAX_RETRIES", "3"))
    backoff = float(ov.get("retry_backoff_seconds") or os.getenv("RETRY_BACKOFF_SECONDS", "1.0"))
    severities = _parse_severities(ov.get("severities") or os.getenv("ALERT_SEVERITIES", "critical,high"))
    log_level = str(ov.get("log_level") or os.getenv("LOG_LEVEL", "INFO")).upper()
    log_file = str(ov.get("log_file") or os.getenv("LOG_FILE", "logs/integration.log"))
    payload_dir = str(ov.get("payload_dir") or os.getenv("PAYLOAD_DIR", "payloads"))

    if not base_url:
        raise ValueError("INSIGHTVM_BASE_URL is required.")
    if not user or not password:
        raise ValueError("INSIGHTVM_USER and INSIGHTVM_PASSWORD are required.")
    if interval <= 0:
        raise ValueError("PULL_INTERVAL_SECONDS must be > 0.")
    if max_retries < 1:
        raise ValueError("MAX_RETRIES must be >= 1.")
    if page_size < 1:
        raise ValueError("PAGE_SIZE must be >= 1.")

    return Settings(
        insightvm_base_url=base_url,
        insightvm_user=user,
        insightvm_password=password,
        insightvm_timeout=timeout,
        insightvm_verify_ssl=verify_ssl,
        page_size=page_size,
        interval_seconds=interval,
        max_retries=max_retries,
        retry_backoff_seconds=backoff,
        severities=severities,
        log_level=log_level,
        log_file=log_file,
        payload_dir=payload_dir,
    )

