from __future__ import annotations

import logging
from typing import Any, Iterator

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from insightvm_pull.config import Settings

log = logging.getLogger("insightvm_pull.client")


class InsightVMError(Exception):
    """Clase base para errores de la API de InsightVM."""
    pass


class InsightVMAuthError(InsightVMError):
    """Excepción para errores de autenticación o autorización (401, 403)."""
    pass


class InsightVMClient:
    def __init__(self, settings: Settings, session: requests.Session | None = None) -> None:
        self.settings = settings
        self.session = session or requests.Session()
        retry = Retry(
            total=3,
            connect=3,
            read=3,
            backoff_factor=0.5,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(["GET"]),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def get(self, endpoint: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        url = self.settings.insightvm_base_url.rstrip("/") + "/" + endpoint.lstrip("/")
        log.debug("GET %s params=%s", endpoint, params)
        response = self.session.get(
            url,
            auth=(self.settings.insightvm_user, self.settings.insightvm_password),
            params=params,
            timeout=self.settings.insightvm_timeout,
            verify=self.settings.insightvm_verify_ssl,
        )
        if response.status_code >= 400:
            if response.status_code in (401, 403):
                raise InsightVMAuthError(f"InsightVM HTTP {response.status_code} on {endpoint}: {response.text[:300]}")
            raise RuntimeError(f"InsightVM HTTP {response.status_code} on {endpoint}: {response.text[:300]}")
        try:
            data = response.json()
        except ValueError as exc:
            raise RuntimeError(f"Non-JSON response from {endpoint}") from exc
        if not isinstance(data, dict):
            raise RuntimeError(f"Unexpected response type from {endpoint}: {type(data)!r}")
        return data

    def get_paged(
        self,
        endpoint: str,
        size: int,
        params: dict[str, Any] | None = None,
        items_key: str = "resources",
    ) -> Iterator[dict[str, Any]]:
        page = 0
        while True:
            query = dict(params or {})
            query.update({"page": page, "size": size})
            data = self.get(endpoint, params=query)
            items = data.get(items_key)
            if not isinstance(items, list):
                raise RuntimeError(f"Missing list key '{items_key}' in paged response for {endpoint}.")

            log.info("endpoint=%s page=%s items=%s", endpoint, page, len(items))
            for item in items:
                if isinstance(item, dict):
                    yield item

            if len(items) < size:
                break
            page += 1

