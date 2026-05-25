from __future__ import annotations

import json
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


@pytest.fixture
def insightvm_test_server():
    class State:
        assets_calls = 0
        fail_assets_times = 0
        assets_pages = {}
        asset_vulns = {}
        vuln_defs = {}

    state = State()
    state.assets_pages = {
        0: [{"id": "a1", "hostName": "srv-1", "addresses": [{"ip": "10.0.0.1"}]}],
        1: [],
    }
    state.asset_vulns = {"a1": [{"id": "v1"}, {"id": "v2"}]}
    state.vuln_defs = {
        "v1": {"id": "v1", "title": "Critical vuln", "severity": "critical", "riskScore": 900},
        "v2": {"id": "v2", "title": "Medium vuln", "severity": "medium", "riskScore": 300},
    }

    class Handler(BaseHTTPRequestHandler):
        def _json(self, payload: dict, status: int = 200) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            query = urllib.parse.parse_qs(parsed.query)

            if path == "/api/3/assets":
                state.assets_calls += 1
                if state.assets_calls <= state.fail_assets_times:
                    self._json({"error": "temporary"}, status=500)
                    return
                page = int(query.get("page", ["0"])[0])
                resources = state.assets_pages.get(page, [])
                self._json({"resources": resources})
                return

            if path.startswith("/api/3/assets/") and path.endswith("/vulnerabilities"):
                parts = path.split("/")
                asset_id = parts[-2]
                self._json({"resources": state.asset_vulns.get(asset_id, [])})
                return

            if path.startswith("/api/3/vulnerabilities/"):
                vuln_id = path.split("/")[-1]
                payload = state.vuln_defs.get(vuln_id)
                if payload is None:
                    self._json({"error": "not found"}, status=404)
                else:
                    self._json(payload)
                return

            self._json({"error": "not found"}, status=404)

        def log_message(self, *_args, **_kwargs) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {"base_url": f"http://127.0.0.1:{server.server_port}/api/3", "state": state}
    finally:
        server.shutdown()
        thread.join(timeout=1)
