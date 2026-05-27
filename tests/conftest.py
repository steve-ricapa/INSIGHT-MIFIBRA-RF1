from __future__ import annotations

import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest


@pytest.fixture
def insightvm_test_server():
    class State:
        assets_calls = 0
        fail_assets_times = 0
        fail_auth = False
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
                if state.fail_auth:
                    self._json({"error": "unauthorized"}, status=401)
                    return
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
                resources = state.asset_vulns.get(asset_id, [])
                
                # Paginación en pruebas
                page_list = query.get("page")
                size_list = query.get("size")
                if page_list and size_list:
                    try:
                        page = int(page_list[0])
                        size = int(size_list[0])
                        start = page * size
                        end = start + size
                        resources = resources[start:end]
                    except (ValueError, IndexError):
                        pass

                self._json({"resources": resources})
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


@pytest.fixture
def backend_alarm_test_server():
    class State:
        mode = "success"  # success | conflict | missing
        requests = []

    state = State()

    class Handler(BaseHTTPRequestHandler):
        def _json(self, payload: dict, status: int = 200) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/txdxsecure/guarda_alarma.php":
                self._json({"success": False, "message": "Not found"}, status=404)
                return
            size = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(size).decode("utf-8")
            try:
                payload = json.loads(raw_body) if raw_body else {}
            except Exception:
                payload = {}
            state.requests.append(payload)

            if state.mode == "missing":
                self._json({"success": False, "message": "Campos requeridos faltantes: servidor, ip"})
                return
            if state.mode == "conflict":
                self._json(
                    {
                        "success": False,
                        "message": "Ya existe un registro activo (estado 0 o 7) para el servidor 'OLT-CENTRAL-01' e IP '192.168.1.100'",
                    }
                )
                return
            self._json({"success": True})

        def log_message(self, *_args, **_kwargs) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {"url": f"http://127.0.0.1:{server.server_port}/txdxsecure/guarda_alarma.php", "state": state}
    finally:
        server.shutdown()
        thread.join(timeout=1)
