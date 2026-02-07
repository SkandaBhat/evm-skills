from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
MANIFEST = ROOT / "references" / "method-manifest.json"


def _run_exec(request: dict, extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    cmd = [
        sys.executable,
        str(SCRIPTS / "evm_rpc.py"),
        "exec",
        "--manifest",
        str(MANIFEST),
        "--request-json",
        json.dumps(request),
    ]
    env = os.environ.copy()
    env.pop("ETH_RPC_URL", None)
    if extra_env:
        env.update(extra_env)
    return subprocess.run(cmd, capture_output=True, text=True, check=False, env=env)


class _RPCHandler(BaseHTTPRequestHandler):
    response_payload: dict = {"jsonrpc": "2.0", "id": 1, "result": "0x1"}
    status_code: int = 200
    last_request: dict | None = None

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        try:
            _RPCHandler.last_request = json.loads(body)
        except Exception:  # noqa: BLE001
            _RPCHandler.last_request = {"raw": body}
        payload = json.dumps(_RPCHandler.response_payload).encode("utf-8")
        self.send_response(_RPCHandler.status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


def _serve_once(payload: dict, status: int = 200) -> tuple[HTTPServer, str]:
    _RPCHandler.response_payload = payload
    _RPCHandler.status_code = status
    _RPCHandler.last_request = None
    server = HTTPServer(("127.0.0.1", 0), _RPCHandler)
    url = f"http://127.0.0.1:{server.server_address[1]}"
    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()
    return server, url


def test_requires_rpc_url():
    req = {"method": "eth_blockNumber", "params": [], "context": {}, "timeout_seconds": 2}
    proc = _run_exec(req)
    assert proc.returncode == 4
    payload = json.loads(proc.stdout)
    assert payload["error_code"] == "RPC_URL_REQUIRED"


def test_local_sensitive_denied_without_flag():
    req = {"method": "eth_sign", "params": ["0x0", "0x0"], "context": {}, "timeout_seconds": 2}
    proc = _run_exec(req, {"ETH_RPC_URL": "http://127.0.0.1:1"})
    assert proc.returncode == 4
    payload = json.loads(proc.stdout)
    assert payload["status"] == "denied"
    assert payload["error_code"] == "POLICY_DENIED"


def test_broadcast_denied_without_confirmation():
    req = {
        "method": "eth_sendRawTransaction",
        "params": ["0x00"],
        "context": {"allow_broadcast": True},
        "timeout_seconds": 2,
    }
    proc = _run_exec(req, {"ETH_RPC_URL": "http://127.0.0.1:1"})
    assert proc.returncode == 4
    payload = json.loads(proc.stdout)
    assert payload["status"] == "denied"
    assert payload["error_code"] == "POLICY_DENIED"


def test_broadcast_denied_with_short_confirmation_token():
    req = {
        "method": "eth_sendRawTransaction",
        "params": ["0x0102"],
        "context": {"allow_broadcast": True, "confirmation_token": "short"},
        "timeout_seconds": 2,
    }
    proc = _run_exec(req, {"ETH_RPC_URL": "http://127.0.0.1:1"})
    assert proc.returncode == 4
    payload = json.loads(proc.stdout)
    assert payload["status"] == "denied"
    assert payload["error_code"] == "POLICY_DENIED"
    assert "length >=" in payload["error_message"]


def test_adapter_validation_eth_accounts_rejects_params():
    req = {
        "method": "eth_accounts",
        "params": ["unexpected"],
        "context": {"allow_local_sensitive": True},
        "timeout_seconds": 2,
    }
    proc = _run_exec(req, {"ETH_RPC_URL": "http://127.0.0.1:1"})
    assert proc.returncode == 2
    payload = json.loads(proc.stdout)
    assert payload["status"] == "error"
    assert payload["error_code"] == "ADAPTER_VALIDATION_FAILED"


def test_adapter_validation_eth_sendtransaction_rejects_mixed_fee_mode():
    req = {
        "method": "eth_sendTransaction",
        "params": [
            {
                "from": "0x1111111111111111111111111111111111111111",
                "to": "0x2222222222222222222222222222222222222222",
                "gasPrice": "0x1",
                "maxFeePerGas": "0x2",
            }
        ],
        "context": {"allow_broadcast": True, "confirmation_token": "confirm-ok"},
        "timeout_seconds": 2,
    }
    proc = _run_exec(req, {"ETH_RPC_URL": "http://127.0.0.1:1"})
    assert proc.returncode == 2
    payload = json.loads(proc.stdout)
    assert payload["status"] == "error"
    assert payload["error_code"] == "ADAPTER_VALIDATION_FAILED"
    assert "gasPrice" in payload["error_message"]


def test_rpc_success_response():
    server, url = _serve_once({"jsonrpc": "2.0", "id": 7, "result": "0x1234"})
    try:
        req = {"method": "eth_blockNumber", "params": [], "id": 7, "context": {}, "timeout_seconds": 2}
        proc = _run_exec(req, {"ETH_RPC_URL": url})
        assert proc.returncode == 0, proc.stdout + proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["ok"] is True
        assert payload["result"] == "0x1234"
        assert _RPCHandler.last_request is not None
        assert _RPCHandler.last_request["method"] == "eth_blockNumber"
    finally:
        server.server_close()


def test_rpc_error_response_maps_to_remote_error():
    server, url = _serve_once(
        {"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "failure"}}
    )
    try:
        req = {"method": "eth_blockNumber", "params": [], "id": 1, "context": {}, "timeout_seconds": 2}
        proc = _run_exec(req, {"ETH_RPC_URL": url})
        assert proc.returncode == 1
        payload = json.loads(proc.stdout)
        assert payload["error_code"] == "RPC_REMOTE_ERROR"
        assert payload["status"] == "error"
    finally:
        server.server_close()


def test_broadcast_remote_error_maps_to_specific_code():
    server, url = _serve_once(
        {"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "nonce too low"}}
    )
    try:
        req = {
            "method": "eth_sendRawTransaction",
            "params": ["0x0102"],
            "id": 1,
            "context": {"allow_broadcast": True, "confirmation_token": "confirm-ok"},
            "timeout_seconds": 2,
        }
        proc = _run_exec(req, {"ETH_RPC_URL": url})
        assert proc.returncode == 1
        payload = json.loads(proc.stdout)
        assert payload["status"] == "error"
        assert payload["error_code"] == "RPC_BROADCAST_NONCE_TOO_LOW"
    finally:
        server.server_close()
