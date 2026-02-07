from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
MANIFEST = ROOT / "references" / "method-manifest.json"

ENS_REGISTRY = "0x00000000000c2e074ec69a0dfb2997ba6c7d2e1e"
VITALIK_NODEHASH = "0xee6c4522aab0003e8d14cd40a6af439055fd2577951148c14b6cea9a53475835"


def _run_cmd(
    command: str,
    args: list[str],
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    cmd = [
        sys.executable,
        str(SCRIPTS / "evm_rpc.py"),
        command,
        *args,
    ]
    env = os.environ.copy()
    env.pop("ETH_RPC_URL", None)
    if extra_env:
        env.update(extra_env)
    return subprocess.run(cmd, capture_output=True, text=True, check=False, env=env)


def _run_exec(
    request: dict,
    extra_env: dict[str, str] | None = None,
    extra_args: list[str] | None = None,
) -> subprocess.CompletedProcess[str]:
    args = [
        "--manifest",
        str(MANIFEST),
        "--request-json",
        json.dumps(request),
    ]
    if extra_args:
        args.extend(extra_args)
    return _run_cmd("exec", args, extra_env=extra_env)


def _run_chain(
    request: dict,
    extra_env: dict[str, str] | None = None,
    command: str = "chain",
    extra_args: list[str] | None = None,
) -> subprocess.CompletedProcess[str]:
    args = [
        "--manifest",
        str(MANIFEST),
        "--request-json",
        json.dumps(request),
    ]
    if extra_args:
        args.extend(extra_args)
    return _run_cmd(command, args, extra_env=extra_env)


def _run_ens_resolve(
    name: str,
    extra_env: dict[str, str] | None = None,
    extra_args: list[str] | None = None,
) -> subprocess.CompletedProcess[str]:
    args = [
        "resolve",
        name,
        "--manifest",
        str(MANIFEST),
    ]
    if extra_args:
        args.extend(extra_args)
    return _run_cmd("ens", args, extra_env=extra_env)


def _run_balance(
    target: str,
    extra_env: dict[str, str] | None = None,
    extra_args: list[str] | None = None,
) -> subprocess.CompletedProcess[str]:
    args = [
        target,
        "--manifest",
        str(MANIFEST),
    ]
    if extra_args:
        args.extend(extra_args)
    return _run_cmd("balance", args, extra_env=extra_env)


class _RPCHandler(BaseHTTPRequestHandler):
    responses: list[Any] = []
    calls: list[dict[str, Any]] = []

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        try:
            payload = json.loads(body)
        except Exception:  # noqa: BLE001
            payload = {"raw": body}
        _RPCHandler.calls.append(payload)

        status_code = 200
        if _RPCHandler.responses:
            next_response = _RPCHandler.responses.pop(0)
            if isinstance(next_response, tuple) and len(next_response) == 2:
                status_code = int(next_response[0])
                response_payload = next_response[1]
            else:
                response_payload = next_response
        else:
            response_payload = {"jsonrpc": "2.0", "id": payload.get("id", 1), "result": "0x1"}

        encoded = json.dumps(response_payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


def _serve(responses: list[Any]) -> tuple[HTTPServer, str]:
    _RPCHandler.responses = list(responses)
    _RPCHandler.calls = []
    server = HTTPServer(("127.0.0.1", 0), _RPCHandler)
    url = f"http://127.0.0.1:{server.server_address[1]}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, url


def _stop(server: HTTPServer) -> None:
    server.shutdown()
    server.server_close()


def _pad_address(addr: str) -> str:
    return f"0x{'0'*24}{addr[2:].lower()}"


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
    server, url = _serve([{"jsonrpc": "2.0", "id": 7, "result": "0x1234"}])
    try:
        req = {"method": "eth_blockNumber", "params": [], "id": 7, "context": {}, "timeout_seconds": 2}
        proc = _run_exec(req, {"ETH_RPC_URL": url})
        assert proc.returncode == 0, proc.stdout + proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["ok"] is True
        assert payload["result"] == "0x1234"
        assert _RPCHandler.calls
        assert _RPCHandler.calls[0]["method"] == "eth_blockNumber"
    finally:
        _stop(server)


def test_rpc_error_response_maps_to_remote_error():
    server, url = _serve([
        {"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "failure"}},
    ])
    try:
        req = {"method": "eth_blockNumber", "params": [], "id": 1, "context": {}, "timeout_seconds": 2}
        proc = _run_exec(req, {"ETH_RPC_URL": url})
        assert proc.returncode == 1
        payload = json.loads(proc.stdout)
        assert payload["error_code"] == "RPC_REMOTE_ERROR"
        assert payload["status"] == "error"
    finally:
        _stop(server)


def test_broadcast_remote_error_maps_to_specific_code():
    server, url = _serve([
        {"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "nonce too low"}},
    ])
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
        _stop(server)


def test_exec_result_only_prints_raw_result():
    server, url = _serve([{"jsonrpc": "2.0", "id": 1, "result": "0x7b"}])
    try:
        req = {"method": "eth_blockNumber", "params": [], "id": 1, "context": {}, "timeout_seconds": 2}
        proc = _run_exec(req, {"ETH_RPC_URL": url}, ["--result-only"])
        assert proc.returncode == 0
        assert proc.stdout.strip() == "0x7b"
    finally:
        _stop(server)


def test_exec_select_prints_selected_value():
    server, url = _serve([{"jsonrpc": "2.0", "id": 1, "result": "0x7b"}])
    try:
        req = {"method": "eth_blockNumber", "params": [], "id": 1, "context": {}, "timeout_seconds": 2}
        proc = _run_exec(req, {"ETH_RPC_URL": url}, ["--select", "$.result"])
        assert proc.returncode == 0
        assert proc.stdout.strip() == "0x7b"
    finally:
        _stop(server)


def test_chain_success_with_templates_and_transforms():
    server, url = _serve([
        {"jsonrpc": "2.0", "id": 1, "result": "0x1bc16d674ec80000"},
    ])
    try:
        req = {
            "steps": [
                {
                    "id": "balance",
                    "method": "eth_getBalance",
                    "params": ["0x1111111111111111111111111111111111111111", "latest"],
                },
                {"id": "eth", "transform": "wei_to_eth", "input": "{{balance.result}}"},
                {"id": "count", "transform": "hex_to_int", "input": "0x2a"},
            ]
        }
        proc = _run_chain(req, {"ETH_RPC_URL": url})
        assert proc.returncode == 0, proc.stdout + proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["ok"] is True
        assert payload["final_result"] == 42
        assert payload["outputs"]["eth"]["result"] == "2"
        assert payload["steps_executed"] == 3
    finally:
        _stop(server)


def test_chain_fail_fast_on_rpc_error():
    server, url = _serve([
        {"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "boom"}},
        {"jsonrpc": "2.0", "id": 2, "result": "0x2"},
    ])
    try:
        req = {
            "steps": [
                {"id": "first", "method": "eth_blockNumber", "params": []},
                {"id": "second", "method": "eth_blockNumber", "params": []},
            ]
        }
        proc = _run_chain(req, {"ETH_RPC_URL": url})
        assert proc.returncode == 1
        payload = json.loads(proc.stdout)
        assert payload["ok"] is False
        assert payload["failed_step_id"] == "first"
        assert payload["steps_executed"] == 1
        assert len(_RPCHandler.calls) == 1
    finally:
        _stop(server)


def test_chain_template_missing_reference_fails():
    req = {
        "steps": [
            {"id": "first", "transform": "hex_to_int", "input": "0x2a"},
            {"id": "second", "transform": "wei_to_eth", "input": "{{missing.result}}"},
        ]
    }
    proc = _run_chain(req)
    assert proc.returncode == 2
    payload = json.loads(proc.stdout)
    assert payload["ok"] is False
    assert payload["failed_step_id"] == "second"
    assert "template" in payload["error_message"]


def test_batch_alias_matches_chain_behavior():
    server, url = _serve([
        {"jsonrpc": "2.0", "id": 1, "result": "0x1"},
    ])
    try:
        req = {
            "steps": [
                {"id": "one", "method": "eth_blockNumber", "params": []},
            ]
        }
        proc = _run_chain(req, {"ETH_RPC_URL": url}, command="batch")
        assert proc.returncode == 0
        payload = json.loads(proc.stdout)
        assert payload["ok"] is True
        assert payload["final_result"] == "0x1"
    finally:
        _stop(server)


def test_chain_select_outputs_value_for_piping():
    server, url = _serve([
        {"jsonrpc": "2.0", "id": 1, "result": "0x2a"},
    ])
    try:
        req = {
            "steps": [
                {"id": "one", "method": "eth_blockNumber", "params": []},
            ]
        }
        proc = _run_chain(req, {"ETH_RPC_URL": url}, extra_args=["--select", "$.outputs.one.result"])
        assert proc.returncode == 0
        assert proc.stdout.strip() == "0x2a"
    finally:
        _stop(server)


def test_ens_resolve_uses_registry_and_resolver_calls():
    resolver = "0x231b0ee14048e9dccd1d247744d114a4eb5e8e63"
    resolved = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045"
    server, url = _serve([
        {"jsonrpc": "2.0", "id": 1, "result": _pad_address(resolver)},
        {"jsonrpc": "2.0", "id": 2, "result": _pad_address(resolved)},
    ])
    try:
        proc = _run_ens_resolve("vitalik.eth", {"ETH_RPC_URL": url})
        assert proc.returncode == 0, proc.stdout + proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["ok"] is True
        assert payload["result"] == resolved

        assert len(_RPCHandler.calls) == 2
        first_call = _RPCHandler.calls[0]
        second_call = _RPCHandler.calls[1]
        assert first_call["method"] == "eth_call"
        assert first_call["params"][0]["to"].lower() == ENS_REGISTRY
        assert first_call["params"][0]["data"] == f"0x0178b8bf{VITALIK_NODEHASH[2:]}"

        assert second_call["method"] == "eth_call"
        assert second_call["params"][0]["to"].lower() == resolver
        assert second_call["params"][0]["data"] == f"0x3b3b57de{VITALIK_NODEHASH[2:]}"
    finally:
        _stop(server)


def test_balance_for_ens_uses_resolution_and_formats_eth():
    resolver = "0x231b0ee14048e9dccd1d247744d114a4eb5e8e63"
    resolved = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045"
    server, url = _serve([
        {"jsonrpc": "2.0", "id": 1, "result": _pad_address(resolver)},
        {"jsonrpc": "2.0", "id": 2, "result": _pad_address(resolved)},
        {"jsonrpc": "2.0", "id": 3, "result": "0x1bc16d674ec80000"},
    ])
    try:
        proc = _run_balance("vitalik.eth", {"ETH_RPC_URL": url})
        assert proc.returncode == 0, proc.stdout + proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["ok"] is True
        assert payload["resolved_address"] == resolved
        assert payload["result"]["wei_hex"] == "0x1bc16d674ec80000"
        assert payload["result"]["eth"] == "2"
        assert len(_RPCHandler.calls) == 3
    finally:
        _stop(server)


def test_balance_result_only_outputs_compact_result_object():
    server, url = _serve([
        {"jsonrpc": "2.0", "id": 1, "result": "0x1"},
    ])
    try:
        proc = _run_balance(
            "0x1111111111111111111111111111111111111111",
            {"ETH_RPC_URL": url},
            extra_args=["--result-only", "--compact"],
        )
        assert proc.returncode == 0
        payload = json.loads(proc.stdout)
        assert payload["wei_hex"] == "0x1"
        assert payload["eth"] == "0.000000000000000001"
    finally:
        _stop(server)
