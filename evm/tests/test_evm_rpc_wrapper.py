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


def _run_logs(
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
    return _run_cmd("logs", args, extra_env=extra_env)


def _run_abi(
    request: dict,
    extra_args: list[str] | None = None,
) -> subprocess.CompletedProcess[str]:
    args = ["--request-json", json.dumps(request)]
    if extra_args:
        args.extend(extra_args)
    return _run_cmd("abi", args)


def _run_multicall(
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
    return _run_cmd("multicall", args, extra_env=extra_env)


def _run_simulate(
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
    return _run_cmd("simulate", args, extra_env=extra_env)


def _run_trace(
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
    return _run_cmd("trace", args, extra_env=extra_env)


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


def test_exec_reports_clear_error_when_cast_missing():
    req = {"method": "eth_blockNumber", "params": [], "id": 1, "context": {}, "timeout_seconds": 2}
    proc = _run_exec(
        req,
        {
            "ETH_RPC_URL": "http://127.0.0.1:1",
            "PATH": "",
        },
    )
    assert proc.returncode == 1
    payload = json.loads(proc.stdout)
    assert payload["error_code"] == "RPC_TRANSPORT_ERROR"
    assert "cast is required but not installed" in payload["error_message"].lower()
    assert "install Foundry cast".lower() in str(payload.get("hint", "")).lower()


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


def test_logs_still_work_when_cast_missing():
    server, url = _serve(
        [
            {"jsonrpc": "2.0", "id": 1, "result": []},
        ]
    )
    try:
        req = {
            "filter": {
                "fromBlock": 1,
                "toBlock": 1,
                "address": "0x1111111111111111111111111111111111111111",
                "topics": [],
            },
        }
        proc = _run_logs(
            req,
            {
                "ETH_RPC_URL": url,
                "PATH": "",
            },
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["ok"] is True
        assert payload["result"] == []
    finally:
        _stop(server)


def test_logs_requires_rpc_url():
    req = {
        "filter": {
            "fromBlock": 1,
            "toBlock": 1,
            "address": "0x1111111111111111111111111111111111111111",
            "topics": [],
        }
    }
    proc = _run_logs(req)
    assert proc.returncode == 4
    payload = json.loads(proc.stdout)
    assert payload["error_code"] == "RPC_URL_REQUIRED"


def test_logs_heavy_read_requires_flag():
    req = {
        "filter": {
            "fromBlock": 1,
            "toBlock": 60000,
            "address": "0x1111111111111111111111111111111111111111",
            "topics": [],
        },
        "chunk_size": 10000,
    }
    proc = _run_logs(req, {"ETH_RPC_URL": "http://127.0.0.1:1"})
    assert proc.returncode == 4
    payload = json.loads(proc.stdout)
    assert payload["status"] == "denied"
    assert payload["error_code"] == "POLICY_DENIED"
    assert "allow_heavy_read=true" in payload["error_message"]


def test_logs_chunking_and_dedupe():
    log1 = {
        "address": "0x1111111111111111111111111111111111111111",
        "blockNumber": "0x1",
        "logIndex": "0x0",
        "transactionHash": "0x" + "a" * 64,
    }
    log2 = {
        "address": "0x1111111111111111111111111111111111111111",
        "blockNumber": "0x2",
        "logIndex": "0x0",
        "transactionHash": "0x" + "b" * 64,
    }
    server, url = _serve(
        [
            {"jsonrpc": "2.0", "id": 1, "result": [log1]},
            {"jsonrpc": "2.0", "id": 1, "result": [log1, log2]},
        ]
    )
    try:
        req = {
            "filter": {
                "fromBlock": 1,
                "toBlock": 2,
                "address": "0x1111111111111111111111111111111111111111",
                "topics": [],
            },
            "chunk_size": 1,
            "context": {"allow_heavy_read": True},
        }
        proc = _run_logs(req, {"ETH_RPC_URL": url})
        assert proc.returncode == 0, proc.stdout + proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["ok"] is True
        assert len(payload["result"]) == 2
        assert payload["summary"]["attempted_chunks"] == 2
        assert payload["summary"]["deduped_logs"] == 1
        assert len(_RPCHandler.calls) == 2
        assert _RPCHandler.calls[0]["params"][0]["fromBlock"] == "0x1"
        assert _RPCHandler.calls[0]["params"][0]["toBlock"] == "0x1"
        assert _RPCHandler.calls[1]["params"][0]["fromBlock"] == "0x2"
        assert _RPCHandler.calls[1]["params"][0]["toBlock"] == "0x2"
    finally:
        _stop(server)


def test_logs_adaptive_split_on_remote_error():
    log1 = {
        "address": "0x1111111111111111111111111111111111111111",
        "blockNumber": "0x1",
        "logIndex": "0x0",
        "transactionHash": "0x" + "a" * 64,
    }
    log2 = {
        "address": "0x1111111111111111111111111111111111111111",
        "blockNumber": "0x3",
        "logIndex": "0x0",
        "transactionHash": "0x" + "b" * 64,
    }
    server, url = _serve(
        [
            {"jsonrpc": "2.0", "id": 1, "error": {"code": -32005, "message": "query returned more than 10000 results"}},
            {"jsonrpc": "2.0", "id": 1, "result": [log1]},
            {"jsonrpc": "2.0", "id": 1, "result": [log2]},
        ]
    )
    try:
        req = {
            "filter": {
                "fromBlock": 1,
                "toBlock": 4,
                "address": "0x1111111111111111111111111111111111111111",
                "topics": [],
            },
            "chunk_size": 4,
            "adaptive_split": True,
            "context": {"allow_heavy_read": True},
        }
        proc = _run_logs(req, {"ETH_RPC_URL": url})
        assert proc.returncode == 0, proc.stdout + proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["ok"] is True
        assert payload["summary"]["split_count"] == 1
        assert payload["summary"]["attempted_chunks"] == 3
        assert len(payload["result"]) == 2
        assert len(_RPCHandler.calls) == 3
        assert _RPCHandler.calls[1]["params"][0]["fromBlock"] == "0x1"
        assert _RPCHandler.calls[1]["params"][0]["toBlock"] == "0x2"
        assert _RPCHandler.calls[2]["params"][0]["fromBlock"] == "0x3"
        assert _RPCHandler.calls[2]["params"][0]["toBlock"] == "0x4"
    finally:
        _stop(server)


def test_logs_respects_max_chunks_limit():
    server, url = _serve(
        [
            {"jsonrpc": "2.0", "id": 1, "result": []},
            {"jsonrpc": "2.0", "id": 1, "result": []},
        ]
    )
    try:
        req = {
            "filter": {
                "fromBlock": 1,
                "toBlock": 10,
                "address": "0x1111111111111111111111111111111111111111",
                "topics": [],
            },
            "chunk_size": 1,
            "max_chunks": 2,
            "context": {"allow_heavy_read": True},
        }
        proc = _run_logs(req, {"ETH_RPC_URL": url})
        assert proc.returncode == 2
        payload = json.loads(proc.stdout)
        assert payload["error_code"] == "LOGS_RANGE_TOO_LARGE"
        assert payload["summary"]["attempted_chunks"] == 2
        assert len(_RPCHandler.calls) == 2
    finally:
        _stop(server)


def test_abi_encode_decode_and_event_decode():
    addr = "0x1111111111111111111111111111111111111111"
    proc_enc = _run_abi(
        {
            "operation": "encode_call",
            "signature": "balanceOf(address)",
            "args": [addr],
        }
    )
    assert proc_enc.returncode == 0, proc_enc.stdout + proc_enc.stderr
    payload_enc = json.loads(proc_enc.stdout)
    assert payload_enc["ok"] is True
    assert payload_enc["result"]["selector"] == "0x70a08231"
    assert payload_enc["result"]["calldata"].startswith("0x70a08231")

    proc_dec = _run_abi(
        {
            "operation": "decode_output",
            "types": ["uint256"],
            "data": "0x" + ("0" * 63) + "2",
        }
    )
    assert proc_dec.returncode == 0, proc_dec.stdout + proc_dec.stderr
    payload_dec = json.loads(proc_dec.stdout)
    assert payload_dec["ok"] is True
    assert payload_dec["result"]["values"] == ["2"]

    proc_topic = _run_abi(
        {
            "operation": "event_topic0",
            "event": "Transfer(address,address,uint256)",
        }
    )
    assert proc_topic.returncode == 0
    topic0 = json.loads(proc_topic.stdout)["result"]["topic0"]

    proc_log = _run_abi(
        {
            "operation": "decode_log",
            "event": "Transfer(address indexed from,address indexed to,uint256 value)",
            "topics": [topic0, _pad_address(addr), _pad_address("0x2222222222222222222222222222222222222222")],
            "data": "0x" + ("0" * 63) + "a",
        }
    )
    assert proc_log.returncode == 0, proc_log.stdout + proc_log.stderr
    payload_log = json.loads(proc_log.stdout)
    args = payload_log["result"]["args"]
    assert args[0]["value"] == addr
    assert args[1]["value"] == "0x2222222222222222222222222222222222222222"
    assert args[2]["value"] == "10"


def test_chain_abi_transforms_roundtrip():
    server, url = _serve(
        [
            {"jsonrpc": "2.0", "id": 2, "result": "0x" + ("0" * 63) + "2"},
        ]
    )
    try:
        req = {
            "steps": [
                {
                    "id": "enc",
                    "transform": "abi_encode_call",
                    "input": {
                        "signature": "balanceOf(address)",
                        "args": ["0x1111111111111111111111111111111111111111"],
                    },
                },
                {
                    "id": "call",
                    "method": "eth_call",
                    "params": [
                        {
                            "to": "0x3333333333333333333333333333333333333333",
                            "data": "{{enc.result.calldata}}",
                        },
                        "latest",
                    ],
                },
                {
                    "id": "dec",
                    "transform": "abi_decode_output",
                    "input": {
                        "types": ["uint256"],
                        "data": "{{call.result}}",
                    },
                },
            ]
        }
        proc = _run_chain(req, {"ETH_RPC_URL": url})
        assert proc.returncode == 0, proc.stdout + proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["ok"] is True
        assert payload["outputs"]["dec"]["result"]["values"] == ["2"]
        assert _RPCHandler.calls[0]["params"][0]["data"].startswith("0x70a08231")
    finally:
        _stop(server)


def test_multicall_success_with_decode():
    server, url = _serve(
        [
            {"jsonrpc": "2.0", "id": 1, "result": "0x" + ("0" * 63) + "a"},
            {"jsonrpc": "2.0", "id": 2, "result": "0x" + ("0" * 63) + "b"},
        ]
    )
    try:
        req = {
            "calls": [
                {
                    "id": "a",
                    "to": "0x1111111111111111111111111111111111111111",
                    "data": "0x70a082310000000000000000000000001111111111111111111111111111111111111111",
                    "decode_output": ["uint256"],
                },
                {
                    "id": "b",
                    "to": "0x2222222222222222222222222222222222222222",
                    "signature": "balanceOf(address)",
                    "args": ["0x2222222222222222222222222222222222222222"],
                    "decode_output": ["uint256"],
                },
            ],
            "fail_fast": True,
        }
        proc = _run_multicall(req, {"ETH_RPC_URL": url})
        assert proc.returncode == 0, proc.stdout + proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["ok"] is True
        assert payload["summary"]["successful_calls"] == 2
        assert payload["result"][0]["decoded"]["values"] == ["10"]
        assert payload["result"][1]["decoded"]["values"] == ["11"]
        assert len(_RPCHandler.calls) == 2
    finally:
        _stop(server)


def test_multicall_partial_failure_without_fail_fast():
    server, url = _serve(
        [
            {"jsonrpc": "2.0", "id": 1, "result": "0x" + ("0" * 63) + "1"},
            {"jsonrpc": "2.0", "id": 2, "error": {"code": -32000, "message": "boom"}},
        ]
    )
    try:
        req = {
            "calls": [
                {
                    "id": "ok",
                    "to": "0x1111111111111111111111111111111111111111",
                    "data": "0x70a082310000000000000000000000001111111111111111111111111111111111111111",
                },
                {
                    "id": "bad",
                    "to": "0x2222222222222222222222222222222222222222",
                    "data": "0x70a082310000000000000000000000002222222222222222222222222222222222222222",
                },
            ],
            "fail_fast": False,
        }
        proc = _run_multicall(req, {"ETH_RPC_URL": url})
        assert proc.returncode == 1
        payload = json.loads(proc.stdout)
        assert payload["error_code"] == "MULTICALL_PARTIAL_FAILURE"
        assert payload["summary"]["failed_calls"] == 1
        assert len(payload["result"]) == 2
    finally:
        _stop(server)


def test_simulate_success_with_estimate():
    server, url = _serve(
        [
            {"jsonrpc": "2.0", "id": 1, "result": "0x1234"},
            {"jsonrpc": "2.0", "id": 2, "result": "0x5208"},
        ]
    )
    try:
        req = {
            "call_object": {
                "to": "0x1111111111111111111111111111111111111111",
                "data": "0x70a082310000000000000000000000001111111111111111111111111111111111111111",
            },
            "block_tag": "latest",
            "include_estimate_gas": True,
        }
        proc = _run_simulate(req, {"ETH_RPC_URL": url})
        assert proc.returncode == 0, proc.stdout + proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["ok"] is True
        assert payload["result"]["call"]["result"] == "0x1234"
        assert payload["result"]["estimate_gas"]["result"] == "0x5208"
        assert _RPCHandler.calls[0]["method"] == "eth_call"
        assert _RPCHandler.calls[1]["method"] == "eth_estimateGas"
    finally:
        _stop(server)


def test_simulate_revert_decoding():
    reason = "NotAllowed"
    reason_hex = reason.encode("utf-8").hex()
    reason_padded = reason_hex.ljust(64, "0")
    revert_data = (
        "0x08c379a0"
        + f"{32:064x}"
        + f"{len(reason):064x}"
        + reason_padded
    )
    server, url = _serve(
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "error": {
                    "code": 3,
                    "message": "execution reverted",
                    "data": revert_data,
                },
            },
        ]
    )
    try:
        req = {
            "call_object": {
                "to": "0x1111111111111111111111111111111111111111",
                "data": "0x1234",
            },
            "include_estimate_gas": False,
        }
        proc = _run_simulate(req, {"ETH_RPC_URL": url})
        assert proc.returncode == 1
        payload = json.loads(proc.stdout)
        assert payload["error_code"] == "SIMULATION_REVERTED"
        assert payload["result"]["reverted"] is True
        assert payload["result"]["revert"]["data"]["reason"] == reason
    finally:
        _stop(server)


def test_trace_reports_unsupported_when_methods_not_in_manifest():
    req = {
        "mode": "call",
        "call_object": {
            "to": "0x1111111111111111111111111111111111111111",
            "data": "0x1234",
        },
    }
    proc = _run_trace(req, {"ETH_RPC_URL": "http://127.0.0.1:1"})
    assert proc.returncode == 1
    payload = json.loads(proc.stdout)
    assert payload["error_code"] == "TRACE_UNSUPPORTED"
    assert isinstance(payload["attempts"], list)


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
