from __future__ import annotations

import json

from ._evm_rpc_helpers import (
    ENS_REGISTRY,
    MANIFEST,
    VITALIK_NODEHASH,
    _pad_address,
    _RPCHandler,
    _run_abi,
    _run_analytics,
    _run_balance,
    _run_chain,
    _run_exec,
    _run_ens_resolve,
    _run_logs,
    _run_multicall,
    _run_simulate,
    _run_trace,
    _serve,
    _stop,
)

def test_exec_uses_default_pool_when_rpc_url_missing():
    server, url = _serve([{"jsonrpc": "2.0", "id": 1, "result": "0x2a"}])
    try:
        req = {"method": "eth_blockNumber", "params": [], "context": {}, "timeout_seconds": 2}
        proc = _run_exec(req, {"ETH_RPC_DEFAULT_URLS": url})
        assert proc.returncode == 0, proc.stdout + proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["ok"] is True
        assert payload["result"] == "0x2a"
        assert payload["rpc_request"]["rpc_endpoint_source"] == "env_default_pool"
    finally:
        _stop(server)

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
