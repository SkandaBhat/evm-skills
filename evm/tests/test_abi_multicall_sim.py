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
    _serve,
    _stop,
)

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
