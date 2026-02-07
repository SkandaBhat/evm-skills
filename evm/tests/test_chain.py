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
