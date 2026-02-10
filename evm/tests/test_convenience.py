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
