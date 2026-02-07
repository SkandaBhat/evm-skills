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
