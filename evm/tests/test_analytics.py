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


def _int256_word(value: int) -> str:
    return f"{(value + (1 << 256)) % (1 << 256):064x}"


def test_analytics_dex_swap_flow_decodes_pool_events():
    pool = "0x9999999999999999999999999999999999999999"
    token0 = "0x1111111111111111111111111111111111111111"
    token1 = "0x2222222222222222222222222222222222222222"
    sender = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    to = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    swap_topic0 = "0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822"
    swap_data = "0x" + f"{1000:064x}{2000:064x}{100:064x}{300:064x}"
    swap_log = {
        "address": pool,
        "blockNumber": "0x64",
        "logIndex": "0x0",
        "transactionHash": "0x" + "a" * 64,
        "topics": [swap_topic0, _pad_address(sender), _pad_address(to)],
        "data": swap_data,
    }
    server, url = _serve(
        [
            {"jsonrpc": "2.0", "id": 1, "result": "0x64"},  # latest block
            {"jsonrpc": "2.0", "id": 2, "result": _pad_address(token0)},  # token0()
            {"jsonrpc": "2.0", "id": 3, "result": _pad_address(token1)},  # token1()
            {"jsonrpc": "2.0", "id": 4, "result": "0x6"},  # token0 decimals
            {"jsonrpc": "2.0", "id": 5, "result": "0x6"},  # token1 decimals
            {"jsonrpc": "2.0", "id": 6, "result": [swap_log]},  # logs
        ]
    )
    try:
        proc = _run_analytics(
            "dex-swap-flow",
            [
                "--pool",
                pool,
                "--last-blocks",
                "10",
                "--manifest",
                str(MANIFEST),
            ],
            {"ETH_RPC_URL": url},
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["ok"] is True
        result = payload["result"]
        assert result["pool"] == pool
        assert result["token0"] == token0
        assert result["token1"] == token1
        assert result["summary"]["token0_pool_net_raw"] == "900"
        assert result["summary"]["token1_pool_net_raw"] == "1700"
        assert result["summary"]["events"] == 1
        assert len(result["rows"]) == 1
    finally:
        _stop(server)


def test_analytics_arbitrage_patterns_detects_cyclic_route():
    tx_hash = "0x" + "a" * 64
    block_number_hex = "0x64"

    pool1 = "0x1111111111111111111111111111111111111111"
    pool2 = "0x2222222222222222222222222222222222222222"
    pool3 = "0x3333333333333333333333333333333333333333"
    weth = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
    usdc = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
    dai = "0x6b175474e89094c44da98b954eedeac495271d0f"

    v2_swap_topic0 = "0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822"
    v3_swap_topic0 = "0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67"

    sender = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    recipient = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

    swap1_data = "0x" + f"{1000:064x}{0:064x}{0:064x}{3000:064x}"  # WETH -> USDC
    swap2_data = "0x" + _int256_word(3000) + _int256_word(-2900)  # USDC -> DAI
    swap3_data = "0x" + f"{2900:064x}{0:064x}{0:064x}{950:064x}"  # DAI -> WETH

    receipt_logs = [
        {
            "address": pool1,
            "topics": [v2_swap_topic0, _pad_address(sender), _pad_address(recipient)],
            "data": swap1_data,
            "logIndex": "0x0",
            "transactionHash": tx_hash,
        },
        {
            "address": pool2,
            "topics": [v3_swap_topic0, _pad_address(sender), _pad_address(recipient)],
            "data": swap2_data,
            "logIndex": "0x1",
            "transactionHash": tx_hash,
        },
        {
            "address": pool3,
            "topics": [v2_swap_topic0, _pad_address(sender), _pad_address(recipient)],
            "data": swap3_data,
            "logIndex": "0x2",
            "transactionHash": tx_hash,
        },
    ]

    server, url = _serve(
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "number": block_number_hex,
                    "hash": "0x" + "1" * 64,
                    "timestamp": "0x65",
                    "transactions": [
                        {
                            "hash": tx_hash,
                            "from": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                            "to": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                            "value": "0x0",
                        }
                    ],
                },
            },
            {"jsonrpc": "2.0", "id": 2, "result": {"logs": receipt_logs}},
            {"jsonrpc": "2.0", "id": 3, "result": _pad_address(weth)},
            {"jsonrpc": "2.0", "id": 4, "result": _pad_address(usdc)},
            {"jsonrpc": "2.0", "id": 5, "result": _pad_address(usdc)},
            {"jsonrpc": "2.0", "id": 6, "result": _pad_address(dai)},
            {"jsonrpc": "2.0", "id": 7, "result": _pad_address(dai)},
            {"jsonrpc": "2.0", "id": 8, "result": _pad_address(weth)},
        ]
    )
    try:
        proc = _run_analytics(
            "arbitrage-patterns",
            [
                "--block",
                block_number_hex,
                "--manifest",
                str(MANIFEST),
            ],
            {"ETH_RPC_URL": url},
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr

        payload = json.loads(proc.stdout)
        assert payload["ok"] is True
        result = payload["result"]
        assert result["summary"]["arbitrage_candidates_total"] == 1
        assert len(result["candidates"]) == 1
        candidate = result["candidates"][0]
        assert candidate["tx_hash"] == tx_hash
        assert candidate["has_cycle"] is True
        assert candidate["swap_count"] == 3
        assert "mixed Uniswap V2 + V3 swaps" in candidate["reasons"]
        assert candidate["path_tokens"][0] == weth
        assert candidate["path_tokens"][-1] == weth
    finally:
        _stop(server)


def test_analytics_arbitrage_patterns_rejects_invalid_block_tag():
    proc = _run_analytics(
        "arbitrage-patterns",
        [
            "--block",
            "not-a-block",
            "--manifest",
            str(MANIFEST),
        ],
    )
    assert proc.returncode == 2, proc.stdout + proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["ok"] is False
    assert payload["error_code"] == "INVALID_REQUEST"

def test_analytics_factory_new_pools_uniswap_v2():
    factory = "0xfafafafafafafafafafafafafafafafafafafafa"
    token0 = "0x1111111111111111111111111111111111111111"
    token1 = "0x2222222222222222222222222222222222222222"
    pair = "0x3333333333333333333333333333333333333333"
    topic0 = "0x0d3648bd0f6ba80134a33ba9275ac585d9d315f0ad8355cddefde31afa28d0e9"
    pair_created_log = {
        "address": factory,
        "blockNumber": "0x32",
        "logIndex": "0x0",
        "transactionHash": "0x" + "b" * 64,
        "topics": [topic0, _pad_address(token0), _pad_address(token1)],
        "data": "0x" + _pad_address(pair)[2:] + f"{1:064x}",
    }
    server, url = _serve(
        [
            {"jsonrpc": "2.0", "id": 1, "result": "0x32"},  # latest block
            {"jsonrpc": "2.0", "id": 2, "result": [pair_created_log]},  # logs
        ]
    )
    try:
        proc = _run_analytics(
            "factory-new-pools",
            [
                "--factory",
                factory,
                "--protocol",
                "uniswap-v2",
                "--last-blocks",
                "100",
                "--manifest",
                str(MANIFEST),
            ],
            {"ETH_RPC_URL": url},
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["ok"] is True
        result = payload["result"]
        assert result["factory"] == factory
        assert result["protocol"] == "uniswap-v2"
        assert result["summary"]["events"] == 1
        assert len(result["rows"]) == 1
        assert result["rows"][0]["pool"] == pair
    finally:
        _stop(server)
