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
            {
                "jsonrpc": "2.0",
                "id": 2,
                "result": [
                    {
                        "transactionHash": tx_hash,
                        "logs": receipt_logs,
                    }
                ],
            },
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


def test_analytics_arbitrage_patterns_last_blocks_window_uses_block_receipts():
    tx_hash = "0x" + "c" * 64
    tx_hash_other = "0x" + "d" * 64

    pool1 = "0x1111111111111111111111111111111111111111"
    pool2 = "0x2222222222222222222222222222222222222222"
    weth = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
    dai = "0x6b175474e89094c44da98b954eedeac495271d0f"

    v2_swap_topic0 = "0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822"
    sender = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    recipient = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

    swap1_data = "0x" + f"{1000:064x}{0:064x}{0:064x}{1500:064x}"  # WETH -> DAI (pool1)
    swap2_data = "0x" + f"{1500:064x}{0:064x}{0:064x}{1005:064x}"  # DAI -> WETH (pool2)

    receipt_with_swaps = {
        "transactionHash": tx_hash,
        "logs": [
            {
                "address": pool1,
                "topics": [v2_swap_topic0, _pad_address(sender), _pad_address(recipient)],
                "data": swap1_data,
                "logIndex": "0x0",
                "transactionHash": tx_hash,
            },
            {
                "address": pool2,
                "topics": [v2_swap_topic0, _pad_address(sender), _pad_address(recipient)],
                "data": swap2_data,
                "logIndex": "0x1",
                "transactionHash": tx_hash,
            },
        ],
    }
    receipt_empty = {"transactionHash": tx_hash_other, "logs": []}

    server, url = _serve(
        [
            {"jsonrpc": "2.0", "id": 1, "result": "0x65"},  # latest block for --last-blocks
            {
                "jsonrpc": "2.0",
                "id": 2,
                "result": {
                    "number": "0x64",
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
            {"jsonrpc": "2.0", "id": 3, "result": [receipt_with_swaps]},  # eth_getBlockReceipts(0x64)
            {"jsonrpc": "2.0", "id": 4, "result": _pad_address(weth)},  # pool1 token0()
            {"jsonrpc": "2.0", "id": 5, "result": _pad_address(dai)},  # pool1 token1()
            {"jsonrpc": "2.0", "id": 6, "result": _pad_address(dai)},  # pool2 token0()
            {"jsonrpc": "2.0", "id": 7, "result": _pad_address(weth)},  # pool2 token1()
            {
                "jsonrpc": "2.0",
                "id": 8,
                "result": {
                    "number": "0x65",
                    "hash": "0x" + "2" * 64,
                    "timestamp": "0x66",
                    "transactions": [
                        {
                            "hash": tx_hash_other,
                            "from": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                            "to": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                            "value": "0x0",
                        }
                    ],
                },
            },
            {"jsonrpc": "2.0", "id": 9, "result": [receipt_empty]},  # eth_getBlockReceipts(0x65)
        ]
    )
    try:
        proc = _run_analytics(
            "arbitrage-patterns",
            [
                "--last-blocks",
                "2",
                "--manifest",
                str(MANIFEST),
            ],
            {"ETH_RPC_URL": url},
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["ok"] is True
        result = payload["result"]
        assert result["range"]["from_block"] == 100
        assert result["range"]["to_block"] == 101
        assert result["summary"]["blocks_scanned"] == 2
        assert result["summary"]["arbitrage_candidates_total"] == 1
        assert result["summary"]["receipt_collection"]["eth_getBlockReceipts_blocks"] == 2
        assert result["summary"]["receipt_collection"]["eth_getTransactionReceipt_calls"] == 0
        assert len(result["blocks"]) == 2
        assert len(result["candidates"]) == 1
        assert result["candidates"][0]["tx_hash"] == tx_hash
        assert result["candidates"][0]["has_cycle"] is True
    finally:
        _stop(server)


def test_analytics_arbitrage_patterns_falls_back_when_block_receipts_unsupported():
    tx_hash = "0x" + "e" * 64
    block_number_hex = "0x64"

    pool1 = "0x1111111111111111111111111111111111111111"
    pool2 = "0x2222222222222222222222222222222222222222"
    weth = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
    dai = "0x6b175474e89094c44da98b954eedeac495271d0f"

    v2_swap_topic0 = "0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822"
    sender = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    recipient = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

    swap1_data = "0x" + f"{1000:064x}{0:064x}{0:064x}{1500:064x}"  # WETH -> DAI
    swap2_data = "0x" + f"{1500:064x}{0:064x}{0:064x}{1010:064x}"  # DAI -> WETH

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
            "topics": [v2_swap_topic0, _pad_address(sender), _pad_address(recipient)],
            "data": swap2_data,
            "logIndex": "0x1",
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
                    "hash": "0x" + "3" * 64,
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
            {
                "jsonrpc": "2.0",
                "id": 2,
                "error": {"code": -32601, "message": "Method not found"},
            },  # eth_getBlockReceipts unsupported
            {"jsonrpc": "2.0", "id": 3, "result": {"logs": receipt_logs}},  # fallback receipt
            {"jsonrpc": "2.0", "id": 4, "result": _pad_address(weth)},  # pool1 token0()
            {"jsonrpc": "2.0", "id": 5, "result": _pad_address(dai)},  # pool1 token1()
            {"jsonrpc": "2.0", "id": 6, "result": _pad_address(dai)},  # pool2 token0()
            {"jsonrpc": "2.0", "id": 7, "result": _pad_address(weth)},  # pool2 token1()
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
        assert result["summary"]["receipt_collection"]["eth_getBlockReceipts_blocks"] == 0
        assert result["summary"]["receipt_collection"]["eth_getBlockReceipts_failures"] == 1
        assert result["summary"]["receipt_collection"]["eth_getBlockReceipts_method_missing"] == 1
        assert result["summary"]["receipt_collection"]["eth_getTransactionReceipt_calls"] == 1

        methods = [call.get("method") for call in _RPCHandler.calls]
        assert "eth_getBlockReceipts" in methods
        assert "eth_getTransactionReceipt" in methods
    finally:
        _stop(server)


def test_analytics_arbitrage_patterns_summary_only_hides_rows():
    tx_hash = "0x" + "f" * 64
    block_number_hex = "0x64"

    pool1 = "0x1111111111111111111111111111111111111111"
    pool2 = "0x2222222222222222222222222222222222222222"
    weth = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
    dai = "0x6b175474e89094c44da98b954eedeac495271d0f"

    v2_swap_topic0 = "0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822"
    sender = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    recipient = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

    swap1_data = "0x" + f"{1000:064x}{0:064x}{0:064x}{1500:064x}"  # WETH -> DAI
    swap2_data = "0x" + f"{1500:064x}{0:064x}{0:064x}{1012:064x}"  # DAI -> WETH

    server, url = _serve(
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "number": block_number_hex,
                    "hash": "0x" + "4" * 64,
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
            {
                "jsonrpc": "2.0",
                "id": 2,
                "result": [
                    {
                        "transactionHash": tx_hash,
                        "logs": [
                            {
                                "address": pool1,
                                "topics": [v2_swap_topic0, _pad_address(sender), _pad_address(recipient)],
                                "data": swap1_data,
                                "logIndex": "0x0",
                                "transactionHash": tx_hash,
                            },
                            {
                                "address": pool2,
                                "topics": [v2_swap_topic0, _pad_address(sender), _pad_address(recipient)],
                                "data": swap2_data,
                                "logIndex": "0x1",
                                "transactionHash": tx_hash,
                            },
                        ],
                    }
                ],
            },
            {"jsonrpc": "2.0", "id": 3, "result": _pad_address(weth)},  # pool1 token0()
            {"jsonrpc": "2.0", "id": 4, "result": _pad_address(dai)},  # pool1 token1()
            {"jsonrpc": "2.0", "id": 5, "result": _pad_address(dai)},  # pool2 token0()
            {"jsonrpc": "2.0", "id": 6, "result": _pad_address(weth)},  # pool2 token1()
        ]
    )
    try:
        proc = _run_analytics(
            "arbitrage-patterns",
            [
                "--block",
                block_number_hex,
                "--summary-only",
                "--manifest",
                str(MANIFEST),
            ],
            {"ETH_RPC_URL": url},
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["ok"] is True
        result = payload["result"]
        assert result["summary_only"] is True
        assert result["summary"]["arbitrage_candidates_total"] == 1
        assert "candidates" not in result
        assert "blocks" not in result
    finally:
        _stop(server)


def test_analytics_arbitrage_patterns_paginates_candidates():
    tx_hash1 = "0x" + "1" * 64
    tx_hash2 = "0x" + "2" * 64
    tx_hash3 = "0x" + "3" * 64
    block_number_hex = "0x64"

    pool1 = "0x1111111111111111111111111111111111111111"
    pool2 = "0x2222222222222222222222222222222222222222"
    weth = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
    dai = "0x6b175474e89094c44da98b954eedeac495271d0f"

    v2_swap_topic0 = "0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822"
    sender = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    recipient = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

    swap1_data = "0x" + f"{1000:064x}{0:064x}{0:064x}{1500:064x}"  # WETH -> DAI
    swap2_data = "0x" + f"{0:064x}{1500:064x}{1005:064x}{0:064x}"  # DAI -> WETH

    def _swap_logs(tx_hash: str) -> list[dict]:
        return [
            {
                "address": pool1,
                "topics": [v2_swap_topic0, _pad_address(sender), _pad_address(recipient)],
                "data": swap1_data,
                "logIndex": "0x0",
                "transactionHash": tx_hash,
            },
            {
                "address": pool2,
                "topics": [v2_swap_topic0, _pad_address(sender), _pad_address(recipient)],
                "data": swap2_data,
                "logIndex": "0x1",
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
                    "hash": "0x" + "5" * 64,
                    "timestamp": "0x65",
                    "transactions": [
                        {
                            "hash": tx_hash1,
                            "from": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                            "to": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                            "value": "0x0",
                        },
                        {
                            "hash": tx_hash2,
                            "from": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                            "to": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                            "value": "0x0",
                        },
                        {
                            "hash": tx_hash3,
                            "from": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                            "to": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                            "value": "0x0",
                        },
                    ],
                },
            },
            {
                "jsonrpc": "2.0",
                "id": 2,
                "result": [
                    {"transactionHash": tx_hash1, "logs": _swap_logs(tx_hash1)},
                    {"transactionHash": tx_hash2, "logs": _swap_logs(tx_hash2)},
                    {"transactionHash": tx_hash3, "logs": _swap_logs(tx_hash3)},
                ],
            },
            {"jsonrpc": "2.0", "id": 3, "result": _pad_address(weth)},  # pool1 token0()
            {"jsonrpc": "2.0", "id": 4, "result": _pad_address(dai)},  # pool1 token1()
            {"jsonrpc": "2.0", "id": 5, "result": _pad_address(weth)},  # pool2 token0()
            {"jsonrpc": "2.0", "id": 6, "result": _pad_address(dai)},  # pool2 token1()
        ]
    )
    try:
        proc = _run_analytics(
            "arbitrage-patterns",
            [
                "--block",
                block_number_hex,
                "--limit",
                "3",
                "--page",
                "2",
                "--page-size",
                "1",
                "--manifest",
                str(MANIFEST),
            ],
            {"ETH_RPC_URL": url},
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["ok"] is True
        result = payload["result"]
        assert result["summary"]["arbitrage_candidates_total"] == 3
        assert len(result["candidates"]) == 1
        assert result["candidates"][0]["tx_hash"] == tx_hash2

        pagination = result["pagination"]
        assert pagination["page"] == 2
        assert pagination["page_size"] == 1
        assert pagination["offset"] == 1
        assert pagination["returned"] == 1
        assert pagination["capped_candidates"] == 3
        assert pagination["total_candidates"] == 3
        assert pagination["has_next_page"] is True
        assert pagination["is_truncated_by_limit"] is False
        assert pagination["limit"] == 3
    finally:
        _stop(server)


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
