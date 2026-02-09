"""Arbitrage-pattern analytics engine for Uniswap V2/V3 swap routing."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any, Callable

from analytics_registry import (
    UNISWAP_V2_SWAP_TOPIC0,
    UNISWAP_V2_TOKEN0_SELECTOR,
    UNISWAP_V2_TOKEN1_SELECTOR,
    UNISWAP_V3_SWAP_TOPIC0,
)
from error_map import ERR_INVALID_REQUEST
from provider_capabilities import is_provider_method_missing
from quantity import parse_nonnegative_quantity_str
from transforms import apply_transform

ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

ARBITRAGE_KNOWN_SYMBOLS: dict[str, str] = {
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": "WETH",
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": "USDC",
    "0xdac17f958d2ee523a2206206994597c13d831ec7": "USDT",
    "0x6b175474e89094c44da98b954eedeac495271d0f": "DAI",
    "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599": "WBTC",
    "0xae7ab96520de3a18e5e111b5eaab095312d7fe84": "stETH",
    "0x7f39c581f595b53c5cb6a5f1a9f8da6c935e2ca0": "wstETH",
}

RpcExecutor = Callable[[dict[str, Any]], tuple[int, dict[str, Any]]]


def parse_arbitrage_block_tag(raw_block: str | None) -> tuple[bool, str, str]:
    block_tag = str(raw_block or "latest").strip().lower()
    if not block_tag:
        return True, "latest", ""
    if block_tag in {"latest", "earliest", "pending", "safe", "finalized"}:
        return True, block_tag, ""
    try:
        block_number = parse_nonnegative_quantity_str(block_tag)
    except Exception:  # noqa: BLE001
        return (
            False,
            "",
            "block must be latest/earliest/pending/safe/finalized or a non-negative block number",
        )
    return True, hex(block_number), ""


def _quantity_to_int(value: Any) -> tuple[bool, int, str]:
    if not isinstance(value, str):
        return False, 0, "expected hex quantity string"
    try:
        if value.startswith("0x"):
            return True, int(value, 16), ""
        return True, int(value, 10), ""
    except Exception:  # noqa: BLE001
        return False, 0, f"invalid quantity: {value}"


def _decode_uint256_word(word_hex: str) -> tuple[bool, int]:
    if not isinstance(word_hex, str) or len(word_hex) != 64:
        return False, 0
    try:
        return True, int(word_hex, 16)
    except Exception:  # noqa: BLE001
        return False, 0


def _decode_int256_word(word_hex: str) -> tuple[bool, int]:
    ok, as_uint = _decode_uint256_word(word_hex)
    if not ok:
        return False, 0
    if as_uint >= 2**255:
        return True, as_uint - 2**256
    return True, as_uint


def _token_label(token: str) -> str:
    as_lower = str(token).lower()
    symbol = ARBITRAGE_KNOWN_SYMBOLS.get(as_lower)
    if symbol:
        return symbol
    if len(as_lower) < 10:
        return as_lower
    return f"{as_lower[:6]}...{as_lower[-4:]}"


def _format_path(tokens: list[str]) -> str:
    return " -> ".join(_token_label(token) for token in tokens)


def _eth_call_result(
    *,
    to: str,
    data: str,
    block_tag: str,
    execute_rpc: RpcExecutor,
) -> tuple[int, dict[str, Any] | None, str | None]:
    req = {
        "method": "eth_call",
        "params": [{"to": to, "data": data}, block_tag],
    }
    rc, payload = execute_rpc(req)
    if rc != 0:
        return rc, payload, None
    result = payload.get("result")
    if not isinstance(result, str):
        return 2, {
            "error_code": ERR_INVALID_REQUEST,
            "error_message": "eth_call returned non-string result",
        }, None
    return 0, None, result


def _word_to_address(word_hex: str) -> tuple[bool, str, str]:
    ok, value, err = apply_transform("slice_last_20_bytes_to_address", word_hex)
    if not ok or not isinstance(value, str):
        return False, "", err or "failed to decode address"
    return True, value, ""


def _fetch_pool_tokens(
    *,
    pool: str,
    block_tag: str,
    execute_rpc: RpcExecutor,
) -> tuple[int, dict[str, Any], tuple[str | None, str | None]]:
    rc0, cause0, token0_raw = _eth_call_result(
        to=pool,
        data=UNISWAP_V2_TOKEN0_SELECTOR,
        block_tag=block_tag,
        execute_rpc=execute_rpc,
    )
    if rc0 != 0 or token0_raw is None:
        return rc0, cause0 or {}, (None, None)

    rc1, cause1, token1_raw = _eth_call_result(
        to=pool,
        data=UNISWAP_V2_TOKEN1_SELECTOR,
        block_tag=block_tag,
        execute_rpc=execute_rpc,
    )
    if rc1 != 0 or token1_raw is None:
        return rc1, cause1 or {}, (None, None)

    ok0, token0, err0 = _word_to_address(token0_raw)
    if not ok0:
        return 2, {"error_code": ERR_INVALID_REQUEST, "error_message": f"token0 decode failed: {err0}"}, (None, None)
    ok1, token1, err1 = _word_to_address(token1_raw)
    if not ok1:
        return 2, {"error_code": ERR_INVALID_REQUEST, "error_message": f"token1 decode failed: {err1}"}, (None, None)

    return 0, {}, (token0.lower(), token1.lower())


def _decode_swap(
    *,
    log_item: dict[str, Any],
    topic0: str,
    pool: str,
    token0: str,
    token1: str,
    log_index: int,
) -> tuple[bool, dict[str, Any] | None]:
    data = log_item.get("data")
    if not isinstance(data, str) or not data.startswith("0x"):
        return False, None
    body = data[2:]

    if topic0 == UNISWAP_V2_SWAP_TOPIC0:
        if len(body) < 64 * 4:
            return False, None
        words = [body[i : i + 64] for i in range(0, 64 * 4, 64)]
        ok0, amount0_in = _decode_uint256_word(words[0])
        ok1, amount1_in = _decode_uint256_word(words[1])
        ok2, amount0_out = _decode_uint256_word(words[2])
        ok3, amount1_out = _decode_uint256_word(words[3])
        if not all((ok0, ok1, ok2, ok3)):
            return False, None

        in_token: str | None = None
        out_token: str | None = None
        in_amount = 0
        out_amount = 0
        if amount0_in > 0 and amount1_out > 0:
            in_token = token0
            out_token = token1
            in_amount = amount0_in
            out_amount = amount1_out
        elif amount1_in > 0 and amount0_out > 0:
            in_token = token1
            out_token = token0
            in_amount = amount1_in
            out_amount = amount0_out
        if not in_token or not out_token:
            return False, None

        return True, {
            "log_index": log_index,
            "pool": pool,
            "version": "v2",
            "in_token": in_token,
            "out_token": out_token,
            "in_amount_raw": str(in_amount),
            "out_amount_raw": str(out_amount),
        }

    if topic0 == UNISWAP_V3_SWAP_TOPIC0:
        if len(body) < 64 * 2:
            return False, None
        word0 = body[0:64]
        word1 = body[64:128]
        ok0, amount0 = _decode_int256_word(word0)
        ok1, amount1 = _decode_int256_word(word1)
        if not ok0 or not ok1:
            return False, None

        in_token: str | None = None
        out_token: str | None = None
        in_amount = 0
        out_amount = 0
        if amount0 > 0 and amount1 < 0:
            in_token = token0
            out_token = token1
            in_amount = amount0
            out_amount = -amount1
        elif amount1 > 0 and amount0 < 0:
            in_token = token1
            out_token = token0
            in_amount = amount1
            out_amount = -amount0
        if not in_token or not out_token:
            return False, None

        return True, {
            "log_index": log_index,
            "pool": pool,
            "version": "v3",
            "in_token": in_token,
            "out_token": out_token,
            "in_amount_raw": str(in_amount),
            "out_amount_raw": str(out_amount),
        }

    return False, None


def _build_candidate(
    *,
    tx_hash: str,
    tx_from: str | None,
    tx_to: str | None,
    tx_value: Any,
    swaps: list[dict[str, Any]],
    min_swaps: int,
    include_swaps: bool,
) -> dict[str, Any] | None:
    if len(swaps) < min_swaps:
        return None

    unique_pools = len({str(item.get("pool", "")).lower() for item in swaps if item.get("pool")})
    versions = sorted({str(item.get("version", "")) for item in swaps if item.get("version")})

    continuity_links = 0
    for idx in range(len(swaps) - 1):
        out_token = str(swaps[idx].get("out_token", "")).lower()
        next_in = str(swaps[idx + 1].get("in_token", "")).lower()
        if out_token and next_in and out_token == next_in:
            continuity_links += 1

    first_in = str(swaps[0].get("in_token", "")).lower()
    last_out = str(swaps[-1].get("out_token", "")).lower()
    has_cycle = bool(first_in and last_out and first_in == last_out)

    cycle_gain_raw: str | None = None
    if has_cycle:
        try:
            first_in_amount = int(str(swaps[0].get("in_amount_raw", "0")), 10)
            last_out_amount = int(str(swaps[-1].get("out_amount_raw", "0")), 10)
            cycle_gain_raw = str(last_out_amount - first_in_amount)
        except Exception:  # noqa: BLE001
            cycle_gain_raw = None

    reasons: list[str] = []
    if has_cycle:
        reasons.append("cyclic path (token returns to start)")
    if continuity_links >= 1 and unique_pools >= 2:
        reasons.append("multi-pool routed swaps in one tx")
    if len(versions) > 1:
        reasons.append("mixed Uniswap V2 + V3 swaps")

    is_candidate = (
        has_cycle
        or (continuity_links >= 1 and len(swaps) >= 3)
        or (len(versions) > 1 and len(swaps) >= 2)
    )
    if not is_candidate:
        return None

    path_tokens: list[str] = []
    if first_in:
        path_tokens.append(first_in)
    for item in swaps:
        out_token = str(item.get("out_token", "")).lower()
        if out_token:
            path_tokens.append(out_token)

    candidate: dict[str, Any] = {
        "tx_hash": tx_hash,
        "from": tx_from,
        "to": tx_to,
        "value_wei": tx_value,
        "swap_count": len(swaps),
        "unique_pools": unique_pools,
        "versions": versions,
        "continuity_links": continuity_links,
        "has_cycle": has_cycle,
        "cycle_gain_raw": cycle_gain_raw,
        "reasons": reasons,
        "path_tokens": path_tokens,
        "path_display": _format_path(path_tokens),
    }
    if include_swaps:
        candidate["swaps"] = swaps
    return candidate


def scan_arbitrage_blocks(
    *,
    execute_rpc: RpcExecutor,
    block_tags: list[str],
    min_swaps: int,
    limit: int,
    max_transactions: int | None,
    include_swaps: bool,
    use_block_receipts: bool,
) -> tuple[int, dict[str, Any]]:
    pool_cache: dict[str, tuple[str | None, str | None]] = {}
    receipt_failures: list[dict[str, Any]] = []
    pool_failures: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    block_rows: list[dict[str, Any]] = []
    tx_count_total = 0
    tx_count_scanned = 0
    txs_with_swaps_total = 0
    block_receipt_fastpath_success = 0
    block_receipt_fastpath_failures = 0
    block_receipt_fastpath_method_missing = 0
    per_tx_receipt_calls = 0

    for block_tag in block_tags:
        rc_block, block_payload = execute_rpc({"method": "eth_getBlockByNumber", "params": [block_tag, True]})
        if rc_block != 0:
            return rc_block, {
                "ok": False,
                "kind": "stage_failure",
                "stage": f"eth_getBlockByNumber({block_tag})",
                "cause": block_payload,
            }

        block_result = block_payload.get("result")
        if not isinstance(block_result, dict):
            return 2, {
                "ok": False,
                "kind": "invalid_response",
                "message": "eth_getBlockByNumber returned non-object result",
                "request_block": block_tag,
            }

        txs = block_result.get("transactions", [])
        if not isinstance(txs, list):
            return 2, {
                "ok": False,
                "kind": "invalid_response",
                "message": "block.transactions must be a list",
                "request_block": block_tag,
            }

        txs_to_scan = txs if max_transactions is None else txs[:max_transactions]

        block_number_raw = block_result.get("number")
        block_number: int | None = None
        if isinstance(block_number_raw, str):
            ok_number, as_number, _ = _quantity_to_int(block_number_raw)
            if ok_number:
                block_number = as_number

        block_timestamp_raw = block_result.get("timestamp")
        block_timestamp_utc: str | None = None
        if isinstance(block_timestamp_raw, str):
            ok_ts, as_ts, _ = _quantity_to_int(block_timestamp_raw)
            if ok_ts:
                try:
                    block_timestamp_utc = datetime.fromtimestamp(as_ts, tz=UTC).isoformat()
                except Exception:  # noqa: BLE001
                    block_timestamp_utc = None

        block_for_calls = block_number_raw if isinstance(block_number_raw, str) else block_tag

        receipts_by_hash: dict[str, dict[str, Any]] = {}
        block_receipts_error: dict[str, Any] | None = None
        if use_block_receipts:
            rc_receipts, receipts_payload = execute_rpc(
                {"method": "eth_getBlockReceipts", "params": [block_for_calls]}
            )
            if rc_receipts == 0:
                result = receipts_payload.get("result")
                if isinstance(result, list):
                    block_receipt_fastpath_success += 1
                    for item in result:
                        if not isinstance(item, dict):
                            continue
                        tx_hash = item.get("transactionHash")
                        if isinstance(tx_hash, str):
                            receipts_by_hash[tx_hash] = item
                else:
                    block_receipt_fastpath_failures += 1
                    block_receipts_error = {
                        "error_code": ERR_INVALID_REQUEST,
                        "error_message": "eth_getBlockReceipts returned non-array result",
                    }
            else:
                block_receipt_fastpath_failures += 1
                if is_provider_method_missing(receipts_payload):
                    block_receipt_fastpath_method_missing += 1
                block_receipts_error = {
                    "error_code": receipts_payload.get("error_code"),
                    "error_message": receipts_payload.get("error_message"),
                    "hint": receipts_payload.get("hint"),
                }

        txs_with_swaps = 0
        block_candidates: list[dict[str, Any]] = []
        block_receipt_failures = 0
        block_pool_failures = 0
        block_unique_pools: set[str] = set()
        receipts_from_block = 0
        receipts_from_per_tx = 0

        for tx_item in txs_to_scan:
            tx_hash: str | None = None
            tx_from: str | None = None
            tx_to: str | None = None
            tx_value: Any = None

            if isinstance(tx_item, dict):
                raw_hash = tx_item.get("hash")
                if isinstance(raw_hash, str):
                    tx_hash = raw_hash
                raw_from = tx_item.get("from")
                if isinstance(raw_from, str):
                    tx_from = raw_from
                raw_to = tx_item.get("to")
                if isinstance(raw_to, str):
                    tx_to = raw_to
                tx_value = tx_item.get("value")
            elif isinstance(tx_item, str):
                tx_hash = tx_item

            if not tx_hash:
                continue

            receipt = receipts_by_hash.get(tx_hash)
            if isinstance(receipt, dict):
                receipts_from_block += 1
            else:
                per_tx_receipt_calls += 1
                receipts_from_per_tx += 1
                rc_receipt, receipt_payload = execute_rpc(
                    {"method": "eth_getTransactionReceipt", "params": [tx_hash]}
                )
                if rc_receipt != 0:
                    block_receipt_failures += 1
                    receipt_failures.append(
                        {
                            "block_number": block_number,
                            "block_number_hex": block_number_raw if isinstance(block_number_raw, str) else None,
                            "tx_hash": tx_hash,
                            "error_code": receipt_payload.get("error_code"),
                            "error_message": receipt_payload.get("error_message"),
                        }
                    )
                    continue
                receipt = receipt_payload.get("result")

            if not isinstance(receipt, dict):
                block_receipt_failures += 1
                receipt_failures.append(
                    {
                        "block_number": block_number,
                        "block_number_hex": block_number_raw if isinstance(block_number_raw, str) else None,
                        "tx_hash": tx_hash,
                        "error_code": ERR_INVALID_REQUEST,
                        "error_message": "transaction receipt returned non-object result",
                    }
                )
                continue

            logs = receipt.get("logs", [])
            if not isinstance(logs, list):
                continue

            swaps: list[dict[str, Any]] = []
            for idx, log_item in enumerate(logs):
                if not isinstance(log_item, dict):
                    continue
                topics = log_item.get("topics", [])
                if not isinstance(topics, list) or not topics:
                    continue
                if not isinstance(topics[0], str):
                    continue
                topic0 = str(topics[0]).lower()
                if topic0 not in {UNISWAP_V2_SWAP_TOPIC0, UNISWAP_V3_SWAP_TOPIC0}:
                    continue

                pool = str(log_item.get("address", "")).lower()
                if not ADDRESS_RE.fullmatch(pool):
                    continue
                block_unique_pools.add(pool)

                tokens = pool_cache.get(pool)
                if tokens is None:
                    rc_pool, pool_payload, resolved_tokens = _fetch_pool_tokens(
                        pool=pool,
                        block_tag=block_for_calls,
                        execute_rpc=execute_rpc,
                    )
                    pool_cache[pool] = resolved_tokens
                    tokens = resolved_tokens
                    if rc_pool != 0:
                        block_pool_failures += 1
                        pool_failures.append(
                            {
                                "block_number": block_number,
                                "block_number_hex": block_number_raw if isinstance(block_number_raw, str) else None,
                                "tx_hash": tx_hash,
                                "pool": pool,
                                "error_code": pool_payload.get("error_code"),
                                "error_message": pool_payload.get("error_message"),
                            }
                        )
                        continue

                token0, token1 = tokens
                if not token0 or not token1:
                    continue

                ok_swap, swap = _decode_swap(
                    log_item=log_item,
                    topic0=topic0,
                    pool=pool,
                    token0=token0,
                    token1=token1,
                    log_index=idx,
                )
                if ok_swap and isinstance(swap, dict):
                    swaps.append(swap)

            if not swaps:
                continue
            txs_with_swaps += 1

            candidate = _build_candidate(
                tx_hash=tx_hash,
                tx_from=tx_from,
                tx_to=tx_to,
                tx_value=tx_value,
                swaps=swaps,
                min_swaps=min_swaps,
                include_swaps=include_swaps,
            )
            if candidate is not None:
                candidate["block_number"] = block_number
                candidate["block_number_hex"] = block_number_raw if isinstance(block_number_raw, str) else None
                candidate["block_hash"] = block_result.get("hash")
                candidate["block_timestamp_utc"] = block_timestamp_utc
                candidates.append(candidate)
                block_candidates.append(candidate)

        receipt_source = "eth_getTransactionReceipt"
        if receipts_from_block > 0 and receipts_from_per_tx > 0:
            receipt_source = "mixed"
        elif receipts_from_block > 0:
            receipt_source = "eth_getBlockReceipts"

        block_row: dict[str, Any] = {
            "requested_block": block_tag,
            "number": block_number,
            "number_hex": block_number_raw if isinstance(block_number_raw, str) else None,
            "hash": block_result.get("hash"),
            "timestamp_utc": block_timestamp_utc,
            "tx_count_total": len(txs),
            "tx_count_scanned": len(txs_to_scan),
            "transactions_with_swap_logs": txs_with_swaps,
            "arbitrage_candidates_total": len(block_candidates),
            "receipt_failures": block_receipt_failures,
            "pool_metadata_failures": block_pool_failures,
            "unique_pools_seen": len(block_unique_pools),
            "receipt_source": receipt_source,
            "receipts_from_block": receipts_from_block,
            "receipts_from_transaction_calls": receipts_from_per_tx,
        }
        if block_receipts_error is not None:
            block_row["block_receipts_error"] = block_receipts_error
        block_rows.append(block_row)

        tx_count_total += len(txs)
        tx_count_scanned += len(txs_to_scan)
        txs_with_swaps_total += txs_with_swaps

    candidates.sort(
        key=lambda item: (
            1 if bool(item.get("has_cycle")) else 0,
            int(item.get("swap_count", 0)),
            int(item.get("continuity_links", 0)),
            int(item.get("unique_pools", 0)),
        ),
        reverse=True,
    )
    returned_candidates = candidates[:limit]

    summary: dict[str, Any] = {
        "transactions_with_swap_logs": txs_with_swaps_total,
        "arbitrage_candidates_total": len(candidates),
        "arbitrage_candidates_returned": len(returned_candidates),
        "receipt_failures": len(receipt_failures),
        "pool_metadata_failures": len(pool_failures),
        "unique_pools_seen": len(pool_cache),
        "blocks_scanned": len(block_rows),
        "tx_count_total": tx_count_total,
        "tx_count_scanned": tx_count_scanned,
        "receipt_collection": {
            "eth_getBlockReceipts_blocks": block_receipt_fastpath_success,
            "eth_getBlockReceipts_failures": block_receipt_fastpath_failures,
            "eth_getBlockReceipts_method_missing": block_receipt_fastpath_method_missing,
            "eth_getTransactionReceipt_calls": per_tx_receipt_calls,
        },
    }

    return 0, {
        "ok": True,
        "summary": summary,
        "blocks": block_rows,
        "candidates": returned_candidates,
        "receipt_failures": receipt_failures,
        "pool_failures": pool_failures,
    }

