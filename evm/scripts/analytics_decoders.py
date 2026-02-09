"""Analytics log-row decoder helpers."""

from __future__ import annotations

from typing import Any, Callable

from abi_codec import decode_log
from analytics_registry import UNISWAP_V2_SWAP_EVENT

FormatUnitsFn = Callable[[str, int], str]


def decode_swap_flow_rows(
    *,
    items: list[Any],
    decimals0: int,
    decimals1: int,
    format_units_fn: FormatUnitsFn,
) -> tuple[list[dict[str, Any]], int]:
    rows: list[dict[str, Any]] = []
    decode_failures = 0
    for item in items:
        if not isinstance(item, dict):
            decode_failures += 1
            continue
        try:
            decoded = decode_log(
                UNISWAP_V2_SWAP_EVENT,
                list(item.get("topics", [])),
                str(item.get("data", "0x")),
                anonymous=False,
            )
            args_out = decoded.get("args", [])
            row = {
                "block_number": item.get("blockNumber"),
                "tx_hash": item.get("transactionHash"),
                "log_index": item.get("logIndex"),
                "sender": str(args_out[0].get("value")).lower(),
                "to": str(args_out[5].get("value")).lower(),
                "amount0_in_raw": str(args_out[1].get("value")),
                "amount1_in_raw": str(args_out[2].get("value")),
                "amount0_out_raw": str(args_out[3].get("value")),
                "amount1_out_raw": str(args_out[4].get("value")),
            }
            amount0_net = int(row["amount0_in_raw"]) - int(row["amount0_out_raw"])
            amount1_net = int(row["amount1_in_raw"]) - int(row["amount1_out_raw"])
            row["pool_token0_net_raw"] = str(amount0_net)
            row["pool_token1_net_raw"] = str(amount1_net)
            row["pool_token0_net"] = format_units_fn(str(amount0_net), decimals0)
            row["pool_token1_net"] = format_units_fn(str(amount1_net), decimals1)
            row["amount0_in"] = format_units_fn(row["amount0_in_raw"], decimals0)
            row["amount0_out"] = format_units_fn(row["amount0_out_raw"], decimals0)
            row["amount1_in"] = format_units_fn(row["amount1_in_raw"], decimals1)
            row["amount1_out"] = format_units_fn(row["amount1_out_raw"], decimals1)
            rows.append(row)
        except Exception:
            decode_failures += 1
    return rows, decode_failures


def decode_factory_new_pool_rows(
    *,
    items: list[Any],
    protocol: str,
    event_decl: str,
) -> tuple[list[dict[str, Any]], int]:
    rows: list[dict[str, Any]] = []
    decode_failures = 0
    for item in items:
        if not isinstance(item, dict):
            decode_failures += 1
            continue
        try:
            decoded = decode_log(
                event_decl,
                list(item.get("topics", [])),
                str(item.get("data", "0x")),
                anonymous=False,
            )
            args_out = decoded.get("args", [])
            if protocol == "uniswap-v2":
                row = {
                    "block_number": item.get("blockNumber"),
                    "tx_hash": item.get("transactionHash"),
                    "log_index": item.get("logIndex"),
                    "token0": str(args_out[0].get("value")).lower(),
                    "token1": str(args_out[1].get("value")).lower(),
                    "pool": str(args_out[2].get("value")).lower(),
                    "pair_index_raw": str(args_out[3].get("value")),
                }
            else:
                row = {
                    "block_number": item.get("blockNumber"),
                    "tx_hash": item.get("transactionHash"),
                    "log_index": item.get("logIndex"),
                    "token0": str(args_out[0].get("value")).lower(),
                    "token1": str(args_out[1].get("value")).lower(),
                    "fee_raw": str(args_out[2].get("value")),
                    "tick_spacing_raw": str(args_out[3].get("value")),
                    "pool": str(args_out[4].get("value")).lower(),
                }
            rows.append(row)
        except Exception:
            decode_failures += 1
    return rows, decode_failures

