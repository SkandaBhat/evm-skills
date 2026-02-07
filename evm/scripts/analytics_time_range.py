"""Helpers to resolve human-friendly windows into block ranges."""

from __future__ import annotations

import re
from typing import Any, Callable

from quantity import parse_nonnegative_quantity_str

ERR_ANALYTICS_INVALID_RANGE = "ANALYTICS_INVALID_RANGE"
ERR_ANALYTICS_RANGE_RESOLUTION_FAILED = "ANALYTICS_RANGE_RESOLUTION_FAILED"

RpcExecutor = Callable[[dict[str, Any]], tuple[int, dict[str, Any]]]

SINCE_RE = re.compile(r"^\s*(\d+)\s*([smhdw])\s*$", re.IGNORECASE)


def _parse_since_seconds(raw: str) -> int:
    m = SINCE_RE.fullmatch(str(raw))
    if not m:
        raise ValueError("since must look like <int><unit>, e.g. 30m, 24h, 7d")
    qty = int(m.group(1), 10)
    unit = m.group(2).lower()
    scale = {
        "s": 1,
        "m": 60,
        "h": 3600,
        "d": 86400,
        "w": 604800,
    }[unit]
    return qty * scale


def _rpc_req(
    *,
    method: str,
    params: list[Any],
    context: dict[str, Any],
    env: dict[str, Any],
    timeout_seconds: float,
) -> dict[str, Any]:
    req: dict[str, Any] = {
        "method": method,
        "params": params,
        "context": context,
        "timeout_seconds": timeout_seconds,
    }
    if env:
        req["env"] = env
    return req


def _get_latest_block(
    *,
    execute_rpc: RpcExecutor,
    context: dict[str, Any],
    env: dict[str, Any],
    timeout_seconds: float,
) -> tuple[int, dict[str, Any] | None, int | None]:
    rc, payload = execute_rpc(
        _rpc_req(
            method="eth_blockNumber",
            params=[],
            context=context,
            env=env,
            timeout_seconds=timeout_seconds,
        )
    )
    if rc != 0:
        return rc, payload, None
    result = payload.get("result")
    if not isinstance(result, str):
        return 2, {
            "error_code": ERR_ANALYTICS_RANGE_RESOLUTION_FAILED,
            "error_message": "eth_blockNumber returned non-string result",
            "cause": payload,
        }, None
    try:
        return 0, None, parse_nonnegative_quantity_str(result)
    except Exception as err:  # noqa: BLE001
        return 2, {
            "error_code": ERR_ANALYTICS_RANGE_RESOLUTION_FAILED,
            "error_message": f"invalid block number quantity: {err}",
            "cause": payload,
        }, None


def _get_block_timestamp(
    *,
    block_number: int,
    execute_rpc: RpcExecutor,
    context: dict[str, Any],
    env: dict[str, Any],
    timeout_seconds: float,
) -> tuple[int, dict[str, Any] | None, int | None]:
    block_hex = hex(block_number)
    rc, payload = execute_rpc(
        _rpc_req(
            method="eth_getBlockByNumber",
            params=[block_hex, False],
            context=context,
            env=env,
            timeout_seconds=timeout_seconds,
        )
    )
    if rc != 0:
        return rc, payload, None
    result = payload.get("result")
    if not isinstance(result, dict):
        return 2, {
            "error_code": ERR_ANALYTICS_RANGE_RESOLUTION_FAILED,
            "error_message": "eth_getBlockByNumber returned non-object result",
            "cause": payload,
        }, None
    ts = result.get("timestamp")
    if not isinstance(ts, str):
        return 2, {
            "error_code": ERR_ANALYTICS_RANGE_RESOLUTION_FAILED,
            "error_message": "block timestamp missing or non-string",
            "cause": payload,
        }, None
    try:
        return 0, None, parse_nonnegative_quantity_str(ts)
    except Exception as err:  # noqa: BLE001
        return 2, {
            "error_code": ERR_ANALYTICS_RANGE_RESOLUTION_FAILED,
            "error_message": f"invalid block timestamp quantity: {err}",
            "cause": payload,
        }, None


def resolve_block_window(
    *,
    execute_rpc: RpcExecutor,
    context: dict[str, Any],
    env: dict[str, Any],
    timeout_seconds: float,
    last_blocks: int | None,
    since: str | None,
) -> tuple[int, dict[str, Any]]:
    if last_blocks is not None and since is not None:
        return 2, {
            "error_code": ERR_ANALYTICS_INVALID_RANGE,
            "error_message": "--last-blocks and --since are mutually exclusive",
        }
    if last_blocks is None and since is None:
        return 2, {
            "error_code": ERR_ANALYTICS_INVALID_RANGE,
            "error_message": "must provide either --last-blocks or --since",
        }

    latest_rc, latest_err, latest_block = _get_latest_block(
        execute_rpc=execute_rpc,
        context=context,
        env=env,
        timeout_seconds=timeout_seconds,
    )
    if latest_rc != 0 or latest_block is None:
        return latest_rc, {
            "error_code": ERR_ANALYTICS_RANGE_RESOLUTION_FAILED,
            "error_message": "failed to resolve latest block",
            "cause": latest_err,
        }

    if last_blocks is not None:
        if isinstance(last_blocks, bool) or last_blocks <= 0:
            return 2, {
                "error_code": ERR_ANALYTICS_INVALID_RANGE,
                "error_message": "--last-blocks must be a positive integer",
            }
        from_block = max(0, latest_block - int(last_blocks) + 1)
        return 0, {
            "from_block": from_block,
            "to_block": latest_block,
            "basis": "last_blocks",
            "last_blocks": int(last_blocks),
            "latest_block": latest_block,
        }

    try:
        since_seconds = _parse_since_seconds(str(since))
    except Exception as err:  # noqa: BLE001
        return 2, {
            "error_code": ERR_ANALYTICS_INVALID_RANGE,
            "error_message": str(err),
        }

    latest_ts_rc, latest_ts_err, latest_ts = _get_block_timestamp(
        block_number=latest_block,
        execute_rpc=execute_rpc,
        context=context,
        env=env,
        timeout_seconds=timeout_seconds,
    )
    if latest_ts_rc != 0 or latest_ts is None:
        return latest_ts_rc, {
            "error_code": ERR_ANALYTICS_RANGE_RESOLUTION_FAILED,
            "error_message": "failed to resolve latest block timestamp",
            "cause": latest_ts_err,
        }

    target_ts = max(0, latest_ts - since_seconds)
    low = 0
    high = latest_block
    ts_cache: dict[int, int] = {latest_block: latest_ts}

    def get_ts(block_num: int) -> tuple[int, dict[str, Any] | None, int | None]:
        cached = ts_cache.get(block_num)
        if cached is not None:
            return 0, None, cached
        rc, err, ts_val = _get_block_timestamp(
            block_number=block_num,
            execute_rpc=execute_rpc,
            context=context,
            env=env,
            timeout_seconds=timeout_seconds,
        )
        if rc == 0 and ts_val is not None:
            ts_cache[block_num] = ts_val
        return rc, err, ts_val

    while low < high:
        mid = (low + high) // 2
        ts_rc, ts_err, mid_ts = get_ts(mid)
        if ts_rc != 0 or mid_ts is None:
            return ts_rc, {
                "error_code": ERR_ANALYTICS_RANGE_RESOLUTION_FAILED,
                "error_message": f"failed while resolving timestamp for block {mid}",
                "cause": ts_err,
            }
        if mid_ts < target_ts:
            low = mid + 1
        else:
            high = mid

    return 0, {
        "from_block": low,
        "to_block": latest_block,
        "basis": "since",
        "since": str(since),
        "since_seconds": since_seconds,
        "target_timestamp": target_ts,
        "latest_block": latest_block,
        "latest_timestamp": latest_ts,
    }
