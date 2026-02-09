"""Pool metadata helpers for analytics commands."""

from __future__ import annotations

from typing import Any, Callable

from analytics_registry import ERC20_DECIMALS_SELECTOR, UNISWAP_V2_TOKEN0_SELECTOR, UNISWAP_V2_TOKEN1_SELECTOR
from error_map import ERR_INVALID_REQUEST

RpcExecutor = Callable[[dict[str, Any]], tuple[int, dict[str, Any]]]
ErrorBuilder = Callable[..., dict[str, Any]]
StageFailureBuilder = Callable[[str, str, dict[str, Any]], dict[str, Any]]
TransformFn = Callable[[str, Any], tuple[bool, Any, str]]


def _hex_to_int(value: Any) -> tuple[bool, int, str]:
    if not isinstance(value, str):
        return False, 0, "expected hex quantity string"
    try:
        if value.startswith("0x"):
            return True, int(value, 16), ""
        return True, int(value, 10), ""
    except Exception:  # noqa: BLE001
        return False, 0, f"invalid quantity: {value}"


def _eth_call_result(
    *,
    to: str,
    data: str,
    block_tag: str,
    execute_rpc: RpcExecutor,
    build_error_payload: ErrorBuilder,
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
        return 2, build_error_payload(
            method="analytics",
            status="error",
            code=ERR_INVALID_REQUEST,
            message="eth_call returned non-string result",
        ), None
    return 0, None, result


def _word_to_address(word_hex: str, *, apply_transform_fn: TransformFn) -> tuple[bool, str, str]:
    ok, value, err = apply_transform_fn("slice_last_20_bytes_to_address", word_hex)
    if not ok or not isinstance(value, str):
        return False, "", err or "failed to decode address"
    return True, value, ""


def fetch_uniswap_v2_pool_metadata(
    *,
    pool: str,
    block_tag: str,
    execute_rpc: RpcExecutor,
    build_error_payload: ErrorBuilder,
    wrap_stage_failure: StageFailureBuilder,
    apply_transform_fn: TransformFn,
) -> tuple[int, dict[str, Any]]:
    rc0, cause0, token0_raw = _eth_call_result(
        to=pool,
        data=UNISWAP_V2_TOKEN0_SELECTOR,
        block_tag=block_tag,
        execute_rpc=execute_rpc,
        build_error_payload=build_error_payload,
    )
    if rc0 != 0 or token0_raw is None:
        return rc0, wrap_stage_failure("analytics.dex_swap_flow", "token0()", cause0 or {})
    rc1, cause1, token1_raw = _eth_call_result(
        to=pool,
        data=UNISWAP_V2_TOKEN1_SELECTOR,
        block_tag=block_tag,
        execute_rpc=execute_rpc,
        build_error_payload=build_error_payload,
    )
    if rc1 != 0 or token1_raw is None:
        return rc1, wrap_stage_failure("analytics.dex_swap_flow", "token1()", cause1 or {})

    ok0, token0, err0 = _word_to_address(token0_raw, apply_transform_fn=apply_transform_fn)
    if not ok0:
        return 2, build_error_payload(
            method="analytics.dex_swap_flow",
            status="error",
            code=ERR_INVALID_REQUEST,
            message=f"token0 decode failed: {err0}",
        )
    ok1, token1, err1 = _word_to_address(token1_raw, apply_transform_fn=apply_transform_fn)
    if not ok1:
        return 2, build_error_payload(
            method="analytics.dex_swap_flow",
            status="error",
            code=ERR_INVALID_REQUEST,
            message=f"token1 decode failed: {err1}",
        )

    def read_decimals(token: str) -> tuple[int, dict[str, Any] | None, int | None]:
        rc, cause, raw = _eth_call_result(
            to=token,
            data=ERC20_DECIMALS_SELECTOR,
            block_tag=block_tag,
            execute_rpc=execute_rpc,
            build_error_payload=build_error_payload,
        )
        if rc != 0 or raw is None:
            return rc, cause, None
        ok, val, err = _hex_to_int(raw)
        if not ok:
            return 2, build_error_payload(
                method="analytics.dex_swap_flow",
                status="error",
                code=ERR_INVALID_REQUEST,
                message=f"decimals decode failed for {token}: {err}",
            ), None
        return 0, None, int(val)

    rcd0, caused0, decimals0 = read_decimals(token0)
    if rcd0 != 0 or decimals0 is None:
        return rcd0, wrap_stage_failure(
            "analytics.dex_swap_flow",
            f"decimals() token0 {token0}",
            caused0 or {},
        )
    rcd1, caused1, decimals1 = read_decimals(token1)
    if rcd1 != 0 or decimals1 is None:
        return rcd1, wrap_stage_failure(
            "analytics.dex_swap_flow",
            f"decimals() token1 {token1}",
            caused1 or {},
        )

    return 0, {
        "token0": token0.lower(),
        "token1": token1.lower(),
        "decimals0": decimals0,
        "decimals1": decimals1,
    }

