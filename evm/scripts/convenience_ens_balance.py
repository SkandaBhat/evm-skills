"""ENS resolution + balance convenience command engine."""

from __future__ import annotations

import re
from typing import Any, Callable

from error_map import ERR_INTERNAL, ERR_INVALID_REQUEST

ENS_REGISTRY = "0x00000000000c2e074ec69a0dfb2997ba6c7d2e1e"
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
HEX32_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")

RpcExecutor = Callable[[dict[str, Any]], tuple[int, dict[str, Any]]]
ErrorBuilder = Callable[..., dict[str, Any]]
StageFailureBuilder = Callable[[str, str, dict[str, Any]], dict[str, Any]]
NamehashFn = Callable[[str], tuple[bool, str, str]]
TransformFn = Callable[[str, Any], tuple[bool, Any, str]]
TimestampFn = Callable[[], str]


def resolve_ens_address(
    *,
    name: str,
    block_tag: str,
    execute_rpc: RpcExecutor,
    build_error_payload: ErrorBuilder,
    wrap_stage_failure: StageFailureBuilder,
    ens_namehash_fn: NamehashFn,
    apply_transform_fn: TransformFn,
    timestamp_fn: TimestampFn,
) -> tuple[int, dict[str, Any], str | None]:
    ok, nodehash, err = ens_namehash_fn(name)
    if not ok:
        payload = build_error_payload(
            method="ens_resolve",
            status="error",
            code=ERR_INVALID_REQUEST,
            message=err,
        )
        return 2, payload, None

    if not isinstance(nodehash, str) or not HEX32_RE.fullmatch(nodehash):
        payload = build_error_payload(
            method="ens_resolve",
            status="error",
            code=ERR_INTERNAL,
            message="internal namehash computation failed",
        )
        return 2, payload, None

    resolver_call_data = f"0x0178b8bf{nodehash[2:]}"
    rc_resolver, resolver_payload = execute_rpc(
        {"method": "eth_call", "params": [{"to": ENS_REGISTRY, "data": resolver_call_data}, block_tag]}
    )
    if rc_resolver != 0:
        return rc_resolver, wrap_stage_failure("ens_resolve", "resolver lookup", resolver_payload), None

    t_ok, resolver_addr, t_err = apply_transform_fn(
        "slice_last_20_bytes_to_address", resolver_payload.get("result")
    )
    if not t_ok or not isinstance(resolver_addr, str):
        payload = build_error_payload(
            method="ens_resolve",
            status="error",
            code=ERR_INVALID_REQUEST,
            message=f"resolver lookup parse failed: {t_err}",
        )
        payload["resolver_call"] = resolver_payload
        return 2, payload, None

    if resolver_addr.lower() == ZERO_ADDRESS:
        payload = build_error_payload(
            method="ens_resolve",
            status="error",
            code=ERR_INVALID_REQUEST,
            message="ens resolver is not set for name",
        )
        payload["nodehash"] = nodehash
        payload["resolver"] = resolver_addr
        return 2, payload, None

    addr_call_data = f"0x3b3b57de{nodehash[2:]}"
    rc_addr, addr_payload = execute_rpc(
        {"method": "eth_call", "params": [{"to": resolver_addr, "data": addr_call_data}, block_tag]}
    )
    if rc_addr != 0:
        return rc_addr, wrap_stage_failure("ens_resolve", "address lookup", addr_payload), None

    a_ok, resolved_addr, a_err = apply_transform_fn(
        "slice_last_20_bytes_to_address", addr_payload.get("result")
    )
    if not a_ok or not isinstance(resolved_addr, str):
        payload = build_error_payload(
            method="ens_resolve",
            status="error",
            code=ERR_INVALID_REQUEST,
            message=f"address lookup parse failed: {a_err}",
        )
        payload["resolver"] = resolver_addr
        payload["address_call"] = addr_payload
        return 2, payload, None

    payload = {
        "timestamp_utc": timestamp_fn(),
        "method": "ens_resolve",
        "status": "ok",
        "ok": True,
        "error_code": None,
        "error_message": None,
        "name": name,
        "nodehash": nodehash,
        "resolver": resolver_addr,
        "result": resolved_addr,
        "resolver_call": resolver_payload,
        "address_call": addr_payload,
    }
    return 0, payload, resolved_addr


def resolve_balance(
    *,
    target: str,
    at: str,
    execute_rpc: RpcExecutor,
    resolve_ens_address_fn: Callable[[str], tuple[int, dict[str, Any], str | None]],
    build_error_payload: ErrorBuilder,
    wrap_stage_failure: StageFailureBuilder,
    apply_transform_fn: TransformFn,
    timestamp_fn: TimestampFn,
) -> tuple[int, dict[str, Any]]:
    normalized_target = str(target).strip()
    if not normalized_target:
        payload = build_error_payload(
            method="balance",
            status="error",
            code=ERR_INVALID_REQUEST,
            message="target cannot be empty",
        )
        return 2, payload

    resolved_address = normalized_target
    resolution_payload: dict[str, Any] | None = None
    if "." in normalized_target:
        rc_resolve, ens_payload, ens_addr = resolve_ens_address_fn(normalized_target)
        if rc_resolve != 0 or not ens_addr:
            wrapped = wrap_stage_failure("balance", "ens resolution", ens_payload)
            return rc_resolve, wrapped
        resolved_address = ens_addr
        resolution_payload = ens_payload

    if not ADDRESS_RE.fullmatch(resolved_address):
        payload = build_error_payload(
            method="balance",
            status="error",
            code=ERR_INVALID_REQUEST,
            message="target must be a 20-byte hex address or ENS name",
        )
        return 2, payload

    exit_code, balance_payload = execute_rpc({"method": "eth_getBalance", "params": [resolved_address, at]})
    if exit_code != 0:
        wrapped = wrap_stage_failure("balance", "eth_getBalance", balance_payload)
        return exit_code, wrapped

    t_ok, eth_value, t_err = apply_transform_fn("wei_to_eth", balance_payload.get("result"))
    if not t_ok:
        payload = build_error_payload(
            method="balance",
            status="error",
            code=ERR_INVALID_REQUEST,
            message=t_err,
        )
        return 2, payload

    payload = {
        "timestamp_utc": timestamp_fn(),
        "method": "balance",
        "status": "ok",
        "ok": True,
        "error_code": None,
        "error_message": None,
        "target": normalized_target,
        "resolved_address": resolved_address,
        "at": at,
        "result": {
            "wei_hex": balance_payload.get("result"),
            "eth": eth_value,
        },
        "balance_call": balance_payload,
    }
    if resolution_payload is not None:
        payload["ens_resolution"] = resolution_payload

    return 0, payload

