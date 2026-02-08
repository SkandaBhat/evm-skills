#!/usr/bin/env python3
"""Agent-facing JSON wrapper around Ethereum JSON-RPC."""

from __future__ import annotations

import argparse
import copy
import csv
import gzip
import hashlib
import json
import re
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Local imports for script execution (python3 scripts/evm_rpc.py ...)
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from error_map import (  # noqa: E402
    ERR_ADAPTER_VALIDATION,
    ERR_ABI_DECODE_FAILED,
    ERR_ABI_ENCODE_FAILED,
    ERR_INVALID_BLOCK_RANGE,
    ERR_INVALID_LOG_ADDRESS,
    ERR_INTERNAL,
    ERR_INVALID_REQUEST,
    ERR_INVALID_TOPIC_FORMAT,
    ERR_INVALID_TOPIC_LENGTH,
    ERR_LOGS_RANGE_TOO_LARGE,
    ERR_MULTICALL_PARTIAL_FAILURE,
    ERR_POLICY_DENIED,
    ERR_RPC_BROADCAST_ALREADY_KNOWN,
    ERR_RPC_BROADCAST_INSUFFICIENT_FUNDS,
    ERR_RPC_BROADCAST_NONCE_TOO_LOW,
    ERR_RPC_BROADCAST_UNDERPRICED,
    ERR_RPC_REMOTE,
    ERR_RPC_TRANSPORT,
    ERR_SIMULATION_REVERTED,
    ERR_TRACE_UNSUPPORTED,
    ERR_RPC_TIMEOUT,
)
from adapters import validate_adapter_preflight  # noqa: E402
from abi_codec import decode_log, event_topic0, run_abi_operation  # noqa: E402
from analytics_aggregators import summarize_swap_rows  # noqa: E402
from analytics_registry import (  # noqa: E402
    ERC20_DECIMALS_SELECTOR,
    UNISWAP_V2_PAIR_CREATED_EVENT,
    UNISWAP_V2_PAIR_CREATED_TOPIC0,
    UNISWAP_V2_SWAP_EVENT,
    UNISWAP_V2_SWAP_TOPIC0,
    UNISWAP_V2_TOKEN0_SELECTOR,
    UNISWAP_V2_TOKEN1_SELECTOR,
    UNISWAP_V3_POOL_CREATED_EVENT,
    UNISWAP_V3_POOL_CREATED_TOPIC0,
    UNISWAP_V3_SWAP_TOPIC0,
)
from analytics_scanner import scan_logs  # noqa: E402
from analytics_time_range import resolve_block_window  # noqa: E402
from cast_adapter import cast_format_units  # noqa: E402
from method_registry import load_manifest_by_method, load_json  # noqa: E402
from multicall_engine import normalize_multicall_request, run_multicall  # noqa: E402
from policy_eval import evaluate_policy  # noqa: E402
from rpc_contract import (  # noqa: E402
    DEFAULT_TIMEOUT_SECONDS,
    build_execution_env,
    normalized_context,
    parse_request_from_args,
    resolve_rpc_endpoints,
    validate_request,
)
from rpc_transport import invoke_rpc  # noqa: E402
from simulate_engine import normalize_simulation_request, run_simulation  # noqa: E402
from trace_engine import normalize_trace_request, run_trace  # noqa: E402
from transforms import apply_transform, ens_namehash  # noqa: E402
from quantity import parse_nonnegative_quantity_str  # noqa: E402
from logs_engine import (  # noqa: E402
    DEFAULT_HEAVY_READ_THRESHOLD,
    is_heavy_read,
    normalize_logs_request,
    run_chunked_logs,
)

DEFAULT_MANIFEST = (SCRIPT_DIR.parent / "references" / "method-manifest.json").resolve()

ENS_REGISTRY = "0x00000000000c2e074ec69a0dfb2997ba6c7d2e1e"
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
HEX32_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
TEMPLATE_FULL_RE = re.compile(r"^\{\{\s*([^{}]+?)\s*\}\}$")
TEMPLATE_ANY_RE = re.compile(r"\{\{\s*([^{}]+?)\s*\}\}")

KNOWN_EVENT_SIGNATURES: dict[str, str] = {
    "transfer": "Transfer(address,address,uint256)",
    "approval": "Approval(address,address,uint256)",
}
ERC20_TRANSFER_EVENT_DECL = "Transfer(address indexed from,address indexed to,uint256 value)"
# Fixed keccak256("Transfer(address,address,uint256)") topic0.
ERC20_TRANSFER_TOPIC0 = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
ARBITRAGE_KNOWN_SYMBOLS: dict[str, str] = {
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": "WETH",
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": "USDC",
    "0xdac17f958d2ee523a2206206994597c13d831ec7": "USDT",
    "0x6b175474e89094c44da98b954eedeac495271d0f": "DAI",
    "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599": "WBTC",
    "0xae7ab96520de3a18e5e111b5eaab095312d7fe84": "stETH",
    "0x7f39c581f595b53c5cb6a5f1a9f8da6c935e2ca0": "wstETH",
}


def _json_dump(payload: Any, pretty: bool = True) -> str:
    return json.dumps(payload, indent=2 if pretty else None, sort_keys=False)


def _timestamp() -> str:
    return datetime.now(UTC).isoformat()


def _base_response(method: str) -> dict[str, Any]:
    return {
        "timestamp_utc": _timestamp(),
        "method": method,
        "status": "error",
        "ok": False,
        "error_code": ERR_INTERNAL,
        "error_message": "unset",
    }


def _sanitized_request(req: dict[str, Any]) -> dict[str, Any]:
    out = dict(req)
    if "env" in out:
        out["env"] = {"keys": sorted(str(k) for k in out.get("env", {}).keys())}
    return out


def _sanitized_chain_request(req: dict[str, Any]) -> dict[str, Any]:
    out = dict(req)
    if "env" in out and isinstance(out["env"], dict):
        out["env"] = {"keys": sorted(str(k) for k in out["env"].keys())}
    steps = out.get("steps")
    if isinstance(steps, list):
        sanitized_steps: list[Any] = []
        for step in steps:
            if not isinstance(step, dict):
                sanitized_steps.append(step)
                continue
            step_copy = dict(step)
            if "env" in step_copy and isinstance(step_copy["env"], dict):
                step_copy["env"] = {"keys": sorted(str(k) for k in step_copy["env"].keys())}
            sanitized_steps.append(step_copy)
        out["steps"] = sanitized_steps
    return out


def _build_error_payload(
    *,
    method: str,
    status: str,
    code: str,
    message: str,
    policy: dict[str, Any] | None = None,
    request: dict[str, Any] | None = None,
    rpc_request: dict[str, Any] | None = None,
    rpc_response: dict[str, Any] | None = None,
    duration_ms: int | None = None,
    hint: str | None = None,
) -> dict[str, Any]:
    payload = _base_response(method)
    payload.update(
        {
            "status": status,
            "ok": False,
            "error_code": code,
            "error_message": message,
        }
    )
    if policy is not None:
        payload["policy"] = policy
    if request is not None:
        payload["request"] = _sanitized_request(request)
    if rpc_request is not None:
        payload["rpc_request"] = rpc_request
    if rpc_response is not None:
        payload["rpc_response"] = rpc_response
    if duration_ms is not None:
        payload["duration_ms"] = duration_ms
    if hint:
        payload["hint"] = hint
    return payload


def _print_error(
    *,
    method: str,
    status: str,
    code: str,
    message: str,
    pretty: bool,
    policy: dict[str, Any] | None = None,
    request: dict[str, Any] | None = None,
    rpc_request: dict[str, Any] | None = None,
    rpc_response: dict[str, Any] | None = None,
    duration_ms: int | None = None,
    hint: str | None = None,
) -> None:
    payload = _build_error_payload(
        method=method,
        status=status,
        code=code,
        message=message,
        policy=policy,
        request=request,
        rpc_request=rpc_request,
        rpc_response=rpc_response,
        duration_ms=duration_ms,
        hint=hint,
    )
    print(_json_dump(payload, pretty=pretty))


def _print_selected_value(value: Any, *, compact: bool) -> None:
    if isinstance(value, (dict, list)):
        print(_json_dump(value, pretty=not compact))
        return
    if value is None:
        print("null")
        return
    if isinstance(value, bool):
        print("true" if value else "false")
        return
    print(str(value))


def _parse_path_segments(path: str, *, require_root: bool = True) -> tuple[bool, list[tuple[str, Any]], str]:
    if not isinstance(path, str) or not path:
        return False, [], "path must be a non-empty string"

    i = 0
    if require_root:
        if not path.startswith("$"):
            return False, [], "path must start with '$'"
        i = 1

    segments: list[tuple[str, Any]] = []
    while i < len(path):
        ch = path[i]
        if ch == ".":
            i += 1
            start = i
            while i < len(path) and path[i] not in ".[":
                i += 1
            key = path[start:i]
            if not key:
                return False, [], "invalid path: empty key segment"
            segments.append(("key", key))
            continue
        if ch == "[":
            i += 1
            start = i
            while i < len(path) and path[i].isdigit():
                i += 1
            if start == i or i >= len(path) or path[i] != "]":
                return False, [], "invalid path: list index must be numeric and closed with ']'"
            idx = int(path[start:i], 10)
            i += 1
            segments.append(("idx", idx))
            continue
        return False, [], f"invalid path syntax at position {i}"
    return True, segments, ""


def _select_by_segments(value: Any, segments: list[tuple[str, Any]]) -> tuple[bool, Any, str]:
    current = value
    for kind, token in segments:
        if kind == "key":
            if not isinstance(current, dict):
                return False, None, f"cannot select key '{token}' from non-object"
            if token not in current:
                return False, None, f"key '{token}' not found"
            current = current[token]
            continue
        if kind == "idx":
            if not isinstance(current, list):
                return False, None, f"cannot select index [{token}] from non-array"
            if token < 0 or token >= len(current):
                return False, None, f"index [{token}] out of range"
            current = current[token]
            continue
    return True, current, ""


def _select_jsonpath(value: Any, path: str) -> tuple[bool, Any, str]:
    ok, segments, err = _parse_path_segments(path, require_root=True)
    if not ok:
        return False, None, err
    return _select_by_segments(value, segments)


def _resolve_template_expr(expr: str, outputs_by_id: dict[str, Any]) -> Any:
    raw = str(expr).strip()
    if not raw:
        raise ValueError("template expression is empty")

    m = re.match(r"^([A-Za-z_][A-Za-z0-9_-]*)(.*)$", raw)
    if not m:
        raise ValueError(f"invalid template expression: {raw}")

    step_id = m.group(1)
    rest = m.group(2)
    if step_id not in outputs_by_id:
        raise ValueError(f"template reference step '{step_id}' not found")

    base = outputs_by_id[step_id]
    if not rest:
        return base

    if rest[0] not in ".[":
        rest = "." + rest
    ok, segments, err = _parse_path_segments(f"${rest}", require_root=True)
    if not ok:
        raise ValueError(f"invalid template path '{raw}': {err}")
    ok, value, select_err = _select_by_segments(base, segments)
    if not ok:
        raise ValueError(f"template path '{raw}' failed: {select_err}")
    return value


def _resolve_templates(value: Any, outputs_by_id: dict[str, Any]) -> Any:
    if isinstance(value, str):
        full_match = TEMPLATE_FULL_RE.fullmatch(value)
        if full_match:
            return _resolve_template_expr(full_match.group(1), outputs_by_id)

        def replace_match(match: re.Match[str]) -> str:
            resolved = _resolve_template_expr(match.group(1), outputs_by_id)
            return str(resolved)

        return TEMPLATE_ANY_RE.sub(replace_match, value)

    if isinstance(value, list):
        return [_resolve_templates(item, outputs_by_id) for item in value]

    if isinstance(value, dict):
        return {k: _resolve_templates(v, outputs_by_id) for k, v in value.items()}

    return value


def _map_broadcast_remote_error(rpc_response: dict[str, Any]) -> str:
    err = rpc_response.get("error")
    if not isinstance(err, dict):
        return ERR_RPC_REMOTE
    message = str(err.get("message", "")).lower()
    if "already known" in message:
        return ERR_RPC_BROADCAST_ALREADY_KNOWN
    if "nonce too low" in message:
        return ERR_RPC_BROADCAST_NONCE_TOO_LOW
    if "replacement transaction underpriced" in message or "underpriced" in message:
        return ERR_RPC_BROADCAST_UNDERPRICED
    if "insufficient funds" in message:
        return ERR_RPC_BROADCAST_INSUFFICIENT_FUNDS
    return ERR_RPC_REMOTE


def _remote_error_hint(method: str, rpc_response: dict[str, Any]) -> str | None:
    err = rpc_response.get("error")
    if not isinstance(err, dict):
        return None

    code = err.get("code")
    message = str(err.get("message", "")).lower()
    combined = f"{method} {message}"

    if code == -32602:
        return (
            "provider rejected params (-32602). check address/topic format and "
            "block range values in your request."
        )

    range_patterns = (
        "query returned more than",
        "too many results",
        "response size exceeded",
        "range",
        "block range",
        "limit exceeded",
    )
    if any(p in combined for p in range_patterns):
        return "provider rejected range/size. reduce range, lower chunk_size, or use --last."

    timeout_patterns = ("timed out", "timeout", "deadline exceeded")
    if any(p in combined for p in timeout_patterns):
        return "provider timed out. reduce range/chunk_size or retry with a faster RPC endpoint."

    if "method not found" in combined:
        return "provider does not support this method on the current endpoint."

    return None


def _transport_error_hint(method: str, error_code: str, error_message: str) -> str | None:
    lowered = str(error_message).lower()
    if "cast is required but not installed" in lowered:
        return "install Foundry cast and ensure it is available in PATH."
    if error_code == ERR_RPC_TIMEOUT:
        if method == "eth_getLogs":
            return "eth_getLogs timed out. reduce range/chunk_size, or use --last for smaller windows."
        return "request timed out. retry or use a faster RPC endpoint."
    if error_code == ERR_RPC_REMOTE and ("timed out" in lowered or "timeout" in lowered):
        return "provider timed out. reduce payload size and retry."
    if error_code != ERR_RPC_TIMEOUT and ("429" in lowered or "rate limit" in lowered):
        return "rate limited by provider. slow down requests or switch endpoint."
    return None


def _load_manifest_or_error(manifest_path: Path) -> tuple[bool, dict[str, dict[str, Any]] | dict[str, Any]]:
    if not manifest_path.exists():
        return False, _build_error_payload(
            method="",
            status="error",
            code="MANIFEST_NOT_FOUND",
            message=f"manifest not found: {manifest_path}",
        )
    return True, load_manifest_by_method(manifest_path)


def _require_manifest(args: argparse.Namespace) -> tuple[bool, dict[str, dict[str, Any]] | int]:
    manifest_path = Path(args.manifest).resolve()
    loaded, manifest_data = _load_manifest_or_error(manifest_path)
    if not loaded:
        print(_json_dump(manifest_data, pretty=not args.compact))
        return False, 2
    return True, manifest_data


def _require_env_json(
    *,
    raw_env_json: str | None,
    method: str,
    compact: bool,
) -> tuple[bool, dict[str, Any] | int]:
    env_ok, env, env_err = _parse_env_json(raw_env_json)
    if not env_ok:
        _print_error(
            method=method,
            status="error",
            code=ERR_INVALID_REQUEST,
            message=env_err,
            pretty=not compact,
        )
        return False, 2
    return True, env


def run_rpc_request(
    *,
    req: dict[str, Any],
    manifest_by_method: dict[str, dict[str, Any]],
) -> tuple[int, dict[str, Any]]:
    valid, validation_message = validate_request(req)
    if not valid:
        return (
            2,
            _build_error_payload(
                method=str(req.get("method", "")),
                status="error",
                code=ERR_INVALID_REQUEST,
                message=validation_message,
                request=req,
            ),
        )

    method = str(req["method"]).strip()
    context = normalized_context(req.get("context"))
    policy = evaluate_policy(manifest_by_method, method, context)
    if not policy["allowed"]:
        return (
            4,
            _build_error_payload(
                method=method,
                status="denied",
                code=policy["error_code"] or "POLICY_DENIED",
                message=policy["reason"],
                policy=policy,
                request=req,
            ),
        )

    method_entry = manifest_by_method.get(method, {})
    implementation = str(method_entry.get("implementation", "proxy"))
    if implementation == "adapter":
        adapter_ok, adapter_error = validate_adapter_preflight(method, req.get("params", []))
        if not adapter_ok:
            return (
                2,
                _build_error_payload(
                    method=method,
                    status="error",
                    code=ERR_ADAPTER_VALIDATION,
                    message=adapter_error,
                    policy=policy,
                    request=req,
                ),
            )

    execution_env = build_execution_env(req)
    rpc_urls, rpc_endpoint_source = resolve_rpc_endpoints(execution_env)

    timeout_seconds = float(req.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS))
    rpc_payload = {
        "jsonrpc": "2.0",
        "id": req.get("id", 1),
        "method": method,
        "params": req.get("params", []),
    }
    retries = 0 if policy.get("tier") == "broadcast" else 2

    start = time.perf_counter()
    transport: dict[str, Any] | None = None
    attempted_endpoints = 0
    for rpc_url in rpc_urls:
        attempted_endpoints += 1
        transport = invoke_rpc(
            rpc_url=rpc_url,
            payload=rpc_payload,
            timeout_seconds=timeout_seconds,
            retries=retries,
        )
        if transport["ok"]:
            break
        if len(rpc_urls) <= 1:
            break
        if str(transport.get("error_code")) not in {ERR_RPC_TIMEOUT, ERR_RPC_TRANSPORT}:
            break

    if transport is None:
        transport = {
            "ok": False,
            "error_code": ERR_RPC_TRANSPORT,
            "error_message": "rpc endpoint resolution produced no usable endpoint",
            "rpc_response": None,
        }

    duration_ms = int((time.perf_counter() - start) * 1000)
    rpc_request_meta = {
        "jsonrpc": "2.0",
        "id": rpc_payload["id"],
        "method": method,
        "rpc_endpoint_source": rpc_endpoint_source,
        "rpc_attempted_endpoints": attempted_endpoints,
    }

    if not transport["ok"]:
        status = "timeout" if transport["error_code"] == ERR_RPC_TIMEOUT else "error"
        hint = _transport_error_hint(
            method,
            str(transport["error_code"]),
            str(transport.get("error_message", "")),
        )
        if not hint and attempted_endpoints > 1 and rpc_endpoint_source != "user_env":
            hint = (
                "all default rpc endpoints failed. set ETH_RPC_URL to your preferred provider and retry."
            )
        return (
            1,
            _build_error_payload(
                method=method,
                status=status,
                code=transport["error_code"],
                message=transport["error_message"],
                policy=policy,
                request=req,
                rpc_request=rpc_request_meta,
                rpc_response=transport.get("rpc_response"),
                duration_ms=duration_ms,
                hint=hint,
            ),
        )

    rpc_response = transport["rpc_response"]
    if isinstance(rpc_response, dict) and "error" in rpc_response:
        remote_code = (
            _map_broadcast_remote_error(rpc_response)
            if policy.get("tier") == "broadcast"
            else ERR_RPC_REMOTE
        )
        hint = _remote_error_hint(method, rpc_response)
        return (
            1,
            _build_error_payload(
                method=method,
                status="error",
                code=remote_code,
                message="rpc returned an error response",
                policy=policy,
                request=req,
                rpc_request=rpc_request_meta,
                rpc_response=rpc_response,
                duration_ms=duration_ms,
                hint=hint,
            ),
        )

    payload = {
        "timestamp_utc": _timestamp(),
        "method": method,
        "status": "ok",
        "ok": True,
        "error_code": None,
        "error_message": None,
        "policy": policy,
        "request": _sanitized_request(req),
        "rpc_request": rpc_request_meta,
        "rpc_response": rpc_response,
        "result": rpc_response.get("result") if isinstance(rpc_response, dict) else None,
        "duration_ms": duration_ms,
    }
    return 0, payload


def _render_output(
    *,
    payload: dict[str, Any],
    compact: bool,
    result_only: bool,
    select: str | None,
    result_field: str,
) -> int:
    if select:
        ok, selected, select_err = _select_jsonpath(payload, select)
        if not ok:
            error_payload = _build_error_payload(
                method=str(payload.get("method", "")),
                status="error",
                code=ERR_INVALID_REQUEST,
                message=f"invalid --select path: {select_err}",
            )
            print(_json_dump(error_payload, pretty=not compact))
            return 2
        _print_selected_value(selected, compact=compact)
        return 0

    if result_only and bool(payload.get("ok", False)):
        _print_selected_value(payload.get(result_field), compact=compact)
        return 0

    print(_json_dump(payload, pretty=not compact))
    return 0


def cmd_exec(args: argparse.Namespace) -> int:
    ok_manifest, manifest_or_rc = _require_manifest(args)
    if not ok_manifest:
        return int(manifest_or_rc)
    manifest_by_method = manifest_or_rc

    try:
        req = parse_request_from_args(args)
    except Exception as err:  # noqa: BLE001
        _print_error(
            method="",
            status="error",
            code=ERR_INVALID_REQUEST,
            message=str(err),
            pretty=not args.compact,
        )
        return 2

    exit_code, payload = run_rpc_request(req=req, manifest_by_method=manifest_by_method)
    render_rc = _render_output(
        payload=payload,
        compact=args.compact,
        result_only=bool(args.result_only),
        select=args.select,
        result_field="result",
    )
    if render_rc != 0:
        return render_rc
    return exit_code


def _parse_logs_request_from_args(args: argparse.Namespace) -> dict[str, Any]:
    if args.request_file:
        with open(args.request_file, encoding="utf-8") as f:
            return json.load(f)
    if args.request_json:
        return json.loads(args.request_json)
    raise ValueError("logs requires --request-file or --request-json")


def _sanitized_logs_request(req: dict[str, Any]) -> dict[str, Any]:
    out = dict(req)
    env = out.get("env")
    if isinstance(env, dict):
        out["env"] = {"keys": sorted(str(k) for k in env.keys())}
    return out


def _resolve_event_signature(raw_event: str) -> str:
    event = str(raw_event).strip()
    if not event:
        raise ValueError("event cannot be empty")
    if "(" in event and ")" in event:
        return event
    alias = KNOWN_EVENT_SIGNATURES.get(event.lower())
    if alias:
        return alias
    raise ValueError(f"unknown event alias: {event}")


def _apply_logs_event_filter(raw_request: dict[str, Any], event_raw: str | None) -> tuple[bool, str]:
    if not event_raw:
        return True, ""

    try:
        event_sig = _resolve_event_signature(event_raw)
        topic0 = event_topic0(event_sig)
    except Exception as err:  # noqa: BLE001
        return False, str(err)

    logs_filter = raw_request.setdefault("filter", {})
    if not isinstance(logs_filter, dict):
        return False, "logs request.filter must be an object"

    topics = logs_filter.get("topics")
    if topics is None:
        logs_filter["topics"] = [topic0]
        raw_request["event"] = event_sig
        return True, ""
    if not isinstance(topics, list):
        return True, ""
    if not topics:
        logs_filter["topics"] = [topic0]
        raw_request["event"] = event_sig
        return True, ""

    first = topics[0]
    if first is None:
        topics[0] = topic0
        raw_request["event"] = event_sig
        return True, ""
    if isinstance(first, str) and first.lower() == topic0.lower():
        raw_request["event"] = event_sig
        return True, ""

    return False, "filter.topics[0] conflicts with --event topic0"


def _parse_nonnegative_hex_or_decimal(raw: str) -> tuple[bool, int]:
    try:
        return True, parse_nonnegative_quantity_str(raw)
    except Exception:  # noqa: BLE001
        return False, 0


def _resolve_logs_last_range(
    *,
    raw_request: dict[str, Any],
    last_blocks: int | None,
    manifest_by_method: dict[str, dict[str, Any]],
) -> tuple[int, dict[str, Any] | None, dict[str, Any] | None]:
    if last_blocks is None:
        return 0, None, None

    if isinstance(last_blocks, bool) or not isinstance(last_blocks, int) or last_blocks <= 0:
        payload = _build_error_payload(
            method="logs",
            status="error",
            code=ERR_INVALID_BLOCK_RANGE,
            message="last_blocks must be a positive integer",
        )
        return 2, payload, None

    logs_filter = raw_request.setdefault("filter", {})
    if not isinstance(logs_filter, dict):
        payload = _build_error_payload(
            method="logs",
            status="error",
            code=ERR_INVALID_REQUEST,
            message="logs request.filter must be an object",
        )
        return 2, payload, None
    if "fromBlock" in logs_filter or "toBlock" in logs_filter:
        payload = _build_error_payload(
            method="logs",
            status="error",
            code=ERR_INVALID_BLOCK_RANGE,
            message="--last cannot be combined with explicit filter.fromBlock/toBlock",
        )
        return 2, payload, None

    req: dict[str, Any] = {
        "method": "eth_blockNumber",
        "params": [],
        "context": raw_request.get("context", {}) if isinstance(raw_request.get("context", {}), dict) else {},
        "timeout_seconds": float(raw_request.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)),
    }
    if isinstance(raw_request.get("env"), dict) and raw_request.get("env"):
        req["env"] = raw_request["env"]

    exit_code, latest_payload = run_rpc_request(req=req, manifest_by_method=manifest_by_method)
    if exit_code != 0:
        wrapped = _wrap_stage_failure("logs", "eth_blockNumber for --last", latest_payload)
        return exit_code, wrapped, None

    latest_raw = latest_payload.get("result")
    if not isinstance(latest_raw, str):
        payload = _build_error_payload(
            method="logs",
            status="error",
            code=ERR_INVALID_BLOCK_RANGE,
            message="eth_blockNumber returned non-string result",
        )
        payload["cause"] = latest_payload
        return 2, payload, None

    ok_latest, latest_block = _parse_nonnegative_hex_or_decimal(latest_raw)
    if not ok_latest:
        payload = _build_error_payload(
            method="logs",
            status="error",
            code=ERR_INVALID_BLOCK_RANGE,
            message="eth_blockNumber returned invalid block quantity",
        )
        payload["cause"] = latest_payload
        return 2, payload, None

    start_block = max(0, latest_block - last_blocks + 1)
    logs_filter["fromBlock"] = start_block
    logs_filter["toBlock"] = latest_block
    meta = {
        "last_blocks": last_blocks,
        "resolved_latest_block": latest_block,
        "resolved_from_block": start_block,
        "resolved_to_block": latest_block,
    }
    return 0, None, meta


def _format_scaled_decimal(raw_value: str, decimals: int) -> str:
    as_int = int(raw_value, 10)
    if decimals <= 0:
        return str(as_int)
    whole, frac = divmod(as_int, 10**decimals)
    if frac == 0:
        return str(whole)
    frac_str = f"{frac:0{decimals}d}".rstrip("0")
    return f"{whole}.{frac_str}"


def _resolve_erc20_decimals(
    *,
    token_addresses: list[str],
    context: dict[str, Any],
    env: dict[str, Any],
    timeout_seconds: float,
    manifest_by_method: dict[str, dict[str, Any]],
) -> tuple[dict[str, int | None], list[dict[str, Any]]]:
    decimals_by_token: dict[str, int | None] = {}
    failures: list[dict[str, Any]] = []

    for token in token_addresses:
        req: dict[str, Any] = {
            "method": "eth_call",
            "params": [{"to": token, "data": "0x313ce567"}, "latest"],
            "context": context,
            "timeout_seconds": timeout_seconds,
        }
        if env:
            req["env"] = env

        exit_code, payload = run_rpc_request(req=req, manifest_by_method=manifest_by_method)
        if exit_code != 0:
            decimals_by_token[token] = None
            failures.append({"token": token, "error": payload})
            continue

        result = payload.get("result")
        if not isinstance(result, str):
            decimals_by_token[token] = None
            failures.append({"token": token, "error": "decimals() returned non-string"})
            continue
        ok_value, as_int = _parse_nonnegative_hex_or_decimal(result)
        if not ok_value or as_int > 255:
            decimals_by_token[token] = None
            failures.append({"token": token, "error": f"invalid decimals() value: {result}"})
            continue
        decimals_by_token[token] = as_int

    return decimals_by_token, failures


def _decode_erc20_transfer_rows(
    *,
    logs: list[Any],
    decimals: int | None,
    decimals_auto: bool,
    context: dict[str, Any],
    env: dict[str, Any],
    timeout_seconds: float,
    manifest_by_method: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    token_addresses = sorted(
        {
            str(item.get("address", "")).lower()
            for item in logs
            if isinstance(item, dict)
            and isinstance(item.get("address"), str)
            and ADDRESS_RE.fullmatch(str(item.get("address")))
        }
    )

    decimals_by_token: dict[str, int | None] = {}
    decimals_failures: list[dict[str, Any]] = []
    if decimals is not None:
        decimals_by_token = {addr: decimals for addr in token_addresses}
    elif decimals_auto and token_addresses:
        decimals_by_token, decimals_failures = _resolve_erc20_decimals(
            token_addresses=token_addresses,
            context=context,
            env=env,
            timeout_seconds=timeout_seconds,
            manifest_by_method=manifest_by_method,
        )

    rows: list[dict[str, Any]] = []
    decode_failures = 0
    for item in logs:
        if not isinstance(item, dict):
            decode_failures += 1
            rows.append({"decode_error": "log item is not an object", "raw": item})
            continue

        token = str(item.get("address", "")).lower()
        topics = item.get("topics", [])
        data = item.get("data", "0x")
        try:
            decoded = decode_log(ERC20_TRANSFER_EVENT_DECL, topics, data, anonymous=False)
            args = decoded.get("args", [])
            from_addr = str(args[0].get("value"))
            to_addr = str(args[1].get("value"))
            value_raw = str(args[2].get("value"))
            decimals_for_token = decimals_by_token.get(token)
            value_decimal = (
                _format_scaled_decimal(value_raw, decimals_for_token)
                if isinstance(decimals_for_token, int)
                else None
            )
            rows.append(
                {
                    "from": from_addr,
                    "to": to_addr,
                    "value_raw": value_raw,
                    "value_decimal": value_decimal,
                    "decimals": decimals_for_token,
                    "token": token,
                    "blockNumber": item.get("blockNumber"),
                    "txHash": item.get("transactionHash"),
                    "logIndex": item.get("logIndex"),
                }
            )
        except Exception as err:  # noqa: BLE001
            decode_failures += 1
            rows.append(
                {
                    "decode_error": str(err),
                    "token": token,
                    "blockNumber": item.get("blockNumber"),
                    "txHash": item.get("transactionHash"),
                    "logIndex": item.get("logIndex"),
                }
            )

    summary: dict[str, Any] = {
        "decoded_rows": len(rows) - decode_failures,
        "decode_failures": decode_failures,
    }
    if decimals_by_token:
        summary["decimals_by_token"] = decimals_by_token
    if decimals_failures:
        summary["decimals_failures"] = decimals_failures
    return rows, summary


def _stable_sample(items: list[Any], sample_size: int) -> list[Any]:
    if sample_size >= len(items):
        return list(items)
    scored: list[tuple[str, int, Any]] = []
    for idx, item in enumerate(items):
        raw = json.dumps(item, sort_keys=True, separators=(",", ":"), default=str)
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        scored.append((digest, idx, item))
    scored.sort(key=lambda row: (row[0], row[1]))
    selected_idx = sorted(row[1] for row in scored[:sample_size])
    return [items[idx] for idx in selected_idx]


def _flatten_csv_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(",", ":"), sort_keys=True)
    return str(value)


def _write_logs_output(
    *,
    out_path: str,
    fmt: str,
    use_gzip: bool,
    rows: list[Any],
) -> dict[str, Any]:
    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    opener = gzip.open if use_gzip else open
    mode = "wt"
    with opener(path, mode, encoding="utf-8", newline="") as handle:  # type: ignore[arg-type]
        if fmt == "json":
            handle.write(_json_dump(rows, pretty=False))
            handle.write("\n")
        elif fmt == "jsonl":
            for row in rows:
                handle.write(json.dumps(row, separators=(",", ":"), sort_keys=False))
                handle.write("\n")
        elif fmt == "csv":
            normalized_rows: list[dict[str, Any]] = []
            for row in rows:
                if isinstance(row, dict):
                    normalized_rows.append(row)
                else:
                    normalized_rows.append({"value": row})
            fieldnames = sorted({key for row in normalized_rows for key in row.keys()})
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            for row in normalized_rows:
                writer.writerow({key: _flatten_csv_value(row.get(key)) for key in fieldnames})
        else:
            raise ValueError(f"unsupported output format: {fmt}")

    return {
        "path": str(path),
        "format": fmt,
        "gzip": use_gzip,
        "rows": len(rows),
    }


def _validate_positive_optional(value: int | None, *, field: str) -> tuple[bool, str]:
    if value is None:
        return True, ""
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return False, f"{field} must be a positive integer"
    return True, ""


def _parse_json_request_from_args(args: argparse.Namespace, *, command: str) -> dict[str, Any]:
    if args.request_file:
        with open(args.request_file, encoding="utf-8") as f:
            return json.load(f)
    if args.request_json:
        return json.loads(args.request_json)
    raise ValueError(f"{command} requires --request-file or --request-json")


def cmd_logs(args: argparse.Namespace) -> int:
    ok_manifest, manifest_or_rc = _require_manifest(args)
    if not ok_manifest:
        return int(manifest_or_rc)
    manifest_by_method = manifest_or_rc

    try:
        logs_req = _parse_logs_request_from_args(args)
    except Exception as err:  # noqa: BLE001
        _print_error(
            method="logs",
            status="error",
            code=ERR_INVALID_REQUEST,
            message=str(err),
            pretty=not args.compact,
        )
        return 2

    if not isinstance(logs_req, dict):
        _print_error(
            method="logs",
            status="error",
            code=ERR_INVALID_REQUEST,
            message="logs request must be an object",
            pretty=not args.compact,
        )
        return 2

    ok_lim, err_lim = _validate_positive_optional(args.limit, field="--limit")
    if not ok_lim:
        _print_error(
            method="logs",
            status="error",
            code=ERR_INVALID_REQUEST,
            message=err_lim,
            pretty=not args.compact,
        )
        return 2
    ok_smp, err_smp = _validate_positive_optional(args.sample, field="--sample")
    if not ok_smp:
        _print_error(
            method="logs",
            status="error",
            code=ERR_INVALID_REQUEST,
            message=err_smp,
            pretty=not args.compact,
        )
        return 2

    if args.decimals is not None and (args.decimals < 0 or args.decimals > 255):
        _print_error(
            method="logs",
            status="error",
            code=ERR_INVALID_REQUEST,
            message="--decimals must be between 0 and 255",
            pretty=not args.compact,
        )
        return 2

    raw_request = copy.deepcopy(logs_req)
    if args.event:
        raw_request["event"] = args.event
    if args.last_blocks is not None:
        raw_request["last_blocks"] = args.last_blocks
    if args.decode_erc20_transfer:
        raw_request["decode_mode"] = "erc20_transfer"
    if args.decimals is not None:
        raw_request["decimals"] = args.decimals
    if args.decimals_auto:
        raw_request["decimals_auto"] = True

    applied_event = raw_request.get("event")
    event_ok, event_err = _apply_logs_event_filter(
        raw_request,
        str(applied_event) if isinstance(applied_event, str) else None,
    )
    if not event_ok:
        payload = _build_error_payload(
            method="logs",
            status="error",
            code=ERR_INVALID_REQUEST,
            message=event_err,
        )
        payload["request"] = _sanitized_logs_request(raw_request)
        print(_json_dump(payload, pretty=not args.compact))
        return 2

    request_last_blocks = raw_request.get("last_blocks")
    cli_last_blocks = args.last_blocks
    last_blocks = cli_last_blocks if cli_last_blocks is not None else request_last_blocks
    last_rc, last_payload, last_meta = _resolve_logs_last_range(
        raw_request=raw_request,
        last_blocks=last_blocks,
        manifest_by_method=manifest_by_method,
    )
    if last_rc != 0:
        if last_payload is None:
            _print_error(
                method="logs",
                status="error",
                code=ERR_INTERNAL,
                message="unexpected --last resolution failure",
                pretty=not args.compact,
            )
            return 2
        render_rc = _render_output(
            payload=last_payload,
            compact=args.compact,
            result_only=bool(args.result_only),
            select=args.select,
            result_field="result",
        )
        if render_rc != 0:
            return render_rc
        return last_rc

    ok, normalized, err_code, err_message = normalize_logs_request(raw_request)
    if not ok:
        payload = _build_error_payload(
            method="logs",
            status="error",
            code=err_code or ERR_INVALID_REQUEST,
            message=err_message or "invalid logs request",
        )
        payload["request"] = _sanitized_logs_request(raw_request)
        print(_json_dump(payload, pretty=not args.compact))
        return 2

    context = normalized_context(normalized.get("context"))
    is_heavy, span = is_heavy_read(normalized)
    threshold = int(normalized.get("heavy_read_block_range_threshold", DEFAULT_HEAVY_READ_THRESHOLD))
    if is_heavy and not bool(context.get("allow_heavy_read", False)):
        policy = {
            "allowed": False,
            "method": "eth_getLogs",
            "tier": "read",
            "error_code": ERR_POLICY_DENIED,
            "reason": (
                "logs query over "
                f"{span} blocks requires allow_heavy_read=true "
                f"(threshold={threshold})"
            ),
            "requires_confirmation": False,
        }
        payload = _build_error_payload(
            method="logs",
            status="denied",
            code=ERR_POLICY_DENIED,
            message=policy["reason"],
            policy=policy,
        )
        payload["request"] = _sanitized_logs_request(normalized)
        print(_json_dump(payload, pretty=not args.compact))
        return 4

    timeout_seconds = normalized.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
    if timeout_seconds is None:
        timeout_seconds = DEFAULT_TIMEOUT_SECONDS

    def fetch_chunk(logs_filter: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        req: dict[str, Any] = {
            "method": "eth_getLogs",
            "params": [logs_filter],
            "context": context,
            "timeout_seconds": float(timeout_seconds),
        }
        env = normalized.get("env", {})
        if isinstance(env, dict) and env:
            req["env"] = env
        return run_rpc_request(req=req, manifest_by_method=manifest_by_method)

    exit_code, logs_result = run_chunked_logs(
        normalized_request=normalized,
        fetch_chunk=fetch_chunk,
    )

    if exit_code != 0 or not bool(logs_result.get("ok", False)):
        payload = _build_error_payload(
            method="logs",
            status=str(logs_result.get("status", "error")),
            code=str(logs_result.get("error_code", ERR_LOGS_RANGE_TOO_LARGE)),
            message=str(logs_result.get("error_message", "log query failed")),
        )
        payload["request"] = _sanitized_logs_request(normalized)
        if "summary" in logs_result:
            payload["summary"] = logs_result["summary"]
        if "failed_interval" in logs_result:
            payload["failed_interval"] = logs_result["failed_interval"]
        if "cause" in logs_result:
            payload["cause"] = logs_result["cause"]
        render_rc = _render_output(
            payload=payload,
            compact=args.compact,
            result_only=bool(args.result_only),
            select=args.select,
            result_field="result",
        )
        if render_rc != 0:
            return render_rc
        return exit_code

    result_rows: list[Any] = list(logs_result.get("result", []))
    summary = dict(logs_result.get("summary", {}))

    decode_mode = str(raw_request.get("decode_mode", "")).strip().lower()
    if decode_mode == "erc20_transfer":
        decimals_raw = raw_request.get("decimals")
        decimals = int(decimals_raw) if isinstance(decimals_raw, int) else None
        decimals_auto = bool(raw_request.get("decimals_auto", False))
        decoded_rows, decode_summary = _decode_erc20_transfer_rows(
            logs=result_rows,
            decimals=decimals,
            decimals_auto=decimals_auto,
            context=context,
            env=normalized.get("env", {}),
            timeout_seconds=float(timeout_seconds),
            manifest_by_method=manifest_by_method,
        )
        result_rows = decoded_rows
        summary["decode_mode"] = "erc20_transfer"
        summary["decode"] = decode_summary

    controls_summary: dict[str, Any] = {"input_rows": len(result_rows)}
    if args.sample is not None:
        result_rows = _stable_sample(result_rows, int(args.sample))
        controls_summary["after_sample"] = len(result_rows)
    if args.limit is not None:
        result_rows = result_rows[: int(args.limit)]
        controls_summary["after_limit"] = len(result_rows)
    if bool(args.summary_only):
        result_rows = []
        controls_summary["summary_only"] = True

    if args.out:
        try:
            file_output = _write_logs_output(
                out_path=args.out,
                fmt=args.format,
                use_gzip=bool(args.gzip),
                rows=result_rows,
            )
            summary["file_output"] = file_output
        except Exception as err:  # noqa: BLE001
            payload = _build_error_payload(
                method="logs",
                status="error",
                code=ERR_INVALID_REQUEST,
                message=f"failed writing output file: {err}",
            )
            payload["request"] = _sanitized_logs_request(raw_request)
            render_rc = _render_output(
                payload=payload,
                compact=args.compact,
                result_only=bool(args.result_only),
                select=args.select,
                result_field="result",
            )
            if render_rc != 0:
                return render_rc
            return 2

    summary["output_controls"] = controls_summary
    if last_meta:
        summary["resolved_last"] = last_meta
    if isinstance(raw_request.get("event"), str):
        summary["event"] = {
            "signature": raw_request["event"],
            "topic0": ERC20_TRANSFER_TOPIC0
            if str(raw_request["event"]).lower() == KNOWN_EVENT_SIGNATURES["transfer"].lower()
            else event_topic0(str(raw_request["event"])),
        }

    payload = {
        "timestamp_utc": _timestamp(),
        "method": "logs",
        "status": "ok",
        "ok": True,
        "error_code": None,
        "error_message": None,
        "request": _sanitized_logs_request(raw_request),
        "result": result_rows,
        "summary": summary,
    }
    render_rc = _render_output(
        payload=payload,
        compact=args.compact,
        result_only=bool(args.result_only),
        select=args.select,
        result_field="result",
    )
    if render_rc != 0:
        return render_rc
    return 0


def cmd_abi(args: argparse.Namespace) -> int:
    try:
        abi_req = _parse_json_request_from_args(args, command="abi")
    except Exception as err:  # noqa: BLE001
        _print_error(
            method="abi",
            status="error",
            code=ERR_INVALID_REQUEST,
            message=str(err),
            pretty=not args.compact,
        )
        return 2

    ok, result, err = run_abi_operation(abi_req)
    if not ok:
        operation = str(abi_req.get("operation", "")).strip().lower() if isinstance(abi_req, dict) else ""
        if operation in {"encode_call", "function_selector", "event_topic0"}:
            code = ERR_ABI_ENCODE_FAILED
        elif operation in {"decode_output", "decode_log"}:
            code = ERR_ABI_DECODE_FAILED
        else:
            code = ERR_INVALID_REQUEST
        payload = _build_error_payload(
            method="abi",
            status="error",
            code=code,
            message=err,
        )
        if isinstance(abi_req, dict):
            payload["request"] = _sanitized_request(abi_req)
        render_rc = _render_output(
            payload=payload,
            compact=args.compact,
            result_only=bool(args.result_only),
            select=args.select,
            result_field="result",
        )
        if render_rc != 0:
            return render_rc
        return 2

    payload = {
        "timestamp_utc": _timestamp(),
        "method": "abi",
        "status": "ok",
        "ok": True,
        "error_code": None,
        "error_message": None,
        "request": _sanitized_request(abi_req),
        "result": result,
    }
    render_rc = _render_output(
        payload=payload,
        compact=args.compact,
        result_only=bool(args.result_only),
        select=args.select,
        result_field="result",
    )
    if render_rc != 0:
        return render_rc
    return 0


def cmd_multicall(args: argparse.Namespace) -> int:
    ok_manifest, manifest_or_rc = _require_manifest(args)
    if not ok_manifest:
        return int(manifest_or_rc)
    manifest_by_method = manifest_or_rc

    try:
        request = _parse_json_request_from_args(args, command="multicall")
    except Exception as err:  # noqa: BLE001
        _print_error(
            method="multicall",
            status="error",
            code=ERR_INVALID_REQUEST,
            message=str(err),
            pretty=not args.compact,
        )
        return 2

    ok, normalized, err = normalize_multicall_request(request)
    if not ok:
        payload = _build_error_payload(
            method="multicall",
            status="error",
            code=ERR_INVALID_REQUEST,
            message=err,
        )
        if isinstance(request, dict):
            payload["request"] = _sanitized_request(request)
        render_rc = _render_output(
            payload=payload,
            compact=args.compact,
            result_only=bool(args.result_only),
            select=args.select,
            result_field="result",
        )
        if render_rc != 0:
            return render_rc
        return 2

    def execute(req: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        return run_rpc_request(req=req, manifest_by_method=manifest_by_method)

    exit_code, mc_result = run_multicall(normalized_request=normalized, execute_call=execute)
    if exit_code != 0 or not bool(mc_result.get("ok", False)):
        payload = _build_error_payload(
            method="multicall",
            status=str(mc_result.get("status", "error")),
            code=str(mc_result.get("error_code", ERR_MULTICALL_PARTIAL_FAILURE)),
            message=str(mc_result.get("error_message", "multicall failed")),
        )
        payload["request"] = _sanitized_request(request if isinstance(request, dict) else {})
        payload["result"] = mc_result.get("result", [])
        payload["summary"] = mc_result.get("summary", {})
        if "failed_call" in mc_result:
            payload["failed_call"] = mc_result["failed_call"]
        render_rc = _render_output(
            payload=payload,
            compact=args.compact,
            result_only=bool(args.result_only),
            select=args.select,
            result_field="result",
        )
        if render_rc != 0:
            return render_rc
        return exit_code

    payload = {
        "timestamp_utc": _timestamp(),
        "method": "multicall",
        "status": "ok",
        "ok": True,
        "error_code": None,
        "error_message": None,
        "request": _sanitized_request(request),
        "result": mc_result.get("result", []),
        "summary": mc_result.get("summary", {}),
    }
    render_rc = _render_output(
        payload=payload,
        compact=args.compact,
        result_only=bool(args.result_only),
        select=args.select,
        result_field="result",
    )
    if render_rc != 0:
        return render_rc
    return 0


def cmd_simulate(args: argparse.Namespace) -> int:
    ok_manifest, manifest_or_rc = _require_manifest(args)
    if not ok_manifest:
        return int(manifest_or_rc)
    manifest_by_method = manifest_or_rc

    try:
        request = _parse_json_request_from_args(args, command="simulate")
    except Exception as err:  # noqa: BLE001
        _print_error(
            method="simulate",
            status="error",
            code=ERR_INVALID_REQUEST,
            message=str(err),
            pretty=not args.compact,
        )
        return 2

    ok, normalized, err = normalize_simulation_request(request)
    if not ok:
        payload = _build_error_payload(
            method="simulate",
            status="error",
            code=ERR_INVALID_REQUEST,
            message=err,
        )
        if isinstance(request, dict):
            payload["request"] = _sanitized_request(request)
        render_rc = _render_output(
            payload=payload,
            compact=args.compact,
            result_only=bool(args.result_only),
            select=args.select,
            result_field="result",
        )
        if render_rc != 0:
            return render_rc
        return 2

    def execute(req: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        return run_rpc_request(req=req, manifest_by_method=manifest_by_method)

    exit_code, sim_result = run_simulation(normalized_request=normalized, execute_rpc=execute)
    if exit_code != 0 or not bool(sim_result.get("ok", False)):
        payload = _build_error_payload(
            method="simulate",
            status=str(sim_result.get("status", "error")),
            code=str(sim_result.get("error_code", ERR_SIMULATION_REVERTED)),
            message=str(sim_result.get("error_message", "simulation failed")),
        )
        payload["request"] = _sanitized_request(request if isinstance(request, dict) else {})
        payload["result"] = sim_result.get("result")
        render_rc = _render_output(
            payload=payload,
            compact=args.compact,
            result_only=bool(args.result_only),
            select=args.select,
            result_field="result",
        )
        if render_rc != 0:
            return render_rc
        return exit_code

    payload = {
        "timestamp_utc": _timestamp(),
        "method": "simulate",
        "status": "ok",
        "ok": True,
        "error_code": None,
        "error_message": None,
        "request": _sanitized_request(request),
        "result": sim_result.get("result"),
    }
    render_rc = _render_output(
        payload=payload,
        compact=args.compact,
        result_only=bool(args.result_only),
        select=args.select,
        result_field="result",
    )
    if render_rc != 0:
        return render_rc
    return 0


def cmd_trace(args: argparse.Namespace) -> int:
    ok_manifest, manifest_or_rc = _require_manifest(args)
    if not ok_manifest:
        return int(manifest_or_rc)
    manifest_by_method = manifest_or_rc

    try:
        request = _parse_json_request_from_args(args, command="trace")
    except Exception as err:  # noqa: BLE001
        _print_error(
            method="trace",
            status="error",
            code=ERR_INVALID_REQUEST,
            message=str(err),
            pretty=not args.compact,
        )
        return 2

    ok, normalized, err = normalize_trace_request(request)
    if not ok:
        payload = _build_error_payload(
            method="trace",
            status="error",
            code=ERR_INVALID_REQUEST,
            message=err,
        )
        if isinstance(request, dict):
            payload["request"] = _sanitized_request(request)
        render_rc = _render_output(
            payload=payload,
            compact=args.compact,
            result_only=bool(args.result_only),
            select=args.select,
            result_field="result",
        )
        if render_rc != 0:
            return render_rc
        return 2

    def execute(req: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        return run_rpc_request(req=req, manifest_by_method=manifest_by_method)

    exit_code, trace_result = run_trace(
        normalized_request=normalized,
        manifest_by_method=manifest_by_method,
        execute_rpc=execute,
    )
    if exit_code != 0 or not bool(trace_result.get("ok", False)):
        payload = _build_error_payload(
            method="trace",
            status=str(trace_result.get("status", "error")),
            code=str(trace_result.get("error_code", ERR_TRACE_UNSUPPORTED)),
            message=str(trace_result.get("error_message", "trace failed")),
        )
        payload["request"] = _sanitized_request(request if isinstance(request, dict) else {})
        if "attempts" in trace_result:
            payload["attempts"] = trace_result["attempts"]
        if "cause" in trace_result:
            payload["cause"] = trace_result["cause"]
        render_rc = _render_output(
            payload=payload,
            compact=args.compact,
            result_only=bool(args.result_only),
            select=args.select,
            result_field="result",
        )
        if render_rc != 0:
            return render_rc
        return exit_code

    payload = {
        "timestamp_utc": _timestamp(),
        "method": "trace",
        "status": "ok",
        "ok": True,
        "error_code": None,
        "error_message": None,
        "request": _sanitized_request(request),
        "result": trace_result.get("result"),
        "method_used": trace_result.get("method_used"),
        "trace_payload": trace_result.get("trace_payload"),
        "attempts": trace_result.get("attempts", []),
    }
    render_rc = _render_output(
        payload=payload,
        compact=args.compact,
        result_only=bool(args.result_only),
        select=args.select,
        result_field="result",
    )
    if render_rc != 0:
        return render_rc
    return 0


def _parse_chain_request_from_args(args: argparse.Namespace) -> dict[str, Any]:
    if args.request_file:
        with open(args.request_file, encoding="utf-8") as f:
            return json.load(f)
    if args.request_json:
        return json.loads(args.request_json)
    raise ValueError("chain requires --request-file or --request-json")


def _validate_chain_request(req: dict[str, Any]) -> tuple[bool, str]:
    if not isinstance(req, dict):
        return False, "chain request must be an object"

    steps = req.get("steps")
    if not isinstance(steps, list) or not steps:
        return False, "chain request.steps must be a non-empty array"

    context_defaults = req.get("context_defaults", {})
    if context_defaults and not isinstance(context_defaults, dict):
        return False, "chain request.context_defaults must be an object"

    env = req.get("env", {})
    if env and (not isinstance(env, dict) or not all(isinstance(k, str) for k in env.keys())):
        return False, "chain request.env must be an object with string keys"

    timeout = req.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
    if not isinstance(timeout, (int, float)) or timeout <= 0:
        return False, "chain request.timeout_seconds must be a positive number"

    seen_ids: set[str] = set()
    for idx, step in enumerate(steps):
        if not isinstance(step, dict):
            return False, f"step[{idx}] must be an object"
        step_id = step.get("id")
        if not isinstance(step_id, str) or not step_id.strip():
            return False, f"step[{idx}] requires non-empty string id"
        if step_id in seen_ids:
            return False, f"duplicate step id: {step_id}"
        seen_ids.add(step_id)

        has_method = "method" in step
        has_transform = "transform" in step
        if has_method == has_transform:
            return False, f"step[{idx}] must include exactly one of 'method' or 'transform'"

    return True, ""


def _build_chain_payload(
    *,
    chain_req: dict[str, Any],
    status: str,
    ok: bool,
    error_code: str | None,
    error_message: str | None,
    failed_step_id: str | None,
    steps: list[dict[str, Any]],
    final_result: Any,
    duration_ms: int,
) -> dict[str, Any]:
    outputs = {
        step.get("step_id", f"step_{idx}"): {
            "status": step.get("status"),
            "ok": step.get("ok"),
            "error_code": step.get("error_code"),
            "error_message": step.get("error_message"),
            "result": step.get("result"),
        }
        for idx, step in enumerate(steps)
    }

    return {
        "timestamp_utc": _timestamp(),
        "method": "chain",
        "status": status,
        "ok": ok,
        "error_code": error_code,
        "error_message": error_message,
        "request": _sanitized_chain_request(chain_req),
        "failed_step_id": failed_step_id,
        "steps_executed": len(steps),
        "steps": steps,
        "outputs": outputs,
        "final_result": final_result,
        "duration_ms": duration_ms,
    }


def _augment_step_payload(step_payload: dict[str, Any], *, step_id: str, step_index: int, kind: str) -> dict[str, Any]:
    out = dict(step_payload)
    out["step_id"] = step_id
    out["step_index"] = step_index
    out["kind"] = kind
    return out


def run_chain_request(
    *,
    chain_req: dict[str, Any],
    manifest_by_method: dict[str, dict[str, Any]],
) -> tuple[int, dict[str, Any]]:
    ok, err = _validate_chain_request(chain_req)
    if not ok:
        return (
            2,
            _build_chain_payload(
                chain_req=chain_req if isinstance(chain_req, dict) else {"steps": []},
                status="error",
                ok=False,
                error_code=ERR_INVALID_REQUEST,
                error_message=err,
                failed_step_id=None,
                steps=[],
                final_result=None,
                duration_ms=0,
            ),
        )

    start = time.perf_counter()
    steps = chain_req["steps"]
    context_defaults = chain_req.get("context_defaults", {}) or {}
    chain_env = chain_req.get("env", {}) or {}
    default_timeout = float(chain_req.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS))

    step_outputs: dict[str, Any] = {}
    executed_steps: list[dict[str, Any]] = []

    for idx, raw_step in enumerate(steps):
        step_id = str(raw_step["id"])

        try:
            resolved_step = _resolve_templates(raw_step, step_outputs)
        except Exception as template_err:  # noqa: BLE001
            step_payload = _augment_step_payload(
                _build_error_payload(
                    method="chain",
                    status="error",
                    code=ERR_INVALID_REQUEST,
                    message=f"template resolution failed: {template_err}",
                ),
                step_id=step_id,
                step_index=idx,
                kind="template",
            )
            executed_steps.append(step_payload)
            duration_ms = int((time.perf_counter() - start) * 1000)
            return (
                2,
                _build_chain_payload(
                    chain_req=chain_req,
                    status="error",
                    ok=False,
                    error_code=step_payload["error_code"],
                    error_message=step_payload["error_message"],
                    failed_step_id=step_id,
                    steps=executed_steps,
                    final_result=None,
                    duration_ms=duration_ms,
                ),
            )

        if "transform" in resolved_step:
            transform_name = str(resolved_step.get("transform", "")).strip()
            transform_input = resolved_step.get("input")
            if "input" not in resolved_step and isinstance(resolved_step.get("params"), list):
                params = resolved_step.get("params", [])
                if len(params) == 1:
                    transform_input = params[0]

            if "input" not in resolved_step and transform_input is None:
                step_payload = _augment_step_payload(
                    _build_error_payload(
                        method=f"transform:{transform_name}",
                        status="error",
                        code=ERR_INVALID_REQUEST,
                        message="transform step requires 'input'",
                    ),
                    step_id=step_id,
                    step_index=idx,
                    kind="transform",
                )
                executed_steps.append(step_payload)
                duration_ms = int((time.perf_counter() - start) * 1000)
                return (
                    2,
                    _build_chain_payload(
                        chain_req=chain_req,
                        status="error",
                        ok=False,
                        error_code=step_payload["error_code"],
                        error_message=step_payload["error_message"],
                        failed_step_id=step_id,
                        steps=executed_steps,
                        final_result=None,
                        duration_ms=duration_ms,
                    ),
                )

            t_start = time.perf_counter()
            t_ok, t_result, t_error = apply_transform(transform_name, transform_input)
            t_duration_ms = int((time.perf_counter() - t_start) * 1000)
            if not t_ok:
                step_payload = _augment_step_payload(
                    _build_error_payload(
                        method=f"transform:{transform_name}",
                        status="error",
                        code=ERR_INVALID_REQUEST,
                        message=t_error,
                        duration_ms=t_duration_ms,
                    ),
                    step_id=step_id,
                    step_index=idx,
                    kind="transform",
                )
                executed_steps.append(step_payload)
                step_outputs[step_id] = step_payload
                duration_ms = int((time.perf_counter() - start) * 1000)
                return (
                    2,
                    _build_chain_payload(
                        chain_req=chain_req,
                        status="error",
                        ok=False,
                        error_code=step_payload["error_code"],
                        error_message=step_payload["error_message"],
                        failed_step_id=step_id,
                        steps=executed_steps,
                        final_result=None,
                        duration_ms=duration_ms,
                    ),
                )

            step_payload = _augment_step_payload(
                {
                    "timestamp_utc": _timestamp(),
                    "method": f"transform:{transform_name}",
                    "status": "ok",
                    "ok": True,
                    "error_code": None,
                    "error_message": None,
                    "result": t_result,
                    "duration_ms": t_duration_ms,
                },
                step_id=step_id,
                step_index=idx,
                kind="transform",
            )
            executed_steps.append(step_payload)
            step_outputs[step_id] = step_payload
            continue

        method = resolved_step.get("method")
        if not isinstance(method, str) or not method.strip():
            step_payload = _augment_step_payload(
                _build_error_payload(
                    method="",
                    status="error",
                    code=ERR_INVALID_REQUEST,
                    message="rpc step requires non-empty method",
                ),
                step_id=step_id,
                step_index=idx,
                kind="rpc",
            )
            executed_steps.append(step_payload)
            duration_ms = int((time.perf_counter() - start) * 1000)
            return (
                2,
                _build_chain_payload(
                    chain_req=chain_req,
                    status="error",
                    ok=False,
                    error_code=step_payload["error_code"],
                    error_message=step_payload["error_message"],
                    failed_step_id=step_id,
                    steps=executed_steps,
                    final_result=None,
                    duration_ms=duration_ms,
                ),
            )

        step_context = resolved_step.get("context", {}) or {}
        if not isinstance(step_context, dict):
            step_payload = _augment_step_payload(
                _build_error_payload(
                    method=method,
                    status="error",
                    code=ERR_INVALID_REQUEST,
                    message="step.context must be an object",
                ),
                step_id=step_id,
                step_index=idx,
                kind="rpc",
            )
            executed_steps.append(step_payload)
            duration_ms = int((time.perf_counter() - start) * 1000)
            return (
                2,
                _build_chain_payload(
                    chain_req=chain_req,
                    status="error",
                    ok=False,
                    error_code=step_payload["error_code"],
                    error_message=step_payload["error_message"],
                    failed_step_id=step_id,
                    steps=executed_steps,
                    final_result=None,
                    duration_ms=duration_ms,
                ),
            )

        merged_context = dict(context_defaults)
        merged_context.update(step_context)

        step_env = resolved_step.get("env", {}) or {}
        if step_env and not isinstance(step_env, dict):
            step_payload = _augment_step_payload(
                _build_error_payload(
                    method=method,
                    status="error",
                    code=ERR_INVALID_REQUEST,
                    message="step.env must be an object",
                ),
                step_id=step_id,
                step_index=idx,
                kind="rpc",
            )
            executed_steps.append(step_payload)
            duration_ms = int((time.perf_counter() - start) * 1000)
            return (
                2,
                _build_chain_payload(
                    chain_req=chain_req,
                    status="error",
                    ok=False,
                    error_code=step_payload["error_code"],
                    error_message=step_payload["error_message"],
                    failed_step_id=step_id,
                    steps=executed_steps,
                    final_result=None,
                    duration_ms=duration_ms,
                ),
            )

        req: dict[str, Any] = {
            "method": method,
            "params": resolved_step.get("params", []),
            "id": resolved_step.get("rpc_id", idx + 1),
            "context": merged_context,
            "timeout_seconds": resolved_step.get("timeout_seconds", default_timeout),
        }

        merged_env = dict(chain_env)
        merged_env.update(step_env)
        if merged_env:
            req["env"] = merged_env

        step_exit, step_payload = run_rpc_request(req=req, manifest_by_method=manifest_by_method)
        step_payload = _augment_step_payload(step_payload, step_id=step_id, step_index=idx, kind="rpc")
        executed_steps.append(step_payload)
        step_outputs[step_id] = step_payload

        if step_exit != 0:
            duration_ms = int((time.perf_counter() - start) * 1000)
            return (
                step_exit,
                _build_chain_payload(
                    chain_req=chain_req,
                    status=step_payload.get("status", "error"),
                    ok=False,
                    error_code=step_payload.get("error_code"),
                    error_message=step_payload.get("error_message"),
                    failed_step_id=step_id,
                    steps=executed_steps,
                    final_result=None,
                    duration_ms=duration_ms,
                ),
            )

    duration_ms = int((time.perf_counter() - start) * 1000)
    final_result = executed_steps[-1].get("result") if executed_steps else None
    return (
        0,
        _build_chain_payload(
            chain_req=chain_req,
            status="ok",
            ok=True,
            error_code=None,
            error_message=None,
            failed_step_id=None,
            steps=executed_steps,
            final_result=final_result,
            duration_ms=duration_ms,
        ),
    )


def _cmd_chain_like(args: argparse.Namespace) -> int:
    ok_manifest, manifest_or_rc = _require_manifest(args)
    if not ok_manifest:
        return int(manifest_or_rc)
    manifest_by_method = manifest_or_rc

    try:
        chain_req = _parse_chain_request_from_args(args)
    except Exception as err:  # noqa: BLE001
        _print_error(
            method="chain",
            status="error",
            code=ERR_INVALID_REQUEST,
            message=str(err),
            pretty=not args.compact,
        )
        return 2

    exit_code, payload = run_chain_request(chain_req=chain_req, manifest_by_method=manifest_by_method)
    render_rc = _render_output(
        payload=payload,
        compact=args.compact,
        result_only=bool(args.result_only),
        select=args.select,
        result_field="final_result",
    )
    if render_rc != 0:
        return render_rc
    return exit_code


def cmd_chain(args: argparse.Namespace) -> int:
    return _cmd_chain_like(args)


def cmd_batch(args: argparse.Namespace) -> int:
    return _cmd_chain_like(args)


def _parse_env_json(raw: str | None) -> tuple[bool, dict[str, Any], str]:
    if not raw:
        return True, {}, ""
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as err:
        return False, {}, f"invalid env json: {err}"
    if not isinstance(parsed, dict):
        return False, {}, "env json must decode to an object"
    return True, parsed, ""


def _wrap_stage_failure(command_method: str, stage: str, cause: dict[str, Any]) -> dict[str, Any]:
    payload = _build_error_payload(
        method=command_method,
        status=str(cause.get("status", "error")),
        code=str(cause.get("error_code", ERR_INTERNAL)),
        message=f"{stage}: {cause.get('error_message', 'unknown error')}",
    )
    payload["cause"] = cause
    return payload


def _trim_decimal_string(value: str) -> str:
    text = str(value).strip()
    if "." not in text:
        return text
    whole, frac = text.split(".", 1)
    frac = frac.rstrip("0")
    return whole if not frac else f"{whole}.{frac}"


def _make_analytics_executor(
    *,
    manifest_by_method: dict[str, dict[str, Any]],
    default_context: dict[str, Any],
    default_env: dict[str, Any],
    default_timeout_seconds: float,
) -> Any:
    def execute(req: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        merged = dict(req)
        req_ctx = merged.get("context")
        context_out = dict(default_context)
        if isinstance(req_ctx, dict):
            context_out.update(req_ctx)
        merged["context"] = context_out

        req_env = merged.get("env")
        env_out = dict(default_env)
        if isinstance(req_env, dict):
            env_out.update(req_env)
        if env_out:
            merged["env"] = env_out
        else:
            merged.pop("env", None)

        if "timeout_seconds" not in merged:
            merged["timeout_seconds"] = float(default_timeout_seconds)
        return run_rpc_request(req=merged, manifest_by_method=manifest_by_method)

    return execute


def _analytics_hex_to_int(value: Any) -> tuple[bool, int, str]:
    if not isinstance(value, str):
        return False, 0, "expected hex quantity string"
    try:
        if value.startswith("0x"):
            return True, int(value, 16), ""
        return True, int(value, 10), ""
    except Exception:  # noqa: BLE001
        return False, 0, f"invalid quantity: {value}"


def _analytics_eth_call_result(
    *,
    to: str,
    data: str,
    block_tag: str,
    execute_rpc: Any,
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
        return 2, _build_error_payload(
            method="analytics",
            status="error",
            code=ERR_INVALID_REQUEST,
            message="eth_call returned non-string result",
        ), None
    return 0, None, result


def _analytics_word_to_address(word_hex: str) -> tuple[bool, str, str]:
    ok, value, err = apply_transform("slice_last_20_bytes_to_address", word_hex)
    if not ok or not isinstance(value, str):
        return False, "", err or "failed to decode address"
    return True, value, ""


def _analytics_fetch_pool_metadata(
    *,
    pool: str,
    block_tag: str,
    execute_rpc: Any,
) -> tuple[int, dict[str, Any]]:
    rc0, cause0, token0_raw = _analytics_eth_call_result(
        to=pool,
        data=UNISWAP_V2_TOKEN0_SELECTOR,
        block_tag=block_tag,
        execute_rpc=execute_rpc,
    )
    if rc0 != 0 or token0_raw is None:
        return rc0, _wrap_stage_failure("analytics.dex_swap_flow", "token0()", cause0 or {})
    rc1, cause1, token1_raw = _analytics_eth_call_result(
        to=pool,
        data=UNISWAP_V2_TOKEN1_SELECTOR,
        block_tag=block_tag,
        execute_rpc=execute_rpc,
    )
    if rc1 != 0 or token1_raw is None:
        return rc1, _wrap_stage_failure("analytics.dex_swap_flow", "token1()", cause1 or {})

    ok0, token0, err0 = _analytics_word_to_address(token0_raw)
    if not ok0:
        return 2, _build_error_payload(
            method="analytics.dex_swap_flow",
            status="error",
            code=ERR_INVALID_REQUEST,
            message=f"token0 decode failed: {err0}",
        )
    ok1, token1, err1 = _analytics_word_to_address(token1_raw)
    if not ok1:
        return 2, _build_error_payload(
            method="analytics.dex_swap_flow",
            status="error",
            code=ERR_INVALID_REQUEST,
            message=f"token1 decode failed: {err1}",
        )

    def read_decimals(token: str) -> tuple[int, dict[str, Any] | None, int | None]:
        rc, cause, raw = _analytics_eth_call_result(
            to=token,
            data=ERC20_DECIMALS_SELECTOR,
            block_tag=block_tag,
            execute_rpc=execute_rpc,
        )
        if rc != 0 or raw is None:
            return rc, cause, None
        ok, val, err = _analytics_hex_to_int(raw)
        if not ok:
            return 2, _build_error_payload(
                method="analytics.dex_swap_flow",
                status="error",
                code=ERR_INVALID_REQUEST,
                message=f"decimals decode failed for {token}: {err}",
            ), None
        return 0, None, int(val)

    rcd0, caused0, decimals0 = read_decimals(token0)
    if rcd0 != 0 or decimals0 is None:
        return rcd0, _wrap_stage_failure(
            "analytics.dex_swap_flow",
            f"decimals() token0 {token0}",
            caused0 or {},
        )
    rcd1, caused1, decimals1 = read_decimals(token1)
    if rcd1 != 0 or decimals1 is None:
        return rcd1, _wrap_stage_failure(
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


def _format_units_or_raw(raw_value: str, decimals: int) -> str:
    try:
        return _trim_decimal_string(cast_format_units(raw_value, decimals))
    except Exception:  # noqa: BLE001
        return raw_value


def cmd_analytics_dex_swap_flow(args: argparse.Namespace) -> int:
    ok_manifest, manifest_or_rc = _require_manifest(args)
    if not ok_manifest:
        return int(manifest_or_rc)
    manifest_by_method = manifest_or_rc

    ok_env, env_or_rc = _require_env_json(
        raw_env_json=args.env_json,
        method="analytics.dex_swap_flow",
        compact=bool(args.compact),
    )
    if not ok_env:
        return int(env_or_rc)
    env = env_or_rc

    pool = str(args.pool).strip().lower()
    if not ADDRESS_RE.fullmatch(pool):
        _print_error(
            method="analytics.dex_swap_flow",
            status="error",
            code=ERR_INVALID_REQUEST,
            message="pool must be a 20-byte hex address",
            pretty=not args.compact,
        )
        return 2

    context = {
        "allow_heavy_read": bool(args.allow_heavy_read),
    }
    execute_rpc = _make_analytics_executor(
        manifest_by_method=manifest_by_method,
        default_context=context,
        default_env=env,
        default_timeout_seconds=float(args.timeout_seconds),
    )

    range_rc, range_payload = resolve_block_window(
        execute_rpc=execute_rpc,
        context=context,
        env=env,
        timeout_seconds=float(args.timeout_seconds),
        last_blocks=args.last_blocks,
        since=args.since,
    )
    if range_rc != 0:
        payload = _build_error_payload(
            method="analytics.dex_swap_flow",
            status="error",
            code=str(range_payload.get("error_code", ERR_INVALID_REQUEST)),
            message=str(range_payload.get("error_message", "failed to resolve range")),
        )
        if "cause" in range_payload:
            payload["cause"] = range_payload["cause"]
        render_rc = _render_output(
            payload=payload,
            compact=args.compact,
            result_only=bool(args.result_only),
            select=args.select,
            result_field="result",
        )
        if render_rc != 0:
            return render_rc
        return range_rc

    from_block = int(range_payload["from_block"])
    to_block = int(range_payload["to_block"])
    to_block_tag = hex(to_block)

    meta_rc, meta_payload = _analytics_fetch_pool_metadata(
        pool=pool,
        block_tag=to_block_tag,
        execute_rpc=execute_rpc,
    )
    if meta_rc != 0:
        render_rc = _render_output(
            payload=meta_payload,
            compact=args.compact,
            result_only=bool(args.result_only),
            select=args.select,
            result_field="result",
        )
        if render_rc != 0:
            return render_rc
        return meta_rc

    scan_rc, scan_payload = scan_logs(
        execute_rpc=execute_rpc,
        logs_filter={
            "address": pool,
            "topics": [UNISWAP_V2_SWAP_TOPIC0],
            "fromBlock": from_block,
            "toBlock": to_block,
        },
        context=context,
        env=env,
        timeout_seconds=float(args.timeout_seconds),
        chunk_size=int(args.chunk_size),
        max_chunks=int(args.max_chunks),
        max_logs=int(args.max_logs),
        adaptive_split=not bool(args.no_adaptive_split),
        allow_heavy_read=bool(args.allow_heavy_read),
        checkpoint_file=args.checkpoint_file,
        filter_signature={"command": "dex-swap-flow", "pool": pool},
    )
    if scan_rc != 0 or not bool(scan_payload.get("ok", False)):
        payload = _build_error_payload(
            method="analytics.dex_swap_flow",
            status="error",
            code=str(scan_payload.get("error_code", ERR_INTERNAL)),
            message=str(scan_payload.get("error_message", "log scan failed")),
        )
        payload["scan"] = scan_payload
        render_rc = _render_output(
            payload=payload,
            compact=args.compact,
            result_only=bool(args.result_only),
            select=args.select,
            result_field="result",
        )
        if render_rc != 0:
            return render_rc
        return scan_rc

    token0 = str(meta_payload["token0"])
    token1 = str(meta_payload["token1"])
    decimals0 = int(meta_payload["decimals0"])
    decimals1 = int(meta_payload["decimals1"])

    rows: list[dict[str, Any]] = []
    decode_failures = 0
    for item in list(scan_payload.get("result", [])):
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
            row["pool_token0_net"] = _format_units_or_raw(str(amount0_net), decimals0)
            row["pool_token1_net"] = _format_units_or_raw(str(amount1_net), decimals1)
            row["amount0_in"] = _format_units_or_raw(row["amount0_in_raw"], decimals0)
            row["amount0_out"] = _format_units_or_raw(row["amount0_out_raw"], decimals0)
            row["amount1_in"] = _format_units_or_raw(row["amount1_in_raw"], decimals1)
            row["amount1_out"] = _format_units_or_raw(row["amount1_out_raw"], decimals1)
            rows.append(row)
        except Exception:
            decode_failures += 1

    if args.limit is not None:
        rows = rows[: int(args.limit)]

    summary = summarize_swap_rows(rows)
    summary["decode_failures"] = decode_failures
    summary["token0_pool_net"] = _format_units_or_raw(summary["token0_pool_net_raw"], decimals0)
    summary["token1_pool_net"] = _format_units_or_raw(summary["token1_pool_net_raw"], decimals1)
    summary["token0_volume"] = _format_units_or_raw(summary["token0_volume_raw"], decimals0)
    summary["token1_volume"] = _format_units_or_raw(summary["token1_volume_raw"], decimals1)

    result = {
        "pool": pool,
        "token0": token0,
        "token1": token1,
        "token0_decimals": decimals0,
        "token1_decimals": decimals1,
        "range": range_payload,
        "rows": rows,
        "summary": summary,
        "scan_summary": scan_payload.get("summary", {}),
    }
    if "checkpoint" in scan_payload:
        result["checkpoint"] = scan_payload["checkpoint"]

    payload = {
        "timestamp_utc": _timestamp(),
        "method": "analytics.dex_swap_flow",
        "status": "ok",
        "ok": True,
        "error_code": None,
        "error_message": None,
        "result": result,
    }
    render_rc = _render_output(
        payload=payload,
        compact=args.compact,
        result_only=bool(args.result_only),
        select=args.select,
        result_field="result",
    )
    if render_rc != 0:
        return render_rc
    return 0


def cmd_analytics_factory_new_pools(args: argparse.Namespace) -> int:
    ok_manifest, manifest_or_rc = _require_manifest(args)
    if not ok_manifest:
        return int(manifest_or_rc)
    manifest_by_method = manifest_or_rc

    ok_env, env_or_rc = _require_env_json(
        raw_env_json=args.env_json,
        method="analytics.factory_new_pools",
        compact=bool(args.compact),
    )
    if not ok_env:
        return int(env_or_rc)
    env = env_or_rc

    factory = str(args.factory).strip().lower()
    if not ADDRESS_RE.fullmatch(factory):
        _print_error(
            method="analytics.factory_new_pools",
            status="error",
            code=ERR_INVALID_REQUEST,
            message="factory must be a 20-byte hex address",
            pretty=not args.compact,
        )
        return 2

    context = {
        "allow_heavy_read": bool(args.allow_heavy_read),
    }
    execute_rpc = _make_analytics_executor(
        manifest_by_method=manifest_by_method,
        default_context=context,
        default_env=env,
        default_timeout_seconds=float(args.timeout_seconds),
    )

    range_rc, range_payload = resolve_block_window(
        execute_rpc=execute_rpc,
        context=context,
        env=env,
        timeout_seconds=float(args.timeout_seconds),
        last_blocks=args.last_blocks,
        since=args.since,
    )
    if range_rc != 0:
        payload = _build_error_payload(
            method="analytics.factory_new_pools",
            status="error",
            code=str(range_payload.get("error_code", ERR_INVALID_REQUEST)),
            message=str(range_payload.get("error_message", "failed to resolve range")),
        )
        if "cause" in range_payload:
            payload["cause"] = range_payload["cause"]
        render_rc = _render_output(
            payload=payload,
            compact=args.compact,
            result_only=bool(args.result_only),
            select=args.select,
            result_field="result",
        )
        if render_rc != 0:
            return render_rc
        return range_rc

    protocol = str(args.protocol).strip().lower()
    if protocol == "uniswap-v2":
        event_decl = UNISWAP_V2_PAIR_CREATED_EVENT
        topic0 = UNISWAP_V2_PAIR_CREATED_TOPIC0
    else:
        event_decl = UNISWAP_V3_POOL_CREATED_EVENT
        topic0 = UNISWAP_V3_POOL_CREATED_TOPIC0

    scan_rc, scan_payload = scan_logs(
        execute_rpc=execute_rpc,
        logs_filter={
            "address": factory,
            "topics": [topic0],
            "fromBlock": int(range_payload["from_block"]),
            "toBlock": int(range_payload["to_block"]),
        },
        context=context,
        env=env,
        timeout_seconds=float(args.timeout_seconds),
        chunk_size=int(args.chunk_size),
        max_chunks=int(args.max_chunks),
        max_logs=int(args.max_logs),
        adaptive_split=not bool(args.no_adaptive_split),
        allow_heavy_read=bool(args.allow_heavy_read),
        checkpoint_file=args.checkpoint_file,
        filter_signature={"command": "factory-new-pools", "factory": factory, "protocol": protocol},
    )
    if scan_rc != 0 or not bool(scan_payload.get("ok", False)):
        payload = _build_error_payload(
            method="analytics.factory_new_pools",
            status="error",
            code=str(scan_payload.get("error_code", ERR_INTERNAL)),
            message=str(scan_payload.get("error_message", "log scan failed")),
        )
        payload["scan"] = scan_payload
        render_rc = _render_output(
            payload=payload,
            compact=args.compact,
            result_only=bool(args.result_only),
            select=args.select,
            result_field="result",
        )
        if render_rc != 0:
            return render_rc
        return scan_rc

    rows: list[dict[str, Any]] = []
    decode_failures = 0
    for item in list(scan_payload.get("result", [])):
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

    if args.limit is not None:
        rows = rows[: int(args.limit)]

    result = {
        "factory": factory,
        "protocol": protocol,
        "range": range_payload,
        "rows": rows,
        "summary": {
            "events": len(rows),
            "decode_failures": decode_failures,
        },
        "scan_summary": scan_payload.get("summary", {}),
    }
    if "checkpoint" in scan_payload:
        result["checkpoint"] = scan_payload["checkpoint"]

    payload = {
        "timestamp_utc": _timestamp(),
        "method": "analytics.factory_new_pools",
        "status": "ok",
        "ok": True,
        "error_code": None,
        "error_message": None,
        "result": result,
    }
    render_rc = _render_output(
        payload=payload,
        compact=args.compact,
        result_only=bool(args.result_only),
        select=args.select,
        result_field="result",
    )
    if render_rc != 0:
        return render_rc
    return 0


def _analytics_parse_block_tag(raw_block: str | None) -> tuple[bool, str, str]:
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


def _analytics_decode_uint256_word(word_hex: str) -> tuple[bool, int]:
    if not isinstance(word_hex, str) or len(word_hex) != 64:
        return False, 0
    try:
        return True, int(word_hex, 16)
    except Exception:  # noqa: BLE001
        return False, 0


def _analytics_decode_int256_word(word_hex: str) -> tuple[bool, int]:
    ok, as_uint = _analytics_decode_uint256_word(word_hex)
    if not ok:
        return False, 0
    if as_uint >= 2**255:
        return True, as_uint - 2**256
    return True, as_uint


def _analytics_token_label(token: str) -> str:
    as_lower = str(token).lower()
    symbol = ARBITRAGE_KNOWN_SYMBOLS.get(as_lower)
    if symbol:
        return symbol
    if len(as_lower) < 10:
        return as_lower
    return f"{as_lower[:6]}...{as_lower[-4:]}"


def _analytics_format_path(tokens: list[str]) -> str:
    return " -> ".join(_analytics_token_label(token) for token in tokens)


def _analytics_fetch_pool_tokens_for_arbitrage(
    *,
    pool: str,
    block_tag: str,
    execute_rpc: Any,
) -> tuple[int, dict[str, Any], tuple[str | None, str | None]]:
    rc0, cause0, token0_raw = _analytics_eth_call_result(
        to=pool,
        data=UNISWAP_V2_TOKEN0_SELECTOR,
        block_tag=block_tag,
        execute_rpc=execute_rpc,
    )
    if rc0 != 0 or token0_raw is None:
        payload = _wrap_stage_failure(
            "analytics.arbitrage_patterns",
            f"token0() pool {pool}",
            cause0 or {},
        )
        return rc0, payload, (None, None)

    rc1, cause1, token1_raw = _analytics_eth_call_result(
        to=pool,
        data=UNISWAP_V2_TOKEN1_SELECTOR,
        block_tag=block_tag,
        execute_rpc=execute_rpc,
    )
    if rc1 != 0 or token1_raw is None:
        payload = _wrap_stage_failure(
            "analytics.arbitrage_patterns",
            f"token1() pool {pool}",
            cause1 or {},
        )
        return rc1, payload, (None, None)

    ok0, token0, err0 = _analytics_word_to_address(token0_raw)
    if not ok0:
        payload = _build_error_payload(
            method="analytics.arbitrage_patterns",
            status="error",
            code=ERR_INVALID_REQUEST,
            message=f"token0 decode failed for pool {pool}: {err0}",
        )
        return 2, payload, (None, None)

    ok1, token1, err1 = _analytics_word_to_address(token1_raw)
    if not ok1:
        payload = _build_error_payload(
            method="analytics.arbitrage_patterns",
            status="error",
            code=ERR_INVALID_REQUEST,
            message=f"token1 decode failed for pool {pool}: {err1}",
        )
        return 2, payload, (None, None)

    return 0, {}, (token0.lower(), token1.lower())


def _analytics_decode_swap_for_arbitrage(
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
        ok0, amount0_in = _analytics_decode_uint256_word(words[0])
        ok1, amount1_in = _analytics_decode_uint256_word(words[1])
        ok2, amount0_out = _analytics_decode_uint256_word(words[2])
        ok3, amount1_out = _analytics_decode_uint256_word(words[3])
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
        ok0, amount0 = _analytics_decode_int256_word(word0)
        ok1, amount1 = _analytics_decode_int256_word(word1)
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


def _analytics_build_arbitrage_candidate(
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
        "path_display": _analytics_format_path(path_tokens),
    }
    if include_swaps:
        candidate["swaps"] = swaps
    return candidate


def cmd_analytics_arbitrage_patterns(args: argparse.Namespace) -> int:
    ok_manifest, manifest_or_rc = _require_manifest(args)
    if not ok_manifest:
        return int(manifest_or_rc)
    manifest_by_method = manifest_or_rc

    ok_env, env_or_rc = _require_env_json(
        raw_env_json=args.env_json,
        method="analytics.arbitrage_patterns",
        compact=bool(args.compact),
    )
    if not ok_env:
        return int(env_or_rc)
    env = env_or_rc

    limit = int(args.limit)
    if limit < 0:
        _print_error(
            method="analytics.arbitrage_patterns",
            status="error",
            code=ERR_INVALID_REQUEST,
            message="limit must be a non-negative integer",
            pretty=not args.compact,
        )
        return 2

    min_swaps = int(args.min_swaps)
    if min_swaps < 2:
        _print_error(
            method="analytics.arbitrage_patterns",
            status="error",
            code=ERR_INVALID_REQUEST,
            message="min-swaps must be >= 2",
            pretty=not args.compact,
        )
        return 2

    max_transactions: int | None = None
    if args.max_transactions is not None:
        max_transactions = int(args.max_transactions)
        if max_transactions <= 0:
            _print_error(
                method="analytics.arbitrage_patterns",
                status="error",
                code=ERR_INVALID_REQUEST,
                message="max-transactions must be a positive integer",
                pretty=not args.compact,
            )
            return 2

    ok_block, block_tag, block_err = _analytics_parse_block_tag(args.block)
    if not ok_block:
        _print_error(
            method="analytics.arbitrage_patterns",
            status="error",
            code=ERR_INVALID_REQUEST,
            message=block_err,
            pretty=not args.compact,
        )
        return 2

    execute_rpc = _make_analytics_executor(
        manifest_by_method=manifest_by_method,
        default_context={},
        default_env=env,
        default_timeout_seconds=float(args.timeout_seconds),
    )

    rc_block, block_payload = execute_rpc(
        {"method": "eth_getBlockByNumber", "params": [block_tag, True]}
    )
    if rc_block != 0:
        payload = _wrap_stage_failure(
            "analytics.arbitrage_patterns",
            f"eth_getBlockByNumber({block_tag})",
            block_payload,
        )
        render_rc = _render_output(
            payload=payload,
            compact=args.compact,
            result_only=bool(args.result_only),
            select=args.select,
            result_field="result",
        )
        if render_rc != 0:
            return render_rc
        return rc_block

    block_result = block_payload.get("result")
    if not isinstance(block_result, dict):
        payload = _build_error_payload(
            method="analytics.arbitrage_patterns",
            status="error",
            code=ERR_INVALID_REQUEST,
            message="eth_getBlockByNumber returned non-object result",
        )
        payload["request_block"] = block_tag
        render_rc = _render_output(
            payload=payload,
            compact=args.compact,
            result_only=bool(args.result_only),
            select=args.select,
            result_field="result",
        )
        if render_rc != 0:
            return render_rc
        return 2

    txs = block_result.get("transactions", [])
    if not isinstance(txs, list):
        payload = _build_error_payload(
            method="analytics.arbitrage_patterns",
            status="error",
            code=ERR_INVALID_REQUEST,
            message="block.transactions must be a list",
        )
        render_rc = _render_output(
            payload=payload,
            compact=args.compact,
            result_only=bool(args.result_only),
            select=args.select,
            result_field="result",
        )
        if render_rc != 0:
            return render_rc
        return 2

    txs_to_scan = txs
    if max_transactions is not None:
        txs_to_scan = txs_to_scan[:max_transactions]

    block_number_raw = block_result.get("number")
    block_number: int | None = None
    if isinstance(block_number_raw, str):
        ok_number, as_number, _ = _analytics_hex_to_int(block_number_raw)
        if ok_number:
            block_number = as_number

    block_timestamp_raw = block_result.get("timestamp")
    block_timestamp_utc: str | None = None
    if isinstance(block_timestamp_raw, str):
        ok_ts, as_ts, _ = _analytics_hex_to_int(block_timestamp_raw)
        if ok_ts:
            try:
                block_timestamp_utc = datetime.fromtimestamp(as_ts, tz=UTC).isoformat()
            except Exception:  # noqa: BLE001
                block_timestamp_utc = None

    block_for_calls = block_number_raw if isinstance(block_number_raw, str) else block_tag

    pool_cache: dict[str, tuple[str | None, str | None]] = {}
    receipt_failures: list[dict[str, Any]] = []
    pool_failures: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    txs_with_swaps = 0

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

        rc_receipt, receipt_payload = execute_rpc(
            {"method": "eth_getTransactionReceipt", "params": [tx_hash]}
        )
        if rc_receipt != 0:
            receipt_failures.append(
                {
                    "tx_hash": tx_hash,
                    "error_code": receipt_payload.get("error_code"),
                    "error_message": receipt_payload.get("error_message"),
                }
            )
            continue

        receipt = receipt_payload.get("result")
        if not isinstance(receipt, dict):
            receipt_failures.append(
                {
                    "tx_hash": tx_hash,
                    "error_code": ERR_INVALID_REQUEST,
                    "error_message": "eth_getTransactionReceipt returned non-object result",
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

            tokens = pool_cache.get(pool)
            if tokens is None:
                rc_pool, pool_payload, resolved_tokens = _analytics_fetch_pool_tokens_for_arbitrage(
                    pool=pool,
                    block_tag=block_for_calls,
                    execute_rpc=execute_rpc,
                )
                pool_cache[pool] = resolved_tokens
                tokens = resolved_tokens
                if rc_pool != 0:
                    pool_failures.append(
                        {
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

            ok_swap, swap = _analytics_decode_swap_for_arbitrage(
                log_item=log_item,
                topic0=topic0,
                pool=pool,
                token0=token0,
                token1=token1,
                log_index=idx,
            )
            if not ok_swap or not isinstance(swap, dict):
                continue
            swaps.append(swap)

        if not swaps:
            continue
        txs_with_swaps += 1

        candidate = _analytics_build_arbitrage_candidate(
            tx_hash=tx_hash,
            tx_from=tx_from,
            tx_to=tx_to,
            tx_value=tx_value,
            swaps=swaps,
            min_swaps=min_swaps,
            include_swaps=bool(args.include_swaps),
        )
        if candidate is not None:
            candidates.append(candidate)

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

    result: dict[str, Any] = {
        "requested_block": block_tag,
        "block": {
            "number": block_number,
            "number_hex": block_number_raw if isinstance(block_number_raw, str) else None,
            "hash": block_result.get("hash"),
            "timestamp_utc": block_timestamp_utc,
            "tx_count_total": len(txs),
            "tx_count_scanned": len(txs_to_scan),
        },
        "summary": {
            "transactions_with_swap_logs": txs_with_swaps,
            "arbitrage_candidates_total": len(candidates),
            "arbitrage_candidates_returned": len(returned_candidates),
            "receipt_failures": len(receipt_failures),
            "pool_metadata_failures": len(pool_failures),
            "unique_pools_seen": len(pool_cache),
        },
        "heuristic": (
            "Detect Uniswap V2/V3 swap chains in each transaction and flag cyclic token paths, "
            "multi-pool continuity, and mixed V2+V3 routing as arbitrage-like patterns."
        ),
        "candidates": returned_candidates,
    }
    if bool(args.include_failures):
        result["failures"] = {
            "receipt_failures": receipt_failures,
            "pool_metadata_failures": pool_failures,
        }

    payload = {
        "timestamp_utc": _timestamp(),
        "method": "analytics.arbitrage_patterns",
        "status": "ok",
        "ok": True,
        "error_code": None,
        "error_message": None,
        "result": result,
    }
    render_rc = _render_output(
        payload=payload,
        compact=args.compact,
        result_only=bool(args.result_only),
        select=args.select,
        result_field="result",
    )
    if render_rc != 0:
        return render_rc
    return 0


def _eth_call_req(
    *,
    to: str,
    data: str,
    block_tag: str,
    env: dict[str, Any],
    timeout_seconds: float,
) -> dict[str, Any]:
    req: dict[str, Any] = {
        "method": "eth_call",
        "params": [{"to": to, "data": data}, block_tag],
        "context": {},
        "timeout_seconds": timeout_seconds,
    }
    if env:
        req["env"] = env
    return req


def _resolve_ens_address(
    *,
    name: str,
    block_tag: str,
    env: dict[str, Any],
    timeout_seconds: float,
    manifest_by_method: dict[str, dict[str, Any]],
) -> tuple[int, dict[str, Any], str | None]:
    ok, nodehash, err = ens_namehash(name)
    if not ok:
        payload = _build_error_payload(
            method="ens_resolve",
            status="error",
            code=ERR_INVALID_REQUEST,
            message=err,
        )
        return 2, payload, None

    if not isinstance(nodehash, str) or not HEX32_RE.fullmatch(nodehash):
        payload = _build_error_payload(
            method="ens_resolve",
            status="error",
            code=ERR_INTERNAL,
            message="internal namehash computation failed",
        )
        return 2, payload, None

    resolver_call_data = f"0x0178b8bf{nodehash[2:]}"
    resolver_req = _eth_call_req(
        to=ENS_REGISTRY,
        data=resolver_call_data,
        block_tag=block_tag,
        env=env,
        timeout_seconds=timeout_seconds,
    )
    rc_resolver, resolver_payload = run_rpc_request(req=resolver_req, manifest_by_method=manifest_by_method)
    if rc_resolver != 0:
        return rc_resolver, _wrap_stage_failure("ens_resolve", "resolver lookup", resolver_payload), None

    t_ok, resolver_addr, t_err = apply_transform(
        "slice_last_20_bytes_to_address", resolver_payload.get("result")
    )
    if not t_ok or not isinstance(resolver_addr, str):
        payload = _build_error_payload(
            method="ens_resolve",
            status="error",
            code=ERR_INVALID_REQUEST,
            message=f"resolver lookup parse failed: {t_err}",
        )
        payload["resolver_call"] = resolver_payload
        return 2, payload, None

    if resolver_addr.lower() == ZERO_ADDRESS:
        payload = _build_error_payload(
            method="ens_resolve",
            status="error",
            code=ERR_INVALID_REQUEST,
            message="ens resolver is not set for name",
        )
        payload["nodehash"] = nodehash
        payload["resolver"] = resolver_addr
        return 2, payload, None

    addr_call_data = f"0x3b3b57de{nodehash[2:]}"
    addr_req = _eth_call_req(
        to=resolver_addr,
        data=addr_call_data,
        block_tag=block_tag,
        env=env,
        timeout_seconds=timeout_seconds,
    )
    rc_addr, addr_payload = run_rpc_request(req=addr_req, manifest_by_method=manifest_by_method)
    if rc_addr != 0:
        return rc_addr, _wrap_stage_failure("ens_resolve", "address lookup", addr_payload), None

    a_ok, resolved_addr, a_err = apply_transform("slice_last_20_bytes_to_address", addr_payload.get("result"))
    if not a_ok or not isinstance(resolved_addr, str):
        payload = _build_error_payload(
            method="ens_resolve",
            status="error",
            code=ERR_INVALID_REQUEST,
            message=f"address lookup parse failed: {a_err}",
        )
        payload["resolver"] = resolver_addr
        payload["address_call"] = addr_payload
        return 2, payload, None

    payload = {
        "timestamp_utc": _timestamp(),
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


def cmd_ens_resolve(args: argparse.Namespace) -> int:
    ok_manifest, manifest_or_rc = _require_manifest(args)
    if not ok_manifest:
        return int(manifest_or_rc)
    manifest_by_method = manifest_or_rc

    ok_env, env_or_rc = _require_env_json(
        raw_env_json=args.env_json,
        method="ens_resolve",
        compact=bool(args.compact),
    )
    if not ok_env:
        return int(env_or_rc)
    env = env_or_rc

    exit_code, payload, _ = _resolve_ens_address(
        name=args.name,
        block_tag=args.at,
        env=env,
        timeout_seconds=float(args.timeout_seconds),
        manifest_by_method=manifest_by_method,
    )
    render_rc = _render_output(
        payload=payload,
        compact=args.compact,
        result_only=bool(args.result_only),
        select=args.select,
        result_field="result",
    )
    if render_rc != 0:
        return render_rc
    return exit_code


def cmd_balance(args: argparse.Namespace) -> int:
    ok_manifest, manifest_or_rc = _require_manifest(args)
    if not ok_manifest:
        return int(manifest_or_rc)
    manifest_by_method = manifest_or_rc

    ok_env, env_or_rc = _require_env_json(
        raw_env_json=args.env_json,
        method="balance",
        compact=bool(args.compact),
    )
    if not ok_env:
        return int(env_or_rc)
    env = env_or_rc

    target = str(args.target).strip()
    if not target:
        _print_error(
            method="balance",
            status="error",
            code=ERR_INVALID_REQUEST,
            message="target cannot be empty",
            pretty=not args.compact,
        )
        return 2

    resolved_address = target
    resolution_payload: dict[str, Any] | None = None
    if "." in target:
        rc_resolve, ens_payload, ens_addr = _resolve_ens_address(
            name=target,
            block_tag=args.at,
            env=env,
            timeout_seconds=float(args.timeout_seconds),
            manifest_by_method=manifest_by_method,
        )
        if rc_resolve != 0 or not ens_addr:
            wrapped = _wrap_stage_failure("balance", "ens resolution", ens_payload)
            render_rc = _render_output(
                payload=wrapped,
                compact=args.compact,
                result_only=bool(args.result_only),
                select=args.select,
                result_field="result",
            )
            if render_rc != 0:
                return render_rc
            return rc_resolve
        resolved_address = ens_addr
        resolution_payload = ens_payload

    if not ADDRESS_RE.fullmatch(resolved_address):
        _print_error(
            method="balance",
            status="error",
            code=ERR_INVALID_REQUEST,
            message="target must be a 20-byte hex address or ENS name",
            pretty=not args.compact,
        )
        return 2

    req: dict[str, Any] = {
        "method": "eth_getBalance",
        "params": [resolved_address, args.at],
        "context": {},
        "timeout_seconds": float(args.timeout_seconds),
    }
    if env:
        req["env"] = env

    exit_code, balance_payload = run_rpc_request(req=req, manifest_by_method=manifest_by_method)
    if exit_code != 0:
        wrapped = _wrap_stage_failure("balance", "eth_getBalance", balance_payload)
        render_rc = _render_output(
            payload=wrapped,
            compact=args.compact,
            result_only=bool(args.result_only),
            select=args.select,
            result_field="result",
        )
        if render_rc != 0:
            return render_rc
        return exit_code

    t_ok, eth_value, t_err = apply_transform("wei_to_eth", balance_payload.get("result"))
    if not t_ok:
        _print_error(
            method="balance",
            status="error",
            code=ERR_INVALID_REQUEST,
            message=t_err,
            pretty=not args.compact,
        )
        return 2

    payload = {
        "timestamp_utc": _timestamp(),
        "method": "balance",
        "status": "ok",
        "ok": True,
        "error_code": None,
        "error_message": None,
        "target": target,
        "resolved_address": resolved_address,
        "at": args.at,
        "result": {
            "wei_hex": balance_payload.get("result"),
            "eth": eth_value,
        },
        "balance_call": balance_payload,
    }
    if resolution_payload is not None:
        payload["ens_resolution"] = resolution_payload

    render_rc = _render_output(
        payload=payload,
        compact=args.compact,
        result_only=bool(args.result_only),
        select=args.select,
        result_field="result",
    )
    if render_rc != 0:
        return render_rc
    return 0


def cmd_supported_methods(args: argparse.Namespace) -> int:
    manifest_by_method = load_manifest_by_method(Path(args.manifest).resolve())
    methods = sorted(
        method for method, entry in manifest_by_method.items() if bool(entry.get("enabled", True))
    )
    print(json.dumps({"supported_methods": methods, "count": len(methods)}, indent=2))
    return 0


def cmd_manifest_summary(args: argparse.Namespace) -> int:
    manifest = load_json(Path(args.manifest).resolve())
    entries = manifest.get("entries", [])
    tier_counts: dict[str, int] = {}
    impl_counts: dict[str, int] = {}
    for entry in entries:
        tier = str(entry.get("tier", "unknown"))
        impl = str(entry.get("implementation", "unknown"))
        tier_counts[tier] = tier_counts.get(tier, 0) + 1
        impl_counts[impl] = impl_counts.get(impl, 0) + 1
    payload = {
        "manifest": str(Path(args.manifest).resolve()),
        "count": len(entries),
        "tier_counts": tier_counts,
        "implementation_counts": impl_counts,
        "source_repository": manifest.get("source_repository"),
        "source_commit": manifest.get("source_commit"),
    }
    print(json.dumps(payload, indent=2))
    return 0


def _add_output_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--compact", action="store_true", help="compact JSON output")
    parser.add_argument("--result-only", action="store_true", help="print only result field")
    parser.add_argument(
        "--select",
        help="jsonpath-lite selector (supports $, .key, [index])",
    )


def _add_manifest_request_output_args(parser: argparse.ArgumentParser, *, label: str) -> None:
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST), help="method manifest path")
    parser.add_argument("--request-file", help=f"{label} request JSON file")
    parser.add_argument("--request-json", help=f"{label} request JSON string")
    _add_output_args(parser)


def _add_request_output_args(parser: argparse.ArgumentParser, *, label: str) -> None:
    parser.add_argument("--request-file", help=f"{label} request JSON file")
    parser.add_argument("--request-json", help=f"{label} request JSON string")
    _add_output_args(parser)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    exec_parser = sub.add_parser("exec", help="Execute one JSON-RPC method through policy wrapper")
    exec_parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST), help="method manifest path")
    exec_parser.add_argument("--request-file", help="request JSON file")
    exec_parser.add_argument("--request-json", help="request JSON string")
    exec_parser.add_argument("--method", help="method name (if not using request JSON)")
    exec_parser.add_argument("--params-json", help="params list as JSON")
    exec_parser.add_argument("--id-json", help="id value as JSON")
    exec_parser.add_argument("--context-json", help="context object as JSON")
    exec_parser.add_argument("--env-json", help="env object as JSON")
    exec_parser.add_argument("--timeout-seconds", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    _add_output_args(exec_parser)
    exec_parser.set_defaults(func=cmd_exec)

    logs_parser = sub.add_parser("logs", help="Execute chunked eth_getLogs workflows")
    _add_manifest_request_output_args(logs_parser, label="logs")
    logs_parser.add_argument("--event", help="event signature or alias (e.g. transfer)")
    logs_parser.add_argument(
        "--last",
        "--last-blocks",
        dest="last_blocks",
        type=int,
        help="query only the latest N blocks (cannot be combined with explicit fromBlock/toBlock)",
    )
    logs_parser.add_argument(
        "--decode-erc20-transfer",
        action="store_true",
        help="decode logs as ERC20 Transfer events",
    )
    logs_parser.add_argument(
        "--decimals",
        type=int,
        help="fixed decimals to use for ERC20 value_decimal formatting",
    )
    logs_parser.add_argument(
        "--decimals-auto",
        action="store_true",
        help="resolve decimals() per token via eth_call when decoding ERC20 transfers",
    )
    logs_parser.add_argument("--limit", type=int, help="limit output rows after processing")
    logs_parser.add_argument(
        "--sample",
        type=int,
        help="deterministically sample N rows before applying --limit",
    )
    logs_parser.add_argument(
        "--summary-only",
        action="store_true",
        help="return summary metadata without row payloads",
    )
    logs_parser.add_argument("--out", help="write rows to file")
    logs_parser.add_argument(
        "--format",
        default="json",
        choices=("json", "jsonl", "csv"),
        help="row output format when using --out",
    )
    logs_parser.add_argument("--gzip", action="store_true", help="gzip --out file contents")
    logs_parser.set_defaults(func=cmd_logs)

    abi_parser = sub.add_parser("abi", help="ABI encode/decode helpers")
    _add_request_output_args(abi_parser, label="abi")
    abi_parser.set_defaults(func=cmd_abi)

    multicall_parser = sub.add_parser(
        "multicall",
        help="Run many eth_call requests with shared context and deterministic output",
    )
    _add_manifest_request_output_args(multicall_parser, label="multicall")
    multicall_parser.set_defaults(func=cmd_multicall)

    simulate_parser = sub.add_parser("simulate", help="Run eth_call and optional eth_estimateGas preflight")
    _add_manifest_request_output_args(simulate_parser, label="simulate")
    simulate_parser.set_defaults(func=cmd_simulate)

    trace_parser = sub.add_parser("trace", help="Run trace methods when provider and manifest support them")
    _add_manifest_request_output_args(trace_parser, label="trace")
    trace_parser.set_defaults(func=cmd_trace)

    chain_parser = sub.add_parser("chain", help="Execute a chain of JSON-RPC and transform steps")
    _add_manifest_request_output_args(chain_parser, label="chain")
    chain_parser.set_defaults(func=cmd_chain)

    batch_parser = sub.add_parser("batch", help="Alias for chain")
    _add_manifest_request_output_args(batch_parser, label="chain")
    batch_parser.set_defaults(func=cmd_batch)

    ens_parser = sub.add_parser("ens", help="ENS convenience commands")
    ens_sub = ens_parser.add_subparsers(dest="ens_command", required=True)

    ens_resolve_parser = ens_sub.add_parser("resolve", help="Resolve ENS name to address")
    ens_resolve_parser.add_argument("name", help="ENS name")
    ens_resolve_parser.add_argument("--at", default="latest", help="block tag for eth_call")
    ens_resolve_parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST), help="method manifest path")
    ens_resolve_parser.add_argument("--env-json", help="runtime env object as JSON")
    ens_resolve_parser.add_argument("--timeout-seconds", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    _add_output_args(ens_resolve_parser)
    ens_resolve_parser.set_defaults(func=cmd_ens_resolve)

    balance_parser = sub.add_parser("balance", help="Read ETH balance for address or ENS name")
    balance_parser.add_argument("target", help="address or ENS name")
    balance_parser.add_argument("--at", default="latest", help="block tag")
    balance_parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST), help="method manifest path")
    balance_parser.add_argument("--env-json", help="runtime env object as JSON")
    balance_parser.add_argument("--timeout-seconds", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    _add_output_args(balance_parser)
    balance_parser.set_defaults(func=cmd_balance)

    analytics_parser = sub.add_parser("analytics", help="High-level analytics workflows")
    analytics_sub = analytics_parser.add_subparsers(dest="analytics_command", required=True)

    swap_flow_parser = analytics_sub.add_parser(
        "dex-swap-flow",
        help="Scan Uniswap V2 Swap logs for one pool and compute net flow",
    )
    swap_flow_parser.add_argument("--pool", required=True, help="Uniswap V2 pair address")
    swap_flow_parser.add_argument("--last-blocks", type=int, help="scan latest N blocks")
    swap_flow_parser.add_argument("--since", help="time window like 30m, 24h, 7d")
    swap_flow_parser.add_argument("--chunk-size", type=int, default=2000)
    swap_flow_parser.add_argument("--max-chunks", type=int, default=200)
    swap_flow_parser.add_argument("--max-logs", type=int, default=10000)
    swap_flow_parser.add_argument("--limit", type=int, help="cap decoded rows")
    swap_flow_parser.add_argument("--no-adaptive-split", action="store_true")
    swap_flow_parser.add_argument("--allow-heavy-read", action="store_true")
    swap_flow_parser.add_argument("--checkpoint-file", help="json checkpoint path for resumable scans")
    swap_flow_parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST), help="method manifest path")
    swap_flow_parser.add_argument("--env-json", help="runtime env object as JSON")
    swap_flow_parser.add_argument("--timeout-seconds", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    _add_output_args(swap_flow_parser)
    swap_flow_parser.set_defaults(func=cmd_analytics_dex_swap_flow)

    new_pools_parser = analytics_sub.add_parser(
        "factory-new-pools",
        help="Decode factory PairCreated/PoolCreated logs",
    )
    new_pools_parser.add_argument("--factory", required=True, help="factory contract address")
    new_pools_parser.add_argument(
        "--protocol",
        choices=("uniswap-v2", "uniswap-v3"),
        default="uniswap-v2",
    )
    new_pools_parser.add_argument("--last-blocks", type=int, help="scan latest N blocks")
    new_pools_parser.add_argument("--since", help="time window like 30m, 24h, 7d")
    new_pools_parser.add_argument("--chunk-size", type=int, default=2000)
    new_pools_parser.add_argument("--max-chunks", type=int, default=200)
    new_pools_parser.add_argument("--max-logs", type=int, default=10000)
    new_pools_parser.add_argument("--limit", type=int, help="cap decoded rows")
    new_pools_parser.add_argument("--no-adaptive-split", action="store_true")
    new_pools_parser.add_argument("--allow-heavy-read", action="store_true")
    new_pools_parser.add_argument("--checkpoint-file", help="json checkpoint path for resumable scans")
    new_pools_parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST), help="method manifest path")
    new_pools_parser.add_argument("--env-json", help="runtime env object as JSON")
    new_pools_parser.add_argument("--timeout-seconds", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    _add_output_args(new_pools_parser)
    new_pools_parser.set_defaults(func=cmd_analytics_factory_new_pools)

    arbitrage_parser = analytics_sub.add_parser(
        "arbitrage-patterns",
        help="Inspect one block and flag arbitrage-like swap routing patterns",
    )
    arbitrage_parser.add_argument(
        "--block",
        default="latest",
        help="block tag (latest/earliest/pending/safe/finalized) or block number",
    )
    arbitrage_parser.add_argument("--limit", type=int, default=10, help="cap returned candidates")
    arbitrage_parser.add_argument(
        "--min-swaps",
        type=int,
        default=2,
        help="minimum swap count in a transaction to consider candidate classification",
    )
    arbitrage_parser.add_argument(
        "--max-transactions",
        type=int,
        help="scan only the first N transactions from the block",
    )
    arbitrage_parser.add_argument(
        "--include-swaps",
        action="store_true",
        help="include per-swap hop rows in each candidate",
    )
    arbitrage_parser.add_argument(
        "--include-failures",
        action="store_true",
        help="include receipt/pool metadata failure details",
    )
    arbitrage_parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST), help="method manifest path")
    arbitrage_parser.add_argument("--env-json", help="runtime env object as JSON")
    arbitrage_parser.add_argument("--timeout-seconds", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    _add_output_args(arbitrage_parser)
    arbitrage_parser.set_defaults(func=cmd_analytics_arbitrage_patterns)

    list_parser = sub.add_parser("supported-methods", help="List enabled methods from manifest")
    list_parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST), help="method manifest path")
    list_parser.set_defaults(func=cmd_supported_methods)

    summary_parser = sub.add_parser("manifest-summary", help="Print manifest summary")
    summary_parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST), help="method manifest path")
    summary_parser.set_defaults(func=cmd_manifest_summary)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
