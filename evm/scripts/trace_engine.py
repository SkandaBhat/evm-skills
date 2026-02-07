"""Trace capability negotiation and normalized execution."""

from __future__ import annotations

import re
from typing import Any, Callable

from error_map import ERR_TRACE_UNSUPPORTED

HEX32_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")

TraceExecutor = Callable[[dict[str, Any]], tuple[int, dict[str, Any]]]


def normalize_trace_request(request: dict[str, Any]) -> tuple[bool, dict[str, Any], str]:
    if not isinstance(request, dict):
        return False, {}, "trace request must be an object"

    mode = str(request.get("mode", "call")).strip().lower()
    if mode not in {"call", "transaction"}:
        return False, {}, "trace request.mode must be 'call' or 'transaction'"

    block_tag = request.get("block_tag", "latest")
    if not isinstance(block_tag, str) or not block_tag.strip():
        return False, {}, "trace request.block_tag must be a non-empty string"

    context = request.get("context", {})
    if context and not isinstance(context, dict):
        return False, {}, "trace request.context must be an object"

    env = request.get("env", {})
    if env and (not isinstance(env, dict) or not all(isinstance(k, str) for k in env.keys())):
        return False, {}, "trace request.env must be an object with string keys"

    timeout_seconds = request.get("timeout_seconds")
    if timeout_seconds is not None and (
        not isinstance(timeout_seconds, (int, float)) or timeout_seconds <= 0
    ):
        return False, {}, "trace request.timeout_seconds must be a positive number"

    trace_config = request.get("trace_config", {})
    if trace_config and not isinstance(trace_config, dict):
        return False, {}, "trace request.trace_config must be an object"

    if mode == "call":
        call_object = request.get("call_object")
        if not isinstance(call_object, dict):
            return False, {}, "trace request.call_object must be an object when mode=call"
        tx_hash = None
    else:
        tx_hash = request.get("tx_hash")
        if not isinstance(tx_hash, str) or not HEX32_RE.fullmatch(tx_hash):
            return False, {}, "trace request.tx_hash must be 0x-prefixed 32-byte hash when mode=transaction"
        call_object = None

    return (
        True,
        {
            "mode": mode,
            "block_tag": block_tag,
            "context": context or {},
            "env": env or {},
            "timeout_seconds": timeout_seconds,
            "trace_config": trace_config or {},
            "call_object": call_object,
            "tx_hash": tx_hash,
            "request": request,
        },
        "",
    )


def _candidate_methods(normalized_request: dict[str, Any]) -> list[tuple[str, list[Any]]]:
    mode = normalized_request["mode"]
    trace_config = normalized_request.get("trace_config", {})

    if mode == "call":
        call_object = normalized_request["call_object"]
        block_tag = normalized_request["block_tag"]
        return [
            ("debug_traceCall", [call_object, block_tag, trace_config]),
            ("trace_call", [call_object, ["trace"], block_tag]),
        ]

    tx_hash = normalized_request["tx_hash"]
    return [
        ("debug_traceTransaction", [tx_hash, trace_config]),
        ("trace_replayTransaction", [tx_hash, ["trace"]]),
    ]


def _is_provider_method_missing(payload: dict[str, Any]) -> bool:
    rpc_response = payload.get("rpc_response")
    if not isinstance(rpc_response, dict):
        return False

    error_obj = rpc_response.get("error")
    if not isinstance(error_obj, dict):
        return False

    message = str(error_obj.get("message", "")).lower()
    patterns = (
        "method not found",
        "does not exist",
        "unsupported",
        "not enabled",
        "not available",
    )
    return any(p in message for p in patterns)


def run_trace(
    *,
    normalized_request: dict[str, Any],
    manifest_by_method: dict[str, dict[str, Any]],
    execute_rpc: TraceExecutor,
) -> tuple[int, dict[str, Any]]:
    candidates = _candidate_methods(normalized_request)
    context = dict(normalized_request.get("context", {}))
    env = dict(normalized_request.get("env", {}))
    timeout_seconds = normalized_request.get("timeout_seconds")

    attempts: list[dict[str, Any]] = []

    for method, params in candidates:
        entry = manifest_by_method.get(method)
        if not isinstance(entry, dict) or not bool(entry.get("enabled", True)):
            attempts.append(
                {
                    "method": method,
                    "status": "skipped",
                    "reason": "method not enabled in manifest",
                }
            )
            continue

        req: dict[str, Any] = {
            "method": method,
            "params": params,
            "context": context,
        }
        if env:
            req["env"] = env
        if timeout_seconds is not None:
            req["timeout_seconds"] = timeout_seconds

        exit_code, payload = execute_rpc(req)
        if exit_code == 0:
            return 0, {
                "ok": True,
                "status": "ok",
                "error_code": None,
                "error_message": None,
                "method_used": method,
                "result": payload.get("result"),
                "trace_payload": payload,
                "attempts": attempts,
            }

        attempts.append(
            {
                "method": method,
                "status": "error",
                "error_code": payload.get("error_code"),
                "error_message": payload.get("error_message"),
            }
        )

        if _is_provider_method_missing(payload):
            continue

        return exit_code, {
            "ok": False,
            "status": payload.get("status", "error"),
            "error_code": payload.get("error_code"),
            "error_message": payload.get("error_message"),
            "attempts": attempts,
            "cause": payload,
        }

    return 1, {
        "ok": False,
        "status": "error",
        "error_code": ERR_TRACE_UNSUPPORTED,
        "error_message": "trace methods unavailable in manifest or remote provider",
        "attempts": attempts,
    }
