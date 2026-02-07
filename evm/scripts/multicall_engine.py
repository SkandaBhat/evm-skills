"""Client-side aggregated eth_call execution helpers."""

from __future__ import annotations

import copy
import re
from typing import Any, Callable

from abi_codec import decode_output, encode_call
from error_map import ERR_INVALID_REQUEST, ERR_MULTICALL_PARTIAL_FAILURE

ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
HEX_RE = re.compile(r"^0x[0-9a-fA-F]*$")

DEFAULT_CHUNK_SIZE = 25
DEFAULT_MAX_CALLS = 200


CallExecutor = Callable[[dict[str, Any]], tuple[int, dict[str, Any]]]


def _parse_positive_int(raw: Any, *, field: str, default: int) -> tuple[bool, int, str]:
    value = default if raw is None else raw
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return False, 0, f"{field} must be a positive integer"
    return True, value, ""


def normalize_multicall_request(request: dict[str, Any]) -> tuple[bool, dict[str, Any], str]:
    if not isinstance(request, dict):
        return False, {}, "multicall request must be an object"

    calls = request.get("calls")
    if not isinstance(calls, list) or not calls:
        return False, {}, "multicall request.calls must be a non-empty array"

    ok_chunk, chunk_size, chunk_err = _parse_positive_int(
        request.get("chunk_size"),
        field="multicall request.chunk_size",
        default=DEFAULT_CHUNK_SIZE,
    )
    if not ok_chunk:
        return False, {}, chunk_err

    ok_max, max_calls, max_err = _parse_positive_int(
        request.get("max_calls"),
        field="multicall request.max_calls",
        default=DEFAULT_MAX_CALLS,
    )
    if not ok_max:
        return False, {}, max_err

    if len(calls) > max_calls:
        return False, {}, f"multicall request.calls exceeds max_calls={max_calls}"

    block_tag = request.get("block_tag", "latest")
    if not isinstance(block_tag, str) or not block_tag.strip():
        return False, {}, "multicall request.block_tag must be a non-empty string"

    context = request.get("context", {})
    if context and not isinstance(context, dict):
        return False, {}, "multicall request.context must be an object"

    env = request.get("env", {})
    if env and (not isinstance(env, dict) or not all(isinstance(k, str) for k in env.keys())):
        return False, {}, "multicall request.env must be an object with string keys"

    timeout_seconds = request.get("timeout_seconds")
    if timeout_seconds is not None and (
        not isinstance(timeout_seconds, (int, float)) or timeout_seconds <= 0
    ):
        return False, {}, "multicall request.timeout_seconds must be a positive number"

    fail_fast = bool(request.get("fail_fast", True))

    normalized_calls: list[dict[str, Any]] = []
    for idx, raw_call in enumerate(calls):
        if not isinstance(raw_call, dict):
            return False, {}, f"calls[{idx}] must be an object"

        call_id = raw_call.get("id", f"call_{idx}")
        if not isinstance(call_id, str) or not call_id.strip():
            return False, {}, f"calls[{idx}].id must be a non-empty string"

        to = raw_call.get("to")
        if not isinstance(to, str) or not ADDRESS_RE.fullmatch(to):
            return False, {}, f"calls[{idx}].to must be a 20-byte hex address"

        data = raw_call.get("data")
        signature = raw_call.get("signature")
        args = raw_call.get("args", [])

        if data is None and signature is None:
            return False, {}, f"calls[{idx}] requires either data or signature"
        if data is not None and signature is not None:
            return False, {}, f"calls[{idx}] cannot include both data and signature"

        if data is not None:
            if not isinstance(data, str) or not HEX_RE.fullmatch(data) or (len(data) % 2 != 0):
                return False, {}, f"calls[{idx}].data must be even-length 0x-prefixed hex"
            calldata = data
            selector = data[:10] if len(data) >= 10 else None
            canonical_signature = None
        else:
            if not isinstance(signature, str) or not signature.strip():
                return False, {}, f"calls[{idx}].signature must be non-empty string"
            if not isinstance(args, list):
                return False, {}, f"calls[{idx}].args must be an array"
            try:
                encoded = encode_call(signature, args)
            except Exception as err:  # noqa: BLE001
                return False, {}, f"calls[{idx}] signature/args encode failed: {err}"
            calldata = str(encoded["calldata"])
            selector = str(encoded["selector"])
            canonical_signature = str(encoded["signature"])

        decode_types = raw_call.get("decode_output")
        if decode_types is not None and not isinstance(decode_types, (str, list)):
            return False, {}, f"calls[{idx}].decode_output must be string or array of strings"

        per_call_block_tag = raw_call.get("block_tag", block_tag)
        if not isinstance(per_call_block_tag, str) or not per_call_block_tag.strip():
            return False, {}, f"calls[{idx}].block_tag must be a non-empty string"

        call_entry = {
            "id": call_id,
            "index": idx,
            "to": to.lower(),
            "data": calldata,
            "selector": selector,
            "signature": canonical_signature,
            "decode_output": decode_types,
            "block_tag": per_call_block_tag,
            "call_object": raw_call.get("call_object", {}),
            "allow_failure": bool(raw_call.get("allow_failure", False)),
        }
        if call_entry["call_object"] and not isinstance(call_entry["call_object"], dict):
            return False, {}, f"calls[{idx}].call_object must be an object"

        normalized_calls.append(call_entry)

    normalized = {
        "calls": normalized_calls,
        "chunk_size": chunk_size,
        "max_calls": max_calls,
        "block_tag": block_tag,
        "fail_fast": fail_fast,
        "context": context or {},
        "env": env or {},
        "timeout_seconds": timeout_seconds,
        "request": copy.deepcopy(request),
    }
    return True, normalized, ""


def _build_eth_call_req(
    *,
    to: str,
    data: str,
    block_tag: str,
    call_object: dict[str, Any],
    context: dict[str, Any],
    env: dict[str, Any],
    timeout_seconds: float | None,
) -> dict[str, Any]:
    tx_obj = {"to": to, "data": data}
    for key in ("from", "gas", "gasPrice", "maxFeePerGas", "maxPriorityFeePerGas", "value"):
        if key in call_object:
            tx_obj[key] = call_object[key]

    req: dict[str, Any] = {
        "method": "eth_call",
        "params": [tx_obj, block_tag],
        "context": context,
    }
    if timeout_seconds is not None:
        req["timeout_seconds"] = timeout_seconds
    if env:
        req["env"] = env
    return req


def run_multicall(
    *,
    normalized_request: dict[str, Any],
    execute_call: CallExecutor,
) -> tuple[int, dict[str, Any]]:
    calls = list(normalized_request["calls"])
    chunk_size = int(normalized_request["chunk_size"])
    fail_fast = bool(normalized_request["fail_fast"])
    context = dict(normalized_request.get("context", {}))
    env = dict(normalized_request.get("env", {}))
    timeout_seconds = normalized_request.get("timeout_seconds")

    call_results: list[dict[str, Any]] = []
    success_count = 0
    failed_count = 0

    first_error_exit_code = 1
    first_error_payload: dict[str, Any] | None = None

    for chunk_start in range(0, len(calls), chunk_size):
        chunk = calls[chunk_start : chunk_start + chunk_size]
        for call in chunk:
            req = _build_eth_call_req(
                to=call["to"],
                data=call["data"],
                block_tag=call["block_tag"],
                call_object=call.get("call_object", {}),
                context=context,
                env=env,
                timeout_seconds=timeout_seconds,
            )
            exit_code, payload = execute_call(req)
            if exit_code != 0:
                failed_count += 1
                item = {
                    "id": call["id"],
                    "index": call["index"],
                    "status": "error",
                    "ok": False,
                    "error_code": payload.get("error_code"),
                    "error_message": payload.get("error_message"),
                    "to": call["to"],
                    "data": call["data"],
                    "selector": call.get("selector"),
                    "signature": call.get("signature"),
                    "result": None,
                    "decoded": None,
                    "cause": payload,
                }
                call_results.append(item)
                if first_error_payload is None:
                    first_error_payload = item
                    first_error_exit_code = exit_code
                if fail_fast and not call.get("allow_failure", False):
                    summary = {
                        "requested_calls": len(calls),
                        "executed_calls": len(call_results),
                        "successful_calls": success_count,
                        "failed_calls": failed_count,
                        "chunk_size": chunk_size,
                        "fail_fast": fail_fast,
                    }
                    return first_error_exit_code, {
                        "ok": False,
                        "status": "error",
                        "error_code": ERR_MULTICALL_PARTIAL_FAILURE,
                        "error_message": "multicall failed before completing all calls",
                        "result": call_results,
                        "summary": summary,
                        "failed_call": first_error_payload,
                    }
                continue

            result_hex = payload.get("result")
            decoded: Any = None
            decode_error: str | None = None
            decode_types = call.get("decode_output")
            if decode_types is not None:
                try:
                    decoded = decode_output(decode_types, str(result_hex))
                except Exception as err:  # noqa: BLE001
                    decode_error = str(err)
                    failed_count += 1
                    if first_error_payload is None:
                        first_error_exit_code = 2
                        first_error_payload = {
                            "id": call["id"],
                            "index": call["index"],
                            "status": "error",
                            "ok": False,
                            "error_code": ERR_INVALID_REQUEST,
                            "error_message": f"decode_output failed: {decode_error}",
                            "to": call["to"],
                            "data": call["data"],
                            "selector": call.get("selector"),
                            "signature": call.get("signature"),
                            "result": result_hex,
                            "decoded": None,
                        }

            ok_item = decode_error is None
            if ok_item:
                success_count += 1

            item = {
                "id": call["id"],
                "index": call["index"],
                "status": "ok" if ok_item else "error",
                "ok": ok_item,
                "error_code": None if ok_item else ERR_INVALID_REQUEST,
                "error_message": None if ok_item else f"decode_output failed: {decode_error}",
                "to": call["to"],
                "data": call["data"],
                "selector": call.get("selector"),
                "signature": call.get("signature"),
                "result": result_hex,
                "decoded": decoded,
            }
            call_results.append(item)

            if (not ok_item) and fail_fast and not call.get("allow_failure", False):
                summary = {
                    "requested_calls": len(calls),
                    "executed_calls": len(call_results),
                    "successful_calls": success_count,
                    "failed_calls": failed_count,
                    "chunk_size": chunk_size,
                    "fail_fast": fail_fast,
                }
                return 2, {
                    "ok": False,
                    "status": "error",
                    "error_code": ERR_MULTICALL_PARTIAL_FAILURE,
                    "error_message": "multicall decode failed before completing all calls",
                    "result": call_results,
                    "summary": summary,
                    "failed_call": item,
                }

    summary = {
        "requested_calls": len(calls),
        "executed_calls": len(call_results),
        "successful_calls": success_count,
        "failed_calls": failed_count,
        "chunk_size": chunk_size,
        "fail_fast": fail_fast,
    }

    if failed_count > 0:
        return first_error_exit_code, {
            "ok": False,
            "status": "error",
            "error_code": ERR_MULTICALL_PARTIAL_FAILURE,
            "error_message": "multicall completed with failures",
            "result": call_results,
            "summary": summary,
            "failed_call": first_error_payload,
        }

    return 0, {
        "ok": True,
        "status": "ok",
        "error_code": None,
        "error_message": None,
        "result": call_results,
        "summary": summary,
    }
