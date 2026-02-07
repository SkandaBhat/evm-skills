#!/usr/bin/env python3
"""Agent-facing JSON wrapper around Ethereum JSON-RPC."""

from __future__ import annotations

import argparse
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
    ERR_INTERNAL,
    ERR_INVALID_REQUEST,
    ERR_RPC_BROADCAST_ALREADY_KNOWN,
    ERR_RPC_BROADCAST_INSUFFICIENT_FUNDS,
    ERR_RPC_BROADCAST_NONCE_TOO_LOW,
    ERR_RPC_BROADCAST_UNDERPRICED,
    ERR_RPC_REMOTE,
    ERR_RPC_TIMEOUT,
    ERR_RPC_URL_REQUIRED,
    RPC_URL_REQUIRED_MESSAGE,
)
from adapters import validate_adapter_preflight  # noqa: E402
from method_registry import load_manifest_by_method, load_json  # noqa: E402
from policy_eval import evaluate_policy  # noqa: E402
from rpc_contract import (  # noqa: E402
    DEFAULT_TIMEOUT_SECONDS,
    build_execution_env,
    normalized_context,
    parse_request_from_args,
    validate_request,
)
from rpc_transport import invoke_rpc  # noqa: E402
from transforms import apply_transform, ens_namehash  # noqa: E402

DEFAULT_MANIFEST = (SCRIPT_DIR.parent / "references" / "method-manifest.json").resolve()

ENS_REGISTRY = "0x00000000000c2e074ec69a0dfb2997ba6c7d2e1e"
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
HEX32_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
TEMPLATE_FULL_RE = re.compile(r"^\{\{\s*([^{}]+?)\s*\}\}$")
TEMPLATE_ANY_RE = re.compile(r"\{\{\s*([^{}]+?)\s*\}\}")


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


def _load_manifest_or_error(manifest_path: Path) -> tuple[bool, dict[str, dict[str, Any]] | dict[str, Any]]:
    if not manifest_path.exists():
        return False, _build_error_payload(
            method="",
            status="error",
            code="MANIFEST_NOT_FOUND",
            message=f"manifest not found: {manifest_path}",
        )
    return True, load_manifest_by_method(manifest_path)


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
    rpc_url = str(execution_env.get("ETH_RPC_URL", "")).strip()
    if not rpc_url:
        return (
            4,
            _build_error_payload(
                method=method,
                status="denied",
                code=ERR_RPC_URL_REQUIRED,
                message=RPC_URL_REQUIRED_MESSAGE,
                policy=policy,
                request=req,
                hint="Set ETH_RPC_URL in env before retrying.",
            ),
        )

    timeout_seconds = float(req.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS))
    rpc_payload = {
        "jsonrpc": "2.0",
        "id": req.get("id", 1),
        "method": method,
        "params": req.get("params", []),
    }
    rpc_request_meta = {"jsonrpc": "2.0", "id": rpc_payload["id"], "method": method}
    retries = 0 if policy.get("tier") == "broadcast" else 2

    start = time.perf_counter()
    transport = invoke_rpc(
        rpc_url=rpc_url,
        payload=rpc_payload,
        timeout_seconds=timeout_seconds,
        retries=retries,
    )
    duration_ms = int((time.perf_counter() - start) * 1000)

    if not transport["ok"]:
        status = "timeout" if transport["error_code"] == ERR_RPC_TIMEOUT else "error"
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
            ),
        )

    rpc_response = transport["rpc_response"]
    if isinstance(rpc_response, dict) and "error" in rpc_response:
        remote_code = (
            _map_broadcast_remote_error(rpc_response)
            if policy.get("tier") == "broadcast"
            else ERR_RPC_REMOTE
        )
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
    manifest_path = Path(args.manifest).resolve()
    loaded, manifest_data = _load_manifest_or_error(manifest_path)
    if not loaded:
        print(_json_dump(manifest_data, pretty=not args.compact))
        return 2
    manifest_by_method = manifest_data

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
    manifest_path = Path(args.manifest).resolve()
    loaded, manifest_data = _load_manifest_or_error(manifest_path)
    if not loaded:
        print(_json_dump(manifest_data, pretty=not args.compact))
        return 2
    manifest_by_method = manifest_data

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
    manifest_path = Path(args.manifest).resolve()
    loaded, manifest_data = _load_manifest_or_error(manifest_path)
    if not loaded:
        print(_json_dump(manifest_data, pretty=not args.compact))
        return 2
    manifest_by_method = manifest_data

    env_ok, env, env_err = _parse_env_json(args.env_json)
    if not env_ok:
        _print_error(
            method="ens_resolve",
            status="error",
            code=ERR_INVALID_REQUEST,
            message=env_err,
            pretty=not args.compact,
        )
        return 2

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
    manifest_path = Path(args.manifest).resolve()
    loaded, manifest_data = _load_manifest_or_error(manifest_path)
    if not loaded:
        print(_json_dump(manifest_data, pretty=not args.compact))
        return 2
    manifest_by_method = manifest_data

    env_ok, env, env_err = _parse_env_json(args.env_json)
    if not env_ok:
        _print_error(
            method="balance",
            status="error",
            code=ERR_INVALID_REQUEST,
            message=env_err,
            pretty=not args.compact,
        )
        return 2

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


def _add_chain_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST), help="method manifest path")
    parser.add_argument("--request-file", help="chain request JSON file")
    parser.add_argument("--request-json", help="chain request JSON string")
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

    chain_parser = sub.add_parser("chain", help="Execute a chain of JSON-RPC and transform steps")
    _add_chain_args(chain_parser)
    chain_parser.set_defaults(func=cmd_chain)

    batch_parser = sub.add_parser("batch", help="Alias for chain")
    _add_chain_args(batch_parser)
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
