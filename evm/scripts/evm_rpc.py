#!/usr/bin/env python3
"""Agent-facing JSON wrapper around Ethereum JSON-RPC."""

from __future__ import annotations

import argparse
import json
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
    ERR_INTERNAL,
    ERR_INVALID_REQUEST,
    ERR_RPC_REMOTE,
    ERR_RPC_TIMEOUT,
    ERR_RPC_URL_REQUIRED,
    RPC_URL_REQUIRED_MESSAGE,
)
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

DEFAULT_MANIFEST = (SCRIPT_DIR.parent / "references" / "method-manifest.json").resolve()


def _json_dump(payload: dict[str, Any], pretty: bool = True) -> str:
    return json.dumps(payload, indent=2 if pretty else None, sort_keys=False)


def _base_response(method: str) -> dict[str, Any]:
    return {
        "timestamp_utc": datetime.now(UTC).isoformat(),
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
    print(_json_dump(payload, pretty=pretty))


def cmd_exec(args: argparse.Namespace) -> int:
    manifest_path = Path(args.manifest).resolve()
    if not manifest_path.exists():
        _print_error(
            method="",
            status="error",
            code="MANIFEST_NOT_FOUND",
            message=f"manifest not found: {manifest_path}",
            pretty=not args.compact,
        )
        return 2

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

    valid, validation_message = validate_request(req)
    if not valid:
        _print_error(
            method=str(req.get("method", "")),
            status="error",
            code=ERR_INVALID_REQUEST,
            message=validation_message,
            pretty=not args.compact,
            request=req,
        )
        return 2

    method = str(req["method"]).strip()
    context = normalized_context(req.get("context"))
    manifest_by_method = load_manifest_by_method(manifest_path)
    policy = evaluate_policy(manifest_by_method, method, context)
    if not policy["allowed"]:
        _print_error(
            method=method,
            status="denied",
            code=policy["error_code"] or "POLICY_DENIED",
            message=policy["reason"],
            pretty=not args.compact,
            policy=policy,
            request=req,
        )
        return 4

    execution_env = build_execution_env(req)
    rpc_url = str(execution_env.get("ETH_RPC_URL", "")).strip()
    if not rpc_url:
        _print_error(
            method=method,
            status="denied",
            code=ERR_RPC_URL_REQUIRED,
            message=RPC_URL_REQUIRED_MESSAGE,
            pretty=not args.compact,
            policy=policy,
            request=req,
            hint="Set ETH_RPC_URL in env before retrying.",
        )
        return 4

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
        _print_error(
            method=method,
            status=status,
            code=transport["error_code"],
            message=transport["error_message"],
            pretty=not args.compact,
            policy=policy,
            request=req,
            rpc_request=rpc_request_meta,
            rpc_response=transport.get("rpc_response"),
            duration_ms=duration_ms,
        )
        return 1

    rpc_response = transport["rpc_response"]
    if isinstance(rpc_response, dict) and "error" in rpc_response:
        _print_error(
            method=method,
            status="error",
            code=ERR_RPC_REMOTE,
            message="rpc returned an error response",
            pretty=not args.compact,
            policy=policy,
            request=req,
            rpc_request=rpc_request_meta,
            rpc_response=rpc_response,
            duration_ms=duration_ms,
        )
        return 1

    payload = {
        "timestamp_utc": datetime.now(UTC).isoformat(),
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
    print(_json_dump(payload, pretty=not args.compact))
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
    exec_parser.add_argument("--compact", action="store_true", help="compact JSON output")
    exec_parser.set_defaults(func=cmd_exec)

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
