"""Request/response contract helpers for evm_rpc wrapper."""

from __future__ import annotations

import json
import os
from argparse import Namespace
from typing import Any

DEFAULT_TIMEOUT_SECONDS = 20.0


def parse_request_from_args(args: Namespace) -> dict[str, Any]:
    if args.request_file:
        with open(args.request_file, encoding="utf-8") as f:
            return json.load(f)
    if args.request_json:
        return json.loads(args.request_json)

    req: dict[str, Any] = {
        "method": args.method or "",
        "params": json.loads(args.params_json) if args.params_json else [],
        "id": json.loads(args.id_json) if args.id_json else 1,
        "context": json.loads(args.context_json) if args.context_json else {},
        "timeout_seconds": args.timeout_seconds,
    }
    if args.env_json:
        req["env"] = json.loads(args.env_json)
    return req


def validate_request(req: dict[str, Any]) -> tuple[bool, str]:
    if not isinstance(req, dict):
        return False, "request must be an object"

    method = req.get("method")
    if not isinstance(method, str) or not method.strip():
        return False, "request.method must be a non-empty string"

    params = req.get("params", [])
    if not isinstance(params, list):
        return False, "request.params must be an array"

    timeout = req.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
    if not isinstance(timeout, (int, float)) or timeout <= 0:
        return False, "request.timeout_seconds must be a positive number"

    context = req.get("context", {})
    if not isinstance(context, dict):
        return False, "request.context must be an object"

    env = req.get("env", {})
    if env and (not isinstance(env, dict) or not all(isinstance(k, str) for k in env.keys())):
        return False, "request.env must be an object with string keys"

    return True, ""


def normalized_context(raw_context: dict[str, Any] | None) -> dict[str, Any]:
    ctx = raw_context or {}
    return {
        "allow_local_sensitive": bool(ctx.get("allow_local_sensitive", False)),
        "allow_broadcast": bool(ctx.get("allow_broadcast", False)),
        "allow_operator": bool(ctx.get("allow_operator", False)),
        "allow_heavy_read": bool(ctx.get("allow_heavy_read", False)),
        "confirmation_token": str(ctx.get("confirmation_token", "")).strip(),
    }


def build_execution_env(req: dict[str, Any]) -> dict[str, str]:
    env = os.environ.copy()
    extra = req.get("env", {})
    if isinstance(extra, dict):
        for k, v in extra.items():
            env[str(k)] = str(v)
    return env
