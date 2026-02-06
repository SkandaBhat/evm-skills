#!/usr/bin/env python3
"""Agent-facing JSON wrapper around Foundry cast."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Local import for script execution (python3 scripts/evm_cast.py ...)
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from policy_eval import evaluate_policy, load_manifest  # noqa: E402


DEFAULT_MANIFEST = (SCRIPT_DIR.parent / "references" / "command-manifest.json").resolve()
RPC_REQUIRED_TOP_LEVEL = {
    "access-list",
    "admin",
    "age",
    "balance",
    "base-fee",
    "block",
    "block-number",
    "call",
    "chain",
    "chain-id",
    "client",
    "code",
    "codehash",
    "codesize",
    "estimate",
    "find-block",
    "gas-price",
    "implementation",
    "logs",
    "lookup-address",
    "nonce",
    "proof",
    "publish",
    "receipt",
    "resolve-name",
    "rpc",
    "run",
    "send",
    "storage",
    "storage-root",
    "trace",
    "tx",
    "tx-pool",
}
RPC_REQUIRED_PATHS = {
    "wallet sign-auth",
}
RPC_MISSING_MESSAGE = (
    "couldnt find an rpc url. give me an rpc url so i can add it to env."
)


def _json_dump(payload: dict[str, Any], pretty: bool = True) -> str:
    return json.dumps(payload, indent=2 if pretty else None, sort_keys=False)


def _base_response(command_path: str) -> dict[str, Any]:
    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "command_path": command_path,
        "status": "error",
        "ok": False,
        "error_code": "UNSET",
        "error_message": "unset",
    }


def _parse_request(args: argparse.Namespace) -> dict[str, Any]:
    if args.request_file:
        return json.loads(Path(args.request_file).read_text(encoding="utf-8"))
    if args.request_json:
        return json.loads(args.request_json)

    command_path = args.command_path or ""
    request: dict[str, Any] = {
        "command_path": command_path,
        "args": json.loads(args.args_json) if args.args_json else [],
        "context": json.loads(args.context_json) if args.context_json else {},
        "timeout_seconds": args.timeout_seconds,
    }
    if args.env_json:
        request["env"] = json.loads(args.env_json)
    return request


def _validate_request(req: dict[str, Any]) -> tuple[bool, str]:
    if not isinstance(req, dict):
        return False, "request must be an object"
    command_path = req.get("command_path")
    if not isinstance(command_path, str) or not command_path.strip():
        return False, "request.command_path must be a non-empty string"
    argv_args = req.get("args", [])
    if not isinstance(argv_args, list) or not all(isinstance(item, str) for item in argv_args):
        return False, "request.args must be a string array"
    context = req.get("context", {})
    if not isinstance(context, dict):
        return False, "request.context must be an object"
    timeout_seconds = req.get("timeout_seconds", 45)
    if not isinstance(timeout_seconds, (int, float)) or timeout_seconds <= 0:
        return False, "request.timeout_seconds must be a positive number"
    env = req.get("env", {})
    if env and (not isinstance(env, dict) or not all(isinstance(k, str) for k in env.keys())):
        return False, "request.env must be an object with string keys"
    return True, ""


def _maybe_parse_json(text: str) -> Any:
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _build_env(req: dict[str, Any]) -> dict[str, str]:
    env = os.environ.copy()
    extra = req.get("env", {})
    if isinstance(extra, dict):
        for key, value in extra.items():
            env[str(key)] = str(value)
    return env


def _command_requires_rpc(command_path: str) -> bool:
    if command_path in RPC_REQUIRED_PATHS:
        return True
    head = command_path.split(" ", 1)[0]
    return head in RPC_REQUIRED_TOP_LEVEL


def _args_include_rpc_url(args: list[str]) -> bool:
    for i, arg in enumerate(args):
        if arg == "--flashbots":
            return True
        if arg == "--rpc-url":
            if i + 1 < len(args) and args[i + 1]:
                return True
        if arg.startswith("--rpc-url="):
            return True
        if arg == "-r":
            if i + 1 < len(args) and args[i + 1]:
                return True
    return False


def _has_rpc_url_for_request(command_path: str, args: list[str], env: dict[str, str]) -> bool:
    if not _command_requires_rpc(command_path):
        return True
    if _args_include_rpc_url(args):
        return True
    rpc_from_env = str(env.get("ETH_RPC_URL", "")).strip()
    return bool(rpc_from_env)


def cmd_exec(args: argparse.Namespace) -> int:
    manifest_path = Path(args.manifest).resolve()
    if not manifest_path.exists():
        payload = _base_response("")
        payload.update(
            {
                "status": "error",
                "ok": False,
                "error_code": "MANIFEST_NOT_FOUND",
                "error_message": f"Manifest not found: {manifest_path}",
            }
        )
        print(_json_dump(payload, pretty=not args.compact))
        return 2

    req = _parse_request(args)
    valid, message = _validate_request(req)
    if not valid:
        payload = _base_response(str(req.get("command_path", "")))
        payload.update(
            {
                "status": "error",
                "ok": False,
                "error_code": "INVALID_REQUEST",
                "error_message": message,
                "request": req,
            }
        )
        print(_json_dump(payload, pretty=not args.compact))
        return 2

    command_path = str(req["command_path"]).strip()
    context = req.get("context", {})
    manifest_by_path = load_manifest(manifest_path)
    policy = evaluate_policy(manifest_by_path, command_path, context)

    if not policy["allowed"]:
        payload = _base_response(command_path)
        payload.update(
            {
                "status": "denied",
                "ok": False,
                "error_code": policy["error_code"] or "POLICY_DENIED",
                "error_message": policy["reason"],
                "policy": policy,
                "request": req,
            }
        )
        print(_json_dump(payload, pretty=not args.compact))
        return 4

    cast_binary = args.cast_binary
    request_args = [str(a) for a in req.get("args", [])]
    execution_env = _build_env(req)
    if not _has_rpc_url_for_request(command_path, request_args, execution_env):
        payload = _base_response(command_path)
        payload.update(
            {
                "status": "denied",
                "ok": False,
                "error_code": "RPC_URL_REQUIRED",
                "error_message": RPC_MISSING_MESSAGE,
                "policy": policy,
                "request": req,
                "hint": "Set ETH_RPC_URL in env, or pass --rpc-url in args.",
            }
        )
        print(_json_dump(payload, pretty=not args.compact))
        return 4

    cmd = [cast_binary, *command_path.split(), *request_args]
    timeout_seconds = float(req.get("timeout_seconds", 45))
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            env=execution_env,
            check=False,
        )
    except subprocess.TimeoutExpired as err:
        elapsed = int((time.perf_counter() - start) * 1000)
        payload = _base_response(command_path)
        payload.update(
            {
                "status": "timeout",
                "ok": False,
                "error_code": "EXEC_TIMEOUT",
                "error_message": str(err),
                "policy": policy,
                "argv": cmd,
                "duration_ms": elapsed,
            }
        )
        print(_json_dump(payload, pretty=not args.compact))
        return 1
    except FileNotFoundError:
        elapsed = int((time.perf_counter() - start) * 1000)
        payload = _base_response(command_path)
        payload.update(
            {
                "status": "error",
                "ok": False,
                "error_code": "COMMAND_NOT_FOUND",
                "error_message": f"Cast binary not found: {cast_binary}",
                "policy": policy,
                "argv": cmd,
                "duration_ms": elapsed,
            }
        )
        print(_json_dump(payload, pretty=not args.compact))
        return 1

    elapsed = int((time.perf_counter() - start) * 1000)
    parsed_stdout = _maybe_parse_json(proc.stdout)
    payload = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "command_path": command_path,
        "status": "ok" if proc.returncode == 0 else "error",
        "ok": proc.returncode == 0,
        "error_code": None if proc.returncode == 0 else "EXEC_FAILED",
        "error_message": None if proc.returncode == 0 else "cast command returned non-zero exit",
        "policy": policy,
        "argv": cmd,
        "exit_code": proc.returncode,
        "duration_ms": elapsed,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "parsed_stdout_json": parsed_stdout,
    }
    print(_json_dump(payload, pretty=not args.compact))
    return 0 if proc.returncode == 0 else 1


def cmd_supported_paths(args: argparse.Namespace) -> int:
    manifest = load_manifest(Path(args.manifest).resolve())
    paths = sorted(path for path, entry in manifest.items() if entry.get("enabled", True))
    print(json.dumps({"supported_paths": paths, "count": len(paths)}, indent=2))
    return 0


def cmd_manifest_summary(args: argparse.Namespace) -> int:
    manifest_raw = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    entries = manifest_raw.get("entries", [])
    tier_counts: dict[str, int] = {}
    for entry in entries:
        tier = str(entry.get("tier", "unknown"))
        tier_counts[tier] = tier_counts.get(tier, 0) + 1
    payload = {
        "manifest": str(Path(args.manifest).resolve()),
        "entries": len(entries),
        "tier_counts": tier_counts,
        "cast_version": manifest_raw.get("cast_version"),
    }
    print(json.dumps(payload, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    exec_parser = sub.add_parser("exec", help="Execute a cast command via JSON request")
    exec_parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST), help="manifest JSON path")
    exec_parser.add_argument("--cast-binary", default="cast", help="cast binary path/name")
    exec_parser.add_argument("--request-file", help="request JSON file")
    exec_parser.add_argument("--request-json", help="request JSON string")
    exec_parser.add_argument("--command-path", help="command path (if not using request JSON)")
    exec_parser.add_argument("--args-json", help="args list as JSON")
    exec_parser.add_argument("--context-json", help="context object as JSON")
    exec_parser.add_argument("--env-json", help="env object as JSON")
    exec_parser.add_argument("--timeout-seconds", type=float, default=45)
    exec_parser.add_argument("--compact", action="store_true", help="compact JSON output")
    exec_parser.set_defaults(func=cmd_exec)

    supported_parser = sub.add_parser(
        "supported-paths", help="Emit command paths supported by current manifest"
    )
    supported_parser.add_argument(
        "--manifest", default=str(DEFAULT_MANIFEST), help="manifest JSON path"
    )
    supported_parser.set_defaults(func=cmd_supported_paths)

    summary_parser = sub.add_parser("manifest-summary", help="Print manifest summary stats")
    summary_parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST), help="manifest JSON path")
    summary_parser.set_defaults(func=cmd_manifest_summary)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
