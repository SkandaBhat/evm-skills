"""Shared analytics runtime orchestration helpers."""

from __future__ import annotations

import argparse
from typing import Any, Callable

from analytics_scanner import scan_logs
from analytics_time_range import resolve_block_window
from error_map import ERR_INTERNAL, ERR_INVALID_REQUEST

RpcExecutor = Callable[[dict[str, Any]], tuple[int, dict[str, Any]]]
RunRpcRequestFn = Callable[..., tuple[int, dict[str, Any]]]
RequireManifestFn = Callable[[argparse.Namespace], tuple[bool, dict[str, dict[str, Any]] | int]]
RequireEnvJsonFn = Callable[..., tuple[bool, dict[str, Any] | int]]
ErrorBuilder = Callable[..., dict[str, Any]]
RenderForArgsAndExit = Callable[..., int]


def make_analytics_executor(
    *,
    manifest_by_method: dict[str, dict[str, Any]],
    default_context: dict[str, Any],
    default_env: dict[str, Any],
    default_timeout_seconds: float,
    run_rpc_request_fn: RunRpcRequestFn,
) -> RpcExecutor:
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
        return run_rpc_request_fn(req=merged, manifest_by_method=manifest_by_method)

    return execute


def runtime_or_exit(
    *,
    args: argparse.Namespace,
    method: str,
    default_context: dict[str, Any] | None = None,
    require_manifest_fn: RequireManifestFn,
    require_env_json_fn: RequireEnvJsonFn,
    run_rpc_request_fn: RunRpcRequestFn,
) -> tuple[bool, tuple[dict[str, Any], dict[str, Any], float, RpcExecutor] | int]:
    ok_manifest, manifest_or_rc = require_manifest_fn(args)
    if not ok_manifest:
        return False, int(manifest_or_rc)
    manifest_by_method = manifest_or_rc

    ok_env, env_or_rc = require_env_json_fn(
        raw_env_json=args.env_json,
        method=method,
        compact=bool(args.compact),
    )
    if not ok_env:
        return False, int(env_or_rc)
    env = env_or_rc

    context = dict(default_context or {})
    timeout_seconds = float(args.timeout_seconds)
    execute_rpc = make_analytics_executor(
        manifest_by_method=manifest_by_method,
        default_context=context,
        default_env=env,
        default_timeout_seconds=timeout_seconds,
        run_rpc_request_fn=run_rpc_request_fn,
    )
    return True, (env, context, timeout_seconds, execute_rpc)


def resolve_range_or_exit(
    *,
    args: argparse.Namespace,
    command_method: str,
    execute_rpc: RpcExecutor,
    context: dict[str, Any],
    env: dict[str, Any],
    timeout_seconds: float,
    last_blocks: int | None,
    since: str | None,
    build_error_payload_fn: ErrorBuilder,
    render_for_args_and_exit_fn: RenderForArgsAndExit,
) -> tuple[bool, dict[str, Any] | int]:
    range_rc, range_payload = resolve_block_window(
        execute_rpc=execute_rpc,
        context=context,
        env=env,
        timeout_seconds=timeout_seconds,
        last_blocks=last_blocks,
        since=since,
    )
    if range_rc == 0:
        return True, range_payload

    payload = build_error_payload_fn(
        method=command_method,
        status="error",
        code=str(range_payload.get("error_code", ERR_INVALID_REQUEST)),
        message=str(range_payload.get("error_message", "failed to resolve range")),
    )
    if "cause" in range_payload:
        payload["cause"] = range_payload["cause"]
    return False, render_for_args_and_exit_fn(
        args=args,
        payload=payload,
        exit_code=range_rc,
        result_field="result",
    )


def scan_logs_or_exit(
    *,
    args: argparse.Namespace,
    command_method: str,
    execute_rpc: RpcExecutor,
    logs_filter: dict[str, Any],
    context: dict[str, Any],
    env: dict[str, Any],
    timeout_seconds: float,
    chunk_size: int,
    max_chunks: int,
    max_logs: int,
    adaptive_split: bool,
    allow_heavy_read: bool,
    checkpoint_file: str | None,
    filter_signature: dict[str, Any],
    build_error_payload_fn: ErrorBuilder,
    render_for_args_and_exit_fn: RenderForArgsAndExit,
) -> tuple[bool, dict[str, Any] | int]:
    scan_rc, scan_payload = scan_logs(
        execute_rpc=execute_rpc,
        logs_filter=logs_filter,
        context=context,
        env=env,
        timeout_seconds=timeout_seconds,
        chunk_size=chunk_size,
        max_chunks=max_chunks,
        max_logs=max_logs,
        adaptive_split=adaptive_split,
        allow_heavy_read=allow_heavy_read,
        checkpoint_file=checkpoint_file,
        filter_signature=filter_signature,
    )
    if scan_rc == 0 and bool(scan_payload.get("ok", False)):
        return True, scan_payload

    payload = build_error_payload_fn(
        method=command_method,
        status="error",
        code=str(scan_payload.get("error_code", ERR_INTERNAL)),
        message=str(scan_payload.get("error_message", "log scan failed")),
    )
    payload["scan"] = scan_payload
    return False, render_for_args_and_exit_fn(
        args=args,
        payload=payload,
        exit_code=scan_rc,
        result_field="result",
    )

