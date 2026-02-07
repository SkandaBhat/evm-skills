"""Reusable log scanner wrappers for analytics commands."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from logs_engine import (
    DEFAULT_CHUNK_SIZE,
    DEFAULT_MAX_CHUNKS,
    DEFAULT_MAX_LOGS,
    DEFAULT_HEAVY_READ_THRESHOLD,
    is_heavy_read,
    normalize_logs_request,
    run_chunked_logs,
)

ERR_ANALYTICS_CHECKPOINT_INVALID = "ANALYTICS_CHECKPOINT_INVALID"
ERR_ANALYTICS_HEAVY_READ_DENIED = "ANALYTICS_HEAVY_READ_DENIED"

RpcExecutor = Callable[[dict[str, Any]], tuple[int, dict[str, Any]]]


def _to_int_block(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        if value.startswith("0x"):
            return int(value, 16)
        return int(value, 10)
    raise ValueError(f"invalid block value: {value!r}")


def _checkpoint_base_state(
    *,
    range_from_block: int,
    range_to_block: int,
    filter_signature: dict[str, Any],
) -> dict[str, Any]:
    return {
        "version": 1,
        "range_from_block": range_from_block,
        "range_to_block": range_to_block,
        "next_from_block": range_from_block,
        "complete": False,
        "filter_signature": filter_signature,
    }


def _load_checkpoint(path: Path) -> tuple[bool, dict[str, Any], str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as err:  # noqa: BLE001
        return False, {}, f"failed reading checkpoint: {err}"
    if not isinstance(data, dict):
        return False, {}, "checkpoint must be a JSON object"
    return True, data, ""


def _save_checkpoint(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def scan_logs(
    *,
    execute_rpc: RpcExecutor,
    logs_filter: dict[str, Any],
    context: dict[str, Any],
    env: dict[str, Any],
    timeout_seconds: float,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    max_chunks: int = DEFAULT_MAX_CHUNKS,
    max_logs: int = DEFAULT_MAX_LOGS,
    adaptive_split: bool = True,
    heavy_read_block_range_threshold: int = DEFAULT_HEAVY_READ_THRESHOLD,
    allow_heavy_read: bool = False,
    checkpoint_file: str | None = None,
    filter_signature: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any]]:
    req = {
        "filter": dict(logs_filter),
        "context": dict(context),
        "env": dict(env),
        "timeout_seconds": float(timeout_seconds),
        "chunk_size": int(chunk_size),
        "max_chunks": int(max_chunks),
        "max_logs": int(max_logs),
        "adaptive_split": bool(adaptive_split),
        "heavy_read_block_range_threshold": int(heavy_read_block_range_threshold),
    }

    checkpoint_path: Path | None = Path(checkpoint_file).resolve() if checkpoint_file else None
    checkpoint_state: dict[str, Any] | None = None
    if checkpoint_path and checkpoint_path.exists():
        ok_cp, cp, cp_err = _load_checkpoint(checkpoint_path)
        if not ok_cp:
            return 2, {
                "ok": False,
                "error_code": ERR_ANALYTICS_CHECKPOINT_INVALID,
                "error_message": cp_err,
            }
        checkpoint_state = cp
        try:
            req["filter"]["fromBlock"] = int(cp["next_from_block"])
            req["filter"]["toBlock"] = int(cp["range_to_block"])
        except Exception as err:  # noqa: BLE001
            return 2, {
                "ok": False,
                "error_code": ERR_ANALYTICS_CHECKPOINT_INVALID,
                "error_message": f"invalid checkpoint fields: {err}",
                "checkpoint": cp,
            }

    ok, normalized, err_code, err_message = normalize_logs_request(req)
    if not ok:
        return 2, {
            "ok": False,
            "error_code": err_code,
            "error_message": err_message,
            "request": req,
        }

    numeric_range = normalized.get("numeric_range")
    if checkpoint_path and checkpoint_state is None and isinstance(numeric_range, tuple):
        from_block, to_block = int(numeric_range[0]), int(numeric_range[1])
        base_cp = _checkpoint_base_state(
            range_from_block=from_block,
            range_to_block=to_block,
            filter_signature=filter_signature or {},
        )
        _save_checkpoint(checkpoint_path, base_cp)
        checkpoint_state = base_cp

    is_heavy, span = is_heavy_read(normalized)
    if is_heavy and not allow_heavy_read:
        return 4, {
            "ok": False,
            "error_code": ERR_ANALYTICS_HEAVY_READ_DENIED,
            "error_message": (
                "log scan requires allow_heavy_read=true "
                f"(span={span}, threshold={normalized['heavy_read_block_range_threshold']})"
            ),
            "request": req,
        }

    progress: dict[str, Any] = {
        "last_success_from_block": None,
        "last_success_to_block": None,
    }

    def fetch_chunk(chunk_filter: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        rpc_req: dict[str, Any] = {
            "method": "eth_getLogs",
            "params": [chunk_filter],
            "context": dict(context),
            "timeout_seconds": float(timeout_seconds),
        }
        if env:
            rpc_req["env"] = dict(env)
        rc, payload = execute_rpc(rpc_req)
        if rc == 0 and checkpoint_path:
            try:
                from_block = _to_int_block(chunk_filter.get("fromBlock"))
                to_block = _to_int_block(chunk_filter.get("toBlock"))
                progress["last_success_from_block"] = from_block
                progress["last_success_to_block"] = to_block
                cp_payload = dict(checkpoint_state or {})
                cp_payload.update(
                    {
                        "next_from_block": to_block + 1,
                        "last_success_from_block": from_block,
                        "last_success_to_block": to_block,
                        "complete": False,
                    }
                )
                _save_checkpoint(checkpoint_path, cp_payload)
            except Exception:
                pass
        return rc, payload

    rc, payload = run_chunked_logs(
        normalized_request=normalized,
        fetch_chunk=fetch_chunk,
    )

    if checkpoint_path and rc == 0:
        cp_payload = dict(checkpoint_state or {})
        cp_payload.update(
            {
                "next_from_block": (
                    int(cp_payload.get("range_to_block", 0)) + 1
                    if isinstance(cp_payload.get("range_to_block"), int)
                    else progress.get("last_success_to_block", 0) + 1
                ),
                "last_success_from_block": progress.get("last_success_from_block"),
                "last_success_to_block": progress.get("last_success_to_block"),
                "complete": True,
            }
        )
        _save_checkpoint(checkpoint_path, cp_payload)

    if checkpoint_path:
        payload = dict(payload)
        payload["checkpoint"] = str(checkpoint_path)
    return rc, payload

