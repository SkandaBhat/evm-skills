"""Shared analytics result/payload envelope helpers."""

from __future__ import annotations

from typing import Any, Callable

TimestampFn = Callable[[], str]


def build_scan_result(
    *,
    base: dict[str, Any],
    range_payload: dict[str, Any],
    summary: dict[str, Any],
    scan_payload: dict[str, Any],
) -> dict[str, Any]:
    """Build common analytics result shape for range+scan commands."""
    result = dict(base)
    result["range"] = range_payload
    result["summary"] = summary
    result["scan_summary"] = scan_payload.get("summary", {})
    if "checkpoint" in scan_payload:
        result["checkpoint"] = scan_payload["checkpoint"]
    return result


def build_ok_payload(
    *,
    method: str,
    result: dict[str, Any],
    timestamp_fn: TimestampFn,
) -> dict[str, Any]:
    """Build a standard successful analytics payload envelope."""
    return {
        "timestamp_utc": timestamp_fn(),
        "method": method,
        "status": "ok",
        "ok": True,
        "error_code": None,
        "error_message": None,
        "result": result,
    }

