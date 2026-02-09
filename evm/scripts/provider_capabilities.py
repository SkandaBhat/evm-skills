"""Provider capability detection helpers shared across command engines."""

from __future__ import annotations

from typing import Any


def is_provider_method_missing(payload: dict[str, Any]) -> bool:
    """Return True when provider error implies RPC method is unavailable."""
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

