"""Policy evaluation for EVM JSON-RPC methods."""

from __future__ import annotations

from typing import Any

from error_map import ERR_METHOD_DISABLED, ERR_METHOD_NOT_IN_MANIFEST, ERR_POLICY_DENIED

MIN_CONFIRMATION_TOKEN_LEN = 8


def evaluate_policy(
    manifest_by_method: dict[str, dict[str, Any]],
    method: str,
    context: dict[str, Any],
) -> dict[str, Any]:
    entry = manifest_by_method.get(method)
    if entry is None:
        return {
            "allowed": False,
            "method": method,
            "tier": None,
            "error_code": ERR_METHOD_NOT_IN_MANIFEST,
            "reason": "method not found in manifest",
            "requires_confirmation": False,
        }

    if not bool(entry.get("enabled", True)):
        return {
            "allowed": False,
            "method": method,
            "tier": entry.get("tier"),
            "error_code": ERR_METHOD_DISABLED,
            "reason": "method disabled in manifest",
            "requires_confirmation": bool(entry.get("requires_confirmation", False)),
        }

    tier = str(entry.get("tier", "read"))
    requires_confirmation = bool(entry.get("requires_confirmation", False))
    confirmation = str(context.get("confirmation_token", "")).strip()

    if tier == "local-sensitive":
        if not bool(context.get("allow_local_sensitive", False)):
            return {
                "allowed": False,
                "method": method,
                "tier": tier,
                "error_code": ERR_POLICY_DENIED,
                "reason": "local-sensitive method requires allow_local_sensitive=true",
                "requires_confirmation": requires_confirmation,
            }

    if tier == "broadcast":
        if not bool(context.get("allow_broadcast", False)):
            return {
                "allowed": False,
                "method": method,
                "tier": tier,
                "error_code": ERR_POLICY_DENIED,
                "reason": "broadcast method requires allow_broadcast=true",
                "requires_confirmation": requires_confirmation,
            }
        if requires_confirmation and not confirmation:
            return {
                "allowed": False,
                "method": method,
                "tier": tier,
                "error_code": ERR_POLICY_DENIED,
                "reason": "broadcast method requires confirmation_token",
                "requires_confirmation": requires_confirmation,
            }
        if requires_confirmation and len(confirmation) < MIN_CONFIRMATION_TOKEN_LEN:
            return {
                "allowed": False,
                "method": method,
                "tier": tier,
                "error_code": ERR_POLICY_DENIED,
                "reason": (
                    f"broadcast method requires confirmation_token length >= {MIN_CONFIRMATION_TOKEN_LEN}"
                ),
                "requires_confirmation": requires_confirmation,
            }

    if tier == "operator":
        if not bool(context.get("allow_operator", False)):
            return {
                "allowed": False,
                "method": method,
                "tier": tier,
                "error_code": ERR_POLICY_DENIED,
                "reason": "operator method requires allow_operator=true",
                "requires_confirmation": requires_confirmation,
            }
        if requires_confirmation and not confirmation:
            return {
                "allowed": False,
                "method": method,
                "tier": tier,
                "error_code": ERR_POLICY_DENIED,
                "reason": "operator method requires confirmation_token",
                "requires_confirmation": requires_confirmation,
            }
        if requires_confirmation and len(confirmation) < MIN_CONFIRMATION_TOKEN_LEN:
            return {
                "allowed": False,
                "method": method,
                "tier": tier,
                "error_code": ERR_POLICY_DENIED,
                "reason": (
                    f"operator method requires confirmation_token length >= {MIN_CONFIRMATION_TOKEN_LEN}"
                ),
                "requires_confirmation": requires_confirmation,
            }

    return {
        "allowed": True,
        "method": method,
        "tier": tier,
        "error_code": None,
        "reason": "allowed",
        "requires_confirmation": requires_confirmation,
    }
