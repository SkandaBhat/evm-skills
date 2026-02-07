"""Method-specific adapter preflight checks for v0.2."""

from __future__ import annotations

import re
from typing import Any


ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
HEX_BYTES_RE = re.compile(r"^0x(?:[0-9a-fA-F]{2})*$")
HEX_QUANTITY_RE = re.compile(r"^0x[0-9a-fA-F]+$")


def _is_address(value: Any) -> bool:
    return isinstance(value, str) and bool(ADDRESS_RE.fullmatch(value))


def _is_hex_bytes(value: Any) -> bool:
    return isinstance(value, str) and bool(HEX_BYTES_RE.fullmatch(value))


def _is_hex_quantity(value: Any) -> bool:
    return isinstance(value, str) and bool(HEX_QUANTITY_RE.fullmatch(value))


def _validate_tx_object(tx: Any, *, method: str) -> tuple[bool, str]:
    if not isinstance(tx, dict):
        return False, f"{method}: tx param must be an object"

    from_addr = tx.get("from")
    if not _is_address(from_addr):
        return False, f"{method}: tx.from must be a 20-byte hex address"

    to_addr = tx.get("to")
    data = tx.get("data")
    if to_addr is not None and not _is_address(to_addr):
        return False, f"{method}: tx.to must be a 20-byte hex address when provided"
    if data is not None and not _is_hex_bytes(data):
        return False, f"{method}: tx.data must be 0x-prefixed hex bytes"
    if to_addr is None and data is None:
        return False, f"{method}: tx must include at least one of 'to' or 'data'"

    # Safety guardrail: disallow mixed fee modes.
    has_legacy_fee = "gasPrice" in tx
    has_1559_fee = "maxFeePerGas" in tx or "maxPriorityFeePerGas" in tx
    if has_legacy_fee and has_1559_fee:
        return (
            False,
            f"{method}: tx cannot include both gasPrice and maxFeePerGas/maxPriorityFeePerGas",
        )

    for field in ("value", "gas", "nonce", "gasPrice", "maxFeePerGas", "maxPriorityFeePerGas"):
        if field in tx and not _is_hex_quantity(tx[field]):
            return False, f"{method}: tx.{field} must be a 0x-prefixed hex quantity"

    return True, ""


def validate_adapter_preflight(method: str, params: Any) -> tuple[bool, str]:
    """Return (ok, message) for adapter methods."""
    if not isinstance(params, list):
        return False, f"{method}: params must be an array"

    if method == "eth_accounts":
        if params:
            return False, "eth_accounts: params must be empty"
        return True, ""

    if method == "eth_sign":
        if len(params) != 2:
            return False, "eth_sign: expected [address, data]"
        addr, data = params
        if not _is_address(addr):
            return False, "eth_sign: address must be a 20-byte hex address"
        if not _is_hex_bytes(data):
            return False, "eth_sign: data must be 0x-prefixed hex bytes"
        return True, ""

    if method == "eth_signTransaction":
        if len(params) != 1:
            return False, "eth_signTransaction: expected [txObject]"
        return _validate_tx_object(params[0], method=method)

    if method == "eth_sendRawTransaction":
        if len(params) != 1:
            return False, "eth_sendRawTransaction: expected [signedTx]"
        raw = params[0]
        if not _is_hex_bytes(raw) or raw == "0x":
            return False, "eth_sendRawTransaction: signedTx must be non-empty 0x-prefixed hex bytes"
        return True, ""

    if method == "eth_sendTransaction":
        if len(params) != 1:
            return False, "eth_sendTransaction: expected [txObject]"
        return _validate_tx_object(params[0], method=method)

    # For other adapter-tagged methods (e.g. engine_*) we currently allow pass-through.
    return True, ""
