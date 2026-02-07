"""Shared parsers for Ethereum quantity-like values."""

from __future__ import annotations

from typing import Any


def parse_nonnegative_quantity_str(raw: str) -> int:
    value = str(raw).strip()
    if not value:
        raise ValueError("quantity cannot be empty")
    if value.startswith("0x"):
        out = int(value, 16)
        if out < 0:
            raise ValueError("quantity must be non-negative")
        return out
    if not value.isdigit():
        raise ValueError("quantity must be a decimal integer or 0x-prefixed hex quantity")
    return int(value, 10)


def parse_nonnegative_quantity(value: Any) -> tuple[bool, int, str]:
    if isinstance(value, bool):
        return False, 0, "value cannot be boolean"
    if isinstance(value, int):
        if value < 0:
            return False, 0, "value must be non-negative"
        return True, value, ""
    if not isinstance(value, str):
        return False, 0, "value must be int or string"

    raw = value.strip()
    if not raw:
        return False, 0, "value cannot be empty"
    if raw.startswith("0x"):
        try:
            return True, int(raw, 16), ""
        except Exception:  # noqa: BLE001
            return False, 0, "value must be a decimal integer or 0x-prefixed hex quantity"
    if raw.isdigit():
        return True, int(raw, 10), ""
    return False, 0, "value must be a decimal integer or 0x-prefixed hex quantity"
