"""Local transform helpers for chain workflows and convenience commands."""

from __future__ import annotations

import re
from typing import Any

from cast_adapter import cast_from_wei, cast_namehash
from quantity import parse_nonnegative_quantity

HEX_BYTES_RE = re.compile(r"^0x(?:[0-9a-fA-F]{2})*$")


def transform_hex_to_int(value: Any) -> tuple[bool, Any, str]:
    ok, as_int, err = parse_nonnegative_quantity(value)
    if not ok:
        return False, None, f"hex_to_int: {err}"
    return True, as_int, ""


def transform_wei_to_eth(value: Any) -> tuple[bool, Any, str]:
    ok, wei, err = parse_nonnegative_quantity(value)
    if not ok:
        return False, None, f"wei_to_eth: {err}"
    try:
        rendered = cast_from_wei(str(wei), "eth")
        if "." in rendered:
            whole, frac = rendered.split(".", 1)
            frac = frac.rstrip("0")
            rendered = whole if not frac else f"{whole}.{frac}"
        return True, rendered, ""
    except Exception as cast_err:  # noqa: BLE001
        return False, None, f"wei_to_eth: {cast_err}"


def transform_slice_last_20_bytes_to_address(value: Any) -> tuple[bool, Any, str]:
    if not isinstance(value, str) or not HEX_BYTES_RE.fullmatch(value):
        return False, None, "slice_last_20_bytes_to_address: value must be 0x-prefixed hex bytes"
    raw = value[2:]
    if len(raw) < 40:
        return False, None, "slice_last_20_bytes_to_address: value must contain at least 20 bytes"
    return True, f"0x{raw[-40:]}".lower(), ""


def ens_namehash(name: str) -> tuple[bool, Any, str]:
    if not isinstance(name, str):
        return False, None, "ens_namehash: name must be a string"
    normalized = name.strip().lower().strip(".")
    if not normalized:
        return False, None, "ens_namehash: name cannot be empty"
    labels = normalized.split(".")
    if any(not label for label in labels):
        return False, None, "ens_namehash: name has empty labels"
    try:
        return True, cast_namehash(normalized), ""
    except Exception as cast_err:  # noqa: BLE001
        return False, None, f"ens_namehash: {cast_err}"


def apply_transform(name: str, value: Any) -> tuple[bool, Any, str]:
    normalized = str(name).strip().lower()
    if normalized == "hex_to_int":
        return transform_hex_to_int(value)
    if normalized == "wei_to_eth":
        return transform_wei_to_eth(value)
    if normalized == "slice_last_20_bytes_to_address":
        return transform_slice_last_20_bytes_to_address(value)
    if normalized == "abi_encode_call":
        if not isinstance(value, dict):
            return False, None, "abi_encode_call: input must be an object"
        signature = value.get("signature")
        args = value.get("args", [])
        if not isinstance(signature, str) or not signature.strip():
            return False, None, "abi_encode_call: signature must be a non-empty string"
        if not isinstance(args, list):
            return False, None, "abi_encode_call: args must be an array"
        try:
            from abi_codec import encode_call  # local import to avoid cycle

            return True, encode_call(signature, args), ""
        except Exception as err:  # noqa: BLE001
            return False, None, f"abi_encode_call: {err}"
    if normalized == "abi_decode_output":
        if not isinstance(value, dict):
            return False, None, "abi_decode_output: input must be an object"
        types = value.get("types")
        data = value.get("data")
        if types is None:
            return False, None, "abi_decode_output: types is required"
        if not isinstance(data, str):
            return False, None, "abi_decode_output: data must be a hex string"
        try:
            from abi_codec import decode_output  # local import to avoid cycle

            return True, decode_output(types, data), ""
        except Exception as err:  # noqa: BLE001
            return False, None, f"abi_decode_output: {err}"
    if normalized == "abi_decode_log":
        if not isinstance(value, dict):
            return False, None, "abi_decode_log: input must be an object"
        event_decl = value.get("event")
        topics = value.get("topics")
        data = value.get("data")
        anonymous = bool(value.get("anonymous", False))
        if not isinstance(event_decl, str) or not event_decl.strip():
            return False, None, "abi_decode_log: event must be a non-empty string"
        if not isinstance(topics, list):
            return False, None, "abi_decode_log: topics must be an array"
        if not isinstance(data, str):
            return False, None, "abi_decode_log: data must be a hex string"
        try:
            from abi_codec import decode_log  # local import to avoid cycle

            return True, decode_log(event_decl, topics, data, anonymous=anonymous), ""
        except Exception as err:  # noqa: BLE001
            return False, None, f"abi_decode_log: {err}"
    return False, None, f"unknown transform: {name}"
