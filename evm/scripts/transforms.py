"""Local transform helpers for chain workflows and convenience commands."""

from __future__ import annotations

import re
from typing import Any

HEX_BYTES_RE = re.compile(r"^0x(?:[0-9a-fA-F]{2})*$")
HEX_QUANTITY_RE = re.compile(r"^0x[0-9a-fA-F]+$")

_MASK_64 = (1 << 64) - 1
_KECCAK_ROUNDS = 24
_KECCAK_RATE_BYTES = 136  # keccak-256 bitrate

_ROTATION_OFFSETS = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]

_ROUND_CONSTANTS = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
]


def _rotl64(value: int, shift: int) -> int:
    shift %= 64
    return ((value << shift) | (value >> (64 - shift))) & _MASK_64


def _keccak_f1600(state: list[int]) -> None:
    for round_idx in range(_KECCAK_ROUNDS):
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl64(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]

        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl64(
                    state[x + 5 * y], _ROTATION_OFFSETS[x][y]
                )

        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = (
                    b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])
                ) & _MASK_64

        state[0] ^= _ROUND_CONSTANTS[round_idx]


def keccak256(data: bytes) -> bytes:
    state = [0] * 25
    padded = bytearray(data)
    padded.append(0x01)
    while (len(padded) % _KECCAK_RATE_BYTES) != (_KECCAK_RATE_BYTES - 1):
        padded.append(0)
    padded.append(0x80)

    for offset in range(0, len(padded), _KECCAK_RATE_BYTES):
        block = padded[offset : offset + _KECCAK_RATE_BYTES]
        for i in range(_KECCAK_RATE_BYTES // 8):
            lane = int.from_bytes(block[i * 8 : (i + 1) * 8], "little")
            state[i] ^= lane
        _keccak_f1600(state)

    output = bytearray()
    while len(output) < 32:
        for i in range(_KECCAK_RATE_BYTES // 8):
            output.extend(state[i].to_bytes(8, "little"))
        if len(output) >= 32:
            break
        _keccak_f1600(state)
    return bytes(output[:32])


def _parse_nonnegative_int(value: Any) -> tuple[bool, int, str]:
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
    if HEX_QUANTITY_RE.fullmatch(raw):
        return True, int(raw, 16), ""
    if raw.isdigit():
        return True, int(raw, 10), ""
    return False, 0, "value must be a decimal integer or 0x-prefixed hex quantity"


def transform_hex_to_int(value: Any) -> tuple[bool, Any, str]:
    ok, as_int, err = _parse_nonnegative_int(value)
    if not ok:
        return False, None, f"hex_to_int: {err}"
    return True, as_int, ""


def transform_wei_to_eth(value: Any) -> tuple[bool, Any, str]:
    ok, wei, err = _parse_nonnegative_int(value)
    if not ok:
        return False, None, f"wei_to_eth: {err}"
    whole, frac = divmod(wei, 10**18)
    if frac == 0:
        return True, str(whole), ""
    frac_str = f"{frac:018d}".rstrip("0")
    return True, f"{whole}.{frac_str}", ""


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

    node = b"\x00" * 32
    for label in reversed(labels):
        label_hash = keccak256(label.encode("utf-8"))
        node = keccak256(node + label_hash)
    return True, f"0x{node.hex()}", ""


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
