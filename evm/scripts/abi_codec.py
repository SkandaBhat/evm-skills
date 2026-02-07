"""Lightweight ABI encode/decode helpers for common Solidity scalar types."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from cast_adapter import cast_calldata, cast_decode_output, cast_event_topic0, cast_function_selector
from transforms import keccak256

HEX_RE = re.compile(r"^0x[0-9a-fA-F]*$")
ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
FUNC_SIG_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\((.*)\)$")


@dataclass(frozen=True)
class AbiType:
    kind: str
    bits: int | None = None
    size: int | None = None


def _split_csv(raw: str) -> list[str]:
    text = raw.strip()
    if not text:
        return []
    out: list[str] = []
    depth = 0
    token_start = 0
    for idx, ch in enumerate(text):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                raise ValueError("unbalanced parentheses in type list")
        elif ch == "," and depth == 0:
            out.append(text[token_start:idx].strip())
            token_start = idx + 1
    if depth != 0:
        raise ValueError("unbalanced parentheses in type list")
    out.append(text[token_start:].strip())
    if any(not item for item in out):
        raise ValueError("empty type entry in list")
    return out


def _parse_int_like(value: Any, *, signed: bool) -> int:
    if isinstance(value, bool):
        raise ValueError("numeric value cannot be boolean")
    if isinstance(value, int):
        return value
    if not isinstance(value, str):
        raise ValueError("numeric value must be int or string")
    raw = value.strip()
    if not raw:
        raise ValueError("numeric value cannot be empty")

    if raw.startswith("-"):
        if not signed:
            raise ValueError("unsigned integer cannot be negative")
        if raw[1:].startswith("0x"):
            base = 16
            digits = raw[3:]
        else:
            base = 10
            digits = raw[1:]
        if not digits:
            raise ValueError("invalid negative integer")
        return -int(digits, base)

    if raw.startswith("0x"):
        if len(raw) == 2:
            raise ValueError("hex integer cannot be empty")
        return int(raw, 16)
    return int(raw, 10)


def _to_word(value: int) -> bytes:
    return value.to_bytes(32, "big", signed=False)


def _left_pad(data: bytes, size: int = 32) -> bytes:
    if len(data) > size:
        raise ValueError("value exceeds abi word size")
    return b"\x00" * (size - len(data)) + data


def _right_pad(data: bytes, size: int = 32) -> bytes:
    pad = (size - (len(data) % size)) % size
    return data + (b"\x00" * pad)


def parse_type(raw_type: str) -> AbiType:
    t = str(raw_type).strip()
    if not t:
        raise ValueError("type cannot be empty")
    if "[" in t or "]" in t:
        raise ValueError(f"unsupported ABI type (arrays/tuples not yet supported): {raw_type}")

    if t == "address":
        return AbiType(kind="address")
    if t == "bool":
        return AbiType(kind="bool")
    if t == "string":
        return AbiType(kind="string")
    if t == "bytes":
        return AbiType(kind="bytes_dyn")

    m_bytes = re.fullmatch(r"bytes([0-9]{1,2})", t)
    if m_bytes:
        n = int(m_bytes.group(1), 10)
        if n < 1 or n > 32:
            raise ValueError(f"invalid fixed bytes size: {t}")
        return AbiType(kind="bytes_fixed", size=n)

    m_uint = re.fullmatch(r"uint([0-9]{0,3})", t)
    if m_uint:
        bits = int(m_uint.group(1) or "256", 10)
        if bits < 8 or bits > 256 or (bits % 8) != 0:
            raise ValueError(f"invalid uint bit size: {t}")
        return AbiType(kind="uint", bits=bits)

    m_int = re.fullmatch(r"int([0-9]{0,3})", t)
    if m_int:
        bits = int(m_int.group(1) or "256", 10)
        if bits < 8 or bits > 256 or (bits % 8) != 0:
            raise ValueError(f"invalid int bit size: {t}")
        return AbiType(kind="int", bits=bits)

    raise ValueError(f"unsupported ABI type: {raw_type}")


def parse_types(types: Any) -> list[AbiType]:
    if isinstance(types, str):
        raw_items = _split_csv(types)
    elif isinstance(types, list) and all(isinstance(item, str) for item in types):
        raw_items = [item.strip() for item in types]
    else:
        raise ValueError("types must be a comma-separated string or array of strings")
    return [parse_type(item) for item in raw_items]


def parse_function_signature(signature: str) -> tuple[str, list[AbiType], str]:
    raw = str(signature).strip()
    m = FUNC_SIG_RE.fullmatch(raw)
    if not m:
        raise ValueError("signature must look like functionName(type1,type2,...)")
    name = m.group(1)
    args_raw = m.group(2)
    arg_types = parse_types(args_raw)
    canonical = f"{name}({','.join(format_type(t) for t in arg_types)})"
    return name, arg_types, canonical


def parse_event_declaration(declaration: str) -> tuple[str, list[AbiType], list[bool], list[str], str]:
    raw = str(declaration).strip()
    m = FUNC_SIG_RE.fullmatch(raw)
    if not m:
        raise ValueError("event declaration must look like EventName(type indexed name, ...)")

    event_name = m.group(1)
    arg_tokens = _split_csv(m.group(2))
    arg_types: list[AbiType] = []
    indexed: list[bool] = []
    names: list[str] = []

    for idx, token in enumerate(arg_tokens):
        parts = [p for p in token.strip().split(" ") if p]
        if not parts:
            raise ValueError("event arg cannot be empty")

        arg_type = parse_type(parts[0])
        is_indexed = "indexed" in parts[1:]
        arg_name = ""
        if parts[-1] != "indexed" and parts[-1] != parts[0]:
            # treat trailing token as name when present
            arg_name = parts[-1]
        if not arg_name:
            arg_name = f"arg{idx}"

        arg_types.append(arg_type)
        indexed.append(is_indexed)
        names.append(arg_name)

    canonical = f"{event_name}({','.join(format_type(t) for t in arg_types)})"
    return event_name, arg_types, indexed, names, canonical


def format_type(t: AbiType) -> str:
    if t.kind == "address":
        return "address"
    if t.kind == "bool":
        return "bool"
    if t.kind == "string":
        return "string"
    if t.kind == "bytes_dyn":
        return "bytes"
    if t.kind == "bytes_fixed":
        return f"bytes{t.size}"
    if t.kind == "uint":
        return f"uint{t.bits}"
    if t.kind == "int":
        return f"int{t.bits}"
    raise ValueError(f"unsupported abi type: {t.kind}")


def is_dynamic(t: AbiType) -> bool:
    return t.kind in {"bytes_dyn", "string"}


def _parse_hex_bytes(value: Any, *, field: str) -> bytes:
    if not isinstance(value, str) or not HEX_RE.fullmatch(value):
        raise ValueError(f"{field} must be 0x-prefixed hex string")
    data = value[2:]
    if len(data) % 2 != 0:
        raise ValueError(f"{field} hex length must be even")
    return bytes.fromhex(data)


def encode_single(t: AbiType, value: Any) -> bytes:
    if t.kind == "address":
        if not isinstance(value, str) or not ADDRESS_RE.fullmatch(value):
            raise ValueError("address value must be 0x-prefixed 20-byte hex string")
        return _left_pad(bytes.fromhex(value[2:].lower()))

    if t.kind == "bool":
        if isinstance(value, bool):
            as_int = 1 if value else 0
        elif isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"true", "1"}:
                as_int = 1
            elif normalized in {"false", "0"}:
                as_int = 0
            else:
                raise ValueError("bool value must be true/false/1/0")
        else:
            raise ValueError("bool value must be boolean or string")
        return _to_word(as_int)

    if t.kind == "uint":
        as_int = _parse_int_like(value, signed=False)
        if as_int < 0:
            raise ValueError("uint cannot be negative")
        if as_int >= (1 << int(t.bits or 256)):
            raise ValueError("uint value exceeds declared bit width")
        return _to_word(as_int)

    if t.kind == "int":
        bits = int(t.bits or 256)
        as_int = _parse_int_like(value, signed=True)
        min_v = -(1 << (bits - 1))
        max_v = (1 << (bits - 1)) - 1
        if as_int < min_v or as_int > max_v:
            raise ValueError("int value exceeds declared bit width")
        if as_int < 0:
            as_int = (1 << bits) + as_int
        return _to_word(as_int)

    if t.kind == "bytes_fixed":
        raw = _parse_hex_bytes(value, field="bytesN value")
        if len(raw) != int(t.size or 0):
            raise ValueError(f"bytes{t.size} must be exactly {t.size} bytes")
        return raw + (b"\x00" * (32 - len(raw)))

    if t.kind == "bytes_dyn":
        raw = _parse_hex_bytes(value, field="bytes value")
        return _to_word(len(raw)) + _right_pad(raw)

    if t.kind == "string":
        if not isinstance(value, str):
            raise ValueError("string value must be a string")
        raw = value.encode("utf-8")
        return _to_word(len(raw)) + _right_pad(raw)

    raise ValueError(f"unsupported type for encoding: {t.kind}")


def encode_abi(types: list[AbiType], values: list[Any]) -> bytes:
    if len(types) != len(values):
        raise ValueError(f"expected {len(types)} values, got {len(values)}")

    head_parts: list[bytes] = []
    tail_parts: list[bytes] = []
    head_size = 32 * len(types)

    for t, value in zip(types, values, strict=True):
        encoded = encode_single(t, value)
        if is_dynamic(t):
            offset = head_size + sum(len(part) for part in tail_parts)
            head_parts.append(_to_word(offset))
            tail_parts.append(encoded)
        else:
            head_parts.append(encoded)

    return b"".join(head_parts + tail_parts)


def decode_static_word(t: AbiType, word: bytes) -> Any:
    if len(word) != 32:
        raise ValueError("abi word must be exactly 32 bytes")

    if t.kind == "address":
        return f"0x{word[-20:].hex()}"

    if t.kind == "bool":
        val = int.from_bytes(word, "big")
        if val not in {0, 1}:
            raise ValueError("invalid bool abi encoding")
        return bool(val)

    if t.kind == "uint":
        return str(int.from_bytes(word, "big"))

    if t.kind == "int":
        bits = int(t.bits or 256)
        val = int.from_bytes(word, "big")
        sign_bit = 1 << (bits - 1)
        if val & sign_bit:
            val = val - (1 << bits)
        return str(val)

    if t.kind == "bytes_fixed":
        n = int(t.size or 0)
        return f"0x{word[:n].hex()}"

    raise ValueError(f"unsupported static decode type: {t.kind}")


def _decode_dynamic(t: AbiType, data: bytes, offset: int) -> Any:
    if offset < 0 or (offset + 32) > len(data):
        raise ValueError("dynamic offset out of bounds")
    length = int.from_bytes(data[offset : offset + 32], "big")
    start = offset + 32
    end = start + length
    if end > len(data):
        raise ValueError("dynamic data out of bounds")

    raw = data[start:end]
    if t.kind == "bytes_dyn":
        return f"0x{raw.hex()}"
    if t.kind == "string":
        return raw.decode("utf-8", errors="strict")
    raise ValueError(f"unsupported dynamic decode type: {t.kind}")


def decode_abi(types: list[AbiType], data_hex: str) -> list[Any]:
    data = _parse_hex_bytes(data_hex, field="data")
    head_size = 32 * len(types)
    if len(data) < head_size:
        raise ValueError("data shorter than ABI head")

    decoded: list[Any] = []
    for idx, t in enumerate(types):
        head_word = data[idx * 32 : (idx + 1) * 32]
        if is_dynamic(t):
            offset = int.from_bytes(head_word, "big")
            decoded.append(_decode_dynamic(t, data, offset))
        else:
            decoded.append(decode_static_word(t, head_word))
    return decoded


def function_selector(signature: str) -> str:
    _, _, canonical = parse_function_signature(signature)
    return cast_function_selector(canonical)


def event_topic0(event_signature_or_declaration: str) -> str:
    raw = str(event_signature_or_declaration).strip()
    if " indexed " in raw or raw.endswith(" indexed"):
        _, _, _, _, canonical = parse_event_declaration(raw)
    else:
        _, _, canonical = parse_function_signature(raw)
    return cast_event_topic0(canonical)


def encode_call(signature: str, args: list[Any]) -> dict[str, Any]:
    _, arg_types, canonical = parse_function_signature(signature)
    if len(arg_types) != len(args):
        raise ValueError("argument count mismatch for function signature")
    calldata = cast_calldata(canonical, list(args))
    selector = function_selector(canonical)
    if not calldata.startswith(selector):
        raise ValueError("cast calldata output did not match computed selector")
    return {
        "signature": canonical,
        "selector": selector,
        "calldata": calldata,
    }


def decode_output(types_spec: Any, data_hex: str) -> dict[str, Any]:
    types = parse_types(types_spec)
    formatted_types = [format_type(t) for t in types]
    decoded_lines = cast_decode_output(formatted_types, data_hex)
    if len(decoded_lines) != len(formatted_types):
        raise ValueError(
            "cast decode-abi returned unexpected value count: "
            f"expected {len(formatted_types)}, got {len(decoded_lines)}"
        )
    return {
        "types": formatted_types,
        "values": decoded_lines,
    }


def decode_log(
    event_declaration: str,
    topics: list[str],
    data_hex: str,
    *,
    anonymous: bool = False,
) -> dict[str, Any]:
    if not isinstance(topics, list) or not all(isinstance(t, str) and HEX_RE.fullmatch(t) for t in topics):
        raise ValueError("topics must be an array of 0x-prefixed hex strings")

    event_name, arg_types, indexed_flags, names, canonical = parse_event_declaration(event_declaration)
    expected_topic0 = f"0x{keccak256(canonical.encode('utf-8')).hex()}"

    topic_cursor = 0
    if not anonymous:
        if not topics:
            raise ValueError("missing topic0 for non-anonymous event")
        if topics[0].lower() != expected_topic0.lower():
            raise ValueError("topic0 does not match event signature")
        topic_cursor = 1

    indexed_types = [t for t, is_indexed in zip(arg_types, indexed_flags, strict=True) if is_indexed]
    expected_indexed_topics = len(indexed_types)
    actual_indexed_topics = len(topics) - topic_cursor
    if actual_indexed_topics < expected_indexed_topics:
        raise ValueError("insufficient indexed topics for event declaration")

    non_indexed_types = [t for t, is_indexed in zip(arg_types, indexed_flags, strict=True) if not is_indexed]
    non_indexed_values = decode_abi(non_indexed_types, data_hex)
    non_idx_cursor = 0

    args_out: list[dict[str, Any]] = []
    for idx, (t, is_indexed, name) in enumerate(zip(arg_types, indexed_flags, names, strict=True)):
        item: dict[str, Any] = {
            "index": idx,
            "name": name,
            "type": format_type(t),
            "indexed": is_indexed,
        }
        if is_indexed:
            topic_word = topics[topic_cursor]
            topic_cursor += 1
            if is_dynamic(t):
                item["value_hash"] = topic_word
            else:
                word_bytes = _left_pad(_parse_hex_bytes(topic_word, field="topic"))[-32:]
                item["value"] = decode_static_word(t, word_bytes)
        else:
            item["value"] = non_indexed_values[non_idx_cursor]
            non_idx_cursor += 1
        args_out.append(item)

    return {
        "event": event_name,
        "signature": canonical,
        "topic0": expected_topic0,
        "anonymous": anonymous,
        "args": args_out,
    }


def run_abi_operation(request: dict[str, Any]) -> tuple[bool, dict[str, Any], str]:
    if not isinstance(request, dict):
        return False, {}, "abi request must be an object"

    operation = str(request.get("operation", "")).strip().lower()
    if operation == "encode_call":
        signature = request.get("signature")
        args = request.get("args", [])
        if not isinstance(signature, str) or not signature.strip():
            return False, {}, "encode_call requires non-empty signature"
        if not isinstance(args, list):
            return False, {}, "encode_call args must be an array"
        try:
            return True, encode_call(signature, args), ""
        except Exception as err:  # noqa: BLE001
            return False, {}, str(err)

    if operation == "decode_output":
        types = request.get("types")
        data = request.get("data")
        if types is None:
            return False, {}, "decode_output requires types"
        if not isinstance(data, str):
            return False, {}, "decode_output requires data hex string"
        try:
            return True, decode_output(types, data), ""
        except Exception as err:  # noqa: BLE001
            return False, {}, str(err)

    if operation == "decode_log":
        event_decl = request.get("event")
        topics = request.get("topics")
        data = request.get("data")
        anonymous = bool(request.get("anonymous", False))
        if not isinstance(event_decl, str) or not event_decl.strip():
            return False, {}, "decode_log requires event declaration"
        if not isinstance(topics, list):
            return False, {}, "decode_log topics must be an array"
        if not isinstance(data, str):
            return False, {}, "decode_log requires data hex string"
        try:
            return True, decode_log(event_decl, topics, data, anonymous=anonymous), ""
        except Exception as err:  # noqa: BLE001
            return False, {}, str(err)

    if operation == "function_selector":
        signature = request.get("signature")
        if not isinstance(signature, str) or not signature.strip():
            return False, {}, "function_selector requires non-empty signature"
        try:
            selector = function_selector(signature)
        except Exception as err:  # noqa: BLE001
            return False, {}, str(err)
        return True, {"selector": selector}, ""

    if operation == "event_topic0":
        event_sig = request.get("event")
        if not isinstance(event_sig, str) or not event_sig.strip():
            return False, {}, "event_topic0 requires event declaration/signature"
        try:
            topic = event_topic0(event_sig)
        except Exception as err:  # noqa: BLE001
            return False, {}, str(err)
        return True, {"topic0": topic}, ""

    return (
        False,
        {},
        "abi operation must be one of encode_call|decode_output|decode_log|function_selector|event_topic0",
    )
