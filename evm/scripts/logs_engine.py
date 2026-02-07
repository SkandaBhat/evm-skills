"""Chunked eth_getLogs execution helpers."""

from __future__ import annotations

from collections import deque
import copy
import re
from typing import Any, Callable

from error_map import (
    ERR_INVALID_BLOCK_RANGE,
    ERR_INVALID_LOG_ADDRESS,
    ERR_INVALID_REQUEST,
    ERR_INVALID_TOPIC_FORMAT,
    ERR_INVALID_TOPIC_LENGTH,
    ERR_LOGS_ENGINE_FAILED,
    ERR_LOGS_RANGE_TOO_LARGE,
    ERR_LOGS_TOO_MANY_RESULTS,
    ERR_RPC_REMOTE,
    ERR_RPC_TIMEOUT,
    ERR_RPC_TRANSPORT,
)

ALLOWED_BLOCK_TAGS = {"earliest", "latest", "pending", "safe", "finalized"}
HEX_QUANTITY_RE = re.compile(r"^0x[0-9a-fA-F]+$")
HEX32_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

DEFAULT_CHUNK_SIZE = 2_000
DEFAULT_MAX_CHUNKS = 200
DEFAULT_MAX_LOGS = 10_000
DEFAULT_HEAVY_READ_THRESHOLD = 50_000

SPLIT_ERROR_PATTERNS = (
    "query returned more than",
    "more than",
    "too many results",
    "response size exceeded",
    "limit exceeded",
    "block range",
    "range too wide",
    "timed out",
    "timeout",
)


def _is_hex_quantity(value: str) -> bool:
    return bool(HEX_QUANTITY_RE.fullmatch(value))


def _to_hex_quantity(value: int) -> str:
    return hex(value)


def parse_block_bound(value: Any, *, field: str) -> tuple[bool, int | str, bool, str]:
    """Return (ok, parsed_value, is_numeric, error_message)."""
    if isinstance(value, bool):
        return False, 0, False, f"{field} cannot be boolean"
    if isinstance(value, int):
        if value < 0:
            return False, 0, False, f"{field} must be >= 0"
        return True, value, True, ""
    if not isinstance(value, str):
        return False, 0, False, f"{field} must be int or string"

    raw = value.strip()
    if not raw:
        return False, 0, False, f"{field} cannot be empty"
    if raw in ALLOWED_BLOCK_TAGS:
        return True, raw, False, ""
    if raw.isdigit():
        return True, int(raw, 10), True, ""
    if _is_hex_quantity(raw):
        return True, int(raw, 16), True, ""
    return (
        False,
        0,
        False,
        f"{field} must be a block tag ({sorted(ALLOWED_BLOCK_TAGS)}), decimal int, or hex quantity",
    )


def _validation_error(code: str, message: str) -> tuple[bool, dict[str, Any], str, str]:
    return False, {}, code, message


def _validate_address_field(value: Any, *, field: str) -> tuple[bool, str, str]:
    if isinstance(value, str):
        if not ADDRESS_RE.fullmatch(value):
            return False, ERR_INVALID_LOG_ADDRESS, f"{field} must be a 20-byte 0x-prefixed hex address"
        return True, "", ""

    if isinstance(value, list):
        if not value:
            return False, ERR_INVALID_LOG_ADDRESS, f"{field} array cannot be empty"
        for idx, item in enumerate(value):
            if not isinstance(item, str) or not ADDRESS_RE.fullmatch(item):
                return (
                    False,
                    ERR_INVALID_LOG_ADDRESS,
                    f"{field}[{idx}] must be a 20-byte 0x-prefixed hex address",
                )
        return True, "", ""

    return False, ERR_INVALID_LOG_ADDRESS, f"{field} must be a string or array of strings"


def _validate_topic_value(value: Any, *, field: str) -> tuple[bool, str, str]:
    if value is None:
        return True, "", ""

    if isinstance(value, str):
        if not value.startswith("0x"):
            return False, ERR_INVALID_TOPIC_FORMAT, f"{field} must be 0x-prefixed hex"
        if len(value) != 66:
            return (
                False,
                ERR_INVALID_TOPIC_LENGTH,
                f"{field} must be exactly 32 bytes (66 chars including 0x)",
            )
        if not HEX32_RE.fullmatch(value):
            return False, ERR_INVALID_TOPIC_FORMAT, f"{field} must contain only hex characters"
        return True, "", ""

    if isinstance(value, list):
        if not value:
            return False, ERR_INVALID_TOPIC_FORMAT, f"{field} OR-array cannot be empty"
        for idx, item in enumerate(value):
            ok, code, err = _validate_topic_value(item, field=f"{field}[{idx}]")
            if not ok:
                return False, code, err
        return True, "", ""

    return False, ERR_INVALID_TOPIC_FORMAT, f"{field} must be null, topic string, or array of topic strings"


def normalize_logs_request(request: dict[str, Any]) -> tuple[bool, dict[str, Any], str, str]:
    if not isinstance(request, dict):
        return _validation_error(ERR_INVALID_REQUEST, "logs request must be an object")

    raw_filter = request.get("filter")
    if not isinstance(raw_filter, dict):
        return _validation_error(ERR_INVALID_REQUEST, "logs request.filter must be an object")

    logs_filter = copy.deepcopy(raw_filter)
    if "blockHash" in logs_filter and ("fromBlock" in logs_filter or "toBlock" in logs_filter):
        return _validation_error(
            ERR_INVALID_BLOCK_RANGE,
            "filter.blockHash cannot be combined with filter.fromBlock/toBlock",
        )

    if "blockHash" in logs_filter:
        block_hash = logs_filter.get("blockHash")
        if not isinstance(block_hash, str) or not HEX32_RE.fullmatch(block_hash):
            return _validation_error(
                ERR_INVALID_BLOCK_RANGE,
                "filter.blockHash must be a 32-byte 0x-prefixed hex hash",
            )

    address = logs_filter.get("address")
    if address is not None:
        ok_addr, addr_code, addr_err = _validate_address_field(address, field="filter.address")
        if not ok_addr:
            return _validation_error(addr_code, addr_err)

    topics = logs_filter.get("topics")
    if topics is not None:
        if not isinstance(topics, list):
            return _validation_error(ERR_INVALID_TOPIC_FORMAT, "filter.topics must be an array when provided")
        if len(topics) > 4:
            return _validation_error(ERR_INVALID_TOPIC_FORMAT, "filter.topics supports at most 4 positions")
        for idx, topic_value in enumerate(topics):
            ok_topic, topic_code, topic_err = _validate_topic_value(topic_value, field=f"filter.topics[{idx}]")
            if not ok_topic:
                return _validation_error(topic_code, topic_err)

    from_bound = logs_filter.get("fromBlock", "latest")
    to_bound = logs_filter.get("toBlock", "latest")
    from_ok, from_value, from_numeric, from_err = parse_block_bound(from_bound, field="filter.fromBlock")
    if not from_ok:
        return _validation_error(ERR_INVALID_BLOCK_RANGE, from_err)
    to_ok, to_value, to_numeric, to_err = parse_block_bound(to_bound, field="filter.toBlock")
    if not to_ok:
        return _validation_error(ERR_INVALID_BLOCK_RANGE, to_err)

    numeric_range: tuple[int, int] | None = None
    if from_numeric and to_numeric:
        start_block = int(from_value)
        end_block = int(to_value)
        if start_block > end_block:
            return _validation_error(ERR_INVALID_BLOCK_RANGE, "filter.fromBlock must be <= filter.toBlock")
        numeric_range = (start_block, end_block)
        logs_filter["fromBlock"] = _to_hex_quantity(start_block)
        logs_filter["toBlock"] = _to_hex_quantity(end_block)
    else:
        logs_filter["fromBlock"] = from_value
        logs_filter["toBlock"] = to_value

    timeout = request.get("timeout_seconds")
    if timeout is not None and (not isinstance(timeout, (int, float)) or timeout <= 0):
        return _validation_error(ERR_INVALID_REQUEST, "logs request.timeout_seconds must be a positive number")

    def parse_positive_int(name: str, default: int) -> tuple[bool, int, str]:
        raw = request.get(name, default)
        if isinstance(raw, bool) or not isinstance(raw, int) or raw <= 0:
            return False, 0, f"logs request.{name} must be a positive integer"
        return True, raw, ""

    ok_chunk, chunk_size, chunk_err = parse_positive_int("chunk_size", DEFAULT_CHUNK_SIZE)
    if not ok_chunk:
        return _validation_error(ERR_INVALID_REQUEST, chunk_err)
    ok_max_chunks, max_chunks, max_chunks_err = parse_positive_int("max_chunks", DEFAULT_MAX_CHUNKS)
    if not ok_max_chunks:
        return _validation_error(ERR_INVALID_REQUEST, max_chunks_err)
    ok_max_logs, max_logs, max_logs_err = parse_positive_int("max_logs", DEFAULT_MAX_LOGS)
    if not ok_max_logs:
        return _validation_error(ERR_INVALID_REQUEST, max_logs_err)

    threshold_raw = request.get("heavy_read_block_range_threshold", DEFAULT_HEAVY_READ_THRESHOLD)
    if isinstance(threshold_raw, bool) or not isinstance(threshold_raw, int) or threshold_raw <= 0:
        return _validation_error(
            ERR_INVALID_REQUEST,
            "logs request.heavy_read_block_range_threshold must be a positive integer",
        )

    adaptive_split = request.get("adaptive_split", True)
    if not isinstance(adaptive_split, bool):
        return _validation_error(ERR_INVALID_REQUEST, "logs request.adaptive_split must be a boolean")

    context = request.get("context", {})
    if context and not isinstance(context, dict):
        return _validation_error(ERR_INVALID_REQUEST, "logs request.context must be an object")

    env = request.get("env", {})
    if env and (not isinstance(env, dict) or not all(isinstance(k, str) for k in env.keys())):
        return _validation_error(ERR_INVALID_REQUEST, "logs request.env must be an object with string keys")

    normalized = {
        "filter": logs_filter,
        "context": context or {},
        "env": env or {},
        "timeout_seconds": request.get("timeout_seconds"),
        "chunk_size": chunk_size,
        "max_chunks": max_chunks,
        "max_logs": max_logs,
        "adaptive_split": adaptive_split,
        "heavy_read_block_range_threshold": threshold_raw,
        "numeric_range": numeric_range,
    }
    return True, normalized, "", ""


def is_heavy_read(normalized_request: dict[str, Any]) -> tuple[bool, int]:
    numeric_range = normalized_request.get("numeric_range")
    if not isinstance(numeric_range, tuple):
        return False, 0
    start_block, end_block = numeric_range
    span = (end_block - start_block) + 1
    threshold = int(normalized_request.get("heavy_read_block_range_threshold", DEFAULT_HEAVY_READ_THRESHOLD))
    return span > threshold, span


def _build_log_key(log_item: Any) -> tuple[Any, Any, Any]:
    if not isinstance(log_item, dict):
        return ("raw", str(log_item), None)
    return (
        log_item.get("blockNumber"),
        log_item.get("logIndex"),
        log_item.get("transactionHash"),
    )


def _extract_remote_message(payload: dict[str, Any]) -> str:
    message_parts: list[str] = []
    top = payload.get("error_message")
    if isinstance(top, str):
        message_parts.append(top.lower())

    rpc_response = payload.get("rpc_response")
    if isinstance(rpc_response, dict):
        error_obj = rpc_response.get("error")
        if isinstance(error_obj, dict):
            err_message = error_obj.get("message")
            if isinstance(err_message, str):
                message_parts.append(err_message.lower())
        raw = rpc_response.get("raw")
        if isinstance(raw, str):
            message_parts.append(raw.lower())
    return " ".join(message_parts)


def _should_split(error_payload: dict[str, Any]) -> bool:
    code = str(error_payload.get("error_code", ""))
    if code in {ERR_RPC_TIMEOUT, ERR_RPC_TRANSPORT}:
        return True
    if code != ERR_RPC_REMOTE:
        return False
    combined = _extract_remote_message(error_payload)
    return any(pattern in combined for pattern in SPLIT_ERROR_PATTERNS)


def run_chunked_logs(
    *,
    normalized_request: dict[str, Any],
    fetch_chunk: Callable[[dict[str, Any]], tuple[int, dict[str, Any]]],
) -> tuple[int, dict[str, Any]]:
    logs_filter = dict(normalized_request["filter"])
    numeric_range = normalized_request.get("numeric_range")
    chunk_size = int(normalized_request["chunk_size"])
    max_chunks = int(normalized_request["max_chunks"])
    max_logs = int(normalized_request["max_logs"])
    adaptive_split = bool(normalized_request["adaptive_split"])

    attempt_count = 0
    success_count = 0
    split_count = 0
    duplicate_count = 0
    seen_keys: set[tuple[Any, Any, Any]] = set()
    merged_logs: list[Any] = []

    if not isinstance(numeric_range, tuple):
        exit_code, payload = fetch_chunk(logs_filter)
        if exit_code != 0:
            return exit_code, {
                "ok": False,
                "status": "error",
                "error_code": payload.get("error_code", ERR_LOGS_ENGINE_FAILED),
                "error_message": payload.get("error_message", "log query failed"),
                "cause": payload,
                "summary": {
                    "attempted_chunks": 1,
                    "successful_chunks": 0,
                    "split_count": 0,
                    "deduped_logs": 0,
                },
            }
        result_logs = payload.get("result")
        if not isinstance(result_logs, list):
            return 1, {
                "ok": False,
                "status": "error",
                "error_code": ERR_LOGS_ENGINE_FAILED,
                "error_message": "eth_getLogs returned a non-array result",
                "cause": payload,
                "summary": {
                    "attempted_chunks": 1,
                    "successful_chunks": 0,
                    "split_count": 0,
                    "deduped_logs": 0,
                },
            }
        return 0, {
            "ok": True,
            "status": "ok",
            "error_code": None,
            "error_message": None,
            "result": result_logs,
            "summary": {
                "attempted_chunks": 1,
                "successful_chunks": 1,
                "split_count": 0,
                "deduped_logs": 0,
                "returned_logs": len(result_logs),
            },
        }

    start_block, end_block = numeric_range
    intervals: deque[tuple[int, int]] = deque()
    cursor = start_block
    while cursor <= end_block:
        chunk_end = min(cursor + chunk_size - 1, end_block)
        intervals.append((cursor, chunk_end))
        cursor = chunk_end + 1

    while intervals:
        if attempt_count >= max_chunks:
            return 2, {
                "ok": False,
                "status": "error",
                "error_code": ERR_LOGS_RANGE_TOO_LARGE,
                "error_message": f"log query exceeded max_chunks={max_chunks}",
                "summary": {
                    "attempted_chunks": attempt_count,
                    "successful_chunks": success_count,
                    "split_count": split_count,
                    "deduped_logs": duplicate_count,
                    "returned_logs": len(merged_logs),
                },
            }

        interval_start, interval_end = intervals.popleft()
        request_filter = dict(logs_filter)
        request_filter["fromBlock"] = _to_hex_quantity(interval_start)
        request_filter["toBlock"] = _to_hex_quantity(interval_end)
        attempt_count += 1

        exit_code, payload = fetch_chunk(request_filter)
        if exit_code != 0:
            if adaptive_split and interval_start < interval_end and _should_split(payload):
                midpoint = (interval_start + interval_end) // 2
                intervals.appendleft((midpoint + 1, interval_end))
                intervals.appendleft((interval_start, midpoint))
                split_count += 1
                continue
            return exit_code, {
                "ok": False,
                "status": "error",
                "error_code": payload.get("error_code", ERR_LOGS_ENGINE_FAILED),
                "error_message": payload.get("error_message", "log query failed"),
                "failed_interval": {
                    "fromBlock": _to_hex_quantity(interval_start),
                    "toBlock": _to_hex_quantity(interval_end),
                },
                "cause": payload,
                "summary": {
                    "attempted_chunks": attempt_count,
                    "successful_chunks": success_count,
                    "split_count": split_count,
                    "deduped_logs": duplicate_count,
                    "returned_logs": len(merged_logs),
                },
            }

        result_logs = payload.get("result")
        if not isinstance(result_logs, list):
            return 1, {
                "ok": False,
                "status": "error",
                "error_code": ERR_LOGS_ENGINE_FAILED,
                "error_message": "eth_getLogs returned a non-array result",
                "failed_interval": {
                    "fromBlock": _to_hex_quantity(interval_start),
                    "toBlock": _to_hex_quantity(interval_end),
                },
                "cause": payload,
                "summary": {
                    "attempted_chunks": attempt_count,
                    "successful_chunks": success_count,
                    "split_count": split_count,
                    "deduped_logs": duplicate_count,
                    "returned_logs": len(merged_logs),
                },
            }

        success_count += 1
        for log_item in result_logs:
            log_key = _build_log_key(log_item)
            if log_key in seen_keys:
                duplicate_count += 1
                continue
            seen_keys.add(log_key)
            merged_logs.append(log_item)
            if len(merged_logs) > max_logs:
                return 2, {
                    "ok": False,
                    "status": "error",
                    "error_code": ERR_LOGS_TOO_MANY_RESULTS,
                    "error_message": f"log query exceeded max_logs={max_logs}",
                    "summary": {
                        "attempted_chunks": attempt_count,
                        "successful_chunks": success_count,
                        "split_count": split_count,
                        "deduped_logs": duplicate_count,
                        "returned_logs": len(merged_logs),
                    },
                }

    return 0, {
        "ok": True,
        "status": "ok",
        "error_code": None,
        "error_message": None,
        "result": merged_logs,
        "summary": {
            "attempted_chunks": attempt_count,
            "successful_chunks": success_count,
            "split_count": split_count,
            "deduped_logs": duplicate_count,
            "returned_logs": len(merged_logs),
            "requested_range": {
                "fromBlock": _to_hex_quantity(start_block),
                "toBlock": _to_hex_quantity(end_block),
                "blocks": (end_block - start_block) + 1,
            },
            "limits": {
                "chunk_size": chunk_size,
                "max_chunks": max_chunks,
                "max_logs": max_logs,
            },
        },
    }
