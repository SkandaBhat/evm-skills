"""Thin adapter layer over the `cast` CLI for low-level EVM primitives."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from typing import Any

from error_map import (
    ERR_RPC_TIMEOUT,
    ERR_RPC_TRANSPORT,
)

RETRYABLE_CAST_ERROR_PATTERNS = (
    "connection refused",
    "temporarily unavailable",
    "network is unreachable",
    "connection reset",
    "broken pipe",
)

REMOTE_ERROR_RE = re.compile(r"error code\s+(-?\d+):\s*(.+)$", re.IGNORECASE)
REMOTE_ERROR_DATA_RE = re.compile(r'^(?P<message>.*?),\s*data:\s*"?((?P<data>0x[0-9a-fA-F]*))"?$')


def _sleep_backoff(attempt: int) -> None:
    backoffs = [0.15, 0.40]
    if attempt < len(backoffs):
        time.sleep(backoffs[attempt])


def is_cast_installed() -> bool:
    return shutil.which("cast") is not None


def _normalise_timeout_seconds(timeout_seconds: float) -> int:
    if timeout_seconds <= 0:
        return 1
    rounded = int(timeout_seconds)
    if float(rounded) < timeout_seconds:
        rounded += 1
    return max(1, rounded)


def _cast_arg(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, separators=(",", ":"))


def _run_cast(
    args: list[str],
    *,
    timeout_seconds: float | None = None,
) -> tuple[int, str, str]:
    if not is_cast_installed():
        raise FileNotFoundError("cast")

    cmd = ["cast", *args]
    timeout = None if timeout_seconds is None else max(1.0, float(timeout_seconds) + 1.0)
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def _transport_error_payload(message: str, *, timeout: bool = False) -> dict[str, Any]:
    return {
        "ok": False,
        "error_code": ERR_RPC_TIMEOUT if timeout else ERR_RPC_TRANSPORT,
        "error_message": message,
        "rpc_response": None,
    }


def cast_rpc(
    *,
    rpc_url: str,
    payload: dict[str, Any],
    timeout_seconds: float,
    retries: int,
) -> dict[str, Any]:
    method = str(payload.get("method", "")).strip()
    params = payload.get("params", [])
    if not method:
        return _transport_error_payload("missing rpc method in payload")
    if not isinstance(params, list):
        return _transport_error_payload("rpc params must be an array")

    params_raw = json.dumps(params, separators=(",", ":"))
    rpc_timeout = _normalise_timeout_seconds(timeout_seconds)
    request_id = payload.get("id", 1)

    last_error: dict[str, Any] | None = None
    for attempt in range(retries + 1):
        try:
            rc, stdout, stderr = _run_cast(
                [
                    "rpc",
                    "--rpc-url",
                    rpc_url,
                    "--rpc-timeout",
                    str(rpc_timeout),
                    method,
                    params_raw,
                    "--raw",
                ],
                timeout_seconds=timeout_seconds,
            )
        except FileNotFoundError:
            return _transport_error_payload(
                "cast is required but not installed. install Foundry cast before using this skill."
            )
        except subprocess.TimeoutExpired:
            return _transport_error_payload("cast rpc request timed out", timeout=True)
        except Exception as err:  # noqa: BLE001
            return _transport_error_payload(str(err))

        if rc == 0:
            parsed_result: Any
            if not stdout:
                parsed_result = None
            else:
                try:
                    parsed_result = json.loads(stdout)
                except json.JSONDecodeError:
                    parsed_result = stdout
            return {
                "ok": True,
                "error_code": None,
                "error_message": None,
                "rpc_response": {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": parsed_result,
                },
            }

        message = stderr or stdout or f"cast rpc failed with exit code {rc}"
        remote_match = REMOTE_ERROR_RE.search(message)
        if remote_match:
            code = int(remote_match.group(1))
            remote_message = remote_match.group(2).strip()
            remote_data: str | None = None
            data_match = REMOTE_ERROR_DATA_RE.match(remote_message)
            if data_match:
                remote_message = str(data_match.group("message")).strip()
                remote_data = str(data_match.group("data")).strip()
            err_obj: dict[str, Any] = {
                "code": code,
                "message": remote_message,
            }
            if remote_data:
                err_obj["data"] = remote_data
            return {
                "ok": True,
                "error_code": None,
                "error_message": None,
                "rpc_response": {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": err_obj,
                },
            }

        lower = message.lower()
        is_timeout = "timed out" in lower or "timeout" in lower
        candidate = _transport_error_payload(message, timeout=is_timeout)
        candidate["rpc_response"] = {"exit_code": rc, "stderr": stderr, "stdout": stdout}
        last_error = candidate

        is_retryable = any(pat in lower for pat in RETRYABLE_CAST_ERROR_PATTERNS)
        if attempt < retries and not is_timeout and is_retryable:
            _sleep_backoff(attempt)
            continue
        return candidate

    return last_error or _transport_error_payload("unknown cast rpc failure")


def cast_namehash(name: str) -> str:
    rc, stdout, stderr = _run_cast(["namehash", name])
    if rc != 0:
        raise ValueError(stderr or f"cast namehash failed with exit code {rc}")
    if not stdout.startswith("0x") or len(stdout) != 66:
        raise ValueError(f"unexpected cast namehash output: {stdout}")
    return stdout.lower()


def cast_from_wei(value: Any, unit: str = "eth") -> str:
    rc, stdout, stderr = _run_cast(["from-wei", _cast_arg(value), unit])
    if rc != 0:
        raise ValueError(stderr or f"cast from-wei failed with exit code {rc}")
    return stdout


def cast_format_units(value: Any, unit: int | str) -> str:
    rc, stdout, stderr = _run_cast(["format-units", _cast_arg(value), str(unit)])
    if rc != 0:
        raise ValueError(stderr or f"cast format-units failed with exit code {rc}")
    return stdout


def cast_function_selector(signature: str) -> str:
    rc, stdout, stderr = _run_cast(["sig", signature])
    if rc != 0:
        raise ValueError(stderr or f"cast sig failed with exit code {rc}")
    if not stdout.startswith("0x") or len(stdout) != 10:
        raise ValueError(f"unexpected cast sig output: {stdout}")
    return stdout.lower()


def cast_event_topic0(event_signature: str) -> str:
    rc, stdout, stderr = _run_cast(["sig-event", event_signature])
    if rc != 0:
        raise ValueError(stderr or f"cast sig-event failed with exit code {rc}")
    if not stdout.startswith("0x") or len(stdout) != 66:
        raise ValueError(f"unexpected cast sig-event output: {stdout}")
    return stdout.lower()


def cast_calldata(signature: str, args: list[Any]) -> str:
    cmd = ["calldata", signature, *[_cast_arg(arg) for arg in args]]
    rc, stdout, stderr = _run_cast(cmd)
    if rc != 0:
        raise ValueError(stderr or f"cast calldata failed with exit code {rc}")
    if not stdout.startswith("0x"):
        raise ValueError(f"unexpected cast calldata output: {stdout}")
    return stdout.lower()


def cast_decode_output(types: list[str], data_hex: str) -> list[str]:
    signature = f"f()({','.join(types)})"
    rc, stdout, stderr = _run_cast(["decode-abi", signature, data_hex])
    if rc != 0:
        raise ValueError(stderr or f"cast decode-abi failed with exit code {rc}")
    if not stdout:
        return []
    return stdout.splitlines()
