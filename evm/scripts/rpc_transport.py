"""HTTP JSON-RPC transport with bounded retries."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from socket import timeout as SocketTimeout
from typing import Any

from error_map import ERR_RPC_TIMEOUT, ERR_RPC_TRANSPORT

RETRYABLE_HTTP_CODES = {429, 502, 503, 504}


def _sleep_backoff(attempt: int) -> None:
    backoffs = [0.15, 0.40]
    if attempt < len(backoffs):
        time.sleep(backoffs[attempt])


def invoke_rpc(
    *,
    rpc_url: str,
    payload: dict[str, Any],
    timeout_seconds: float,
    retries: int,
) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    last_error: dict[str, Any] | None = None

    for attempt in range(retries + 1):
        req = urllib.request.Request(
            rpc_url,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
                text = resp.read().decode("utf-8")
                try:
                    rpc_response = json.loads(text)
                except json.JSONDecodeError:
                    return {
                        "ok": False,
                        "error_code": ERR_RPC_TRANSPORT,
                        "error_message": "rpc endpoint returned non-json response",
                        "rpc_response": {"raw": text},
                    }
                return {
                    "ok": True,
                    "error_code": None,
                    "error_message": None,
                    "rpc_response": rpc_response,
                }
        except SocketTimeout as err:
            return {
                "ok": False,
                "error_code": ERR_RPC_TIMEOUT,
                "error_message": str(err),
                "rpc_response": None,
            }
        except urllib.error.HTTPError as err:
            text = err.read().decode("utf-8", errors="replace")
            last_error = {
                "ok": False,
                "error_code": ERR_RPC_TRANSPORT,
                "error_message": f"http error {err.code}",
                "rpc_response": {"status": err.code, "raw": text},
            }
            if err.code in RETRYABLE_HTTP_CODES and attempt < retries:
                _sleep_backoff(attempt)
                continue
            return last_error
        except urllib.error.URLError as err:
            last_error = {
                "ok": False,
                "error_code": ERR_RPC_TRANSPORT,
                "error_message": str(err),
                "rpc_response": None,
            }
            if attempt < retries:
                _sleep_backoff(attempt)
                continue
            return last_error
        except Exception as err:  # noqa: BLE001
            return {
                "ok": False,
                "error_code": ERR_RPC_TRANSPORT,
                "error_message": str(err),
                "rpc_response": None,
            }

    return last_error or {
        "ok": False,
        "error_code": ERR_RPC_TRANSPORT,
        "error_message": "unknown transport failure",
        "rpc_response": None,
    }
