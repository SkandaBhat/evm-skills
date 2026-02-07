"""Simulation helpers built on eth_call + eth_estimateGas."""

from __future__ import annotations

import re
from typing import Any, Callable

from error_map import ERR_INVALID_REQUEST, ERR_SIMULATION_REVERTED

HEX_RE = re.compile(r"^0x[0-9a-fA-F]*$")
ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

SimulationExecutor = Callable[[dict[str, Any]], tuple[int, dict[str, Any]]]


def normalize_simulation_request(request: dict[str, Any]) -> tuple[bool, dict[str, Any], str]:
    if not isinstance(request, dict):
        return False, {}, "simulate request must be an object"

    call_object = request.get("call_object")
    if not isinstance(call_object, dict):
        return False, {}, "simulate request.call_object must be an object"

    to = call_object.get("to")
    data = call_object.get("data")
    if to is not None and (not isinstance(to, str) or not ADDRESS_RE.fullmatch(to)):
        return False, {}, "simulate request.call_object.to must be a 20-byte hex address"
    if data is not None and (not isinstance(data, str) or not HEX_RE.fullmatch(data) or (len(data) % 2 != 0)):
        return False, {}, "simulate request.call_object.data must be even-length 0x-prefixed hex"

    for key in ("from", "gas", "gasPrice", "maxFeePerGas", "maxPriorityFeePerGas", "value"):
        if key in call_object and not isinstance(call_object[key], str):
            return False, {}, f"simulate request.call_object.{key} must be a string"

    block_tag = request.get("block_tag", "latest")
    if not isinstance(block_tag, str) or not block_tag.strip():
        return False, {}, "simulate request.block_tag must be a non-empty string"

    include_estimate_gas = bool(request.get("include_estimate_gas", True))

    state_override = request.get("state_override")
    if state_override is not None and not isinstance(state_override, dict):
        return False, {}, "simulate request.state_override must be an object"

    context = request.get("context", {})
    if context and not isinstance(context, dict):
        return False, {}, "simulate request.context must be an object"

    env = request.get("env", {})
    if env and (not isinstance(env, dict) or not all(isinstance(k, str) for k in env.keys())):
        return False, {}, "simulate request.env must be an object with string keys"

    timeout_seconds = request.get("timeout_seconds")
    if timeout_seconds is not None and (
        not isinstance(timeout_seconds, (int, float)) or timeout_seconds <= 0
    ):
        return False, {}, "simulate request.timeout_seconds must be a positive number"

    return (
        True,
        {
            "call_object": call_object,
            "block_tag": block_tag,
            "include_estimate_gas": include_estimate_gas,
            "state_override": state_override,
            "context": context or {},
            "env": env or {},
            "timeout_seconds": timeout_seconds,
            "request": request,
        },
        "",
    )


def _parse_hex_bytes(raw: str) -> bytes:
    if not isinstance(raw, str) or not HEX_RE.fullmatch(raw) or len(raw) % 2 != 0:
        raise ValueError("invalid hex bytes")
    return bytes.fromhex(raw[2:])


def _decode_revert_data(data_hex: str) -> dict[str, Any]:
    out: dict[str, Any] = {"raw": data_hex}
    try:
        raw = _parse_hex_bytes(data_hex)
    except Exception:  # noqa: BLE001
        return out

    if len(raw) >= 4:
        selector = raw[:4].hex()
        out["selector"] = f"0x{selector}"

        # Error(string)
        if selector == "08c379a0" and len(raw) >= 4 + 32 + 32 + 32:
            try:
                body = raw[4:]
                string_offset = int.from_bytes(body[0:32], "big")
                strlen_pos = string_offset
                strlen = int.from_bytes(body[strlen_pos : strlen_pos + 32], "big")
                str_start = strlen_pos + 32
                str_end = str_start + strlen
                reason = body[str_start:str_end].decode("utf-8", errors="strict")
                out["reason"] = reason
                out["kind"] = "Error(string)"
            except Exception:  # noqa: BLE001
                pass

        # Panic(uint256)
        if selector == "4e487b71" and len(raw) >= 4 + 32:
            try:
                code = int.from_bytes(raw[4:36], "big")
                out["panic_code"] = code
                out["kind"] = "Panic(uint256)"
            except Exception:  # noqa: BLE001
                pass

    return out


def _extract_revert_from_error_payload(payload: dict[str, Any]) -> dict[str, Any]:
    message = str(payload.get("error_message", ""))
    rpc_response = payload.get("rpc_response")
    rpc_error = rpc_response.get("error") if isinstance(rpc_response, dict) else None

    out: dict[str, Any] = {
        "message": message,
    }
    if isinstance(rpc_error, dict):
        if "code" in rpc_error:
            out["rpc_error_code"] = rpc_error.get("code")
        if "message" in rpc_error:
            out["rpc_error_message"] = rpc_error.get("message")

        data_field = rpc_error.get("data")
        data_hex: str | None = None
        if isinstance(data_field, str) and data_field.startswith("0x"):
            data_hex = data_field
        elif isinstance(data_field, dict):
            for key in ("data", "return", "result", "output"):
                candidate = data_field.get(key)
                if isinstance(candidate, str) and candidate.startswith("0x"):
                    data_hex = candidate
                    break
        if data_hex:
            out["data"] = _decode_revert_data(data_hex)

    lowered = message.lower()
    if "execution reverted" in lowered and "reason" not in out:
        out["kind"] = "execution reverted"
    return out


def _build_req(
    *,
    method: str,
    params: list[Any],
    context: dict[str, Any],
    env: dict[str, Any],
    timeout_seconds: float | None,
) -> dict[str, Any]:
    req: dict[str, Any] = {"method": method, "params": params, "context": context}
    if env:
        req["env"] = env
    if timeout_seconds is not None:
        req["timeout_seconds"] = timeout_seconds
    return req


def run_simulation(
    *,
    normalized_request: dict[str, Any],
    execute_rpc: SimulationExecutor,
) -> tuple[int, dict[str, Any]]:
    call_object = dict(normalized_request["call_object"])
    block_tag = str(normalized_request["block_tag"])
    include_estimate_gas = bool(normalized_request["include_estimate_gas"])
    state_override = normalized_request.get("state_override")
    context = dict(normalized_request.get("context", {}))
    env = dict(normalized_request.get("env", {}))
    timeout_seconds = normalized_request.get("timeout_seconds")

    call_params: list[Any] = [call_object, block_tag]
    if state_override is not None:
        call_params.append(state_override)

    call_req = _build_req(
        method="eth_call",
        params=call_params,
        context=context,
        env=env,
        timeout_seconds=timeout_seconds,
    )
    call_exit, call_payload = execute_rpc(call_req)

    call_result: dict[str, Any] = {
        "ok": call_exit == 0,
        "result": call_payload.get("result") if call_exit == 0 else None,
        "error_code": None if call_exit == 0 else call_payload.get("error_code"),
        "error_message": None if call_exit == 0 else call_payload.get("error_message"),
        "payload": call_payload,
    }

    if call_exit != 0:
        revert = _extract_revert_from_error_payload(call_payload)
        return 1, {
            "ok": False,
            "status": "error",
            "error_code": ERR_SIMULATION_REVERTED,
            "error_message": "eth_call reverted or failed",
            "result": {
                "reverted": True,
                "call": call_result,
                "revert": revert,
                "estimate_gas": None,
            },
        }

    estimate_payload: dict[str, Any] | None = None
    if include_estimate_gas:
        estimate_params: list[Any] = [call_object]
        if state_override is not None:
            estimate_params.append(state_override)
        estimate_req = _build_req(
            method="eth_estimateGas",
            params=estimate_params,
            context=context,
            env=env,
            timeout_seconds=timeout_seconds,
        )
        estimate_exit, estimate_payload = execute_rpc(estimate_req)
        if estimate_exit != 0:
            return estimate_exit, {
                "ok": False,
                "status": "error",
                "error_code": estimate_payload.get("error_code", ERR_INVALID_REQUEST),
                "error_message": "eth_estimateGas failed",
                "result": {
                    "reverted": False,
                    "call": call_result,
                    "revert": None,
                    "estimate_gas": {
                        "ok": False,
                        "result": None,
                        "error_code": estimate_payload.get("error_code"),
                        "error_message": estimate_payload.get("error_message"),
                        "payload": estimate_payload,
                    },
                },
            }

    estimate_result: dict[str, Any] | None = None
    if include_estimate_gas and estimate_payload is not None:
        estimate_result = {
            "ok": True,
            "result": estimate_payload.get("result"),
            "error_code": None,
            "error_message": None,
            "payload": estimate_payload,
        }

    return 0, {
        "ok": True,
        "status": "ok",
        "error_code": None,
        "error_message": None,
        "result": {
            "reverted": False,
            "call": call_result,
            "revert": None,
            "estimate_gas": estimate_result,
        },
    }
