from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
MANIFEST = ROOT / "references" / "method-manifest.json"

ENS_REGISTRY = "0x00000000000c2e074ec69a0dfb2997ba6c7d2e1e"
VITALIK_NODEHASH = "0xee6c4522aab0003e8d14cd40a6af439055fd2577951148c14b6cea9a53475835"


def _run_cmd(
    command: str,
    args: list[str],
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    cmd = [
        sys.executable,
        str(SCRIPTS / "evm_rpc.py"),
        command,
        *args,
    ]
    env = os.environ.copy()
    env.pop("ETH_RPC_URL", None)
    env.pop("ETH_RPC_DEFAULT_URLS", None)
    if extra_env:
        env.update(extra_env)
    return subprocess.run(cmd, capture_output=True, text=True, check=False, env=env)


def _run_exec(
    request: dict,
    extra_env: dict[str, str] | None = None,
    extra_args: list[str] | None = None,
) -> subprocess.CompletedProcess[str]:
    args = [
        "--manifest",
        str(MANIFEST),
        "--request-json",
        json.dumps(request),
    ]
    if extra_args:
        args.extend(extra_args)
    return _run_cmd("exec", args, extra_env=extra_env)


def _run_chain(
    request: dict,
    extra_env: dict[str, str] | None = None,
    command: str = "chain",
    extra_args: list[str] | None = None,
) -> subprocess.CompletedProcess[str]:
    args = [
        "--manifest",
        str(MANIFEST),
        "--request-json",
        json.dumps(request),
    ]
    if extra_args:
        args.extend(extra_args)
    return _run_cmd(command, args, extra_env=extra_env)


def _run_logs(
    request: dict,
    extra_env: dict[str, str] | None = None,
    extra_args: list[str] | None = None,
) -> subprocess.CompletedProcess[str]:
    args = [
        "--manifest",
        str(MANIFEST),
        "--request-json",
        json.dumps(request),
    ]
    if extra_args:
        args.extend(extra_args)
    return _run_cmd("logs", args, extra_env=extra_env)


def _run_abi(
    request: dict,
    extra_args: list[str] | None = None,
) -> subprocess.CompletedProcess[str]:
    args = ["--request-json", json.dumps(request)]
    if extra_args:
        args.extend(extra_args)
    return _run_cmd("abi", args)


def _run_multicall(
    request: dict,
    extra_env: dict[str, str] | None = None,
    extra_args: list[str] | None = None,
) -> subprocess.CompletedProcess[str]:
    args = [
        "--manifest",
        str(MANIFEST),
        "--request-json",
        json.dumps(request),
    ]
    if extra_args:
        args.extend(extra_args)
    return _run_cmd("multicall", args, extra_env=extra_env)


def _run_simulate(
    request: dict,
    extra_env: dict[str, str] | None = None,
    extra_args: list[str] | None = None,
) -> subprocess.CompletedProcess[str]:
    args = [
        "--manifest",
        str(MANIFEST),
        "--request-json",
        json.dumps(request),
    ]
    if extra_args:
        args.extend(extra_args)
    return _run_cmd("simulate", args, extra_env=extra_env)


def _run_trace(
    request: dict,
    extra_env: dict[str, str] | None = None,
    extra_args: list[str] | None = None,
) -> subprocess.CompletedProcess[str]:
    args = [
        "--manifest",
        str(MANIFEST),
        "--request-json",
        json.dumps(request),
    ]
    if extra_args:
        args.extend(extra_args)
    return _run_cmd("trace", args, extra_env=extra_env)


def _run_analytics(
    subcommand: str,
    args: list[str],
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return _run_cmd("analytics", [subcommand, *args], extra_env=extra_env)


def _run_ens_resolve(
    name: str,
    extra_env: dict[str, str] | None = None,
    extra_args: list[str] | None = None,
) -> subprocess.CompletedProcess[str]:
    args = [
        "resolve",
        name,
        "--manifest",
        str(MANIFEST),
    ]
    if extra_args:
        args.extend(extra_args)
    return _run_cmd("ens", args, extra_env=extra_env)


def _run_balance(
    target: str,
    extra_env: dict[str, str] | None = None,
    extra_args: list[str] | None = None,
) -> subprocess.CompletedProcess[str]:
    args = [
        target,
        "--manifest",
        str(MANIFEST),
    ]
    if extra_args:
        args.extend(extra_args)
    return _run_cmd("balance", args, extra_env=extra_env)


class _RPCHandler(BaseHTTPRequestHandler):
    responses: list[Any] = []
    calls: list[dict[str, Any]] = []

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        try:
            payload = json.loads(body)
        except Exception:  # noqa: BLE001
            payload = {"raw": body}
        _RPCHandler.calls.append(payload)

        status_code = 200
        if _RPCHandler.responses:
            next_response = _RPCHandler.responses.pop(0)
            if isinstance(next_response, tuple) and len(next_response) == 2:
                status_code = int(next_response[0])
                response_payload = next_response[1]
            else:
                response_payload = next_response
        else:
            response_payload = {"jsonrpc": "2.0", "id": payload.get("id", 1), "result": "0x1"}

        encoded = json.dumps(response_payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


def _serve(responses: list[Any]) -> tuple[HTTPServer, str]:
    _RPCHandler.responses = list(responses)
    _RPCHandler.calls = []
    server = HTTPServer(("127.0.0.1", 0), _RPCHandler)
    url = f"http://127.0.0.1:{server.server_address[1]}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, url


def _stop(server: HTTPServer) -> None:
    server.shutdown()
    server.server_close()


def _pad_address(addr: str) -> str:
    return f"0x{'0'*24}{addr[2:].lower()}"
