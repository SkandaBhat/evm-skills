"""Small reusable aggregators for analytics outputs."""

from __future__ import annotations

from typing import Any


def summarize_swap_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total_events = len(rows)
    token0_pool_net = 0
    token1_pool_net = 0
    token0_volume = 0
    token1_volume = 0

    for row in rows:
        amount0_in = int(str(row.get("amount0_in_raw", "0")))
        amount1_in = int(str(row.get("amount1_in_raw", "0")))
        amount0_out = int(str(row.get("amount0_out_raw", "0")))
        amount1_out = int(str(row.get("amount1_out_raw", "0")))

        token0_pool_net += amount0_in - amount0_out
        token1_pool_net += amount1_in - amount1_out
        token0_volume += amount0_in + amount0_out
        token1_volume += amount1_in + amount1_out

    return {
        "events": total_events,
        "token0_pool_net_raw": str(token0_pool_net),
        "token1_pool_net_raw": str(token1_pool_net),
        "token0_volume_raw": str(token0_volume),
        "token1_volume_raw": str(token1_volume),
    }
