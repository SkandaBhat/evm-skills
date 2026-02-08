"""Event/ABI registry for analytics commands.

Avoid runtime hashing at import-time so non-analytics commands can start without cast.
"""

from __future__ import annotations

ERC20_DECIMALS_SELECTOR = "0x313ce567"
UNISWAP_V2_TOKEN0_SELECTOR = "0x0dfe1681"
UNISWAP_V2_TOKEN1_SELECTOR = "0xd21220a7"
UNISWAP_V2_GET_RESERVES_SELECTOR = "0x0902f1ac"

UNISWAP_V2_SWAP_EVENT = (
    "Swap(address indexed sender,uint256 amount0In,uint256 amount1In,uint256 amount0Out,uint256 amount1Out,address indexed to)"
)
UNISWAP_V2_PAIR_CREATED_EVENT = (
    "PairCreated(address indexed token0,address indexed token1,address pair,uint256)"
)
UNISWAP_V3_POOL_CREATED_EVENT = (
    "PoolCreated(address indexed token0,address indexed token1,uint24 indexed fee,int24 tickSpacing,address pool)"
)
UNISWAP_V3_SWAP_EVENT = (
    "Swap(address indexed sender,address indexed recipient,int256 amount0,int256 amount1,uint160 sqrtPriceX96,uint128 liquidity,int24 tick)"
)

# keccak256("Swap(address,uint256,uint256,uint256,uint256,address)")
UNISWAP_V2_SWAP_TOPIC0 = "0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822"
# keccak256("PairCreated(address,address,address,uint256)")
UNISWAP_V2_PAIR_CREATED_TOPIC0 = "0x0d3648bd0f6ba80134a33ba9275ac585d9d315f0ad8355cddefde31afa28d0e9"
# keccak256("PoolCreated(address,address,uint24,int24,address)")
UNISWAP_V3_POOL_CREATED_TOPIC0 = "0x783cca1c0412dd0d695e784568c96da2e9c22ff989357a2e8b1d9b2b4e6b7118"
# keccak256("Swap(address,address,int256,int256,uint160,uint128,int24)")
UNISWAP_V3_SWAP_TOPIC0 = "0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67"
