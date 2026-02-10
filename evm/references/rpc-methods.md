# Execution API RPC Methods

Source of truth: `evm/references/rpc-method-inventory.json`.
Source repo: https://github.com/ethereum/execution-apis @ `585763b34564202d4611d318006ea1f3efb43616`.

Total methods: **69**.

## `debug` (5)
- `debug_getBadBlocks`
- `debug_getRawBlock`
- `debug_getRawHeader`
- `debug_getRawReceipts`
- `debug_getRawTransaction`

## `engine` (24)
- `engine_exchangeCapabilities`
- `engine_exchangeTransitionConfigurationV1`
- `engine_forkchoiceUpdatedV1`
- `engine_forkchoiceUpdatedV2`
- `engine_forkchoiceUpdatedV3`
- `engine_forkchoiceUpdatedV4`
- `engine_getBlobsV1`
- `engine_getBlobsV2`
- `engine_getBlobsV3`
- `engine_getPayloadBodiesByHashV1`
- `engine_getPayloadBodiesByHashV2`
- `engine_getPayloadBodiesByRangeV1`
- `engine_getPayloadBodiesByRangeV2`
- `engine_getPayloadV1`
- `engine_getPayloadV2`
- `engine_getPayloadV3`
- `engine_getPayloadV4`
- `engine_getPayloadV5`
- `engine_getPayloadV6`
- `engine_newPayloadV1`
- `engine_newPayloadV2`
- `engine_newPayloadV3`
- `engine_newPayloadV4`
- `engine_newPayloadV5`

## `eth` (40)
- `eth_accounts`
- `eth_blobBaseFee`
- `eth_blockNumber`
- `eth_call`
- `eth_chainId`
- `eth_coinbase`
- `eth_createAccessList`
- `eth_estimateGas`
- `eth_feeHistory`
- `eth_gasPrice`
- `eth_getBalance`
- `eth_getBlockByHash`
- `eth_getBlockByNumber`
- `eth_getBlockReceipts`
- `eth_getBlockTransactionCountByHash`
- `eth_getBlockTransactionCountByNumber`
- `eth_getCode`
- `eth_getFilterChanges`
- `eth_getFilterLogs`
- `eth_getLogs`
- `eth_getProof`
- `eth_getStorageAt`
- `eth_getTransactionByBlockHashAndIndex`
- `eth_getTransactionByBlockNumberAndIndex`
- `eth_getTransactionByHash`
- `eth_getTransactionCount`
- `eth_getTransactionReceipt`
- `eth_getUncleCountByBlockHash`
- `eth_getUncleCountByBlockNumber`
- `eth_maxPriorityFeePerGas`
- `eth_newBlockFilter`
- `eth_newFilter`
- `eth_newPendingTransactionFilter`
- `eth_sendRawTransaction`
- `eth_sendTransaction`
- `eth_sign`
- `eth_signTransaction`
- `eth_simulateV1`
- `eth_syncing`
- `eth_uninstallFilter`
