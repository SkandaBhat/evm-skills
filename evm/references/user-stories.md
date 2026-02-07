# Agent User Stories

Source: `references/user-stories.json`.

## `chain-health-dashboard`
- Title: Monitor chain health and fee conditions
- Tier: `read`
- Persona: `autonomous-observer-agent`
- Goal: As an agent, I want to detect chain liveness and fee pressure before taking actions.
- Methods (8): `eth_chainId`, `eth_syncing`, `eth_blockNumber`, `eth_blobBaseFee`, `eth_gasPrice`, `eth_maxPriorityFeePerGas`, `eth_feeHistory`, `eth_coinbase`
- Acceptance criteria:
  - Returns chain ID and sync state in one workflow.
  - Surfaces fee metrics for decision-making.
  - Fails with RPC_URL_REQUIRED when ETH_RPC_URL is missing.

## `account-state-audit`
- Title: Audit account state
- Tier: `read`
- Persona: `risk-agent`
- Goal: As an agent, I want to inspect account state before simulation or execution.
- Methods (5): `eth_getBalance`, `eth_getTransactionCount`, `eth_getCode`, `eth_getStorageAt`, `eth_getProof`
- Acceptance criteria:
  - Returns balance, nonce, code, and proof data.
  - Supports block tag selection for deterministic reads.

## `contract-read-and-simulate`
- Title: Read and preflight contract execution
- Tier: `read`
- Persona: `execution-planner-agent`
- Goal: As an agent, I want to simulate and estimate execution cost before publishing transactions.
- Methods (4): `eth_call`, `eth_estimateGas`, `eth_createAccessList`, `eth_simulateV1`
- Acceptance criteria:
  - Preflight methods return structured success or RPC_REMOTE_ERROR.
  - No broadcast permission is required.

## `transaction-lookup-by-hash`
- Title: Inspect transaction by hash
- Tier: `read`
- Persona: `support-agent`
- Goal: As an agent, I want to fetch transaction lifecycle details from hash input.
- Methods (2): `eth_getTransactionByHash`, `eth_getTransactionReceipt`
- Acceptance criteria:
  - Returns both transaction envelope and receipt when available.
  - Gracefully handles pending or dropped transactions.

## `transaction-lookup-by-block-position`
- Title: Inspect transaction by block position
- Tier: `read`
- Persona: `forensics-agent`
- Goal: As an agent, I want indexed access to transactions in canonical blocks.
- Methods (2): `eth_getTransactionByBlockHashAndIndex`, `eth_getTransactionByBlockNumberAndIndex`
- Acceptance criteria:
  - Supports both hash-based and number-based addressing.
  - Returns nulls cleanly when index is out of range.

## `block-and-receipts-inspection`
- Title: Inspect block and receipt aggregates
- Tier: `read`
- Persona: `analytics-agent`
- Goal: As an agent, I want complete block-level statistics for monitoring.
- Methods (7): `eth_getBlockByHash`, `eth_getBlockByNumber`, `eth_getBlockReceipts`, `eth_getBlockTransactionCountByHash`, `eth_getBlockTransactionCountByNumber`, `eth_getUncleCountByBlockHash`, `eth_getUncleCountByBlockNumber`
- Acceptance criteria:
  - Supports block retrieval by hash and number.
  - Provides tx and uncle count metrics.

## `log-backfill`
- Title: Backfill contract logs over a range
- Tier: `read`
- Persona: `indexer-agent`
- Goal: As an agent, I want deterministic log extraction for historical windows.
- Methods (1): `eth_getLogs`
- Acceptance criteria:
  - Accepts topic filters and block ranges.
  - Handles empty result sets as normal outcome.

## `custom-filter-lifecycle`
- Title: Run custom filter lifecycle
- Tier: `read`
- Persona: `alerting-agent`
- Goal: As an agent, I want to create, poll, and retire JSON-RPC filters safely.
- Methods (4): `eth_newFilter`, `eth_getFilterChanges`, `eth_getFilterLogs`, `eth_uninstallFilter`
- Acceptance criteria:
  - Filter ID lifecycle is represented end-to-end.
  - Wrapper does not persist filter IDs beyond request scope.

## `new-block-and-pending-filters`
- Title: Monitor new blocks and pending transactions
- Tier: `read`
- Persona: `trading-agent`
- Goal: As an agent, I want low-latency new-head and mempool polling.
- Methods (4): `eth_newBlockFilter`, `eth_newPendingTransactionFilter`, `eth_getFilterChanges`, `eth_uninstallFilter`
- Acceptance criteria:
  - Supports both block and pending filters.
  - Poll/uninstall sequence is explicit in workflow.

## `local-account-operations`
- Title: Use node-local account authority
- Tier: `local-sensitive`
- Persona: `custodial-ops-agent`
- Goal: As an agent, I want controlled access to local signing capabilities.
- Methods (3): `eth_accounts`, `eth_sign`, `eth_signTransaction`
- Acceptance criteria:
  - Denied unless allow_local_sensitive is true.
  - No broadcast should occur in this story.

## `broadcast-raw-signed-transaction`
- Title: Publish signed raw transaction
- Tier: `broadcast`
- Persona: `execution-agent`
- Goal: As an agent, I want to broadcast pre-signed transactions with explicit confirmation.
- Methods (1): `eth_sendRawTransaction`
- Acceptance criteria:
  - Denied unless allow_broadcast and confirmation are provided.
  - Returns tx hash or RPC remote error.

## `broadcast-node-managed-transaction`
- Title: Publish transaction via node-managed account
- Tier: `broadcast`
- Persona: `execution-agent`
- Goal: As an agent, I want to submit transactions through node-managed accounts with safeguards.
- Methods (1): `eth_sendTransaction`
- Acceptance criteria:
  - Denied unless broadcast gate and confirmation token are present.
  - No hidden retries for non-idempotent publish requests by default.

## `debug-raw-artifact-inspection`
- Title: Inspect raw execution artifacts
- Tier: `read`
- Persona: `forensics-agent`
- Goal: As an agent, I want byte-level artifacts for deep incident analysis.
- Methods (5): `debug_getBadBlocks`, `debug_getRawBlock`, `debug_getRawHeader`, `debug_getRawReceipts`, `debug_getRawTransaction`
- Acceptance criteria:
  - Handles pruned-history RPC errors without wrapper crashes.
  - Preserves byte payloads without lossy transforms.

## `engine-capability-handshake`
- Title: Run EL-CL capability handshake
- Tier: `operator`
- Persona: `validator-infra-agent`
- Goal: As an infrastructure agent, I want to verify consensus and execution endpoint compatibility.
- Methods (2): `engine_exchangeCapabilities`, `engine_exchangeTransitionConfigurationV1`
- Acceptance criteria:
  - Denied unless operator gate and confirmation are present.
  - Returns clear diff when transition config mismatches.

## `engine-forkchoice-control`
- Title: Manage forkchoice updates across versions
- Tier: `operator`
- Persona: `validator-infra-agent`
- Goal: As an infrastructure agent, I want versioned forkchoice control for upgrades.
- Methods (4): `engine_forkchoiceUpdatedV1`, `engine_forkchoiceUpdatedV2`, `engine_forkchoiceUpdatedV3`, `engine_forkchoiceUpdatedV4`
- Acceptance criteria:
  - Supports version selection by fork era.
  - Returns structured payload status and latest valid hash.

## `engine-payload-retrieval-and-bodies`
- Title: Retrieve payloads, bodies, and blobs
- Tier: `operator`
- Persona: `builder-relay-agent`
- Goal: As an infrastructure agent, I want to retrieve payload artifacts across protocol versions.
- Methods (13): `engine_getPayloadV1`, `engine_getPayloadV2`, `engine_getPayloadV3`, `engine_getPayloadV4`, `engine_getPayloadV5`, `engine_getPayloadV6`, `engine_getPayloadBodiesByHashV1`, `engine_getPayloadBodiesByHashV2`, `engine_getPayloadBodiesByRangeV1`, `engine_getPayloadBodiesByRangeV2`, `engine_getBlobsV1`, `engine_getBlobsV2`, `engine_getBlobsV3`
- Acceptance criteria:
  - Supports mixed-version payload retrieval workflows.
  - Surfaces unsupported-fork errors explicitly.

## `engine-newpayload-validation`
- Title: Validate incoming payloads across versions
- Tier: `operator`
- Persona: `validator-infra-agent`
- Goal: As an infrastructure agent, I want to validate payload proposals consistently across fork versions.
- Methods (5): `engine_newPayloadV1`, `engine_newPayloadV2`, `engine_newPayloadV3`, `engine_newPayloadV4`, `engine_newPayloadV5`
- Acceptance criteria:
  - Returns VALID/INVALID status variants without schema drift.
  - Handles invalid-params and unsupported-fork error codes.
