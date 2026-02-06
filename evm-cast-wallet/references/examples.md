# Examples

## Read command
```json
{
  "command_path": "address-zero",
  "args": [],
  "context": {},
  "timeout_seconds": 20
}
```

Run:
```bash
python3 scripts/evm_cast.py exec --request-file references/examples-read-request.json
```

Session env reuse (no persistence):
```bash
export ETH_RPC_URL="https://your-rpc-url"
python3 scripts/evm_cast.py exec --request-file references/examples-read-request.json
```

## Broadcast command
```json
{
  "command_path": "send",
  "args": ["0x0000000000000000000000000000000000000000", "--rpc-url", "http://localhost:8545"],
  "context": {
    "allow_broadcast": true,
    "confirmation_token": "approved-by-agent"
  },
  "timeout_seconds": 45
}
```

Run:
```bash
python3 scripts/evm_cast.py exec --request-file references/examples-broadcast-request.json
```

## Check coverage
```bash
python3 scripts/check_coverage.py \
  --discovered references/discovered-cast-paths.json \
  --manifest references/command-manifest.json
```
