# Troubleshooting

## `status=denied`
- Confirm command path exists in manifest.
- Check tier requirements:
  - `local-sensitive`: set `allow_local_sensitive=true`.
  - `broadcast`: set `allow_broadcast=true` and `confirmation_token`.
- For `error_code=RPC_URL_REQUIRED`:
  - provide an RPC URL and set `ETH_RPC_URL` in env, or pass `--rpc-url` in command args.
  - expected message: `couldnt find an rpc url. give me an rpc url so i can add it to env.`

## `status=error` and `error_code=COMMAND_NOT_FOUND`
- Verify `cast` exists on PATH.
- Confirm command path matches discovered path exactly.

## Coverage check failures
- Regenerate discovery JSON:
  - `python3 scripts/discover_cast_tree.py --output references/discovered-cast-paths.json`
- Rebuild manifest:
  - `python3 scripts/build_manifest.py --discovered references/discovered-cast-paths.json --output references/command-manifest.json`
- Re-run:
  - `python3 scripts/check_coverage.py --discovered references/discovered-cast-paths.json --manifest references/command-manifest.json`

## RPC errors
- Ensure the RPC URL is reachable and supports the requested method.
- For local development, run an anvil endpoint and pass `--rpc-url`.
- RPC URLs are env-only in this skill; there is no disk persistence.
