# Troubleshooting

## `status=denied`
- Confirm command path exists in manifest.
- Check tier requirements:
  - `local-sensitive`: set `allow_local_sensitive=true`.
  - `broadcast`: set `allow_broadcast=true` and `confirmation_token`.

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
