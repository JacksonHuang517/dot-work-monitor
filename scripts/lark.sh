#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
exec docker compose exec --user monitor monitor lark-cli "$@"
