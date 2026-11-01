#!/usr/bin/env bash
# Resume the whole classifier pipeline from any terminal: fetch data (incremental), then train.
#   ./run.sh              run in the foreground
#   ./run.sh bg           run detached; follow with `tail -f ml/train.log`
# Output: ../corpus/models/injection-v1.json and MODEL_CARD.md. Then commit them.
set -euo pipefail
cd "$(dirname "$0")"

if [ "${1:-}" = "bg" ]; then
  nohup "$0" > train.log 2>&1 &
  echo "started pid $!; tail -f $(pwd)/train.log"
  exit 0
fi

uv sync --frozen
uv run python fetch_data.py   # safe to re-run: skips what's already in data/
uv run python train.py
