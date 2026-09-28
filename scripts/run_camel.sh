#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
PYTHON_BIN="${PYTHON_BIN:-$ROOT_DIR/.venv/bin/python}"

export ACI_ARENA_API_KEY="${ACI_ARENA_API_KEY:-ollama}"
export ACI_ARENA_BASE_URL="${ACI_ARENA_BASE_URL:-http://127.0.0.1:11434/v1}"
export ACI_ARENA_MODEL_NAME="${ACI_ARENA_MODEL_NAME:-llama3.2:latest}"
export ACI_ARENA_MAX_TOKENS="${ACI_ARENA_MAX_TOKENS:-512}"

mkdir -p results/camel
"$PYTHON_BIN" benchmark.py \
  --mas camel \
  --suite hijacking \
  --attack SafetyCheckInstruction \
  --task_domain code \
  --malicious_agents assistant \
  --max_workers 1 \
  --task_limit 1 \
  --observer_jsonl results/camel/events.jsonl \
  --output_dir results/camel 2>&1 | tee results/camel/run.log
