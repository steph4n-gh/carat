#!/usr/bin/env bash
# Coding-agent PreToolUse hook for Bash tool calls.
# Intercepts `npm install <pkg>` / `npm i <pkg>` / `npm add <pkg>` and runs
# `assay add` before any package enters node_modules.
#
# Exit 0 = allow command
# Exit 2 = block command (agent receives stderr with stop reasons & approval subject)
set -euo pipefail

PAYLOAD="$(cat)"

# Extract tool_input.command and any package arguments from npm install/i/add.
PARSED="$(python3 - "$PAYLOAD" <<'PY'
import json, shlex, sys

raw = sys.argv[1]
try:
    data = json.loads(raw)
except Exception:
    sys.exit(0)

cmd = (
    data.get("tool_input", {}).get("command")
    or data.get("command")
    or ""
)
if not isinstance(cmd, str) or not cmd.strip():
    sys.exit(0)

# Split simple shell chains (`&&`, `;`) and inspect each subcommand.
import re
segments = re.split(r'\s*(?:&&|\|\||;)\s*', cmd)
pkgs = []
for seg in segments:
    seg = seg.strip()
    if not seg:
        continue
    try:
        tokens = shlex.split(seg)
    except ValueError:
        continue
    if len(tokens) < 3:
        continue
    if tokens[0] == "npm" and tokens[1] in ("install", "i", "add"):
        skip_next = False
        for tok in tokens[2:]:
            if skip_next:
                skip_next = False
                continue
            if tok in ("--prefix", "--registry", "--workspace", "-w", "--tag"):
                skip_next = True
                continue
            if tok.startswith("-"):
                continue
            pkgs.append(tok)

for p in pkgs:
    print(p)
PY
)"

if [[ -z "$PARSED" ]]; then
  exit 0
fi

ASSAY_BIN="${ASSAY_BIN:-$(command -v assay || echo "$HOME/.local/bin/assay")}"
if [[ ! -x "$ASSAY_BIN" ]]; then
  echo "BLOCKED by Assay hook: assay binary not found (set ASSAY_BIN or run ./scripts/install.sh)." >&2
  exit 2
fi

EXTRA_ARGS=()
if [[ -n "${ASSAY_STORE_DIR:-}" ]]; then
  EXTRA_ARGS+=(--store-dir "$ASSAY_STORE_DIR")
fi
if [[ "${ASSAY_READ:-0}" == "1" && -n "${ANTHROPIC_API_KEY:-}" ]]; then
  EXTRA_ARGS+=(--read)
fi

while IFS= read -r PKG; do
  [[ -z "$PKG" ]] && continue
  echo "Assay pre-install gate checking ${PKG}..." >&2
  if ! "$ASSAY_BIN" "${EXTRA_ARGS[@]}" add "$PKG" >&2; then
    echo "" >&2
    echo "BLOCKED by Assay: ${PKG} triggered an unapproved stop." >&2
    echo "Do NOT bypass this gate or run 'assay approve'. Report the stop reasons and approval subject above to the user." >&2
    exit 2
  fi
done <<< "$PARSED"

exit 0
