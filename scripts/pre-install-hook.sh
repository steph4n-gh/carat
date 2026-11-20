#!/usr/bin/env bash
# Coding-agent PreToolUse hook for Bash tool calls.
# Redirects `npm install <pkg>` / `npm i <pkg>` / `npm add <pkg>` to Assay's
# single-resolution installer (`assay add <pkg> --install`) or gates before install.
#
# Compatible with stock macOS /bin/bash 3.2 AND bash 5+.
# Exit 0 = allow command
# Exit 2 = block command (agent receives stderr with stop reasons & approval subject)
set -euo pipefail

PAYLOAD="$(cat)"

PARSED="$(python3 - "$PAYLOAD" <<'PY'
import json, re, shlex, sys

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

# Split simple shell chains/newlines and inspect each segment.
segments = re.split(r'(?:\s*(?:&&|\|\||;|\|)\s*|\n+)', cmd)
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

GLOBAL_ARGS=()
if [[ -n "${ASSAY_STORE_DIR:-}" ]]; then
  GLOBAL_ARGS+=(--store-dir "$ASSAY_STORE_DIR")
fi

SUB_ARGS=()
if [[ "${ASSAY_READ:-0}" == "1" && -n "${ANTHROPIC_API_KEY:-}" ]]; then
  SUB_ARGS+=(--read)
fi

while IFS= read -r PKG; do
  [[ -z "$PKG" ]] && continue
  echo "Assay pre-install gate checking ${PKG}..." >&2
  set +e
  "$ASSAY_BIN" ${GLOBAL_ARGS[@]+"${GLOBAL_ARGS[@]}"} add "$PKG" ${SUB_ARGS[@]+"${SUB_ARGS[@]}"} >&2
  RC=$?
  set -e
  if [[ "$RC" -eq 1 ]]; then
    echo "" >&2
    echo "BLOCKED by Assay: ${PKG} triggered an unapproved stop." >&2
    echo "Do NOT bypass this gate or run 'assay approve'. Report the stop reasons, leftover diff, and approval subject above to the user." >&2
    exit 2
  elif [[ "$RC" -ne 0 ]]; then
    echo "" >&2
    echo "BLOCKED by Assay: operational error (exit ${RC}) while checking ${PKG}. Fix the error instead of installing blindly." >&2
    exit 2
  fi
done <<< "$PARSED"

# Even when the check passes, remind agents to prefer `assay add <pkg> --install`
# so npm installs the exact checked lockfile via `npm ci --ignore-scripts` with zero re-resolution.
exit 0
