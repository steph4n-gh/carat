#!/usr/bin/env bash
# Coding-agent PreToolUse hook for Bash tool calls.
# Blocks raw `npm install` / `npm i` / `npm add` / `npm update` calls (including wrappers and aliases)
# so agents MUST use Assay's zero-TOCTOU single-resolution installer (`assay add <pkg> --install`)
# or `npm ci --ignore-scripts` on an Assay-verified lockfile.
#
# Compatible with stock macOS /bin/bash 3.2 AND bash 5+.
# Exit 0 = allow command
# Exit 2 = block command (agent receives stderr explaining the safe Assay command)
set -euo pipefail

PAYLOAD="$(cat)"

PY_SCRIPT='
import json, os, re, shlex, sys

raw = sys.stdin.read()
if not raw.strip():
    sys.exit(0)
try:
    data = json.loads(raw)
except Exception as e:
    sys.stderr.write(f"Assay hook error: invalid JSON payload: {e}\n")
    sys.exit(3)

cmd = (
    data.get("tool_input", {}).get("command")
    or data.get("command")
    or ""
)
if not isinstance(cmd, str) or not cmd.strip():
    sys.exit(0)

NPM_MUTATING = {
    "install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "isntall",
    "add", "update", "up", "upgrade", "udpate", "install-test", "it",
}
FLAGS_WITH_VAL = {"--prefix", "--registry", "--workspace", "-w", "--tag", "--userconfig", "--cache", "-C"}

segments = re.split(r"(?:\s*(?:&&|\|\||;|\|)\s*|\n+)", cmd)
blocked = []
for seg in segments:
    seg = seg.strip()
    if not seg:
        continue
    try:
        tokens = shlex.split(seg)
    except ValueError:
        blocked.append("unparseable shell command")
        continue

    idx = 0
    while idx < len(tokens):
        tok = tokens[idx]
        if tok in ("env", "command", "nohup", "sudo"):
            idx += 1
            continue
        if "=" in tok and not tok.startswith("-"):
            idx += 1
            continue
        break
    if idx >= len(tokens):
        continue

    prog = os.path.basename(tokens[idx])
    if prog != "npm":
        continue

    sub_idx = idx + 1
    skip_next = False
    subcmd = None
    while sub_idx < len(tokens):
        tok = tokens[sub_idx]
        if skip_next:
            skip_next = False
            sub_idx += 1
            continue
        if tok in FLAGS_WITH_VAL:
            skip_next = True
            sub_idx += 1
            continue
        if tok.startswith("-"):
            sub_idx += 1
            continue
        subcmd = tok
        break

    if subcmd in NPM_MUTATING:
        pkgs = []
        skip_next = False
        for tok in tokens[sub_idx + 1:]:
            if skip_next:
                skip_next = False
                continue
            if tok in FLAGS_WITH_VAL:
                skip_next = True
                continue
            if tok.startswith("-"):
                continue
            pkgs.append(tok)
        blocked.append(" ".join(pkgs) if pkgs else f"npm {subcmd}")

for item in blocked:
    print(item)
'

set +e
MATCHED="$(printf '%s' "$PAYLOAD" | python3 -c "$PY_SCRIPT")"
PARSE_RC=$?
set -e

if [[ "$PARSE_RC" -ne 0 ]]; then
  echo "BLOCKED by Assay hook: failed to parse hook payload (exit ${PARSE_RC})." >&2
  exit 2
fi

if [[ -z "$MATCHED" ]]; then
  exit 0
fi

echo "BLOCKED by Assay pre-install hook: direct 'npm install' / 'npm add' / 'npm update' is disabled to prevent re-resolution TOCTOU and lifecycle-script execution." >&2
echo "Use Assay as the installer instead:" >&2
while IFS= read -r TARGET; do
  [[ -z "$TARGET" ]] && continue
  if [[ "$TARGET" == npm\ * || "$TARGET" == "unparseable shell command" ]]; then
    echo "  assay check --base <old-lock> --head <new-lock> --json && npm ci --ignore-scripts" >&2
  else
    echo "  assay add ${TARGET} --install --json" >&2
  fi
done <<< "$MATCHED"
echo "Do NOT bypass this hook or run 'assay approve'. Escalate any stop verdict to the human." >&2
exit 2
