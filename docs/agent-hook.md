# Using Assay with Coding Agents

Coding agents frequently run `npm install <pkg>` without a human inspecting what bytes are entering the project. Assay gives agents two safe, non-bypassable gates:

1. **MCP server (`assay mcp`)** — exposes `assay_explain`, `assay_check`, and `assay_add`. Agents can never approve stops; any `stop` verdict must be reported to a person.
2. **Pre-install shell hook** — intercepts `npm install` commands and runs `assay add` before any package enters `node_modules`.

---

## 1. MCP Server Setup

Add Assay to your agent's MCP configuration (Claude Code, Cursor, T3 Code, etc.):

```json
{
  "mcpServers": {
    "assay": {
      "command": "/path/to/assay",
      "args": ["mcp"],
      "env": {
        "ANTHROPIC_API_KEY": "${ANTHROPIC_API_KEY}"
      }
    }
  }
}
```

Tools exposed to the agent:
- `assay_explain`: balance sheet for one transition (`<name>@<from>..<to>`).
- `assay_check`: diff a base and head `package-lock.json` (lockfile v3).
- `assay_add`: resolves `<name>[@<version>]` in an isolated scratch directory with `npm install --package-lock-only --ignore-scripts`, checks every changed/added transitive package, and returns structured verdicts.

---

## 2. Pre-Install Shell Hook (Claude Code `PreToolUse`)

Save this script as `~/.assay/pre-install-hook.sh` (`chmod +x ~/.assay/pre-install-hook.sh`):

```bash
#!/usr/bin/env bash
set -euo pipefail

# Reads JSON tool input on stdin (e.g. {"tool_input":{"command":"npm install zod"}})
CMD="$(python3 -c 'import sys, json; print(json.load(sys.stdin).get("tool_input", {}).get("command", ""))')"

# Intercept `npm install <pkg>` / `npm i <pkg>` (skip bare `npm ci` / `npm install` with no args)
if [[ "$CMD" =~ ^npm[[:space:]]+(install|i|add)[[:space:]]+(.+) ]]; then
  ARGS="${BASH_REMATCH[2]}"
  # Extract first non-flag package token
  PKG=""
  for tok in $ARGS; do
    if [[ "$tok" != -* ]]; then
      PKG="$tok"
      break
    fi
  done
  if [[ -n "$PKG" ]]; then
    echo "Assay pre-install gate checking $PKG..." >&2
    if ! assay add "$PKG" --json >&2; then
      echo "BLOCKED by Assay: $PKG triggered an unapproved stop. Ask a human to review and approve." >&2
      exit 2
    fi
  fi
fi
```

Wire it in `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "~/.assay/pre-install-hook.sh"
          }
        ]
      }
    ]
  }
}
```
