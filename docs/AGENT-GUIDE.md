# Agent Guide

Carat is designed to run natively alongside coding agents (Claude Code, Codex, Cursor, T3 Code, OpenCode, Windsurf) so agents verify npm packages before installing them while humans keep sole control over approvals.

Combine three integration layers:

1. **MCP Server (`carat mcp`):** Native tool calls (`carat_explain`, `carat_check`, `carat_add`) with no approval tool exposed.
2. **Pre-Install Shell Guardrail (`scripts/pre-install-hook.sh`):** Local `PreToolUse` Bash hook that blocks direct `npm install`, `npm add`, and `npm update` commands and redirects the agent to `carat add <pkg> --install --json`. (Hard enforcement belongs in CI `carat pr` + `npm ci --ignore-scripts`.)
3. **Agent Skill and Instructions (`skills/carat/SKILL.md` and `AGENTS.md`):** Teaches the agent how to invoke Carat, read JSON verdicts, and escalate stops cleanly.

---

## 1. Install Carat and the agent skill

```bash
./scripts/install.sh --install-skill
```

This installs:

- `~/.local/bin/carat`
- `~/.claude/skills/carat/SKILL.md`
- `~/.codex/skills/carat/SKILL.md`

---

## 2. Configure the MCP server

Print the ready-to-paste MCP server block with your resolved binary path:

```bash
carat init --mcp
```

Example configuration:

```json
{
  "mcpServers": {
    "carat": {
      "command": "/Users/you/.local/bin/carat",
      "args": ["mcp"],
      "env": {
        "ANTHROPIC_API_KEY": "${ANTHROPIC_API_KEY}"
      }
    }
  }
}
```

### Exposed MCP tools

| Tool | Required args | Optional args | Purpose |
| --- | --- | --- | --- |
| `carat_explain` | `spec` (`<name>@<from>..<to>`) | `read` (`bool`) | Inspect one npm version jump from the registry |
| `carat_check` | `base_lock`, `head_lock` | `base_pkg`, `head_pkg`, `read` | Check a `package-lock.json` v3 diff |
| `carat_add` | `package` | `dev`, `project_dir`, `read`, `install` | Resolve once in temp, check every transition, and install exact lockfile via `npm ci --ignore-scripts` when `install: true` and `passed: true` |

`carat mcp` deliberately omits any approval or config-mutation tool. Unknown tool names return a JSON-RPC error.

---

## 3. Wire the pre-install Bash hook

In Claude Code (`~/.claude/settings.json` or `.claude/settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "/absolute/path/to/carat/scripts/pre-install-hook.sh"
          }
        ]
      }
    ]
  }
}
```

In Antigravity (`~/.gemini/config/hooks.json` or `.agents/hooks.json`):

```json
{
  "carat-pre-install": {
    "PreToolUse": [
      {
        "matcher": "run_command",
        "hooks": [
          {
            "type": "command",
            "command": "/absolute/path/to/carat/scripts/pre-install-hook.sh",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

How `scripts/pre-install-hook.sh` behaves:

- Compatible with stock macOS `/bin/bash` 3.2 and bash 5+, and auto-detects both Claude Code (`tool_input.command` + `exit 2`) and Antigravity (`toolCall.args.CommandLine` + JSON `{"decision":"allow"|"deny"}` on stdout).
- Uses POSIX `shlex` tokenization (preserving quoted semicolons and heredocs), reads hook JSON strictly from stdin, and fails closed if an unparseable command references `npm`.
- Intercepts direct `npm install`, `npm i`, `npm add`, `npm update`, and common npm install aliases—including leading `env`, `command`, `nohup`, `sudo`, environment assignments, and flags before the subcommand.
- Always blocks mutating `npm` installs and tells the agent to run `carat add [-D] <pkg> --install --json` or `carat check ... && npm ci --ignore-scripts` instead.
- Allows `npm ci`, `npm test`, `npm run ...`, and non-npm commands.

---

## 4. Machine JSON contract

All CLI commands support `--json` with canonical, deterministic JSON output.

### `carat add <pkg> --install --json` / `carat check ... --json`

```json
{
  "installed": false,
  "passed": false,
  "tampered_protected_files": [],
  "transition_errors": [],
  "transitions": [
    {
      "approved_by": null,
      "decision": {
        "age_band": "fresh",
        "as_of": "2026-11-20T05:00:00Z",
        "ledger_id": "f0ea07e387524fb6...",
        "reading_outcome": "not_run",
        "reading_required": true,
        "stop_facts": ["break:anchor_lost", "reading:notrun"],
        "stop_reasons": ["..."],
        "stop_rules": ["S4", "S8"],
        "subject": "4dbf5392e222bdab...",
        "verdict": "stop"
      },
      "ledger": {
        "breaks": ["anchor_lost"],
        "name": "ms",
        "new": { "version": "2.1.3", "sha512": "..." },
        "new_reach": [],
        "reference": { "version": "2.1.2", "sha512": "..." },
        "subject": "4dbf5392e222bdab...",
        "unexplained_code_bytes": 3741
      },
      "reading": null,
      "residual_diffs": [],
      "route": [
        { "from": "root", "kind": "prod", "to": "ms" }
      ]
    }
  ]
}
```

### Decision loop for agents

1. Run `carat add <pkg> --install --json` (or call MCP `carat_add` with `install: true`).
2. If `passed == true` (exit `0`), Carat has already written the checked lockfile and run `npm ci --ignore-scripts`. Report the exact Carat verdict (`explained` or `read`) and never claim the package is "safe."
3. If `passed == false` (exit `1`), stop immediately. Report every transition where `decision.verdict == "stop"` and `approved_by == null`, include `route`, `decision.stop_reasons`, `ledger.breaks`, `ledger.new_reach`, `ledger.unexplained_code_bytes`, any `reading.findings`, and the human approval command `carat approve <decision.ledger_id[..16]>`.
4. If exit `2` (or MCP `isError: true`), report the exact operational error and stop. Do not fall back to `npm install`.
