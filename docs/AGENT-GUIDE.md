# Assay Agent Guide

Assay is built to run natively alongside coding agents (Claude Code, Codex, Cursor, T3 Code, Windsurf, OpenCode) so agents can check npm packages before installing them—while keeping **humans** strictly in charge of approvals.

There are three ways to wire Assay into an agent, and you can combine them:

1. **MCP Server (`assay mcp`)** — native tool calls (`assay_explain`, `assay_check`, `assay_add`).
2. **Pre-Install Shell Hook (`scripts/pre-install-hook.sh`)** — hard enforcement that intercepts `npm install <pkg>` even if the agent forgets to call MCP.
3. **Agent Skill (`skills/assay/SKILL.md` + `AGENTS.md`)** — teaches the agent when to run Assay, how to read JSON verdicts, and how to escalate stops cleanly.

---

## 1. Quick Setup (All Three in One Minute)

First install the `assay` binary (and optionally install the skill into `~/.claude/skills/assay` and `~/.codex/skills/assay`):

```bash
./scripts/install.sh --install-skill
```

Print the ready-to-paste MCP configuration with your exact installed binary path:

```bash
assay init --mcp
```

---

## 2. MCP Server (`assay mcp`)

Add the printed block to your agent's MCP config (e.g. `.mcp.json`, `~/.claude.json`, Cursor MCP settings, or Codex MCP config):

```json
{
  "mcpServers": {
    "assay": {
      "command": "/Users/you/.local/bin/assay",
      "args": ["mcp"],
      "env": {
        "ANTHROPIC_API_KEY": "${ANTHROPIC_API_KEY}"
      }
    }
  }
}
```

### Exposed MCP Tools
| Tool | Inputs | What it does |
| --- | --- | --- |
| `assay_add` | `package` (required), `project_dir`, `read` | Resolves `<package>` in an isolated temp dir (`npm install --package-lock-only --ignore-scripts`), runs Assay on every new/changed transitive package, returns structured verdicts |
| `assay_check` | `base_lock`, `head_lock` (required), `base_pkg`, `head_pkg`, `read` | Diffs two `package-lock.json` v3 files and checks every transition |
| `assay_explain` | `spec` (`<name>@<from>..<to>`), `read`, `no_osv` | Explains a single npm version jump directly from the registry |

**Security boundary:** `assay mcp` **never** exposes an approval tool. If `passed` is `false`, the agent must stop and present the stop reasons and approval subject to the user.

---

## 3. Pre-Install Shell Hook (`PreToolUse`)

MCP gives the agent the ability to check packages; a `PreToolUse` hook **enforces** it on every shell `npm install` command.

Copy or reference `scripts/pre-install-hook.sh` (already executable in this repo):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "/path/to/assay/scripts/pre-install-hook.sh"
          }
        ]
      }
    ]
  }
}
```

Environment knobs supported by `scripts/pre-install-hook.sh`:
- `ASSAY_BIN`: path to `assay` binary (defaults to `assay` on `$PATH`, falling back to `~/.local/bin/assay`).
- `ASSAY_READ=1`: automatically passes `--read` when `ANTHROPIC_API_KEY` is set.
- `ASSAY_STORE_DIR`: override `.assay` store location.

What the hook does:
- Intercepts `npm install <pkg>`, `npm i <pkg>`, and `npm add <pkg>` (supports flags like `-D`, `--save-dev`, `-E`, and multiple package arguments).
- Allows bare `npm ci` and bare `npm install` (with no package args, since lockfile changes are gated by `assay check` / `assay pr`).
- Runs `assay add <pkg>` for each package argument; if any package exits non-zero, blocks the Bash tool call (`exit 2`) and prints the exact stop reasons and `assay approve <subject>` line so the agent can report them to the user.

---

## 4. Machine JSON Contract

All CLI commands support `--json` with deterministic, canonical JSON:

### `assay add <pkg> --json` / `assay check ... --json`
```json
{
  "passed": false,
  "tampered_protected_files": [],
  "transitions": [
    {
      "approved_by": null,
      "decision": {
        "age_band": "settled",
        "as_of": "2026-11-19T23:30:00Z",
        "ledger_id": "...",
        "policy_version": 1,
        "published_age_hours": 1296,
        "reading_outcome": "not_required",
        "reading_required": false,
        "stop_reasons": ["S5: new direct dependency requires human confirmation"],
        "stop_rules": ["S5"],
        "subject": "7ac2cded06cdc20a...",
        "verdict": "stop"
      },
      "ledger": { "...": "full timeless balance sheet" },
      "ledger_id": "...",
      "reading": null,
      "route": [{ "from": "root", "kind": "prod", "to": "chalk" }]
    }
  ]
}
```

### Agent Decision Loop
1. If `passed == true` (exit `0`): proceed.
2. If `passed == false` (exit `1`): **stop**. List every transition where `decision.verdict == "stop"` and `approved_by == null`, include `decision.stop_reasons` and `assay approve <subject[..16]>`, and ask the user whether to approve or abort.
3. On exit `2`: report stderr verbatim and stop.

---

## 5. Custom / Local Reader Contract

If you want to use a local model or a different provider instead of the built-in Anthropic reader, configure `reader.command` in `assay.toml`:

```toml
[reader]
command = "/path/to/my-reader"
model = "my-local-model"
```

Assay pipes a canonical `ReadingPacket` JSON to stdin and expects JSON on stdout matching [SPEC.md Appendix B](../SPEC.md):
- `units`: `[{ "unit_id": "...", "fits_stated_change": "yes" | "no" | "cannot_tell" }]`
- `findings`: `[{ "unit_id": "...", "start_line": 1, "end_line": 3, "excerpt": "verbatim text", "category": "...", "statement": "<=300 chars", "confidence": "low"|"medium"|"high" }]`
- `summary`: `"<=600 chars"`

The deterministic core verifies every finding's line range and verbatim excerpt before accepting it.
