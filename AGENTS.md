# AGENTS.md — Operating Instructions for Coding Agents

This repository builds **Carat**, a local dependency balance-sheet tool for npm. Follow these rules both when working on Carat itself and when using Carat to gate npm dependencies in any project.

---

## Non-Negotiable Rules for Agents Using Carat

1. **Use Carat as the installer.** Run `carat add <pkg> --install --json` (or call MCP `carat_add` with `install: true`) instead of `npm install <pkg>`. Carat resolves once in an isolated temp directory, checks every changed byte in memory, and writes that exact checked lockfile before running `npm ci --ignore-scripts`.
2. **Never approve stops.** You MUST NOT run `carat approve`, edit `.carat/approvals/`, weaken `carat.toml`, or bypass a stop verdict (`exit 1`). Only a human may approve a stop.
3. **Never claim a package is "safe."** Report Carat's exact verdict (`explained`, `read`, or `stop`) and facts. An `explained` verdict means every changed byte matched prior bytes or public Git source with no breaks or new reach, not that the package is guaranteed benign.
4. **Never inspect untrusted archives outside Carat.** Do not extract or execute downloaded npm tarballs to inspect them manually; Carat inspects tarballs strictly in memory.

---

## Command and Tool Reference for Agents

Prefer `--json` on CLI calls, or use `carat mcp` (`carat_explain`, `carat_check`, `carat_add`).

| Task | CLI command | MCP tool |
| --- | --- | --- |
| Check and install a package | `carat add <name>[@<ver>] --install --json` | `carat_add` |
| Check a `package-lock.json` diff (v3) | `carat check --base <old> --head <new> --json` | `carat_check` |
| Inspect one registry version jump | `carat explain <name>@<from>..<to> --json` | `carat_explain` |
| Trace historical exposure in Git and store | `carat exposure <name>@<ver> --json` | *(CLI only)* |
| Inventory standing lockfile debt | `carat inventory --lock package-lock.json --json` | *(CLI only)* |

Pass `--read` when `ANTHROPIC_API_KEY` (or an explicitly configured `reader.command`) is available and you want unexplained diffs read automatically.

### Exit Codes

- `0`: Every transition is `explained`, `read`, or `stop` with an existing valid human approval.
- `1`: At least one unapproved `stop`, transition error, or protected file tamper. **Stop immediately and escalate to the human.**
- `2`: Operational failure (bad input, invalid config, registry or Git fetch error). Report the exact stderr error; do not fall back to `npm install`.

---

## Escalation Template (When Exit Code Is 1)

When Carat stops a package, report these exact fields from the JSON output to the user and wait for their decision:

- **Package and version:** `<name> <ref_version> -> <new_version>`
- **Route:** `root -> ... -> <name>` (or `added directly in package.json`)
- **Stop rules and reasons:** every item in `decision.stop_rules` and `decision.stop_reasons`
- **Breaks, new reach, and unexplained bytes:** `ledger.breaks`, `ledger.new_reach`, `ledger.unexplained_code_bytes`
- **Reading summary (if run):** `reading.summary` and any `reading.findings`
- **Human approval command:** `carat approve <first 16 hex chars of decision.ledger_id>`

---

## Working on the Carat Codebase

- Workspace layout:
  - `crates/carat-core`: pure deterministic library (no network, no subprocesses, no implicit clock).
  - `crates/carat-cli`: single `carat` binary (hardened `curl` and `git` fetch, built-in and external reader, store, PR gate, exposure, replay, MCP server).
- Build and test:
  ```bash
  cargo test
  cargo build --release
  ```
- Maintain strict determinism: never put wall-clock timestamps or relative ages inside `ArtifactProfile` or `TransitionLedger` (relative age belongs only in `Decision` evaluated at explicit `as_of`).
- Maintain reader containment: findings must cite real line ranges with verbatim `excerpt` verified by `carat-core`; reader output can only raise concern and can never lift a deterministic stop.
