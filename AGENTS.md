# AGENTS.md — Operating Instructions for Coding Agents

This repository builds **Assay**, a local dependency balance-sheet tool. Follow these rules both when working on Assay itself and when using Assay to gate npm dependencies in any project.

---

## Non-Negotiable Rules for Agents Using Assay

1. **Check before installing.** Before running `npm install <pkg>` or adding/updating any npm dependency, run `assay add <pkg> --json` (or call the `assay_add` MCP tool).
2. **Never approve stops.** You MUST NOT run `assay approve`, edit `.assay/approvals/`, weaken `assay.toml`, or bypass a stop verdict (`exit 1`). Only a human may approve a stop.
3. **Never claim a package is "safe."** Report Assay's exact verdict (`explained`, `read`, or `stop`) and facts. An `explained` verdict means every changed byte matched prior bytes or public Git source with no breaks or new reach—not that the package is guaranteed benign.
4. **Never inspect untrusted archives outside Assay.** Do not extract or execute downloaded npm tarballs to inspect them manually; Assay inspects tarballs strictly in memory.

---

## Command & Tool Reference for Agents

Prefer `--json` on CLI calls, or use `assay mcp` (`assay_explain`, `assay_check`, `assay_add`).

| Task | CLI command | MCP tool |
| --- | --- | --- |
| Check a package before installing it | `assay add <name>[@<ver>] --json` | `assay_add` |
| Check a `package-lock.json` diff (v3) | `assay check --base <old> --head <new> --json` | `assay_check` |
| Inspect one registry version transition | `assay explain <name>@<from>..<to> --json` | `assay_explain` |
| Trace historical exposure in Git + store | `assay exposure <name>@<ver> --json` | *(CLI only)* |
| Inventory standing lockfile debt | `assay inventory --lock package-lock.json --json` | *(CLI only)* |

Pass `--read` when `ANTHROPIC_API_KEY` (or `reader.command` in `assay.toml`) is configured and you want unexplained diffs read automatically.

### Exit Codes
- `0`: Every transition is `explained`, `read`, or `stop` with an existing valid human approval. Safe to proceed with install/merge per user instructions.
- `1`: At least one unapproved `stop` (or protected policy/workflow tamper). **Stop immediately and escalate to the human.**
- `2`: Operational failure (bad input, invalid config, registry/git fetch error). Report the exact stderr error; do not silently proceed with `npm install`.

---

## Escalation Template (When Exit Code Is 1)

When Assay stops a package, report these exact fields from the JSON output to the user and wait for their decision:

- **Package & version:** `<name> <ref_version> -> <new_version>`
- **Route:** `root -> ... -> <name>` (or `added directly in package.json`)
- **Stop rules & reasons:** every item in `decision.stop_rules` and `decision.stop_reasons`
- **Breaks / new reach / unexplained bytes:** `ledger.breaks`, `ledger.new_reach`, `ledger.unexplained_code_bytes`
- **Reading summary (if run):** `reading.summary` and any `reading.findings`
- **Human approval command:** `assay approve <first 16 hex chars of ledger.subject>`

---

## Working on the Assay Codebase

- Workspace layout:
  - `crates/assay-core`: pure deterministic library (no network, no subprocesses, no implicit clock).
  - `crates/assay-cli`: single `assay` binary (hardened `curl`/`git` fetch, built-in/external reader, store, PR gate, exposure, replay, MCP server).
- Build and test:
  ```bash
  cargo test
  cargo build --release
  ```
- Maintain strict determinism: never put wall-clock timestamps or relative ages inside `ArtifactProfile` or `TransitionLedger` (relative age belongs only in `Decision` evaluated at explicit `as_of`).
- Maintain reader containment: findings must cite real line ranges with verbatim `excerpt` verified by `assay-core`; reader output can only raise concern and can never lift a deterministic stop.
