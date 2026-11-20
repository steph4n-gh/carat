---
name: assay
description: Gate npm dependency additions and updates using Assay's byte-level balance sheet (`assay add`, `assay check`, `assay explain`, or `assay mcp`). Activate before running `npm install <pkg>`, updating `package-lock.json`, or auditing an npm dependency change.
---

# Assay Dependency Gate Skill

Use Assay to verify where every changed byte of an npm dependency came from before installing or merging it.

## When to Run

Run Assay **before**:
- Running `npm install <pkg>` / `npm i <pkg>` / `npm add <pkg>` (use `assay add <pkg> --json`, or MCP tool `assay_add`)
- Updating or reviewing a `package-lock.json` diff (use `assay check --base <old> --head <new> --json`, or MCP tool `assay_check`)
- Investigating a specific npm release jump (use `assay explain <name>@<from>..<to> --json`, or MCP tool `assay_explain`)

## Procedure

1. **Prefer MCP if connected**, otherwise invoke the `assay` CLI with `--json`:
   ```bash
   assay add <package> --json
   ```
   Add `--read` if `ANTHROPIC_API_KEY` (or `reader.command` in `assay.toml`) is available so unexplained built diffs are automatically read.
2. **Check the exit code and JSON `passed` field:**
   - **Exit `0` (`passed: true`):** Every changed package is `explained`, `read`, or already approved by a human. You may proceed with the requested install (`npm install --ignore-scripts <package>` unless lifecycle scripts were explicitly approved).
   - **Exit `1` (`passed: false`):** **STOP.** Do not run `npm install`. Do not run `assay approve`. Do not edit `assay.toml` to loosen policy.
   - **Exit `2`:** Operational error (network/git/config). Report the error to the user; do not install blindly.
3. **On a stop (exit `1`), report clearly to the human:**
   - Package, version transition, and dependency route
   - Every `stop_rules` / `stop_reasons` entry (e.g. `S4` break, `S5` new direct dependency, `S6` unexplained without anchor, `S7` new high/unexplained reach, `S9` fresh release)
   - Unexplained executable byte count and any reading findings/summary
   - The exact approval command for the human: `assay approve <decision.ledger_id[..16]>`

## Strict Rules

- **Never run `assay approve`.** Approvals are strictly human actions bound to exact tarball bytes.
- **Never claim a package is "safe."** State the verdict (`explained`, `read`, `stop`) and the factual basis.
- **Never bypass `assay add`** by editing `package.json` and running `npm install` directly after a stop.
