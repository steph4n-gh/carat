---
name: carat
description: Use Carat to inspect and gate npm dependency installations, package-lock.json diffs, and supply-chain exposure. Always use before running npm install or approving lockfile changes.
---

# Carat — Dependency Balance Sheet Skill

Use **Carat** before installing any npm package or accepting any `package-lock.json` change.

## Workflow

1. **Installing or adding a package:**
   - Run `carat add <pkg> --install --json` (or call MCP tool `carat_add` with `{"package": "<pkg>", "install": true}`).
   - Pass `--read` (or `"read": true`) when `ANTHROPIC_API_KEY` is set.
   - Check the exit code (or `"passed"` boolean in MCP output):
     - **Exit `0` (`passed: true`):** Every transition is `explained`, `read`, or already approved by a human, and Carat installed that exact checked lockfile via `npm ci --ignore-scripts`.
     - **Exit `1` (`passed: false`):** **STOP.** Do not run `npm install`. Do not run `carat approve`. Do not edit `carat.toml` to loosen policy.
     - **Exit `2`:** Operational error. Report stderr and stop.

2. **Escalating a stop (`exit 1`) to the human:**
   Present a concise summary containing:
   - Package, version change, and dependency route (`route`)
   - Every `stop_reasons` entry, `breaks`, `new_reach`, and `unexplained_code_bytes`
   - Any inline `residual_diffs` and reader `findings`
   - The exact approval command for the human: `carat approve <decision.ledger_id[..16]>`

3. **Reviewing lockfile diffs or investigating incidents:**
   - Lockfile diff: `carat check --base <old> --head <new> --json`
   - Single release jump: `carat explain <name>@<from>..<to> --json`
   - Exposure history: `carat exposure <name>@<ver> --json`

## Hard Rules

- **Never run `carat approve`.** Approvals are strictly human actions bound to exact tarball bytes and concrete stop facts.
- **Never claim a package is "safe."** State the exact Carat verdict (`explained`, `read`, or `stop`) and the reported facts.
- **Never unpack untrusted tarballs to inspect them.** Carat inspects archives strictly in memory.
