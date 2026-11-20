# Assay

**A balance sheet for dependency changes.**

Every time you—or a coding agent—run `npm install` or merge a dependency update PR, you admit new code written by strangers. The most common serious npm attack is a **stolen registry token**: an attacker publishes malicious code to npm that never existed in the public GitHub repository.

Assay checks **where every changed byte came from**:
1. **Unchanged** from the version you already had (`Carried`) → ignored.
2. **Identical to the public Git repository** at that release's commit (`Source`, `SourceElsewhere`, `SourceNormalized`) → accounted for, verified by SHA-256.
3. **Leftover (`Unexplained`) bytes or broken publishing habits** (lost provenance, missing anchor, repo change, new `postinstall` script, new network/shell capabilities) → **stopped** or handed to a constrained AI reader (`--read`) that reads *only* the leftover diff.

> **Claims discipline:** Assay reports checkable facts and one of three verdicts (`explained`, `read`, `stop`). It **never** states or implies that a package is safe or free of malware. An explained release can still be harmful if harm was committed openly to public source.

---

## Real Output (Live npm Transitions)

```text
OK    chalk 6.0.0 -> 6.0.1
      anchor: 47fc05abd461 via GitHead @ https://github.com/chalk/chalk
      published: 54d ago (Settled)
      balance: 2 changed file(s) (9.8 KiB), 100.0% explained | 10 carried (45.0 KiB)
        - Source                2 file(s),   9.8 KiB
      subject: 7ac2cded06cdc20a | ledger: 164da6d8dec49315
```

On `zod 4.6.6 -> 4.6.7`, Assay accounted for **838 of 840 files (5.9 MiB)** automatically via carry-over + SLSA provenance monorepo matching, leaving only **866 bytes** (`versions.js` / `versions.cjs`) for the reader.

---

## Install (Single Binary)

```bash
./scripts/install.sh                  # builds & installs ~/.local/bin/assay
./scripts/install.sh --install-skill  # also installs the coding-agent skill
```

Requires Rust (`cargo`), `git`, and `curl`. Optional: set `ANTHROPIC_API_KEY` to enable the built-in `--read` AI diff reader (or configure any custom stdin/stdout reader in `assay.toml`).

---

## For Humans

See **[docs/HUMAN-GUIDE.md](docs/HUMAN-GUIDE.md)** for the complete handbook (stop rules `S1`–`S10`, approving stops, PR workflows, incident response, and offline replay).

```bash
# 1. Explain any npm update (no project needed)
assay explain chalk@6.0.0..6.0.1
assay explain vite@8.3.7..8.3.8 --read

# 2. Bootstrap Assay in a repository (creates assay.toml + GitHub Actions PR workflow)
assay init --github --mcp

# 3. Check a dependency before installing it (runs npm --package-lock-only --ignore-scripts in a temp dir)
assay add zod@4.6.7

# 4. Check a package-lock.json diff (lockfile v3) or a Git PR (objects only, never executes PR head)
assay check --base old/package-lock.json --head new/package-lock.json
assay pr --base origin/main --head HEAD

# 5. Approve a stop (bound to exact tarball bytes; auto-invalidates on S10 if new risks appear)
assay approve 7ac2cded06cdc20a --note "reviewed diff"

# 6. Incident response & offline verification
assay exposure flatmap-stream@0.1.1 --repo .
assay inventory --lock package-lock.json
assay explain chalk@6.0.0..6.0.1 --save-inputs && assay replay .assay/inputs/<ledger-id>
```

---

## For Coding Agents

See **[docs/AGENT-GUIDE.md](docs/AGENT-GUIDE.md)**, **[AGENTS.md](AGENTS.md)**, and the drop-in skill **[skills/assay/SKILL.md](skills/assay/SKILL.md)**.

1. **MCP Server (`assay mcp`):** Run `assay init --mcp` to print the ready-to-paste MCP server config exposing `assay_explain`, `assay_check`, and `assay_add`. Agents **cannot** approve stops.
2. **Pre-Install Shell Hook:** Point your agent's `PreToolUse` Bash hook at **[scripts/pre-install-hook.sh](scripts/pre-install-hook.sh)** to automatically gate every `npm install <pkg>` command.
3. **Stable Machine CLI:** Every command accepts `--json` and uses strict exit codes (`0` = pass, `1` = unapproved stop, `2` = error).

---

## Architecture & Docs

- **[SPEC.md](SPEC.md)** — Full technical specification (draft 0.2), threat model, and validation protocol.
- **[assay.toml.example](assay.toml.example)** — Documented policy & reader configuration template.
- **[docs/workflows/assay-pr.yml](docs/workflows/assay-pr.yml)** — Drop-in GitHub Actions PR gate running strictly from the protected base branch.
- **`crates/assay-core`** — Pure deterministic core (in-memory PAX/USTAR streaming tar parser, SHA-256/512/Git-blob hashing, lockfile v3 diff + routes, normalizations, habit breaks, reach scan, unified-diff packet builder, verbatim-excerpt validator, timeless ledgers + `as_of` decisions).
- **`crates/assay-cli`** — Single `assay` binary (hardened `curl`/`git` fetch, built-in & pluggable reader, content-addressed `.assay/` store, PR gate, exposure tracer, offline replay, `init`, and stdio MCP server).

## License

Apache-2.0
