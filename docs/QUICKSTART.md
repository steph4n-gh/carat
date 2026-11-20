# Quickstart Tutorial

In this tutorial, you install `carat`, inspect a real npm release transition, add a package with zero re-resolution TOCTOU, and bootstrap a Node.js repository for CI and coding agents.

## Prerequisites

- Rust toolchain (`cargo`)
- `git`, `curl`, and `npm` on your `PATH`

## 1. Install the `carat` binary

Clone the repository and run the installer script:

```bash
git clone https://github.com/steph4n-gh/carat.git
cd carat
./scripts/install.sh --install-skill
```

You should see output ending with:

```text
Installed: ~/.local/bin/carat (carat 0.1.0)
Installed agent skill: ~/.claude/skills/carat/SKILL.md
Installed agent skill: ~/.codex/skills/carat/SKILL.md
```

Verify `carat` is on your `PATH`:

```bash
carat --version
```

If `carat` is not found, add `~/.local/bin` to your shell `PATH`.

## 2. Inspect a real npm release transition

Run `carat explain` on an existing package version jump:

```bash
carat explain chalk@5.4.0..5.4.1
```

Carat downloads both tarballs into memory, resolves the Git tag for `chalk@5.4.1`, verifies every changed file against Git blobs by SHA-256, checks release history and OSV advisories, and prints the balance sheet.

When every changed file matches public Git source with no breaks or new reach, `carat explain` exits with code `0` and prints `EXPLAINED`.

Now try a release with unexplained differences:

```bash
carat explain ms@2.1.2..2.1.3
```

Because `ms@2.1.3` moved from `zeit/ms` to `vercel/ms` and has no source anchor, Carat prints `STOP`, displays the exact inline diff for the unexplained files, lists the stop reasons, prints `approve with: carat approve <16-hex-ledger-id>`, and exits with code `1`.

## 3. Add and install a package safely

Create a temporary project directory and install a package through Carat:

```bash
mkdir -p /tmp/carat-demo && cd /tmp/carat-demo
carat add chalk@5.4.1 --install
```

You should see:

```text
Carat: 0 of 1 changed package(s) need a person

ok    1 package(s) fully explained
Installed exact checked lockfile via `npm ci --ignore-scripts`.
```

Carat resolved `package-lock.json` once in an isolated `0700` temp directory with lifecycle scripts disabled, verified the changed bytes, wrote that exact `package.json` and `package-lock.json`, and installed from it with `npm ci --ignore-scripts`.

## 4. Bootstrap your own repository

Inside any Node.js repository, run:

```bash
carat init --github --mcp
```

This creates:

- `carat.toml` — local policy configuration.
- `.github/workflows/carat-pr.yml` — the read-only GitHub Actions PR gate.
- An MCP JSON snippet printed to stdout for Claude Code, Codex, Cursor, or T3 Code.

Add `.carat/` to your `.gitignore` so local cache and store files stay untracked.

## Next steps

- Daily developer workflows and approvals: [Human Guide](HUMAN-GUIDE.md)
- Wiring coding agents via MCP and hooks: [Agent Guide](AGENT-GUIDE.md)
- Enabling the GitHub PR gate: [CI Setup Guide](CI-SETUP.md)
- Full command and policy lookup: [CLI Reference](CLI-REFERENCE.md)
