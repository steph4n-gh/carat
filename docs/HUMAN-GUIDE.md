# Assay Human Guide

Assay gives you a **balance sheet** for npm dependency changes: for every package an update touches, it accounts for every changed byte against what you already had and what is in the public Git repository, checks whether the release broke the package's normal publishing habits, and only asks you (or the AI reader) to look at what is left over.

---

## 1. Install

Requires Rust (`cargo`), `git`, and `curl`.

```bash
git clone <repo-url> assay
cd assay
./scripts/install.sh
```

This builds the single optimized binary (~3.3 MB) and installs it to `~/.local/bin/assay`. Verify:

```bash
assay --version
```

Optional: if you want Assay's built-in reader to inspect unexplained built diffs (like `dist/*.js`), export your Anthropic key:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

---

## 2. Five-Minute Tour

### Inspect any npm update (no project needed)
```bash
assay explain chalk@6.0.0..6.0.1
assay explain zod@4.6.6..4.6.7
assay explain vite@8.3.7..8.3.8 --read
```

### Bootstrap Assay in your project
```bash
cd /path/to/your-js-project
assay init --github --mcp
```
This creates:
- `assay.toml` (policy defaults)
- `.github/workflows/assay-pr.yml` (PR gate running strictly from your protected base branch)
- Prints the exact MCP config JSON (with your installed binary path) for coding agents.

### Check before installing a new dependency
```bash
assay add zod@4.6.7
```
Assay resolves the full transitive tree inside an isolated temp directory using `npm install --package-lock-only --ignore-scripts`—nothing runs and nothing in your repo changes until every transition passes. Pass `--install` to automatically install when everything passes.

### Check a `package-lock.json` diff (lockfile v3)
```bash
assay check --base old/package-lock.json --head new/package-lock.json
```

---

## 3. Reading a Balance Sheet

Every changed package gets one of three verdicts:

| Badge | Verdict | What it means | Action |
| --- | --- | --- | --- |
| `OK` | `explained` | Every changed byte matched prior bytes or public Git source (with declared normalizations only), no breaks, no flags, no new capabilities | None |
| `READ` | `read` | Some unexplained bytes, flags, or ordinary new reach existed; the reader verified them against the stated change and found no concern | None (unless `read_pass = "require_human"`) |
| `STOP` | `stop` | A hard stop rule fired | Review and either reject or run `assay approve <subject>` |
| `APPR` | `stop` (approved) | Previously stopped, and a valid human approval covers these exact bytes and stop reasons | None |

### Origin Classes (where each file's bytes came from)
- **`Carried`**: byte-for-byte identical to the previous version you already had (even if moved).
- **`Source`**: SHA-256 identical to the file at the corresponding path in the anchored Git commit.
- **`SourceElsewhere`**: SHA-256 identical to a file elsewhere in the anchored Git commit (e.g. a monorepo root `LICENSE`).
- **`SourceNormalized`**: identical after one of two explicit normalizations: `CRLF → LF`, or benign `package.json` publish changes (version placeholder replaced, `workspace:`/`catalog:` resolved, `devDependencies` stripped, `publishConfig` applied). Any change to lifecycle scripts, runtime dependencies, `bin`, `main`, `exports`, etc. stays **`Unexplained`**.
- **`Unexplained`**: everything else (typically compiled `dist/` bundles—or injected code). Non-executable `.d.ts`, `.map`, and docs are reported separately so they don't bloat the reading budget.

---

## 4. What the Stop Rules (`S1`–`S10`) Mean

| Rule | Why it stopped |
| --- | --- |
| `S1` | Missing SHA-512 integrity in lockfile, or downloaded tarball bytes did not match it |
| `S2` | Lockfile alarm: same version with changed bytes, registry host changed, or source switched to git/URL/file |
| `S3` | Suspicious archive structure: path traversal (`..`), symlinks/hardlinks, duplicate/case-colliding paths, special entries, or size/entry limit exceeded |
| `S4` | A hard publishing-habit break fired: `anchor_lost`, `provenance_lost`, `repo_changed`, `source_match_drop`, `install_script_new`, `install_script_changed`, `native_or_binary_new`, `registry_manifest_differs`, `known_malicious` (OSV `MAL-*`), or `tag_moved` |
| `S5` | Brand-new direct dependency added to `package.json` (`new_direct_dependency = "confirm"` default) |
| `S6` | Unexplained bytes with no Git source anchor (relaxed only for releases older than `settled_age`, default 30d) |
| `S7` | New high-risk capability (`proc`, `dyn_code`, `native`, `install_exec`, `encoded_blob`, `shell_literal`, `minified_new`) OR any new capability (`net`, `fs`, `env`, etc.) located inside unexplained bytes |
| `S8` | A reading was required and wasn't run (`--read` omitted), found a concern, was invalid, unread (over hard cap), refused, or unavailable |
| `S9` | Release is fresh (`< min_age`, default 24h) and not 100% deterministically `explained` |
| `S10` | An approval existed for these bytes, but **new stop reasons** appeared since it was approved |

---

## 5. Approving a Stop

Approvals are bound to the **subject** (the SHA-256 of `(ecosystem, name, old_sha512, new_sha512)`) and the exact set of stop rules you saw:

```bash
assay approve 7ac2cded06cdc20a --note "Reviewed diff, intentional direct dep"
```

- **Survives rebases and tool upgrades:** same old/new tarball bytes = same subject.
- **Automatically goes stale (`S10`)** if a new stop reason appears later (for example, a new `MAL-*` advisory or a stricter rule).
- **In GitHub PRs:** a maintainer with write access (who is *not* the PR author) posts a standalone single-line comment with the exact `ledger` ID prefix printed in the PR report:
  ```
  assay approve 7ac2cded06cdc20a
  ```
  Because PR comment approvals bind to the exact `ledger_id`, any change to lockfile integrity, anchors, breaks, or advisories invalidates the comment automatically. Known-malicious advisories (`MAL-*`) and reader `Concern` findings cannot be approved by PR comment alone.

---

## 6. Incident Response & Offline Audits

### "Were we exposed to package X?"
Searches both your Git history of `package-lock.json` (without checking out old commits) and your `.assay/ledgers/` store:

```bash
assay exposure flatmap-stream@0.1.1 --repo .
assay exposure --sha512 44e0... --repo .
```

### Offline deterministic replay
Save an input bundle during a check and recompute it later with zero network access to verify byte-identical results:

```bash
assay explain chalk@6.0.0..6.0.1 --save-inputs
assay replay .assay/inputs/<ledger-id>
```

### Standing lockfile inventory (never blocks)
```bash
assay inventory --lock package-lock.json
```
