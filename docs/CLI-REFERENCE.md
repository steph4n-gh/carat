# CLI and Configuration Reference

## Global flags

```text
carat [--json] [--store-dir <PATH>] [--config <PATH>] <COMMAND>
```

| Flag | Default | Description |
| --- | --- | --- |
| `--json` | `false` | Emit canonical JSON to stdout instead of Markdown/text |
| `--store-dir <PATH>` | `.carat` | Local content-addressed store and fetch cache directory |
| `--config <PATH>` | Auto-discovered `carat.toml` or `.carat.toml` | Explicit policy/reader configuration path |
| `-V`, `--version` | — | Print `carat` version |
| `-h`, `--help` | — | Print help |

---

## Exit codes

| Exit code | Meaning |
| --- | --- |
| `0` | Passed. Every transition is `explained`, `read`, or a `stop` with an existing valid human approval. |
| `1` | Blocked. At least one unapproved `stop`, transition error, or protected file tamper occurred. |
| `2` | Operational error. Invalid arguments, invalid config, forbidden specifier, symlink refusal, or network/Git failure. |

---

## Commands

### `carat explain <SPEC>`

Inspect a single npm registry transition (`<name>@<from>..<to>`, including scoped names like `@scope/pkg@1.0.0..1.0.1`).

| Flag | Description |
| --- | --- |
| `--read` | Run the configured reader when unexplained code diffs or flags remain |
| `--as-of <RFC3339>` | Evaluate publish age at an explicit timestamp (for historical backtesting) |
| `--no-osv` | Skip OSV advisory lookup (for zero-day backtesting) |
| `--save-inputs` | Save a self-contained offline replay bundle under `.carat/inputs/<ledger_id>` |

### `carat check`

Check all changed packages between two `package-lock.json` v3 files.

| Flag | Required | Description |
| --- | --- | --- |
| `--base <PATH>` | Yes | Base `package-lock.json` (v3) |
| `--head <PATH>` | Yes | Head `package-lock.json` (v3) |
| `--base-pkg <PATH>` | No | Base `package.json` |
| `--head-pkg <PATH>` | No | Head `package.json` (enables manifest-lockfile desync check) |
| `--read` | No | Run the configured reader when required |
| `--as-of <RFC3339>` | No | Explicit evaluation timestamp |

### `carat pr`

Check a pull request reading revisions strictly from Git object storage (never checks out PR head).

| Flag | Default | Description |
| --- | --- | --- |
| `--base <REV>` | *(required)* | Protected base commit or ref (source of `carat.toml`) |
| `--head <REV>` | *(required)* | PR head commit or ref |
| `--repo <PATH>` | `.` | Git repository directory |
| `--lockfile <REL>` | `package-lock.json` | Lockfile path inside the repo |
| `--manifest <REL>` | `package.json` | Manifest path inside the repo |
| `--comments-json <PATH>` | None | JSON array of `{author, body, has_write_access, created_at}` |
| `--pr-author <USER>` | None | PR author login (prevented from self-approving) |
| `--markdown-out <PATH>` | None | Write Markdown summary alongside `--json` in a single evaluation |
| `--read` | `false` | Run the configured reader when required |

### `carat add [OPTIONS] <PACKAGES>...`

Resolve once in an isolated `0700` temp directory, check every changed package (in parallel across up to 8 workers), and optionally write that exact checked lockfile and install with `npm ci --ignore-scripts`.

| Flag | Default | Description |
| --- | --- | --- |
| `<PACKAGES>...` | *(required)* | One or more registry package specs (`<name>` or `<name>@<ver/range>` without spaces, `||`, leading `-`, URLs, or `file:`/`git+`/`npm:` schemes) |
| `-D`, `--dev` | `false` | Save to `devDependencies` (`npm install --save-dev`) |
| `--project-dir <PATH>` | `.` | Project directory containing `package.json` and `package-lock.json` |
| `--read` | `false` | Run the configured reader when required |
| `--install` | `false` | Write the exact checked `package.json` and `package-lock.json` and run `npm ci --ignore-scripts` if `passed == true` |

### `carat approve <IDS>...`

Record one or more human approvals in `.carat/approvals/<subject>.json` bound to each transition's concrete `stop_facts`. All IDs are validated upfront before any approval file is written.

| Flag | Default | Description |
| --- | --- | --- |
| `<IDS>...` | *(required)* | One or more unique 8–64 hex prefixes of `decision.ledger_id` or `ledger.subject` |
| `--by <NAME>` | `$USER` | Approver identifier |
| `--note <TEXT>` | None | Approval rationale |
| `--non-interactive` | `false` | Allow execution without an interactive TTY (human scripts only) |

### `carat exposure [PACKAGE]`

Search Git history of `package-lock.json` and `.carat/ledgers/` for historical admission of a package or tarball SHA-512.

| Flag | Default | Description |
| --- | --- | --- |
| `[PACKAGE]` | None | `<name>` or `<name>@<version>` |
| `--sha512 <HEX_OR_SRI>` | None | Exact SHA-512 hex prefix or `sha512-<base64>` SRI |
| `--repo <PATH>` | `.` | Git repository directory |
| `--lockfile <REL>` | `package-lock.json` | Lockfile path to trace in Git history |

### `carat inventory`

Summarize standing lockfile debt (missing SHA-512 integrity hashes and non-registry sources). Always exits `0` on valid lockfiles.

| Flag | Default | Description |
| --- | --- | --- |
| `--lock <PATH>` | `package-lock.json` | Lockfile path |

### `carat replay <BUNDLE_DIR>`

Recompute `TransitionLedger` and `Decision` 100% offline from a bundle created by `carat explain --save-inputs`.

| Flag | Default | Description |
| --- | --- | --- |
| `<BUNDLE_DIR>` | *(required)* | Path to `.carat/inputs/<ledger_id>` |
| `--as-of <RFC3339>` | Bundle's `as_of` | Override evaluation timestamp |

### `carat mcp`

Start Carat's stdio JSON-RPC 2.0 MCP server exposing `carat_explain`, `carat_check`, and `carat_add`.

### `carat init`

Bootstrap `carat.toml` and optional GitHub workflow / MCP snippet.

| Flag | Default | Description |
| --- | --- | --- |
| `--dir <PATH>` | `.` | Target directory |
| `--github` | `false` | Write `.github/workflows/carat-pr.yml` |
| `--mcp` | `false` | Print ready-to-paste MCP server JSON config |
| `--force` | `false` | Overwrite existing files |

---

## Configuration (`carat.toml`)

See [carat.toml.example](../carat.toml.example) for a complete template.

```toml
[policy]
min_age = "24h"                     # Releases younger than this are "fresh" (S9)
settled_age = "30d"                 # Releases older than this are "settled"
history_depth = 10                  # Prior stable releases inspected for continuity
new_direct_dependency = "thin_history"  # "thin_history" | "stop" | "check"
read_pass = "allow"                 # "allow" | "require_human"

[reader]
model = "claude-opus-5-5"           # Built-in Anthropic Messages API model
effort = "high"                     # "low" | "medium" | "high" | "max"
timeout_secs = 90
# command = "/abs/path/to/custom-reader"  # Requires --config or CARAT_ALLOW_READER_COMMAND=1

[store]
read_on_stop = false                # Also run reader when deterministic stops already fired
# stores = ["/shared/readonly/.carat"]    # Requires explicit --config
```

---

## Stop rules (`S1`–`S10`)

| Rule | Trigger |
| --- | --- |
| `S1` | Lockfile integrity missing, invalid, multi-digest SRI, or same-version tarball bytes changed |
| `S2` | Lockfile source kind changed (`git+`, `file:`, `http://`, arbitrary URL) or registry host is not `registry.npmjs.org` |
| `S3` | Archive anomaly: path escape, symlink/hardlink, special file, duplicate/case-colliding path, multi-root tarball, tar EOF anomaly, corrupt `package.json`, or over size/entry limit |
| `S4` | Historical break: `known_malicious` (OSV `MAL-*`), `registry_manifest_differs`, `anchor_lost`, `provenance_lost`, `repo_changed`, `source_match_drop`, `unexplained_appeared`, `install_script_new`, `install_script_changed`, `native_or_binary_new` |
| `S5` | New direct dependency policy (`thin_history`: stops when fewer than 3 prior releases or package younger than `settled_age`; `stop`: always stops) |
| `S6` | Anchor conflict, or unanchored non-settled release with unexplained code |
| `S7` | New capability (`new_reach`) introduced inside unexplained bytes |
| `S8` | Unexplained code, flags, or new reach require a reading, and reading did not pass (`NotRun`, `Concern`, `Invalid`, `Unread`, `Refused`, `Unavailable`) |
| `S9` | Fresh release (younger than `min_age`) that is not deterministically explained |
| `S10` | Prior approval is stale because at least one current `stop_facts` entry was absent when approved |

---

## Environment variables

| Variable | Effect |
| --- | --- |
| `ANTHROPIC_API_KEY` | Enables built-in Anthropic reader when `--read` is passed (passed to `curl` via `0600` `-K` config file, never `argv`) |
| `CARAT_ALLOW_READER_COMMAND` | Set to `1` or `true` to allow `reader.command` in auto-discovered `carat.toml` or `carat pr` |
| `CARAT_BIN` | Optional pre-installed binary path in `docs/workflows/carat-pr.yml` |
| `CARAT_RELEASE_URL` / `CARAT_SHA256` | Release tarball URL and expected SHA-256 in `docs/workflows/carat-pr.yml` |
