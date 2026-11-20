# Assay

**A balance sheet for dependency changes.**

When a project updates a dependency, it admits new bytes written by strangers. Almost nobody reads them because there is too much noise. Assay accounts for every changed byte between two versions of a package:

1. **Carried** — identical bytes to the version you already have.
2. **Source / SourceElsewhere / SourceNormalized** — SHA-256 verified against the public Git repository at the commit the release claims to be built from (found via SLSA provenance, tag, or `gitHead`), with explicit declared normalizations (`CRLF → LF` and benign `package.json` publish diffs).
3. **Unexplained** — whatever is left. Unexplained diffs can be read by a structured reader (`--read`) whose findings are verified line-by-line against the actual bytes by the deterministic core.

The governing rule is **nothing appears from nowhere**.

> **Claims discipline:** Assay reports checkable facts and one of three verdicts (`explained`, `read`, `stop`). It **never** claims a package is safe or free of malware. An explained release can still be harmful if harm was committed openly to public source.

---

## Quickstart

Build the single binary (`rustc` 1.85+):

```bash
cargo build --release
```

### Explain a single npm transition (no project needed)

```bash
./target/release/assay explain chalk@6.0.0..6.0.1
./target/release/assay explain zod@4.6.6..4.6.7
./target/release/assay explain vite@8.3.7..8.3.8 --read
```

### Check a `package-lock.json` diff (lockfile v3)

```bash
assay check --base old/package-lock.json --head new/package-lock.json
```

### Gate a pull request strictly from Git objects

```bash
assay pr --base origin/main --head HEAD
```

Reads both revisions via `git show` (never executes PR head code), loads `assay.toml` only from `--base`, and hard-stops if the PR modifies `assay.toml` or `.github/workflows/*assay*.yml`. See [docs/workflows/assay-pr.yml](docs/workflows/assay-pr.yml).

### Gate coding agents before `npm install`

```bash
assay add zod@4.6.7             # resolves full transitive tree in an isolated temp dir (--ignore-scripts)
assay mcp                       # stdio JSON-RPC 2.0 MCP server (exposes explain/check/add, never approve)
```

See [docs/agent-hook.md](docs/agent-hook.md).

### Approvals, exposure tracing, inventory, and offline replay

```bash
assay approve <subject-prefix> --note "reviewed diff"
assay exposure flatmap-stream@0.1.1 --repo .
assay exposure --sha512 <hex-or-sri> --repo .
assay inventory --lock package-lock.json
assay explain chalk@6.0.0..6.0.1 --save-inputs
assay replay .assay/inputs/<ledger-id>
```

---

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Every transition is `explained`, `read`, or `stop` with a valid human approval |
| `1` | At least one unapproved `stop` (or protected policy/workflow edit) |
| `2` | Operational error (bad input, config error, fetch failure) |

---

## Configuration (`assay.toml`)

```toml
min_age = "24h"
settled_age = "30d"
new_direct_dependency = "confirm" # or "check"
read_pass = "allow"               # or "require_human"
readings = 1                      # set 2 for two independent reversed-order passes
read_on_stop = true
history_depth = 20
stores = []

[reader]
model = "claude-opus-5-5"
effort = "high"
# command = "/path/to/custom-reader" # optional stdin/stdout JSON subprocess reader
```

Set `ANTHROPIC_API_KEY` to use the built-in Anthropic reader, or point `reader.command` at any program reading a `ReadingPacket` JSON on stdin and returning findings JSON on stdout (see [SPEC.md](SPEC.md)).

## Architecture

- **`crates/assay-core`** — deterministic, network-free core: strict in-memory PAX/USTAR streaming tar parser, SHA-256/SHA-512/Git-blob hashing, canonical JSON, lockfile v3 diff + shortest introducer routes, declared normalizations, habit-profile breaks, lexical reach scanner, unified-diff reading packet builder (with deterministic single-line minified splitting), verbatim-excerpt finding validator, and timeless `TransitionLedger` + `as_of` `Decision` evaluator.
- **`crates/assay-cli`** — single `assay` binary: hardened `curl`/`git` object-only fetcher, built-in + pluggable reader executor, content-addressed `.assay/` store, PR gate, exposure tracer, offline replay, and stdio MCP server.

## License

Apache-2.0
