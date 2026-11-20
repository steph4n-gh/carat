# Changelog

All notable changes to Carat are documented in this file.

## [0.1.0] - 2026-11-20

### Added
- **Deterministic core (`carat-core`):**
  - In-memory streaming `.tgz` inspector with gzip stream byte caps, tar zero-block differential detection, multi-root detection, UTF-8 BOM stripping, and case-insensitive `package.json`/`Binding.gyp` matching.
  - Lockfile v3 diff engine with shortest introducer routes, workspace root detection, manifest-lockfile desync checks, single-digest SHA-512 SRI enforcement, and nested `inBundle` verification.
  - Five-layer balance sheet: Byte, Source (`provenance -> tag -> gitHead` with Git branch ancestry check and SHA-256 blob confirmation), History (stable-release baseline, OSV `MAL-*` lookup, registry vs tarball manifest diff), Reach (capability and hostname delta), and optional contained LLM Reader.
  - Granular `S1`–`S10` policy engine with timeless `TransitionLedger` records and explicit `as_of` `Decision` evaluation.
  - Atomic, symlink-safe content-addressed local store (`.carat/`) and 100% offline deterministic `carat replay`.
- **Single binary CLI (`carat-cli`):**
  - Commands: `explain`, `check`, `pr`, `add`, `approve`, `exposure`, `inventory`, `replay`, `mcp`, and `init`.
  - Zero-TOCTOU `carat add <pkg> --install` resolver and installer with strict specifier validation, scrubbed npm environment, `.npmrc` safety checks, and rollback on failed install.
  - Git-object-only `carat pr` gate with `merge-base` diffing, protected file tamper detection, single-run `--markdown-out`, and standalone `ledger_id`-bound maintainer approval comments.
  - Stdio JSON-RPC 2.0 MCP server (`carat mcp`) exposing `carat_explain`, `carat_check`, and `carat_add` with no approval surface.
- **Operations & Docs:**
  - Drop-in GitHub Actions workflow (`docs/workflows/carat-pr.yml`) with SHA-256 binary pinning, head-SHA verification, and fork `--read` gating.
  - Agent skill (`skills/carat/SKILL.md`), `AGENTS.md`, `scripts/install.sh`, and bash 3.2-compatible `scripts/pre-install-hook.sh`.
  - Complete documentation suite (`QUICKSTART`, `HUMAN-GUIDE`, `AGENT-GUIDE`, `CI-SETUP`, `CLI-REFERENCE`, `ARCHITECTURE`, `SECURITY`, `SPEC`).
