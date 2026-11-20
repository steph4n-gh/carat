# Contributing to Carat

Thanks for contributing to Carat. Keep changes small, verifiable, and grounded in tests.

## Workspace layout

- [crates/carat-core](crates/carat-core): Pure deterministic verification library. No network calls, no subprocesses, and no implicit system clock.
- [crates/carat-cli](crates/carat-cli): Single `carat` binary handling hardened `curl` and `git` fetching, local store I/O, optional LLM reader execution, CLI rendering, PR gate, exposure tracing, offline replay, and the stdio MCP server.
- [docs/](docs): User, agent, CI, architecture, and CLI reference documentation.
- [scripts/](scripts): Local installer (`install.sh`) and agent pre-install guardrail (`pre-install-hook.sh`).

## Core engineering invariants

Every pull request must preserve these invariants:

1. **Strict determinism in `carat-core`:** Never read wall-clock time inside `ArtifactProfile` or `TransitionLedger`. Relative publish age belongs only inside `Decision`, evaluated at an explicit RFC 3339 `as_of` timestamp.
2. **In-memory archive inspection:** Never extract untrusted npm tarballs to disk.
3. **Reader containment:** LLM reader output can only raise concern (`Concern`, `Invalid`, `Refused`, `Unread`, `Unavailable`) and can never weaken or override a deterministic stop. Every finding must cite valid 1-based line numbers and a non-empty verbatim excerpt verified by `carat-core`.
4. **Human-only approvals:** Never expose approval actions through `carat mcp` or allow an automated path to bypass `S1`–`S10` stops.
5. **Fail closed:** Ambiguous tar headers, malformed `package.json`, multi-digest SRI strings, symlink targets, and unverified `inBundle` entries must stop rather than silently pass.

## Local development

Run the full test suite and release build before opening a pull request:

```bash
cargo test
cargo build --release
```

Every security fix or parser change should include a regression unit test in the affected module.

## Commit messages

Use concise, imperative commit summaries that state what changed and why.
