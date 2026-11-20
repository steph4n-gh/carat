# Security Policy and Threat Model

## Supported Versions

| Version | Supported |
| --- | --- |
| `0.1.x` | Yes |

## Reporting a Vulnerability

Do not open a public GitHub issue for security vulnerabilities.

Use GitHub Private Vulnerability Reporting (the **Security -> Advisories -> Report a vulnerability** tab on this repository) and include:

1. A clear description of the vulnerability and affected file paths.
2. Exact reproduction steps or a minimal proof of concept.
3. The expected fail-closed behavior versus the observed behavior.

We will acknowledge reports within 48 hours and coordinate a fix before disclosure.

---

## Threat Model

Carat is designed to protect developers, CI pipelines, and coding agents from compromised or tampered npm releases before package bytes are extracted or executed.

### What Carat defends against

- **Stolen-token publishes and silent tarball injection:** Every changed byte in a release is compared against the previous tarball and public Git source blobs (confirmed by SHA-256). Unexplained code, manifest changes, provenance drops, and repository switches trigger deterministic stops.
- **Lockfile and SRI tampering:** Carat rejects multi-digest `sha512-` SRI strings (preventing `ssri` OR-ed tarball substitution), verifies lockfile `resolved` URLs and SHA-512 hashes against npm registry metadata, blocks plaintext `http://` and non-`registry.npmjs.org` hosts, catches manifest-lockfile desynchronization, and verifies nested `inBundle` entries against their enclosing bundle-root tarball.
- **Archive parser differentials and decompression bombs:** Tarballs are streamed strictly in memory with a hard cap on total decompressed bytes (`MultiGzDecoder::take`). Path escapes, symlinks, hardlinks, special files, multi-root tarballs, lone zero-block padding tricks, case/Unicode collisions, and malformed `package.json` files trigger deterministic `S3` stops.
- **Pre-install and install-time execution:** `carat add --install` validates package specifiers strictly, passes `--` before the specifier, scrubs `npm_config_*` env vars, rejects dangerous `.npmrc` directives (`git`, `script-shell`, `onload-script`, `node-gyp`, `cafile`, `ignore-scripts`) and `npm-shrinkwrap.json`, resolves once in a `0700` temp directory, checks for concurrent file or symlink changes, and runs `npm ci --ignore-scripts`.
- **Untrusted checkout and PR code execution:** `carat pr` reads policy strictly from the protected base revision and diffs PR files strictly from Git object storage without checking out PR head. Auto-discovered working-directory `carat.toml` files cannot execute `reader.command` or load external `stores`.
- **Prompt injection and LLM reader evasion:** The optional LLM reader sees only unexplained diffs, runs in an environment scrubbed of API keys for external commands, must cite real line ranges with non-empty verbatim excerpts verified by `carat-core`, and can never lift a deterministic stop.
- **Approval forgery and staleness:** `carat mcp` exposes no approval tool. Local `carat approve` requires a human TTY by default and binds to exact `stop_facts` (`S10` invalidates stale approvals). PR comment approvals require write access, forbid self-approval, require a standalone single-line `carat approve <ledger_id>` comment, ignore working-tree `.carat/approvals/`, and cannot approve `MAL-*` advisories or reader `Concern` findings.

### Explicit non-goals

- **Malicious code already committed to the package's public Git repository:** If a legitimate maintainer commits malicious code to their public repository and publishes with provenance, Carat classifies those bytes as `source` (though `new_reach`, `install_script_new`, and `known_malicious` advisories still apply). Carat answers *"do these published bytes match public history and source?"*, not *"is this open-source project bug-free?"*.
- **Runtime sandboxing after install:** Carat gates dependency admission. Once you run your Node.js application, OS or container isolation is still your responsibility.
- **Non-npm ecosystems in v0.1:** Carat v0.1 supports npm `package-lock.json` v3 only. `npm-shrinkwrap.json`, `pnpm-lock.yaml`, and `yarn.lock` are out of scope in v0.1.
- **Local shell hook as a security boundary:** `scripts/pre-install-hook.sh` is a local guardrail that redirects well-behaved coding agents to `carat add --install`. Hard enforcement belongs in CI (`carat pr`) and `npm ci --ignore-scripts`.
