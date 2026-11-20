# Human Guide

This guide covers day-to-day workflows for engineers using Carat locally and in code review.

---

## Read a Carat report

Every transition ends in one of three verdicts:

| Label | JSON verdict | Meaning | Exit code |
| --- | --- | --- | --- |
| `EXPLAINED` | `explained` | Every changed executable byte matches prior bytes or public Git source, with no breaks, no new reach, and no flags. | `0` |
| `READ` | `read` | Unexplained code diffs or flags were reviewed by the configured reader with zero findings, and no deterministic stop fired. | `0` |
| `STOP` | `stop` | One or more stop rules (`S1`–`S10`) fired. Requires human inspection and approval (or rejection). | `1` |

When Carat prints `STOP`, read the output top to bottom:

1. **Route (`via root -> ... -> pkg`):** Shows which direct dependency pulled the package in.
2. **Anchor:** Shows how Carat linked the tarball to public Git (`provenance`, `tag`, `gitHead`, or `none`).
3. **Balance:** Shows how many changed files matched prior bytes (`Carried`), matched Git source (`Source`, `SourceNormalized`), or remain `Unexplained`.
4. **Leftover code diffs:** Inline unified diffs of the unexplained executable or manifest files.
5. **Breaks, new reach, and why stopped:** The exact deterministic facts that triggered the stop.
6. **Approval line:** `carat approve <16-hex-ledger-id>`.

An `EXPLAINED` verdict means the published bytes match prior bytes or public Git source with no detected breaks or new reach. It does not guarantee the upstream repository itself is bug-free.

---

## Add or update a package locally

Use `carat add` instead of `npm install`:

```bash
carat add zod@4.6.7 --install
```

To inspect what a package would pull in without modifying `package.json`, `package-lock.json`, or `node_modules`:

```bash
carat add zod@4.6.7
```

If `ANTHROPIC_API_KEY` is set and you want the built-in reader to inspect unexplained code diffs automatically, pass `--read`:

```bash
carat add zod@4.6.7 --read --install
```

`carat add` rejects CLI flags, URLs, `file:`, `git+`, and `npm:` specifiers, refuses repositories with `npm-shrinkwrap.json` or workspaces (use `carat check` for workspaces), and rolls back `package.json` and `package-lock.json` if `npm ci --ignore-scripts` fails.

---

## Check a lockfile diff

Compare any two `package-lock.json` v3 files directly:

```bash
carat check \
  --base old-package-lock.json \
  --head package-lock.json \
  --base-pkg old-package.json \
  --head-pkg package.json
```

Supplying `--base-pkg` and `--head-pkg` enables direct-dependency detection (`S5`), accurate introducer routes, and manifest-lockfile desynchronization detection.

---

## Approve a stop

### Local approvals

After reviewing the leftover diff and stop reasons, approve the transition from an interactive terminal:

```bash
carat approve f0ea07e387524fb6 --note "Reviewed diff; repository moved from zeit/ms to vercel/ms"
```

How local approvals work:

- `carat approve` accepts a unique 8–64 character lowercase hex prefix of either `ledger_id` or `subject`.
- Approvals are stored in `.carat/approvals/<subject>.json` and bind to the exact set of `stop_facts` present at approval time.
- **Rebases and upgrades:** Same `(ecosystem, name, old_sha512, new_sha512)` produces the same `subject`, so valid approvals survive rebases.
- **Automatic staleness (`S10`):** If any new stop fact appears later (for example, a new `MAL-*` advisory, an anchor disappearing, or a stricter policy rule), `S10` fires and invalidates the old approval.
- **Agent separation:** `carat approve` refuses non-TTY stdin unless `--non-interactive` is explicitly passed by a human script.

### Pull request comment approvals

In GitHub pull requests gated by `docs/workflows/carat-pr.yml`, a maintainer with repository write access (who is not the PR author) posts a standalone single-line comment with the exact `ledger_id` prefix printed in the PR report:

```text
carat approve f0ea07e387524fb6
```

- Multi-line comments, quoted blocks, and bot comments are ignored.
- Binding to `ledger_id` automatically invalidates the comment if the lockfile integrity, anchor, breaks, new reach, or advisories change.
- Known-malicious advisories (`MAL-*`) and reader `Concern` findings cannot be approved by PR comment alone.

---

## Use the optional LLM reader

By default, Carat uses Anthropic's Messages API (`claude-opus-5-5`, `effort = "high"`) when `--read` is passed and `ANTHROPIC_API_KEY` is exported:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
carat explain some-pkg@1.0.0..1.0.1 --read
```

To use a custom external reader executable, pass an explicit `--config` path or opt in via `CARAT_ALLOW_READER_COMMAND=1`:

```bash
carat --config ~/.config/carat/carat.toml explain some-pkg@1.0.0..1.0.1 --read
```

Carat refuses `reader.command` and external `stores` from auto-discovered working-directory `carat.toml` files so untrusted checkouts cannot execute arbitrary commands or inject approvals.

---

## Trace historical exposure (incident response)

When a compromised package or tarball hash is disclosed, search both your repository's Git history of `package-lock.json` (without checking out old commits) and your local `.carat/ledgers/` store:

```bash
carat exposure flatmap-stream@0.1.1 --repo .
carat exposure --sha512 44e0... --repo .
```

The report prints the first commit date, last commit date, lockfile instance path, and whether the package is still present at `HEAD`.

---

## Audit standing lockfile debt

List all packages in a lockfile that lack SHA-512 integrity hashes or use non-registry sources (`git+`, `file:`, `url`) without failing the build:

```bash
carat inventory --lock package-lock.json
```

---

## Replay a ledger 100% offline

Save an offline input bundle during `explain`:

```bash
carat explain ms@2.1.2..2.1.3 --save-inputs
```

Recompute the exact `TransitionLedger` and `Decision` later with zero network access:

```bash
carat replay .carat/inputs/<ledger_id> --json
```

The JSON output includes `"byte_identical": true` when the recomputed `ledger_id` matches the recorded `expected_ledger_id`.
