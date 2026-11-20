# CI Setup Guide (GitHub Actions)

Carat includes a drop-in GitHub Actions workflow at [docs/workflows/carat-pr.yml](workflows/carat-pr.yml) that gates pull request dependency changes without ever checking out or running PR head code.

---

## 1. Install the workflow

Run inside your repository:

```bash
carat init --github
```

Or copy [docs/workflows/carat-pr.yml](workflows/carat-pr.yml) to `.github/workflows/carat-pr.yml`.

---

## 2. Pin the Carat release binary

The workflow verifies the downloaded `carat` tarball against a SHA-256 digest before executing it. Set both values in `.github/workflows/carat-pr.yml`:

```yaml
env:
  CARAT_RELEASE_URL: "https://github.com/steph4n-gh/carat/releases/download/v0.1.0/carat-x86_64-unknown-linux-gnu.tar.gz"
  CARAT_SHA256: "<64-char-lowercase-sha256>"
```

If you host an internal mirror or self-hosted runner with `carat` pre-installed, set `CARAT_BIN` to the executable path instead.

---

## 3. Configure optional `--read` for trusted PRs

To let Carat run its built-in Anthropic reader on unexplained diffs in pull requests:

1. Add `ANTHROPIC_API_KEY` under **Settings -> Secrets and variables -> Actions**.
2. The workflow exposes `ANTHROPIC_API_KEY` only when `pr.author_association` is `OWNER`, `MEMBER`, or `COLLABORATOR`. External fork PRs still run full deterministic checks (`S1`–`S10`), without allowing unauthenticated forks to consume API credits.

---

## 4. Enable branch protection

In **Settings -> Branches -> Branch protection rules** for `main`:

1. Enable **Require status checks to pass before merging**.
2. Require the commit status **`Carat Dependency Gate`**.

Because the workflow publishes a commit status directly on `pr.head.sha` (both on `pull_request_target` and on `issue_comment` re-runs), approving a stop via PR comment updates the required status on the PR's head commit cleanly.

---

## How the PR gate stays isolated

- **`pull_request_target` with base checkout:** Only the protected base branch is checked out (`fetch-depth: 0`). PR head commits are fetched into Git object storage (`refs/carat/pr-head`) and never checked out.
- **Exact head-SHA verification:** Before running `carat pr`, the workflow verifies `git rev-parse refs/carat/pr-head == pr.head.sha` so a concurrent push cannot swap commits between API lookup and fetch.
- **Merge-base diffing:** `carat pr` reads policy (`carat.toml`) strictly from the protected `base` tip, while computing `git merge-base <base> <head>` for lockfile diffs and changed-path inspection so un-rebased PRs are not falsely blamed for newer commits on `main`.
- **Single evaluation:** The workflow runs `carat pr --json --markdown-out /tmp/carat-summary.md` once per event so the posted PR comment, uploaded JSON report, and exit code always match.
- **Working-tree approval isolation:** `carat pr` ignores `.carat/approvals/` in the working tree; only verified PR maintainer comments apply.

---

## Protected file tamper rules

`carat pr` flags changes to any of the following paths as an unapprovable stop (`tampered_protected_files`):

- `carat.toml` and `.carat.toml`
- `.carat/**`
- `.github/workflows/*.yml` and `.github/workflows/*.yaml`
- `.github/actions/**`
- `.npmrc` and `**/.npmrc`
- `npm-shrinkwrap.json` and `**/npm-shrinkwrap.json`
- Deleting `package-lock.json` when `base` had one, or modifying `package.json` dependencies without a lockfile

Note: If `Carat Dependency Gate` is a required status check, PRs that intentionally edit CI workflows or `carat.toml` will stop and require a repository admin merge (or a separate policy review flow).

---

## Approving a stop on a pull request

When a dependency transition stops in CI:

1. Inspect the inline residual diff and stop reasons in the `<!-- carat-pr-report -->` comment.
2. A maintainer with `write`, `maintain`, or `admin` repository permission (who is not the PR author) posts a standalone single-line comment:

```text
carat approve <16-hex-ledger-id>
```

3. The `issue_comment` trigger re-runs `carat pr` against `pr.head.sha` and marks **`Carat Dependency Gate`** as `success` once every stop is resolved.
4. If the PR author pushes any change that alters lockfile integrity, anchors, breaks, new reach, or advisories, `ledger_id` changes and the earlier approval comment automatically becomes invalid.
