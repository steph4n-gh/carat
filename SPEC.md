# Carat: a balance sheet for dependency changes

**Specification, draft 0.2 — 2026-11-19**

"Carat" is a working name (an carat is a test of what a substance is actually made of). Rename freely.

This document defines Carat as a fresh, standalone product in its own repository. It does not depend on any legacy codebase or data.

**Status: initial implementation and live measurement in progress.** The design rests on one core empirical assumption, stated in section 2.3, which is measured against fresh real-world npm updates and known compromises (section 13). Statements about the outside world carry one of three marks:

- **[checked]** — I verified it directly on 2026-11-19.
- **[reported]** — taken from search summaries of secondary sources on 2026-11-19; confirm against the original before relying on it.
- **[unmeasured]** — a design expectation with no data behind it yet.

---

## 1. Summary

When a project takes a dependency update, it admits new code written by strangers. Today almost nobody reads that code, because there is too much of it.

Carat makes the amount that needs reading small, and then reads it. For every package a change touches, it asks one question of every changed byte: **where did this come from?** A byte is explained if it is identical to the version the project already has, or identical to the public source at the commit the release claims to be built from. Whatever is left is **unexplained**. Unexplained bytes are read by a model, and anything the model cannot square with the stated change goes to a person.

The governing rule is: **nothing appears from nowhere.**

The output is a record bound to the exact old and new package bytes. It says what was explained, by what, what was read, and what a person approved. It never says a package is safe.

---

## 2. Problem

### 2.1 What attacks look like

The most common serious attack on the npm ecosystem is a release published with stolen credentials. The attacker has a maintainer's registry token but usually not their source repository. They publish a new version containing code that exists nowhere in the public source.

- 2018, `event-stream`: the payload lived only in the published `flatmap-stream` package, not in its repository.
- 2025, `nx`, `chalk`/`debug`, and the Shai-Hulud worm: malicious versions published directly to the registry with no corresponding source commits.
- 2026 **[reported]**: `axios` and `jscrambler` releases published with stolen tokens; a November `wppconnect` compromise where the tagged source does not contain the code that shipped.

The same shape appears outside npm: the 2024 `xz` backdoor was triggered by a build file present in the release tarball and absent from the Git repository.

### 2.2 What existing defenses cover

| Defense | Who provides it | What it leaves open |
| --- | --- | --- |
| Wait before installing new releases (cooldown) | pnpm, npm **[reported]** | Delays security fixes equally; protects only if someone else notices in time |
| Install scripts off by default, allowed by package name | pnpm, Bun | A new version of an allowed package is trusted automatically |
| Refuse a release whose publishing trust dropped | pnpm `trustPolicy` **[reported]** | Only helps for packages that had provenance to begin with |
| Build provenance and trusted publishing | npm registry | Opt-in per package; says where a build ran, not that the result is honest. One August 2026 report describes malware published with valid provenance **[reported]** |
| Known-malware feeds | Commercial vendors | Silent until someone has already been hit and it has been analyzed |
| Compare a published package with its source | Standalone tools (section 16) | Run by hand, on one package, with no baseline; not part of the update flow |

Nothing in the normal update flow checks whether the bytes being admitted correspond to the public source, relative to how that package has always been published.

### 2.3 The assumption this product rests on

> For ordinary releases of ordinary packages, most changed bytes can be explained deterministically, and the remainder is small enough to read. For releases published with stolen credentials, the changed bytes cannot be explained, and that shows up without any model judgment.

**[unmeasured]** If the first half is false, Carat floods people with stops and nobody leaves it on. Many legitimate packages ship built files that are not in their repository, so this is a real risk. Section 13 tests it first.

### 2.4 Who it is for

1. **Maintainers who merge dependency update PRs** (from Renovate, Dependabot, or by hand) and want to know which ones need a look.
2. **Coding agents that add or update dependencies** without a person watching, and the people responsible for those agents.
3. **Anyone answering "were we exposed?"** when a compromise is announced.

---

## 3. Principles

The design borrows working rules from fields that have dealt with contamination and custody for a long time. Each one is here because it produces a concrete mechanism, not as decoration.

| Field | Rule | What it becomes here |
| --- | --- | --- |
| Chemistry, nuclear safeguards, accounting | Mass balance: outputs must be accounted for by inputs, and what is unaccounted for is the finding | Every changed file is matched to the prior version or to the source. The remainder is the unexplained bytes (section 7.3) |
| Immunology | Self versus non-self: react to departure from the body's own pattern, not to a list of known threats | Each package's publishing history is its baseline. A release is judged against that, not against a malware list (section 7.4) |
| Physics | Conservation: a quantity does not increase without a source | A version that can newly reach the network, processes, files or install-time execution must be explained (section 7.5) |
| Pharmaceuticals | Certificate of analysis: every batch carries its own test record | Every result is a record bound to exact bytes, produced once and reused (section 9) |
| Epidemiology | Incubation and contact tracing | Release age is an input to the verdict, and byte-keyed records answer "where was this admitted?" later (sections 8, 10.5) |
| Food safety | Control hazards at the point where control is cheapest | The check runs at the moment new bytes are admitted: the update PR or the install command (section 10) |

Two rules come from the predecessor project, Tau-Gate (section 15):

- **Judge the change, never the whole lockfile.** A package the change did not touch can never block it.
- **No feature without a decision that reads it.** If a computed fact changes no verdict and no reviewer's action, it is removed.

### Claims discipline

Carat reports facts and one of three verdicts. It never states or implies that a package is safe, benign, or free of malware. "Explained" means every changed byte has a checkable origin and nothing new is reachable. An explained release can still be harmful if the harm is committed openly to the source (section 12.3).

Any public claim about detection or coverage must come from a test whose protocol and pass marks were fixed before it ran.

---

## 4. Scope

### In scope for version 1

- npm packages resolved through `package-lock.json` lockfile version 3.
- Updates, additions and removals of packages in a proposed change.
- A GitHub pull request check, a command-line tool, and a pre-install check that agents can call.
- Public registry packages with public source repositories.

### Later (section 14)

- pnpm and Yarn lockfiles.
- Verifying provenance signatures; independent rebuild attestations.
- PyPI, crates.io, GitHub Actions references.
- Signed records shared between organizations.

### Not in scope

- Known-vulnerability (CVE) scanning, license checks, package quality scores.
- Sandboxing or monitoring code while it runs.
- Verifying who a publisher is.
- Private registries and private source in version 1.
- Predicting what a host machine will actually install or execute.

---

## 5. Vocabulary

These terms are used with exactly these meanings throughout.

| Term | Meaning |
| --- | --- |
| **Artifact** | The exact published archive of one package version, identified by the SHA-512 of its bytes |
| **Transition** | One package instance in the lockfile going from a reference artifact to a new artifact |
| **Reference artifact** | What the new artifact is compared against (section 7.1) |
| **Anchor** | The source commit a release claims to be built from, and how that commit was found |
| **Origin class** | For one file in the new artifact, the strongest checkable explanation of where its bytes came from |
| **Unexplained bytes** | Files in the new artifact with no origin class |
| **Habit profile** | How this package has been published in its recent history |
| **Break** | A named way in which a release departs from its habit profile |
| **Reach** | The sensitive capabilities the package's code visibly refers to |
| **Reading** | A model's examination of unexplained bytes or new reach |
| **Record** | A content-addressed JSON document: a profile, a ledger, a reading, or an approval |
| **Verdict** | One of `explained`, `read`, `stop`, per transition |

---

## 6. How a check works

Given a base lockfile and a head lockfile:

1. **Lock layer.** Diff the lockfiles. Produce the list of transitions and any lockfile-level alarms.
2. **Byte layer.** For each transition, fetch the new artifact (and the reference artifact if not cached), verify the bytes against the lockfile's SHA-512, and inventory every file.
3. **Source layer.** Find the anchor. Match each file that is not carried over from the reference against the source tree at the anchor. Assign origin classes.
4. **History layer.** Build the habit profile from the package's prior releases. List breaks.
5. **Reach layer.** Compute what the new artifact can newly reach.
6. **Reading layer.** If unexplained bytes or new reach remain, build a reading packet and hand it to the reader.
7. **Verdict.** Apply policy to the facts. Write records. Report.

Steps 1 to 5 and 7 are deterministic: the same inputs and the same tool binary give byte-identical records. Step 6 is not, and its output is treated as untrusted input to step 7.

Only packages the change touches are fetched or inspected.

```
base lock ─┐
           ├─ lock diff ─► transitions ─► per transition:
head lock ─┘
              artifact bytes ──► inventory ──┐
              source at anchor ─► matching ──┼─► ledger ─┐
              registry history ─► habit ─────┤           ├─► policy ─► verdict + records
              code scan ────────► reach ─────┘           │
                                   unexplained ─► reader ─┘
```

---

## 7. The layers

### 7.1 Lock layer

**Input:** base and head lockfile bytes, and base and head root `package.json` bytes.

**Transitions.** One transition per lockfile instance whose name, version, resolved source or integrity differs, or which exists on only one side. Transitions with identical (name, reference SHA-512, new SHA-512) are checked once.

**Reference artifact selection**, first match wins:

1. The artifact at the same instance path in the base lockfile. Standing: `admitted`.
2. If the package is new to the project: the newest release older than the new artifact that is *settled* (published at least `settled_age` ago, default 30 days, with no advisory). Standing: `settled`.
3. None. The whole new artifact is treated as not carried.

**Direct or transitive.** A new package is *direct* if the head root manifest names it and the base root manifest does not. Otherwise it is transitive.

**Lock alarms**, each a named fact:

| Fact | Meaning |
| --- | --- |
| `same_version_bytes_changed` | Same name and version, different integrity |
| `source_kind_changed` | A registry package became a Git, URL or file dependency, or the reverse |
| `registry_host_changed` | The resolved host differs from the base |
| `integrity_missing` | The head record has no SHA-512 integrity |

**Route.** For each transition, the shortest dependency path from a root to the instance, with edge kinds, so a reviewer can see why the package is there. A transition with no route from any changed direct dependency is reported as `unattributed`; this is informational.

### 7.2 Byte layer

For each artifact:

- Fetch the archive from the lockfile's resolved URL (registry hosts only; see section 11.3).
- Verify the SHA-512 against the lockfile integrity before anything else reads the bytes.
- Stream the gzip and tar. Never extract to disk. Never execute anything.
- Emit an **inventory**: for every entry, the path, type, mode, size, SHA-256 of the content, and the Git blob identifier of the content (the SHA-1 of `"blob " + length + NUL + content`, used only as a lookup key in section 7.3).

Unlike Tau-Gate, the reader does not reject an archive for unusual but well-formed tar features. It records them as facts:

| Fact | Meaning |
| --- | --- |
| `archive_duplicate_path` | Two entries resolve to the same path, including case-folded or Unicode-normalized collisions |
| `archive_link_entry` | Hard link or symbolic link entries |
| `archive_special_entry` | Device, FIFO or other non-file entries |
| `archive_path_escape` | Absolute paths or parent traversal |
| `archive_over_limit` | A size or count limit was exceeded (section 11.4) |

Any of these makes the transition `stop` with reason `cannot_check`. A person can still approve the exact bytes.

Results are cached per artifact SHA-512. The cached per-artifact result is the **artifact profile** (section 9.1); it is independent of any project.

### 7.3 Source layer

#### Finding the anchor

Three methods, strongest first. All that are available are evaluated.

1. **Provenance.** The registry serves attestations at `/-/npm/v1/attestations/<name>@<version>`. The SLSA provenance statement names the source repository, the workflow file, the ref, and the commit, and its subject is the artifact's SHA-512. **[checked]** for `vite@8.3.8`: the commit is at `predicate.buildDefinition.resolvedDependencies[].digest.gitCommit` and the workflow at `predicate.buildDefinition.externalParameters.workflow`. Until signature verification exists (milestone M6) this is recorded as `provenance_asserted`, not `provenance_verified`.
2. **`gitHead`** in the registry's version metadata. Asserted by the publisher, unsigned, and frequently absent. **[checked]**: absent for `vite@8.3.8`.
3. **Tag by convention.** Look up, in order, `v{version}`, `{version}`, `{name}@{version}`, `{name}-v{version}`, and the same with the scope removed. If matching tags point to different commits, there is no tag anchor.

Rules:

- If two methods give different commits, record `anchor_conflict` and treat the release as unanchored.
- **Repository identity** comes from provenance when present, otherwise from the `repository` field of the `package.json` *inside the verified artifact*. The registry's copy of that field is compared and any difference recorded.
- **Monorepos.** The package directory is `repository.directory` when given **[checked]** present for `vite`. Otherwise it is the unique directory in the anchor tree whose `package.json` has the same `name`. No unique match means no package directory, and only whole-tree matching applies.
- Record whether the anchor commit is reachable from the repository's default branch or a release branch.

An attacker with a stolen registry token can point `repository` at a repository they control. Matching that repository proves nothing. This is caught in the history layer as `repo_changed`, and for a package with no history it is why new direct dependencies need a person (section 8).

#### Matching

For each file in the new artifact that is not carried from the reference:

1. Look up its Git blob identifier in the tree listing of the anchor commit. A partial clone without blobs is enough to get the listing.
2. On a hit, fetch that blob and confirm its SHA-256 equals the artifact file's SHA-256. The blob identifier is only a lookup key; SHA-1 is not relied on for equality.
3. Assign the strongest origin class that applies.

Git is used for object access only: no checkout, no hooks, no submodule initialization, no smudge filters, no replacement objects, no lazy fetching beyond the objects explicitly requested.

Carat relies on Git's object model for the statement "this blob is in the tree of this commit." That reliance on SHA-1 with collision detection is a stated limitation.

#### Origin classes

Every file in the new artifact gets exactly one, the first that applies:

| Class | Meaning |
| --- | --- |
| `carried` | Identical bytes to a file in the reference artifact (same path, or a different path with a `moved` flag) |
| `source` | Identical bytes to the file at the corresponding path in the anchor tree |
| `source_elsewhere` | Identical bytes to a file elsewhere in the anchor tree, for example a license copied from a monorepo root |
| `source_normalized` | Identical after exactly one declared normalization, named in the record |
| `rebuilt` | Identical to the output of an independent rebuild by a named rebuilder (milestone M6) |
| `unexplained` | None of the above |

Files present in the reference and absent from the new artifact are listed as removed.

Provenance is deliberately **not** an origin class. A valid attestation says the artifact was built by a named workflow at a named commit. It does not explain the bytes of a built file. It strengthens the anchor and feeds the history layer.

#### Declared normalizations

Version 1 has two. The table is explicit and versioned; anything not in it is not a normalization.

1. **Line endings.** Content is identical after converting CRLF to LF.
2. **Published `package.json`.** Both manifests are parsed. Differences are sorted into two sets.
   - *Benign publish differences*: key order and whitespace; `version` where the source holds a placeholder; an added `gitHead`; fields moved in by `publishConfig`; `workspace:` and `catalog:` dependency ranges replaced by concrete versions; removal of `devDependencies` and non-lifecycle `scripts`.
   - *Significant differences*: any change to lifecycle scripts (`preinstall`, `install`, `postinstall`); the set of runtime, optional, peer or bundled dependency names; any range change not accounted for above; `bin`, `main`, `module`, `exports`, `imports`, `browser`, `files`, `repository`, `gypfile`, `os`, `cpu`.

   A manifest with only benign differences is `source_normalized`. One with any significant difference is `unexplained`, and the differing fields are listed in the record and shown to the reviewer directly.

Also recorded: `registry_manifest_differs`, when the registry's metadata for the version disagrees with the artifact's own `package.json` on scripts, dependencies or `bin`.

### 7.4 History layer

The habit profile is built from the package's last `K` releases published before the new one (default `K = 20`), using the registry's per-version metadata and the artifact profiles of the reference artifact.

Registry metadata is unsigned and can change. Carat records the SHA-256 of the metadata snapshot it used and labels everything derived from it as asserted by the registry.

**Breaks:**

| Break | Fires when | Default |
| --- | --- | --- |
| `anchor_lost` | Prior releases had an anchor, this one has none | stop |
| `provenance_lost` | Prior releases had provenance or a trusted publisher, this one has less | stop |
| `repo_changed` | Repository identity differs from prior releases | stop |
| `source_match_drop` | A file that was `source` in the reference is `unexplained` at the same path now | stop |
| `install_script_new` | Install-time execution is present and the reference had none. For a package new to the project it fires on any install-time execution, whatever the reference | stop |
| `install_script_changed` | The install-time command text or native build inputs changed | stop |
| `native_or_binary_new` | First appearance of native addons or executable binaries | stop |
| `registry_manifest_differs` | See section 7.3 | stop |
| `known_malicious` | An advisory database (OSV in version 1) lists this exact version as malicious. Absence of an advisory proves nothing | stop |
| `tag_moved` | The tag for a version Carat has recorded before now points to a different commit | stop |
| `publisher_changed` | Publishing account or trusted-publisher configuration not seen in the last `K` releases | flag |
| `dependency_added` | A runtime dependency name was added | flag |
| `size_jump` | File count or unpacked size outside the band of the last `K` releases | flag |
| `version_out_of_sequence` | The version is not the next step on its release line | flag |
| `anchor_unreachable` | The anchor commit is not on the default or a release branch | flag |

Install-time execution follows npm's rules for dependency installs: `preinstall`, `install`, `postinstall`, and an implicit `node-gyp rebuild` when a `binding.gyp` is present and no install script overrides it.

A *flag* does not stop a transition by itself. It prevents the `explained` verdict, so the transition is read.

The default column is a starting point. Section 13 tunes it on development data before the held-out run and freezes it.

**Why history instead of absolutes.** A package that has never had an anchor, or whose built files never match source, is not newly suspicious; that is simply how it is published. Stopping on it would repeat Tau-Gate's "incomplete" problem. A package that always matched and suddenly does not is the signal.

### 7.5 Reach layer

Reach is computed by a deterministic lexical scan of JavaScript, TypeScript and JSON files. It is a set of tokens per artifact.

| Token | Fires on references to | High |
| --- | --- | --- |
| `net` | `http`, `https`, `net`, `tls`, `dgram`, `dns`, `http2`, `fetch`, `XMLHttpRequest`, `WebSocket`, `sendBeacon` | |
| `fs` | `fs`, `fs/promises` | |
| `env` | `process.env` | |
| `host_info` | `os.homedir`, `os.userInfo`, `os.hostname`, and similar | |
| `browser_sensitive` | `document.cookie`, `localStorage`, `indexedDB`, `navigator.clipboard`, `navigator.credentials`, wallet objects such as `window.ethereum` | |
| `proc` | `child_process`, `process.binding`, `process.dlopen` | yes |
| `dyn_code` | `eval`, `new Function`, `vm`, WebAssembly compilation, `require` or `import()` with a non-literal argument | yes |
| `native` | Loading `.node` addons, FFI libraries | yes |
| `install_exec` | Install-time execution, as in section 7.4 | yes |
| `encoded_blob` | Long base64 or hex literals, or high-entropy string literals above a fixed size | yes |
| `shell_literal` | String literals containing shell download-and-run patterns | yes |
| `minified_new` | A file is minified where the same path in the reference was not | yes |

Also recorded, as a list and not a token: **new hostnames and IP addresses** appearing in string literals.

**Delta.** New reach is the set of tokens present in the new artifact's non-carried files and absent from the whole reference artifact. Where there is no reference, every token in the artifact counts as new.

**Limits, stated plainly.** This is a text scan. It has no data-flow analysis and can be evaded. The design response is that the usual means of evasion (building names at run time, encoding payloads, minifying) are themselves high tokens. It will also fire on honest code. It is one input to the verdict, not a detector.

### 7.6 Reading layer

#### When a reading happens

A reading is required when a transition has unexplained bytes, new reach, or a flag, and no rule has already made it `stop`. When a transition is already `stop`, a reading is still run by default (`read_on_stop = true`) so the person has a summary; its result cannot change the verdict.

#### The reading packet

Built deterministically by the core. It contains only public package bytes and public source. It never contains the consuming project's code, lockfile, repository name or secrets.

1. **Header:** package name, versions, whether the step is patch, minor or major.
2. **Stated change:** the changelog difference if the artifact carries one, and the commit subjects between the reference anchor and the new anchor.
3. **Facts:** ledger totals, breaks, new reach, new hostnames.
4. **Units:** one per unexplained file. Each is a line-numbered unified diff against the same path in the reference, or the whole file if new. For built files, the source diff between the two anchors is attached as context. Single-line minified files are formatted/split deterministically into fixed-width or statement-delimited slices before line-numbering so diffs and line citations remain bounded. Non-executable metadata files (`.d.ts`, `.d.mts`, `.d.cts`, `.map`) are tagged separately in the ledger so their byte volume is visible without blowing up the reader budget unless they contain unexpected content.

Nothing is silently truncated. A unit over the per-call budget is split into overlapping chunks. A unit over the hard cap is marked `unread`, which makes the transition `stop`.

#### The reader contract

The reader is either the built-in Anthropic reader inside the single `carat` binary or any external executable configured via `reader.command` (receiving a packet as JSON on standard input and returning a findings object as JSON on standard output).

Findings schema (full version in Appendix B):

- Per unit: `fits_stated_change`, one of `yes`, `no`, `cannot_tell`.
- Zero or more findings, each with a unit identifier, a line range, a verbatim `excerpt` from those lines, a category from a fixed list, a statement of at most 300 characters, and a confidence level.
- One summary of at most 600 characters, for the human reviewer.

Categories: `exfiltration`, `remote_code`, `credential_access`, `persistence`, `destructive`, `obfuscation`, `install_time_behavior`, `addressed_to_reviewer`, `unrelated_to_stated_change`, `other`.

`addressed_to_reviewer` is for text in the package that speaks to a reviewer or a model, or asks for approval. It is treated as a finding like any other.

#### What the core does with reader output

- Validates it against the schema.
- Checks every finding: the line range must exist in the unit and the verbatim `excerpt` must appear in those exact lines. The core then computes and stores `excerpt_sha256` on the validated finding. A finding that cites bytes that are not there is dropped.
- If the output is schema-invalid, or any finding was dropped, the reading is `invalid`.

**The reader can only raise concern.** A reading passes only if every unit is `yes` and there are no findings. Anything else, including `invalid`, `unread`, a refusal, a timeout or an unavailable reader, makes the transition `stop`. No reader output can lift a `stop` produced by another rule.

#### Reference reader

- Built into the single `carat` binary (calling the Anthropic Messages API directly over hardened HTTPS) so end users need no secondary Python or Node runtime, while preserving the external subprocess reader contract for custom models or local runners.
- Default model: `claude-opus-5-5`, set in configuration and recorded in every reading. Reasoning effort is set explicitly because that model's default is `medium`.
- Output constrained with structured outputs (`output_config.format` with a JSON schema). The default model rejects forced tool choice, so structured outputs are the mechanism.
- The fixed instructions go first in the request so that prompt caching applies; the packet goes after them.
- `stop_reason` is checked before reading content. A `refusal` (the API's safety classifiers can decline content that looks like malware) is reported as `reader_refused` and makes the transition `stop`. A `max_tokens` stop is `invalid`.
- The API offers automatic fallback to another model on refusal. The default here is **not** to use it, and to treat a refusal as a stop. Revisit if section 13 shows refusals on ordinary packages.
- Bulk work that nobody is waiting on (the section 13 experiment, backfills) uses the Message Batches API at half price. Pull request checks do not.

Illustrative cost at list price on 2026-11-03 ($4 per million input tokens, $20 per million output): a reading with 20,000 input and 1,000 output tokens costs about $0.10. Real figures come from section 13.

#### Defenses against the package talking to the reader

Package contents are hostile input. The measures are layered because none is sufficient alone:

1. The reader's result is structured data with a fixed schema; free text is confined to short fields shown to humans.
2. Findings must cite real bytes, checked by the core.
3. The reader can only raise concern (above).
4. Deterministic rules decide most stops before the reader is consulted, and the reader cannot undo them.
5. Text addressed to a reviewer is itself a finding category.
6. The reader is not told what verdict its answer will produce.
7. Optional second reading with a different framing and unit order; both must pass (`readings = 2`).
8. Readings record the model and a hash of the instructions, so any admitted bytes can be read again later by a better model. A later reading that raises concern becomes an exposure notice (section 10.5).

Residual risk: a payload that needs no new reach, sits in bytes that are legitimately unexplainable, and persuades the reader. Section 12.3 lists this.

---

## 8. Verdicts and policy

### Verdicts

| Verdict | Meaning | Who acts |
| --- | --- | --- |
| `explained` | Every non-carried byte has an origin class other than `unexplained`. No breaks, no flags, no new reach | Nobody |
| `read` | Unexplained bytes, flags, or ordinary new reach were present. A reading passed. No stop rule fired | Nobody by default |
| `stop` | A stop rule fired | A person approves the exact bytes, or the change is not merged |

### Release age

| Age of the new release | Name | Effect |
| --- | --- | --- |
| Under `min_age` (default 24 hours) | fresh | Only `explained` passes. `read` becomes `stop` |
| Between | recent | Normal rules |
| At least `settled_age` (default 30 days), no advisory | settled | Unexplained bytes do not need an anchor (rule S6 does not apply). They are still read, and every other stop rule still applies |

The settled relaxation is an assumption, the same one a cooldown relies on, over a longer window: a release that has been public for a month without an advisory has survived some exposure. It is not evidence about the bytes, which is why the reading still happens. A reading is paid for once per pair of artifacts and then reused.

The fresh rule is where Carat earns its keep against a plain cooldown. A fresh release that is fully explained can be taken immediately, which matters when the release is a security fix.

### Stop rules

A transition is `stop` if any of these holds:

| # | Rule |
| --- | --- |
| S1 | The new artifact has no SHA-512 integrity, or the fetched bytes do not match it |
| S2 | A lock alarm other than `integrity_missing` (covered by S1) |
| S3 | An archive fact from section 7.2 |
| S4 | A break whose severity is stop |
| S5 | A new direct dependency, when `new_direct_dependency = confirm` (the default) |
| S6 | Unexplained bytes and no anchor, unless the release is settled |
| S7 | A high reach token that is new, or any new reach token located in unexplained bytes |
| S8 | A reading was required and did not pass |
| S9 | The release is fresh and the verdict would otherwise be `read` |
| S10 | An approval exists for these bytes but new stop reasons have appeared since (section 9.4) |

Otherwise the verdict is `explained` if there are no unexplained bytes, flags or new reach, and `read` if a reading passed.

### Change outcome

A change passes if every transition is `explained`, `read`, or `stop` with a valid approval. Otherwise it is blocked, and the report lists each stop with its reasons, route and approval subject.

### Configuration

A small TOML file. In pull request mode it is read from the protected base revision only, so a pull request cannot loosen its own policy.

| Key | Default | Meaning |
| --- | --- | --- |
| `min_age` | `24h` | Fresh threshold |
| `settled_age` | `30d` | Settled threshold |
| `new_direct_dependency` | `confirm` | `confirm` stops for a person; `check` treats it like a transitive one |
| `read_pass` | `allow` | `allow` lets `read` pass; `require_human` turns `read` into `stop` |
| `readings` | `1` | `2` requires two independent readings to pass |
| `read_on_stop` | `true` | Produce a summary even when already stopped |
| `reader.command` | reference reader | The executable to run |
| `reader.model` | `claude-opus-5-5` | Passed to the reference reader |
| `history_depth` | `20` | `K` in section 7.4 |
| `stores` | local only | Additional read-only record stores |

---

## 9. Records

Every result is a JSON document in canonical form: UTF-8, object keys sorted, no insignificant whitespace, integers only, no timestamps inside deterministic records. A record's identifier is the SHA-256 of its canonical bytes.

### 9.1 Artifact profile

Keyed by artifact SHA-512. Independent of any project, so it is computed once and can be shared.

Contents: package name and version; the inventory; archive facts; the anchor and how it was found; origin classes of every file against the artifact's own anchor, ignoring any reference; the reach set; manifest facts (install-time execution, dependency names, declared repository); hashes of every input used; tool version and binary hash.

### 9.2 Transition ledger

A **ledger** is a timeless, deterministic fact record. Its identifier (`ledger_id`) is the SHA-256 of its canonical JSON bytes. It also carries the **subject**: the SHA-256 of the canonical tuple `(ecosystem, name, reference SHA-512 or null, new SHA-512)`, which is what approvals bind to.

Contents: both profile identifiers; reference standing; `published_at` (RFC 3339 string from the registry snapshot, never a relative age); per-file origin classes with `carried` applied; totals in files and bytes per class; breaks and flags; new reach and new hostnames; the registry metadata snapshot hash; tool version.

Time-dependent policy rules (`S6` settled exemption, `S9` freshness) and the final verdict are computed in a **Decision** evaluated at an explicit `as_of` timestamp (default `now` in live runs, PR timestamp in historical replays, saved in input bundles for `carat replay`). Separating the timeless ledger from the `as_of` decision guarantees both byte-identical caching across time and exact replay.

### 9.3 Reading

Keyed by ledger identifier plus reader configuration. Contents: the packet hash, model identifier, instruction hash, schema version, per-unit results, validated findings, dropped-finding count, and the outcome (`passed`, `concern`, `invalid`, `unread`, `refused`, `unavailable`).

### 9.4 Approval

Contents: the subject, the ledger identifier the approver saw, the set of stop reasons at that time, who approved, when, and an optional note.

An approval is bound to the subject, which is to say to the exact bytes. It survives tool upgrades. It goes stale if a later ledger for the same subject has a stop reason the approver did not see (rule S10).

Approvals are made by people. An agent cannot approve.

### 9.5 Storage and sharing

A store is a directory tree: `profiles/`, `ledgers/`, `readings/`, `approvals/`, and optionally `inputs/` holding the exact input bundle for a record so it can be recomputed offline.

Additional read-only stores can be configured. In version 1 they are assumed to be inside the same organization. Profiles and ledgers from any store can be recomputed and compared. Readings and approvals cannot be recomputed, so trusting them across organizations needs signatures, which is milestone M6.

Example record in Appendix A.

---

## 10. Interfaces

### 10.1 Commands

| Command | Purpose |
| --- | --- |
| `carat explain <name>@<from>..<to>` | Check one transition straight from the registry and print the ledger. Needs no project. This is the demonstration |
| `carat check --base <lock> --head <lock>` | Check a change given lockfile and manifest files |
| `carat pr --base <rev> --head <rev>` | The same, reading both revisions from Git objects, never from the working tree |
| `carat add <name>[@<version>]` | Check a dependency before it is installed |
| `carat approve <subject>` | Record a person's approval of a stop |
| `carat exposure <name>@<version>` or `--sha512 <hex>` | Report where and when given bytes were admitted |
| `carat inventory --lock <lock>` | Profile everything currently in a lockfile. Never blocks; shows standing debt |
| `carat replay <bundle>` | Recompute deterministic records offline from a saved input bundle |

All commands take `--json`. Human output is a Markdown summary.

### 10.2 Exit codes

| Code | Meaning |
| --- | --- |
| 0 | No unapproved stops |
| 1 | At least one unapproved stop |
| 2 | The check could not run: bad input, bad configuration, a required fetch failed, tool failure |
| 64 | Usage error |

In CI, codes 1 and 2 both fail the check.

### 10.3 Pull request check

Carried over from Tau-Gate's working design:

- The workflow, the tool and the policy come from the protected base revision. The tool is a release archive pinned by SHA-256.
- The pull request's head is read as Git data and never executed.
- A change to the workflow or to the policy file is itself a stop.
- A maintainer other than the pull request's author, with write access, approves by posting exactly `carat approve <subject>`. The check re-verifies the author, their permission, and the subject before honouring it.
- The summary and JSON report are kept as a workflow artifact.

### 10.4 Agents

- `carat add --json` and `carat check --json` are the stable machine interface.
- An MCP server exposes the same two operations as tools.
- A documented hook recipe intercepts package-manager install commands in a coding agent and runs `carat add` first.
- An agent receives verdicts and reasons. It cannot create approvals. A stop means the agent reports to its person.

### 10.5 Exposure

`carat exposure` searches the record stores and the Git history of lockfiles in the repositories it is pointed at, and reports which projects admitted the given bytes, in which commits, between which dates.

It sees committed lockfiles and recorded checks. It does not see installs that never touched a lockfile.

### 10.6 What a reviewer sees

Illustrative only, not real output:

```
Carat: 2 of 19 changed packages need a person

STOP  somepkg 5.6.0 → 5.6.1        via root → build-tool → somepkg
      1 file changed, 100% unexplained
      no tag or commit for 5.6.1; the previous 20 releases had one   (anchor_lost)
      new: reads wallet objects, contacts 1 new hostname
      approve with: carat approve 7f3c…e21a

STOP  newthing 1.0.2               added directly in package.json
      new direct dependency: needs confirmation
      first published 9 days ago, 3 releases, no provenance

read  bundler 4.1.0 → 4.1.1        14 built files unexplained, read, consistent with 6 source commits
ok    16 packages fully explained
```

---

## 11. Architecture

### 11.1 Components

| Component | Does | Trust |
| --- | --- | --- |
| **core** | Archive inventory, lock diff, matching, history comparison, reach scan, policy, record canonicalization | Deterministic. No network, no subprocesses, no writes except records. Pure Rust with a minimal, pinned dependency set (`sha1`, `sha2`, `flate2`/`miniz_oxide`, `serde`/`serde_json`) |
| **fetch** | Gets artifacts, registry metadata, attestations, Git objects, advisories | Its output is untrusted until the core has verified it by hash, or labelled it as asserted with a snapshot hash |
| **reader** | Reads packets, returns findings | Built-in default or external subprocess. Output is untrusted and validated by the core |
| **gate** | Pull request workflow, approvals by comment | Runs from the protected base |
| **store** | Records and input bundles | Content-addressed |

### 11.2 Implementation

- One fresh Rust workspace producing one binary (`carat`) for core, fetch, built-in reader, gate and store. No legacy code dependencies.
- Fetch calls the system `git` and `curl` as subprocesses with hardened arguments. This avoids pulling a TLS and HTTP dependency tree into a supply chain tool.
- The strict streaming PAX/USTAR tar reader and canonical JSON serializer live directly in `carat-core` so archive anomaly facts, size/entry limits, and canonical hashing are enforced explicitly.
- Every dependency is pinned in `Cargo.lock` and audited. Once Carat supports an ecosystem, Carat's own dependencies in that ecosystem are checked with Carat.
- Releases are reproducible builds with published hashes. Targets: Linux x86_64 and arm64, macOS arm64.

### 11.3 Fetch rules

- Artifacts: HTTPS to `registry.npmjs.org` only in version 1. No redirects to other hosts, no credentials, no proxies.
- Git: HTTPS to the repository host named by the anchor. Objects only.
- Advisories: the OSV API, queried by package name and version only.
- Every fetched input is hashed. The hashes go into the record. With `--save-inputs`, the bytes go into an input bundle.

### 11.4 Limits

Starting values, taken from Tau-Gate's measured limits: 64 MiB per compressed artifact, 256 MiB expanded, 10,000 archive entries, 1 MiB per manifest, JSON nesting of 128. Exceeding a limit stops that one transition with `cannot_check`. It never fails the whole run.

### 11.5 Determinism

For a fixed tool binary and a fixed input bundle, profiles and ledgers are byte-identical on every run and every supported platform. `carat replay` exists to prove it. Readings are excluded from this guarantee.

### 11.6 Performance targets **[unmeasured]**

For a change with up to 20 transitions: deterministic layers under 30 seconds cold and under 5 seconds with a warm cache; readings under 60 seconds in total.

---

## 12. Threat model

### 12.1 Attackers and outcomes

| Attacker has | Typical move | What Carat does |
| --- | --- | --- |
| A stolen registry token, no source access | Publishes a version with code not in the repository | Deterministic stop: `anchor_lost`, `source_match_drop`, unexplained bytes with no anchor, often `provenance_lost` |
| The same, and edits `repository` to their own copy | Makes the source "match" | Deterministic stop: `repo_changed` |
| A stolen token and source write access; pushes a clean tag, publishes dirty built files | Hides behind files that never match source | No deterministic stop if built files are habitually unexplained. Depends on reach and the reading. A local publish usually also triggers `provenance_lost` |
| Control of the release workflow | Valid provenance on a dishonest build | Files that should match source and do not are still caught. Built files depend on reach and the reading until rebuilds exist (M6) |
| Maintainer access, commits harm openly | Sabotage or a backdoor in plain sight | The books balance. Only reach and a reading of the public diff can help. **Weakest case** |
| Nothing but a registry account | Lookalike or made-up package names, including names invented by models | New direct dependency stops for confirmation. A transitive one is checked against its own short history |
| A registry or mirror position | Serves different bytes for the same version | The lockfile's SHA-512 binds the bytes. A changed integrity for the same version is a lock alarm. Shared records make a second hash for one version visible |

### 12.2 Attacks on Carat itself

| Attack | Defense |
| --- | --- |
| Package text instructs the reader to approve | Section 7.6 |
| Malformed archive targets the parser | Strict streaming parser with fixed limits, fuzzed; never extracts or executes |
| Hostile Git repository | Object access only; no checkout, hooks, filters or submodules |
| SHA-1 collision between a source blob and an artifact file | Equality is confirmed with SHA-256 on the actual bytes |
| The pull request edits policy, workflow or tool | All three come from the protected base; edits are stops |
| Poisoned shared records | Profiles and ledgers are recomputable; readings and approvals from outside the organization are not trusted before M6 |
| A compromised Carat release | Reproducible builds, published hashes, pinned by hash in the workflow |
| Resource exhaustion | Per-artifact and per-run limits; a breach stops one transition |

### 12.3 What Carat does not catch

- Harm committed openly to the public source by someone with the right to commit.
- A payload in legitimately unexplainable built files that uses no new reach and gets past the reading.
- Code fetched and run at run time. Carat sees that the package can reach the network and run code, not what arrives.
- Installs that do not go through a checked lockfile.
- A mismatch between what was checked and what is installed, unless the install enforces lockfile integrity (`npm ci`).
- Anything in a package the change did not touch.

---

## 13. Validation

### 13.1 Validation corpus and pass marks

Validation runs against a **fresh corpus** of real public npm updates and known compromises—no legacy datasets required. The protocol file, the policy table and the pass marks are committed before any held-out run and not edited afterwards.

#### Ordinary updates

Two disjoint fresh samples of real public npm dependency-update pull requests (and direct package transitions via `carat explain`), split into a development set for tuning and a held-out set run once under the frozen policy.

Cautions:

- These updates are assumed ordinary, not proven harmless. Every stop is looked at by hand. A stop that turns out to be justified is recorded separately and removed from the false-stop count.
- For historical PRs, the habit profile uses only releases published before the release under test, and policy evaluation uses `--as-of` set to the PR timestamp (with OSV filtered to advisories published before `--as-of`).
- Readings cost real money. Estimate the held-out spend from the development set and confirm before running the held-out set.

#### Known compromises

At least twelve cases in three groups, each with its expected result written down first.

| Group | Candidates | Expected |
| --- | --- | --- |
| Stolen credentials | `flatmap-stream` 2018; `ua-parser-js` 2021; `coa` and `rc` 2021; `eslint-config-prettier` 2025; `nx` 2025; `chalk` and `debug` 2025; Shai-Hulud 2025; `axios`, `jscrambler`, `wppconnect` 2026 **[reported]** | Deterministic stop (without OSV hindsight) |
| Harm committed openly | `colors` and `faker` 2022; `node-ipc` 2022 | Books balance. Record what reach and the reading show |
| Hostile new packages | A sample from a public malicious-package dataset | Stop as new direct dependency. Record what the profile shows |

Removed malicious versions are no longer on the registry. Bytes must come from public research datasets; check availability and terms first. Handle them as hazardous: never execute, never extract outside the streaming reader, never commit to a repository. Where bytes or historical registry metadata cannot be obtained, run the layers that can run and mark the case partial.

#### Measures and pass marks

| # | Measure | Pass mark |
| --- | --- | --- |
| P1 | Stolen-credential cases stopped by a deterministic zero-day rule about the bytes or the release: S2, S4 (excluding `known_malicious` hindsight), S6 or S7. Stops that come only from OSV hindsight, a missing reading (S8), freshness (S9) or being a new direct dependency (S5) do not count | All of them |
| P2 | Held-out pull requests with zero stops under default policy | At least 80% |
| P3 | Reading cost per held-out pull request at list price of the default model | Median at most $0.50, 90th percentile at most $5 |
| P4 | Profiles and ledgers byte-identical across three runs from the same inputs | All |
| P5 | Openly committed harm: what reach and readings report | Reported, no pass mark; the sample is too small |

Also reported without a pass mark: share of changed bytes per origin class; share of transitions needing a reading; per-transition stop rate; which rules cause stops; reader refusals on ordinary packages.

The 80% in P2 continues the floor Tau-Gate used. The cost marks in P3 are a proposal; change them before the run if they are wrong for you, not after.

#### Procedure

1. Write the scripts and tune break severities and thresholds on cohorts A and B only.
2. Commit the protocol, policy table and pass marks. Record the commit.
3. Run the known-compromise cases.
4. Run cohorts C and D once.
5. Report every number, including failures.

**Go** if P1, P2, P3 and P4 pass. If P2 fails, report which rules caused the stops. The fix is a design change, and it must then be tested on pull requests not used here. A failed held-out run is never rescored.

### 13.2 Before any public claim

A fresh cohort, selected under a protocol fixed in advance, from repositories used in none of the above.

### 13.3 Ongoing controls

- Authored test cases for every break, stop rule and normalization, each with its nearest negative case.
- Fuzzing of the archive and JSON parsers, carried over from Tau-Gate.
- A replay suite of the known-compromise cases, run on every release.
- A reader regression set: fixed packets with expected outcomes, including packets containing instructions addressed to the reader.

---

## 14. Milestones

| # | Deliverable | Done when |
| --- | --- | --- |
| M0 | Experiment zero | Section 13.1 reported, with a go or no-go |
| M1 | Deterministic ledger for npm: `explain` and `check`, profiles, ledgers, policy. No reader; anything needing a reading stops | Records are reproducible; the authored controls pass |
| M2 | Reader, readings, approvals, local store | Reader regression set passes; hostile-packet cases stop |
| M3 | Pull request check on GitHub | Blocked, approved and stale-approval states verified on a real repository |
| M4 | Agent interface: `add`, MCP server, hook recipe | An agent installing a hostile test package is stopped end to end |
| M5 | pnpm and Yarn lockfiles; `exposure`; `inventory` | Same transitions produce the same ledgers regardless of lockfile format |
| M6 | Provenance signature verification; rebuild attestations as an origin class; signed records; next ecosystems | Each has its own controls |

M1 before M2 is deliberate: the deterministic layers must be right before a model is put on top of them.

---

## 15. What to take from Tau-Gate

Tau-Gate is at `/Volumes/Storage/taugate4`, release 4.3.0 (release commit `808f5ee`, head `6c1cc63`), Apache-2.0, same owner.

### Reuse

| Path | What it is | Change needed |
| --- | --- | --- |
| `src/digest.rs` | SHA-256 and SHA-512, standard library only | Add SHA-1 for Git blob identifiers |
| `src/artifact.rs` | Integrity verification, gzip and DEFLATE, streaming tar reader | Today it reads only `package.json` and `binding.gyp`. Make it emit the full inventory, and turn dialect rejections into recorded facts |
| `src/parser.rs` | Strict JSON parser with duplicate-key rejection; small TOML-subset config parser | None expected |
| `src/graph.rs`, `src/review.rs` | npm lockfile version 3 parsing, package change diff, introducer paths | Remove whole-snapshot completeness |
| `src/evidence.rs` | npm install-time execution rules, bundled dependency handling | Keep the rules, drop the approval-fingerprint model |
| `src/pnpm.rs`, `src/yarn.rs`, `src/yarn_berry.rs`, `src/npm_legacy.rs` | Other lockfile readers | For M5; only name, version, source and integrity are needed |
| `tools/pr_review.py` | Capturing both revisions from Git objects; approval subject and store logic; summary rendering | Port to Rust inside the one binary |
| `tools/github_pr_approval.py`, `docs/examples/npm-pr-review.yml` | Approval by maintainer comment; the single-file workflow | Adapt names |
| `tools/npm_evidence.py` | Registry acquisition rules | Port |
| `fuzz/` | Archive and JSON fuzz harness and seeds | Carry over |
| `tools/release/`, `.github/workflows/release.yml`, `docs/release-verification.md` | Reproducible release recipe | Carry over |
| `tools/verify_npm_evidence.py`, `tools/verify_pr_review.py` | Black-box control suites | Adapt as the model for section 13.3 |

### Leave behind

`src/math.rs` and the spectral topology; the C interface in `include/`; `src/config.rs`, `src/policy.rs`, `src/telemetry.rs`, `src/semver.rs`; the approval-fingerprint scheme; and every study script under `tools/`.

### Lessons that shaped this design

1. **Whole-lockfile completeness made the tool unusable.** On 120 real pull requests Tau-Gate completed 70. A post-hoc look showed 38 of the 50 failures came from packages the pull request never touched. Carat is change-scoped from the first line.
2. **A single complete-or-incomplete answer hides everything useful.** Carat grades each file and gives a verdict per transition.
3. **"Cannot check" must never be a wall.** It is a stop on one package that a person can approve against exact bytes.
4. **A strict archive reader rejected real packages over harmless dialect differences.** Carat records oddities as facts.
5. **The product surface ended up in Python and shell around a Rust library.** Carat is one binary.
6. **The graph mathematics was computed and never used by any decision.** Carat carries no fact that nothing reads.
7. **Earlier claims had to be withdrawn.** Carat makes none until section 13 has run.

---

## 16. Prior art

From one search pass on 2026-11-19. This is not a market survey. **[reported]** throughout.

| Tool or feature | What it does | Relation to Carat |
| --- | --- | --- |
| `npm-verified`, npm's `package-audit`, `npm-vs-repo` | Compare a published package with its repository at a tag | The same core comparison, run by hand on one package, with no reference version, history or records |
| vlt `reproduce` | Rebuilds a package from source and compares | A source of the `rebuilt` origin class |
| Google OSS Rebuild | Rebuilds popular npm, PyPI and crates packages and publishes attestations | Another source of `rebuilt`; covers only popular packages |
| pnpm `trustPolicy: no-downgrade` | Refuses a release whose publishing trust dropped | The same idea as `provenance_lost`, as one signal among several |
| pnpm and npm `minimumReleaseAge` | Cooldown | Carat uses age as an input and can justify skipping the wait |
| Socket and similar | Commercial analysis of packages, including model-based scanning | Closest in aim. Carat's difference is that it is local, its deterministic part is reproducible by anyone, and its results are bound to exact bytes under the user's own policy |
| `cargo vet` | Shared human audits of Rust crates, including version-to-version audits | The model for shareable records; Carat binds to bytes and produces the first pass by machine |

What I did not find: this comparison running automatically on every update, measured against the package's own history, with the remainder read and the result recorded against exact bytes. That combination is the product. If it already exists, section 13 is still worth running before deciding anything.

---

## 17. Decisions for the owner

1. **Name.** "Carat" is a placeholder.
2. **License.** Apache-2.0 assumed, matching Tau-Gate.
3. **Pass marks.** Confirm or change P2 and P3 before the experiment.
4. **Reader.** Default model, one reading or two, and whether `read` may pass without a person.
5. **Ages.** `min_age` of 24 hours and `settled_age` of 30 days are proposals.
6. **New direct dependencies.** Stopping for confirmation is the default; in an agent setting this is the main gate.
7. **Reader language.** Python or TypeScript for the reference reader.
8. **Tau-Gate.** Frozen at 4.3.0 while this is built, or kept in service.
9. **Users.** The largest gap that code cannot close is that nobody outside the owner has used the predecessor. Decide whether that changes here, and when.

---

## Appendix A. Example ledger

Illustrative. Field names are proposals; hashes are shortened.

```json
{
  "kind": "ledger",
  "schema": 1,
  "subject": "7f3c…e21a",
  "ecosystem": "npm",
  "name": "somepkg",
  "reference": {"version": "5.6.0", "sha512": "9a1b…", "standing": "admitted", "profile": "c2d4…"},
  "new": {"version": "5.6.1", "sha512": "44e0…", "profile": "81aa…", "published_at": "2026-11-19T19:00:00Z"},
  "anchor": {"found": false, "methods_tried": ["provenance", "gitHead", "tag"]},
  "files": [
    {"path": "package/index.js", "sha256": "b0c1…", "bytes": 18211, "class": "unexplained"},
    {"path": "package/package.json", "sha256": "5d7e…", "bytes": 1203, "class": "unexplained"}
  ],
  "totals": {"carried": {"files": 9, "bytes": 30412}, "unexplained": {"files": 2, "bytes": 19414}},
  "breaks": ["anchor_lost", "source_match_drop"],
  "flags": [],
  "new_reach": ["browser_sensitive", "net", "encoded_blob"],
  "new_hostnames": ["example.invalid"],
  "inputs": {"registry_snapshot_sha256": "e9f0…", "reference_tree": "a1b2…"},
  "tool": {"version": "0.1.0"}
}
```

The `Decision` evaluated at `as_of = "2026-11-19T22:00:00Z"` adds `published_age_hours: 3`, `policy_version: 1`, `stop_rules: ["S4", "S6", "S7", "S9"]`, and `verdict: "stop"`.

## Appendix B. Reader findings schema

```json
{
  "type": "object",
  "additionalProperties": false,
  "required": ["units", "findings", "summary"],
  "properties": {
    "units": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["unit_id", "fits_stated_change"],
        "properties": {
          "unit_id": {"type": "string"},
          "fits_stated_change": {"enum": ["yes", "no", "cannot_tell"]}
        }
      }
    },
    "findings": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["unit_id", "start_line", "end_line", "excerpt", "category", "statement", "confidence"],
        "properties": {
          "unit_id": {"type": "string"},
          "start_line": {"type": "integer"},
          "end_line": {"type": "integer"},
          "excerpt": {"type": "string"},
          "category": {"enum": ["exfiltration", "remote_code", "credential_access", "persistence", "destructive",
                                "obfuscation", "install_time_behavior", "addressed_to_reviewer",
                                "unrelated_to_stated_change", "other"]},
          "statement": {"type": "string"},
          "confidence": {"enum": ["low", "medium", "high"]}
        }
      }
    },
    "summary": {"type": "string"}
  }
}
```

The core verifies that `excerpt` matches lines `start_line..end_line` of `unit_id`, computes `excerpt_sha256` for the stored reading record, and enforces length limits (300 characters per statement, 600 for the summary) after parsing.

## Appendix C. Sources

Checked directly on 2026-11-19:

- `https://registry.npmjs.org/vite/latest` — version metadata fields: `repository.directory`, `dist.integrity`, `dist.attestations`, `_npmUser.trustedPublisher`; `gitHead` absent.
- `https://registry.npmjs.org/-/npm/v1/attestations/vite@8.3.8` — publish attestation and SLSA v1 provenance, with workflow repository, path, ref and commit.
- Model identifiers, prices and API behaviour: Anthropic API reference material cached 2026-11-03.

From search summaries, 2026-11-19; confirm before relying on any of them:

- pnpm supply chain settings: https://pnpm.io/supply-chain-security and https://pnpm.io/blog/releases/10.21
- npm `minimumReleaseAge`: https://socket.dev/blog/npm-introduces-minimumreleaseage-and-bulk-oidc-configuration
- `npm-verified`: https://npmjs.com/package/npm-verified
- npm `package-audit`: https://github.com/npm/package-audit
- vlt `reproduce`: https://socket.dev/blog/vlt-launches-reproduce
- Google OSS Rebuild: https://github.com/google/oss-rebuild
- wppconnect compromise: https://www.stepsecurity.io/blog/wppconnect-compromised-malicious-releases-steal-secrets-and-whatsapp-sessions
- axios compromise: https://venturebeat.com/security/axios-npm-supply-chain-attack-rat-maintainer-token-2026
- jscrambler compromise: https://dev.to/netsecops_io/malicious-jscrambler-npm-package-versions-deploy-cross-platform-infostealer-4835
- Provenance on a malicious release: https://dev.to/mr_manushukla/npm-provenance-signed-the-malware-on-4-august-2026-what-attestations-prove-and-what-a-cooldown-2nad
