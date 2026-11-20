use assay_core::archive::{LoadedArchive, strip_archive_root};
use assay_core::canonical::parse_rfc3339_unix;
use assay_core::digest::{parse_sha512_sri, sha256_hex};
use assay_core::history::ReleaseMetaSummary;
use assay_core::model::{Anchor, AnchorMethod, ArchiveLimits, ManifestFacts};
use assay_core::normalize::canonicalize_repo_url;
use assay_core::source::SourceSnapshot;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub struct Fetcher {
    cache_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct RegistryPackageDoc {
    pub raw_bytes: Vec<u8>,
    pub json: Value,
}

#[derive(Debug, Clone)]
pub struct ProvenanceInfo {
    pub commit: String,
    pub repository_url: Option<String>,
    pub workflow_path: Option<String>,
    pub workflow_ref: Option<String>,
}

impl Fetcher {
    pub fn new(cache_dir: PathBuf) -> Result<Self, String> {
        fs::create_dir_all(cache_dir.join("tarballs"))
            .map_err(|e| format!("failed to create cache dir: {e}"))?;
        fs::create_dir_all(cache_dir.join("git"))
            .map_err(|e| format!("failed to create git cache dir: {e}"))?;
        Ok(Self { cache_dir })
    }

    pub fn fetch_registry_package(&self, name: &str) -> Result<RegistryPackageDoc, String> {
        let encoded = encode_npm_name(name);
        let url = format!("https://registry.npmjs.org/{encoded}");
        let bytes = curl_get(&url, &[], true)?;
        let json: Value = serde_json::from_slice(&bytes)
            .map_err(|e| format!("failed to parse registry json for {name}: {e}"))?;
        Ok(RegistryPackageDoc {
            raw_bytes: bytes,
            json,
        })
    }

    pub fn read_cached_tarball(&self, sha512_hex: &str) -> Option<Vec<u8>> {
        fs::read(self.cache_dir.join("tarballs").join(format!("{sha512_hex}.tgz"))).ok()
    }

    /// Selects the newest release strictly older than `new_version` that is settled
    /// (published at least `settled_age_days` before `as_of`).
    pub fn find_settled_reference_version(
        &self,
        doc: &Value,
        new_version: &str,
        as_of_rfc3339: &str,
        settled_age_days: i64,
    ) -> Option<String> {
        let as_of_unix = parse_rfc3339_unix(as_of_rfc3339)?;
        let cutoff = as_of_unix - settled_age_days * 86_400;
        let time_map = doc.get("time")?.as_object()?;
        let versions_map = doc.get("versions")?.as_object()?;
        let new_pub = time_map
            .get(new_version)
            .and_then(|v| v.as_str())
            .and_then(parse_rfc3339_unix);

        let mut best: Option<(i64, String)> = None;
        for ver in versions_map.keys() {
            if ver == new_version || ver.contains('-') {
                continue;
            }
            let Some(ts) = time_map
                .get(ver)
                .and_then(|v| v.as_str())
                .and_then(parse_rfc3339_unix)
            else {
                continue;
            };
            if let Some(np) = new_pub {
                if ts >= np {
                    continue;
                }
            }
            if ts <= cutoff {
                if best.as_ref().map(|(bt, _)| ts > *bt).unwrap_or(true) {
                    best = Some((ts, ver.clone()));
                }
            }
        }
        best.map(|(_, v)| v)
    }

    pub fn fetch_and_inspect_tarball(
        &self,
        tarball_url: &str,
        integrity: Option<&str>,
        limits: ArchiveLimits,
    ) -> Result<LoadedArchive, String> {
        if !tarball_url.starts_with("https://registry.npmjs.org/") {
            return Err(format!(
                "refusing non-npmjs tarball URL in v1: {tarball_url}"
            ));
        }

        let expected_sha512 = integrity.and_then(parse_sha512_sri);
        let cached_bytes = expected_sha512.as_ref().and_then(|hex| {
            let p = self.cache_dir.join("tarballs").join(format!("{hex}.tgz"));
            fs::read(p).ok()
        });

        let compressed = match cached_bytes {
            Some(b) => b,
            None => {
                // Disallow cross-host redirects on artifact fetches.
                let b = curl_get(tarball_url, &[], false)?;
                let actual_hex = assay_core::digest::sha512_hex(&b);
                if let Some(ref exp) = expected_sha512 {
                    if !actual_hex.eq_ignore_ascii_case(exp) {
                        return Err(format!(
                            "tarball SHA-512 mismatch for {tarball_url}: expected {exp}, got {actual_hex}"
                        ));
                    }
                }
                let p = self
                    .cache_dir
                    .join("tarballs")
                    .join(format!("{actual_hex}.tgz"));
                let _ = fs::write(p, &b);
                b
            }
        };

        assay_core::archive::inspect_tgz(&compressed, expected_sha512.as_deref(), limits)
    }

    pub fn fetch_provenance(
        &self,
        name: &str,
        version: &str,
        expected_sha512_hex: &str,
    ) -> Option<ProvenanceInfo> {
        let encoded = encode_npm_name(name);
        let url = format!("https://registry.npmjs.org/-/npm/v1/attestations/{encoded}@{version}");
        let bytes = curl_get(&url, &[], true).ok()?;
        let root: Value = serde_json::from_slice(&bytes).ok()?;
        let attestations = root.get("attestations")?.as_array()?;

        for att in attestations {
            let pred_type = att
                .get("predicateType")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !pred_type.contains("slsa.dev/provenance") {
                continue;
            }
            let payload_b64 = att
                .pointer("/bundle/dsseEnvelope/payload")
                .and_then(|v| v.as_str())?;
            let payload_bytes = base64_decode(payload_b64)?;
            let stmt: Value = serde_json::from_slice(&payload_bytes).ok()?;

            // Confirm the provenance subject digest matches our artifact's SHA-512.
            let subject_matches = stmt
                .get("subject")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter().any(|s| {
                        s.pointer("/digest/sha512")
                            .and_then(|d| d.as_str())
                            .map(|d| d.eq_ignore_ascii_case(expected_sha512_hex))
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false);
            if !subject_matches {
                continue;
            }

            let commit = stmt
                .pointer("/predicate/buildDefinition/resolvedDependencies")
                .and_then(|v| v.as_array())
                .and_then(|deps| {
                    deps.iter().find_map(|d| {
                        d.pointer("/digest/gitCommit")
                            .and_then(|c| c.as_str())
                            .filter(|c| is_hex_commit(c))
                            .map(|c| c.to_ascii_lowercase())
                    })
                })?;

            let repo_url = stmt
                .pointer("/predicate/buildDefinition/externalParameters/workflow/repository")
                .and_then(|v| v.as_str())
                .map(String::from);
            let wf_path = stmt
                .pointer("/predicate/buildDefinition/externalParameters/workflow/path")
                .and_then(|v| v.as_str())
                .map(String::from);
            let wf_ref = stmt
                .pointer("/predicate/buildDefinition/externalParameters/workflow/ref")
                .and_then(|v| v.as_str())
                .map(String::from);

            return Some(ProvenanceInfo {
                commit,
                repository_url: repo_url,
                workflow_path: wf_path,
                workflow_ref: wf_ref,
            });
        }
        None
    }

    pub fn query_osv(
        &self,
        name: &str,
        version: &str,
        as_of_rfc3339: Option<&str>,
    ) -> (Vec<String>, bool) {
        let body = serde_json::json!({
            "package": { "name": name, "ecosystem": "npm" },
            "version": version
        });
        let Ok(resp) = curl_post_json("https://api.osv.dev/v1/query", &body.to_string()) else {
            return (Vec::new(), true);
        };
        let Ok(val) = serde_json::from_slice::<Value>(&resp) else {
            return (Vec::new(), true);
        };
        let Some(vulns) = val.get("vulns").and_then(|v| v.as_array()) else {
            return (Vec::new(), false);
        };

        let cutoff = as_of_rfc3339.and_then(parse_rfc3339_unix);
        let mut ids = Vec::new();
        for v in vulns {
            let Some(id) = v.get("id").and_then(|x| x.as_str()) else {
                continue;
            };
            let is_mal = id.starts_with("MAL-")
                || v.get("aliases")
                    .and_then(|a| a.as_array())
                    .map(|arr| {
                        arr.iter()
                            .any(|x| x.as_str().map(|s| s.starts_with("MAL-")).unwrap_or(false))
                    })
                    .unwrap_or(false);
            if !is_mal {
                continue;
            }
            if let Some(cut) = cutoff {
                if let Some(pub_ts) = v
                    .get("published")
                    .and_then(|p| p.as_str())
                    .and_then(parse_rfc3339_unix)
                {
                    if pub_ts > cut {
                        continue;
                    }
                }
            }
            ids.push(id.to_string());
        }
        ids.sort();
        (ids, false)
    }

    /// Resolves the anchor (provenance -> gitHead -> tag) and fetches a minimal
    /// object-only source snapshot for matching the artifact's files.
    pub fn resolve_anchor_and_source(
        &self,
        name: &str,
        version: &str,
        archive: &LoadedArchive,
        manifest: &ManifestFacts,
        registry_version: &Value,
        non_carried_archive: Option<&LoadedArchive>,
    ) -> (Anchor, Option<SourceSnapshot>) {
        let mut methods_tried = Vec::new();
        let mut found_commits: Vec<(AnchorMethod, String)> = Vec::new();

        // 1. Provenance
        methods_tried.push("provenance".to_string());
        let has_attestation_hint = registry_version.pointer("/dist/attestations").is_some();
        let prov = if has_attestation_hint {
            self.fetch_provenance(name, version, &archive.inventory.sha512)
        } else {
            None
        };
        if let Some(ref p) = prov {
            found_commits.push((AnchorMethod::ProvenanceAsserted, p.commit.clone()));
        }

        // Repository identity: provenance first, then verified artifact's package.json.
        let repo_url = prov
            .as_ref()
            .and_then(|p| p.repository_url.clone())
            .or_else(|| manifest.repository_url.clone())
            .map(|u| canonicalize_repo_url(&u));

        // 2. gitHead
        methods_tried.push("gitHead".to_string());
        if let Some(gh) = registry_version.get("gitHead").and_then(|v| v.as_str()) {
            if is_hex_commit(gh) {
                found_commits.push((AnchorMethod::GitHead, gh.to_ascii_lowercase()));
            }
        }

        // 3. Tag by convention (if repo_url is HTTPS)
        let mut matched_tag_ref: Option<String> = None;
        let mut remote_heads: BTreeMap<String, String> = BTreeMap::new();
        let mut remote_tags: BTreeSet<String> = BTreeSet::new();
        let mut ls_remote_error: Option<String> = None;
        if let Some(ref url) = repo_url {
            if validate_public_https_git_url(url).is_ok() {
                methods_tried.push("tag".to_string());
                match git_ls_remote(&self.cache_dir, url) {
                    Ok(refs) => {
                        for (refname, sha) in &refs {
                            if refname.starts_with("refs/heads/") {
                                remote_heads.insert(refname.clone(), sha.clone());
                            } else if refname.starts_with("refs/tags/") {
                                remote_tags.insert(sha.clone());
                            }
                        }
                        if let Some((tag_ref, commit)) = find_matching_tag(name, version, &refs) {
                            matched_tag_ref = Some(tag_ref);
                            found_commits.push((AnchorMethod::Tag, commit));
                        }
                    }
                    Err(e) => {
                        ls_remote_error = Some(e);
                    }
                }
            }
        }

        // Check for conflicts between anchor methods.
        // Security ordering: Provenance > Tag (repo-backed) > GitHead (unsigned publisher metadata).
        let unique_commits: BTreeSet<String> = found_commits
            .iter()
            .map(|(_, c)| c.to_ascii_lowercase())
            .collect();
        let mut conflict_details: Vec<String> = Vec::new();
        let chosen: Option<(AnchorMethod, String)> = if unique_commits.len() > 1 {
            conflict_details = found_commits
                .iter()
                .map(|(m, c)| format!("{m:?}={c}"))
                .collect();
            let prov_commit = found_commits
                .iter()
                .find(|(m, _)| matches!(m, AnchorMethod::ProvenanceAsserted | AnchorMethod::ProvenanceVerified));
            let tag_commit = found_commits
                .iter()
                .find(|(m, _)| *m == AnchorMethod::Tag);

            match (prov_commit, tag_commit) {
                (Some((_, pc)), Some((_, tc))) if !pc.eq_ignore_ascii_case(tc) => {
                    return (
                        Anchor {
                            found: false,
                            commit: None,
                            method: None,
                            methods_tried,
                            conflict: true,
                            conflict_details,
                            repository_url: repo_url,
                            repository_directory: manifest.repository_directory.clone(),
                            workflow_path: prov.as_ref().and_then(|p| p.workflow_path.clone()),
                            workflow_ref: prov.as_ref().and_then(|p| p.workflow_ref.clone()),
                            reachable_from_branch: None,
                            lookup_error: None,
                        },
                        None,
                    );
                }
                (Some((pm, pc)), _) => Some((*pm, pc.clone())),
                (None, Some((tm, tc))) => Some((*tm, tc.clone())),
                (None, None) => found_commits.into_iter().next(),
            }
        } else {
            found_commits.into_iter().next()
        };

        let Some((method, commit)) = chosen else {
            return (
                Anchor {
                    found: false,
                    commit: None,
                    method: None,
                    methods_tried,
                    conflict: false,
                    conflict_details: Vec::new(),
                    repository_url: repo_url,
                    repository_directory: manifest.repository_directory.clone(),
                    workflow_path: None,
                    workflow_ref: None,
                    reachable_from_branch: None,
                    lookup_error: ls_remote_error,
                },
                None,
            );
        };

        let Some(ref url) = repo_url else {
            return (
                Anchor {
                    found: false,
                    commit: Some(commit),
                    method: Some(method),
                    methods_tried,
                    conflict: false,
                    conflict_details,
                    repository_url: None,
                    repository_directory: manifest.repository_directory.clone(),
                    workflow_path: prov.as_ref().and_then(|p| p.workflow_path.clone()),
                    workflow_ref: prov.as_ref().and_then(|p| p.workflow_ref.clone()),
                    reachable_from_branch: None,
                    lookup_error: None,
                },
                None,
            );
        };

        // Branch/tag reachability check (prevents GitHub fork-PR commit spoofing via unsigned gitHead!):
        // - Tag or Provenance or exact match on a remote branch/tag ref -> reachable = Some(true).
        // - Unsigned GitHead not matching any branch head or tag -> check ancestry against default branch,
        //   or mark reachable = Some(false) so `AnchorUnreachable` fires and prevents silent `explained`!
        let wf_ref = prov.as_ref().and_then(|p| p.workflow_ref.clone());
        let directly_referenced = method == AnchorMethod::Tag
            || matches!(method, AnchorMethod::ProvenanceAsserted | AnchorMethod::ProvenanceVerified)
            || remote_heads.values().any(|s| s.eq_ignore_ascii_case(&commit))
            || remote_tags.iter().any(|s| s.eq_ignore_ascii_case(&commit));

        let fetch_ref = matched_tag_ref.as_deref();
        let (snapshot, _snapshot_err) = match self.fetch_git_source_snapshot(
            url,
            &commit,
            fetch_ref,
            name,
            manifest.repository_directory.as_deref(),
            archive,
            non_carried_archive,
        ) {
            Ok(s) => (Some(s), None),
            Err(e) => (None, Some(e)),
        };

        let reachable_from_branch = if directly_referenced {
            Some(true)
        } else if snapshot.is_some() {
            // For unsigned gitHead commits not directly pointed to by a branch/tag, verify ancestry against
            // the default branch (main/master) with a bounded shallow check so fork-only commits get flagged!
            let default_branch_sha = remote_heads
                .get("refs/heads/main")
                .or_else(|| remote_heads.get("refs/heads/master"))
                .or_else(|| remote_heads.values().next());
            match default_branch_sha {
                Some(head_sha) => Some(self.is_commit_ancestor_of(url, &commit, head_sha)),
                None => Some(false),
            }
        } else {
            None
        };

        let pkg_dir = snapshot
            .as_ref()
            .and_then(|s| s.package_dir.clone())
            .or_else(|| manifest.repository_directory.clone());

        // Only populate `lookup_error` on genuine upstream unreachability (`ls_remote_error`).
        // A nonexistent attacker-chosen `gitHead` commit against a reachable repo MUST NOT suppress `AnchorLost`.
        let anchor = Anchor {
            found: snapshot.is_some(),
            commit: Some(commit),
            method: Some(method),
            methods_tried,
            conflict: false,
            conflict_details,
            repository_url: repo_url,
            repository_directory: pkg_dir,
            workflow_path: prov.as_ref().and_then(|p| p.workflow_path.clone()),
            workflow_ref: wf_ref,
            reachable_from_branch,
            lookup_error: ls_remote_error,
        };

        (anchor, snapshot)
    }

    fn is_commit_ancestor_of(&self, repo_url: &str, commit: &str, branch_head: &str) -> bool {
        if commit.eq_ignore_ascii_case(branch_head) {
            return true;
        }
        let repo_key = sha256_hex(repo_url.as_bytes());
        let repo_dir = self.cache_dir.join("git").join(&repo_key[..24]);
        if !repo_dir.exists() {
            return false;
        }
        // Fetch bounded commit history (treeless/blobless, commit graph only) from default branch head.
        let _ = run_git(
            &repo_dir,
            &[
                "fetch",
                "--no-tags",
                "--filter=blob:none",
                "--depth=200",
                "origin",
                branch_head,
            ],
        );
        run_git(&repo_dir, &["merge-base", "--is-ancestor", commit, branch_head]).is_ok()
    }

    /// Best-effort fetch of commit subjects and a bounded unified source diff
    /// between `from_commit` and `to_commit` for reading packet context.
    #[allow(dead_code)]
    pub fn fetch_commit_subjects_and_source_diff(
        &self,
        repo_url: &str,
        from_commit: &str,
        to_commit: &str,
        pkg_dir: Option<&str>,
    ) -> (Vec<String>, Option<String>) {
        if !repo_url.starts_with("https://") || from_commit.eq_ignore_ascii_case(to_commit) {
            return (Vec::new(), None);
        }
        let repo_key = sha256_hex(repo_url.as_bytes());
        let repo_dir = self.cache_dir.join("git").join(&repo_key[..24]);
        if !repo_dir.exists() {
            return (Vec::new(), None);
        }

        // Shallow deepen slightly so commit range subjects are visible without pulling huge history.
        let _ = run_git(
            &repo_dir,
            &[
                "fetch",
                "--no-tags",
                "--filter=blob:none",
                "--depth=50",
                "origin",
                to_commit,
            ],
        );

        let range = format!("{from_commit}..{to_commit}");
        let mut log_args = vec!["log", "--format=%s", "-n", "30", &range];
        if let Some(dir) = pkg_dir {
            if !dir.is_empty() {
                log_args.push("--");
                log_args.push(dir);
            }
        }
        let subjects: Vec<String> = run_git(&repo_dir, &log_args)
            .ok()
            .map(|b| {
                String::from_utf8_lossy(&b)
                    .lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        // Bounded source diff (max 24 KiB) for reader context on built files.
        let mut diff_args = vec!["diff", "--unified=3", from_commit, to_commit];
        if let Some(dir) = pkg_dir {
            if !dir.is_empty() {
                diff_args.push("--");
                diff_args.push(dir);
            }
        }
        let source_diff = run_git(&repo_dir, &diff_args).ok().and_then(|b| {
            if b.is_empty() {
                return None;
            }
            let s = String::from_utf8_lossy(&b);
            if s.len() <= 24_000 {
                Some(s.to_string())
            } else {
                let mut end = 24_000;
                while !s.is_char_boundary(end) && end > 0 {
                    end -= 1;
                }
                Some(format!("{}\n...[source diff truncated at 24 KiB]", &s[..end]))
            }
        });

        (subjects, source_diff)
    }

    fn fetch_git_source_snapshot(
        &self,
        repo_url: &str,
        commit: &str,
        tag_ref: Option<&str>,
        pkg_name: &str,
        declared_dir: Option<&str>,
        archive: &LoadedArchive,
        ref_archive: Option<&LoadedArchive>,
    ) -> Result<SourceSnapshot, String> {
        validate_public_https_git_url(repo_url)?;
        if !is_hex_commit(commit) {
            return Err(format!("invalid git commit oid '{commit}'"));
        }

        let repo_key = sha256_hex(repo_url.as_bytes());
        let repo_dir = self.cache_dir.join("git").join(&repo_key[..24]);
        let alternates = repo_dir.join("objects").join("info").join("alternates");
        if alternates.exists() {
            return Err("refusing cached git repo with objects/info/alternates".into());
        }
        if !repo_dir.exists() {
            fs::create_dir_all(&repo_dir).map_err(|e| format!("mkdir git cache: {e}"))?;
            run_git(&repo_dir, &["init", "--bare", "--quiet"])?;
        }
        // Always pin a clean bare git config so a planted `.assay/cache/git/<key>/config`
        // can never inject `url.*.insteadOf`, hooks, filters, or sshCommand.
        let clean_config = format!(
            "[core]\n\trepositoryformatversion = 1\n\tfilemode = true\n\tbare = true\n[extensions]\n\tpartialclone = origin\n[remote \"origin\"]\n\turl = {repo_url}\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n\tpromisor = true\n\tpartialclonefilter = blob:none\n"
        );
        assay_core::store::write_atomic_no_symlink(&repo_dir.join("config"), clean_config.as_bytes())?;

        // Check if commit object is already in local bare cache; if not, fetch shallow without blobs.
        let has_commit = run_git(&repo_dir, &["cat-file", "-e", &format!("{commit}^{{commit}}")]).is_ok();
        if !has_commit {
            let fetched = run_git(
                &repo_dir,
                &[
                    "fetch",
                    "--no-tags",
                    "--filter=blob:none",
                    "--depth=1",
                    "origin",
                    commit,
                ],
            )
            .is_ok();
            if !fetched {
                if let Some(tref) = tag_ref {
                    run_git(
                        &repo_dir,
                        &[
                            "fetch",
                            "--no-tags",
                            "--filter=blob:none",
                            "--depth=1",
                            "origin",
                            tref,
                        ],
                    )?;
                } else {
                    return Err(format!("could not fetch commit {commit} from {repo_url}"));
                }
            }
        }

        // List the full commit tree (paths + blob sha1s) with zero blob transfers.
        let tree_out = run_git(&repo_dir, &["ls-tree", "-r", "-z", commit])?;
        let tree_blob_sha1 = parse_ls_tree_z(&tree_out);
        if tree_blob_sha1.is_empty() {
            return Err(format!("empty tree for {commit}"));
        }

        // Determine package_dir (monorepo support).
        let mut blobs_by_sha1: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let package_dir = if let Some(d) = declared_dir {
            let trimmed = d.trim_matches('/').to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        } else {
            // Check if root package.json exists and matches; otherwise locate unique package.json with matching name.
            self.detect_monorepo_dir(&repo_dir, &tree_blob_sha1, pkg_name, &mut blobs_by_sha1)
        };

        // Decide which blobs we actually need to fetch for SHA-256 verification and normalizations:
        // 1. Any blob SHA-1 matching a non-carried artifact entry's git_blob_sha1
        // 2. The blob at expected_repo_path for every non-carried artifact file (for CRLF / package.json normalization)
        let ref_by_path: BTreeMap<&str, &str> = ref_archive
            .map(|ra| {
                ra.inventory
                    .entries
                    .iter()
                    .map(|e| (e.path.as_str(), e.sha256.as_str()))
                    .collect()
            })
            .unwrap_or_default();
        let ref_sha256s: BTreeSet<&str> = ref_archive
            .map(|ra| ra.inventory.entries.iter().map(|e| e.sha256.as_str()).collect())
            .unwrap_or_default();

        let tree_sha1_set: BTreeSet<&str> = tree_blob_sha1.values().map(|s| s.as_str()).collect();
        let mut needed_sha1s: BTreeSet<String> = BTreeSet::new();

        for entry in &archive.inventory.entries {
            let is_carried = ref_by_path.get(entry.path.as_str()) == Some(&entry.sha256.as_str())
                || ref_sha256s.contains(entry.sha256.as_str());
            if is_carried {
                continue;
            }
            if tree_sha1_set.contains(entry.git_blob_sha1.as_str()) {
                needed_sha1s.insert(entry.git_blob_sha1.clone());
            }
            let rel = strip_archive_root(&entry.path);
            let expected_path = match &package_dir {
                Some(dir) => format!("{dir}/{rel}"),
                None => rel.to_string(),
            };
            if let Some(path_blob_sha1) = tree_blob_sha1.get(&expected_path) {
                needed_sha1s.insert(path_blob_sha1.clone());
            }
        }

        // Remove already fetched blobs.
        let to_fetch: Vec<String> = needed_sha1s
            .into_iter()
            .filter(|s| !blobs_by_sha1.contains_key(s))
            .collect();

        if !to_fetch.is_empty() {
            let fetched_blobs = read_git_blobs_batch(&repo_dir, &to_fetch)?;
            blobs_by_sha1.extend(fetched_blobs);
        }

        Ok(SourceSnapshot {
            tree_blob_sha1,
            blobs_by_sha1,
            package_dir,
        })
    }

    fn detect_monorepo_dir(
        &self,
        repo_dir: &Path,
        tree_blob_sha1: &BTreeMap<String, String>,
        pkg_name: &str,
        blobs_cache: &mut BTreeMap<String, Vec<u8>>,
    ) -> Option<String> {
        let mut candidate_manifests: Vec<(&str, &str)> = Vec::new();
        for (path, sha1) in tree_blob_sha1 {
            if path == "package.json" || path.ends_with("/package.json") {
                // Skip test fixtures / node_modules inside repos
                if path.contains("node_modules/")
                    || path.contains("/fixtures/")
                    || path.contains("/test/")
                    || path.contains("/tests/")
                    || path.contains("/examples/")
                {
                    continue;
                }
                candidate_manifests.push((path.as_str(), sha1.as_str()));
            }
        }

        if candidate_manifests.is_empty() || candidate_manifests.len() > 64 {
            return None;
        }

        let sha1s: Vec<String> = candidate_manifests
            .iter()
            .map(|(_, s)| (*s).to_string())
            .collect();
        let Ok(blobs) = read_git_blobs_batch(repo_dir, &sha1s) else {
            return None;
        };

        let mut matches = Vec::new();
        for (path, sha1) in candidate_manifests {
            if let Some(bytes) = blobs.get(sha1) {
                blobs_cache.insert(sha1.to_string(), bytes.clone());
                if let Ok(v) = serde_json::from_slice::<Value>(bytes) {
                    if v.get("name").and_then(|n| n.as_str()) == Some(pkg_name) {
                        let dir = path
                            .strip_suffix("/package.json")
                            .unwrap_or("")
                            .to_string();
                        matches.push(dir);
                    }
                }
            }
        }

        if matches.len() == 1 {
            let only = matches.remove(0);
            if only.is_empty() { None } else { Some(only) }
        } else {
            None
        }
    }
}

#[derive(Debug, Clone)]
pub struct HistoricalSlice {
    pub prior_releases: Vec<ReleaseMetaSummary>,
    pub total_prior_releases: usize,
    pub first_published_at: Option<String>,
    pub new_release: ReleaseMetaSummary,
    /// SHA-256 of the canonical historical slice (timeless: unaffected by future publishes!).
    pub slice_sha256: String,
}

/// Extracts historical prior releases strictly older than `new_version`'s publish time.
pub fn build_release_history(
    doc: &Value,
    new_version: &str,
    history_depth: usize,
) -> HistoricalSlice {
    let time_map = doc.get("time").and_then(|v| v.as_object());
    let versions_map = doc.get("versions").and_then(|v| v.as_object());

    let new_pub_str = time_map
        .and_then(|t| t.get(new_version))
        .and_then(|v| v.as_str())
        .map(String::from);
    let new_pub_unix = new_pub_str.as_deref().and_then(parse_rfc3339_unix);

    let new_summary = versions_map
        .and_then(|vm| vm.get(new_version))
        .map(|v| summarize_version(new_version, v, new_pub_str.clone()))
        .unwrap_or_else(|| ReleaseMetaSummary {
            version: new_version.to_string(),
            published_at: new_pub_str.clone(),
            ..Default::default()
        });

    let new_is_prerelease = new_version.contains('-');
    let mut dated_prior: Vec<(i64, ReleaseMetaSummary)> = Vec::new();
    if let (Some(tm), Some(vm)) = (time_map, versions_map) {
        for (ver, ver_json) in vm {
            if ver == new_version {
                continue;
            }
            // Prevent prerelease flooding (e.g. publishing dummy 1.0.1-alpha.1..3) from poisoning
            // `repo_changed` / `provenance_lost` baselines for stable releases.
            if !new_is_prerelease && ver.contains('-') {
                continue;
            }
            let Some(ts_str) = tm.get(ver).and_then(|v| v.as_str()) else {
                continue;
            };
            let Some(ts_unix) = parse_rfc3339_unix(ts_str) else {
                continue;
            };
            if let Some(new_u) = new_pub_unix {
                if ts_unix >= new_u {
                    continue;
                }
            }
            dated_prior.push((ts_unix, summarize_version(ver, ver_json, Some(ts_str.to_string()))));
        }
    }

    dated_prior.sort_by_key(|(ts, _)| *ts);
    let total_prior_releases = dated_prior.len();
    let first_published_at = dated_prior
        .first()
        .and_then(|(_, s)| s.published_at.clone())
        .or_else(|| new_summary.published_at.clone());
    let start = total_prior_releases.saturating_sub(history_depth);
    let prior: Vec<ReleaseMetaSummary> = dated_prior
        .into_iter()
        .skip(start)
        .map(|(_, s)| s)
        .collect();

    let slice_obj = serde_json::json!({
        "total_prior_releases": total_prior_releases,
        "first_published_at": first_published_at,
        "prior": prior,
        "new": new_summary,
    });
    let slice_sha256 = assay_core::canonical::canonical_id(&slice_obj)
        .unwrap_or_else(|_| sha256_hex(slice_obj.to_string().as_bytes()));

    HistoricalSlice {
        prior_releases: prior,
        total_prior_releases,
        first_published_at,
        new_release: new_summary,
        slice_sha256,
    }
}

fn summarize_version(version: &str, v: &Value, published_at: Option<String>) -> ReleaseMetaSummary {
    let has_provenance = v.pointer("/dist/attestations").is_some();
    let has_trusted_publisher = v.pointer("/_npmUser/trustedPublisher").is_some();
    let has_git_head = v
        .get("gitHead")
        .and_then(|g| g.as_str())
        .map(is_hex_commit)
        .unwrap_or(false);
    let repository_url = match v.get("repository") {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Object(m)) => m.get("url").and_then(|u| u.as_str()).map(String::from),
        _ => None,
    };
    let publisher_id = v
        .pointer("/_npmUser/trustedPublisher/id")
        .and_then(|x| x.as_str())
        .map(|s| format!("trusted:{s}"))
        .or_else(|| {
            v.pointer("/_npmUser/name")
                .and_then(|x| x.as_str())
                .map(|s| format!("npm:{s}"))
        });
    let file_count = v.pointer("/dist/fileCount").and_then(|x| x.as_u64());
    let unpacked_size = v.pointer("/dist/unpackedSize").and_then(|x| x.as_u64());

    ReleaseMetaSummary {
        version: version.to_string(),
        published_at,
        has_provenance,
        has_trusted_publisher,
        has_git_head,
        repository_url,
        publisher_id,
        file_count,
        unpacked_size,
    }
}

fn encode_npm_name(name: &str) -> String {
    name.replace('/', "%2F")
}

fn curl_get(url: &str, extra_headers: &[&str], allow_redirects: bool) -> Result<Vec<u8>, String> {
    let mut cmd = Command::new("curl");
    cmd.args([
        "-q",
        "--silent",
        "--show-error",
        "--fail",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--max-time",
        "30",
        "--user-agent",
        "assay/0.1",
    ]);
    if allow_redirects {
        cmd.args(["--location", "--max-redirs", "5"]);
    } else {
        cmd.args(["--max-redirs", "0"]);
    }
    for h in extra_headers {
        cmd.args(["-H", h]);
    }
    cmd.arg("--");
    cmd.arg(url);

    let out = cmd.output().map_err(|e| format!("failed to run curl: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!("curl GET {url} failed: {}", stderr.trim()));
    }
    Ok(out.stdout)
}

fn curl_post_json(url: &str, body: &str) -> Result<Vec<u8>, String> {
    let mut child = Command::new("curl")
        .args([
            "-q",
            "--silent",
            "--show-error",
            "--fail",
            "--proto",
            "=https",
            "--max-time",
            "15",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "--data-binary",
            "@-",
            "--",
            url,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to spawn curl: {e}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(body.as_bytes())
            .map_err(|e| format!("failed writing curl stdin: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("failed waiting on curl: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!("curl POST {url} failed: {}", stderr.trim()));
    }
    Ok(out.stdout)
}

/// Validates that a repository URL is a public HTTPS Git URL with no SSRF/local targets or flag injection.
fn validate_public_https_git_url(url: &str) -> Result<(), String> {
    if url.starts_with('-') || url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(format!("refusing unsafe git url: {url}"));
    }
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| format!("refusing non-https git url: {url}"))?;
    let authority = rest.split('/').next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return Err(format!("refusing git url with credentials or empty host: {url}"));
    }
    let host_raw = if let Some(bracketed) = authority.strip_prefix('[') {
        bracketed
            .split(']')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase()
    } else {
        authority
            .split(':')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase()
    };
    if host_raw.is_empty()
        || host_raw == "localhost"
        || host_raw.ends_with(".localhost")
        || host_raw.ends_with(".local")
        || host_raw.ends_with(".internal")
        || host_raw == "::1"
        || host_raw.starts_with("fe80:")
        || host_raw.starts_with("fc")
        || host_raw.starts_with("fd")
    {
        return Err(format!("refusing local/private git host: {host_raw}"));
    }
    if let Ok(ip) = host_raw.parse::<std::net::IpAddr>() {
        let forbidden = match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_unspecified()
                    || v4.is_broadcast()
                    || v4.is_documentation()
                    || (v4.octets()[0] == 100 && (v4.octets()[1] & 0b1100_0000) == 64)
            }
            std::net::IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    || (v6.segments()[0] & 0xfe00) == 0xfc00
                    || (v6.segments()[0] & 0xffc0) == 0xfe80
            }
        };
        if forbidden {
            return Err(format!("refusing private/loopback git ip: {host_raw}"));
        }
    }
    Ok(())
}

fn hardened_git_cmd(cwd: Option<&Path>) -> Command {
    let mut cmd = Command::new("git");
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    cmd.env("GIT_TERMINAL_PROMPT", "0");
    cmd.env("GIT_CONFIG_NOSYSTEM", "1");
    cmd.env("GIT_CONFIG_GLOBAL", "/dev/null");
    cmd.args([
        "-c",
        "safe.bareRepository=explicit",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.symlinks=false",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.sshCommand=false",
        "-c",
        "credential.helper=",
        "-c",
        "submodule.recurse=false",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "protocol.ext.allow=never",
        "-c",
        "filter.lfs.smudge=",
        "-c",
        "filter.lfs.process=",
    ]);
    cmd
}

fn run_git(cwd: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let mut cmd = hardened_git_cmd(Some(cwd));
    // Explicitly pass GIT_DIR for bare cache repos (except during `init`) so `safe.bareRepository=explicit` works cleanly.
    if args.first().copied() != Some("init") {
        cmd.env("GIT_DIR", cwd);
    }
    let out = cmd
        .args(args)
        .output()
        .map_err(|e| format!("failed to spawn git: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!("git {:?} failed: {}", args, stderr.trim()));
    }
    Ok(out.stdout)
}

fn git_ls_remote(neutral_dir: &Path, repo_url: &str) -> Result<BTreeMap<String, String>, String> {
    validate_public_https_git_url(repo_url)?;
    // Run inside neutral cache directory (never process CWD) with GIT_CEILING_DIRECTORIES so an
    // untrusted checkout's `.git/config` cannot inject `url.*.insteadOf` or `credential.helper`.
    let out = hardened_git_cmd(Some(neutral_dir))
        .env("GIT_CEILING_DIRECTORIES", neutral_dir)
        .args(["ls-remote", "--tags", "--heads", "--", repo_url])
        .output()
        .map_err(|e| format!("failed to spawn git ls-remote: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!("git ls-remote failed: {}", stderr.trim()));
    }
    let mut refs = BTreeMap::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if let Some((sha, refname)) = line.split_once('\t') {
            refs.insert(refname.trim().to_string(), sha.trim().to_ascii_lowercase());
        }
    }
    Ok(refs)
}

fn find_matching_tag(
    name: &str,
    version: &str,
    refs: &BTreeMap<String, String>,
) -> Option<(String, String)> {
    let unscoped = name.split('/').last().unwrap_or(name);
    let mut candidates = vec![
        format!("v{version}"),
        version.to_string(),
        format!("{name}@{version}"),
        format!("{name}-v{version}"),
    ];
    if unscoped != name {
        candidates.push(format!("{unscoped}@{version}"));
        candidates.push(format!("{unscoped}-v{version}"));
    }

    let mut matched: Vec<(String, String)> = Vec::new();
    for tag in candidates {
        let base_ref = format!("refs/tags/{tag}");
        let peeled_ref = format!("refs/tags/{tag}^{{}}");
        if let Some(sha) = refs.get(&peeled_ref).or_else(|| refs.get(&base_ref)) {
            matched.push((base_ref, sha.clone()));
        }
    }
    if matched.is_empty() {
        return None;
    }
    let unique: BTreeSet<&str> = matched.iter().map(|(_, s)| s.as_str()).collect();
    if unique.len() > 1 {
        // Section 7.3: if matching tags point to different commits, there is no tag anchor.
        return None;
    }
    matched.into_iter().next()
}

fn parse_ls_tree_z(out: &[u8]) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for entry in out.split(|&b| b == 0) {
        if entry.is_empty() {
            continue;
        }
        let Some(tab_pos) = entry.iter().position(|&b| b == b'\t') else {
            continue;
        };
        let meta = std::str::from_utf8(&entry[..tab_pos]).unwrap_or("");
        let path = String::from_utf8_lossy(&entry[tab_pos + 1..]).to_string();
        let parts: Vec<&str> = meta.split_whitespace().collect();
        if parts.len() == 3 && parts[1] == "blob" {
            map.insert(path, parts[2].to_ascii_lowercase());
        }
    }
    map
}

fn read_git_blobs_batch(
    repo_dir: &Path,
    sha1s: &[String],
) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let mut child = hardened_git_cmd(Some(repo_dir))
        .env("GIT_DIR", repo_dir)
        .args(["cat-file", "--batch"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to spawn git cat-file --batch: {e}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        for s in sha1s {
            writeln!(stdin, "{s}").map_err(|e| format!("write stdin cat-file: {e}"))?;
        }
    }

    let out = child
        .wait_with_output()
        .map_err(|e| format!("wait git cat-file: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!("git cat-file --batch failed: {}", stderr.trim()));
    }

    let buf = out.stdout;
    let mut pos = 0usize;
    let mut blobs = BTreeMap::new();
    while pos < buf.len() {
        let Some(nl_rel) = buf[pos..].iter().position(|&b| b == b'\n') else {
            break;
        };
        let header_line = std::str::from_utf8(&buf[pos..pos + nl_rel]).unwrap_or("");
        pos += nl_rel + 1;
        let parts: Vec<&str> = header_line.split_whitespace().collect();
        if parts.len() == 3 && parts[1] == "blob" {
            let oid = parts[0].to_ascii_lowercase();
            let size: usize = parts[2].parse().unwrap_or(0);
            if pos + size <= buf.len() {
                blobs.insert(oid, buf[pos..pos + size].to_vec());
                pos += size;
                if pos < buf.len() && buf[pos] == b'\n' {
                    pos += 1;
                }
            } else {
                break;
            }
        }
    }
    Ok(blobs)
}

fn is_hex_commit(s: &str) -> bool {
    (s.len() == 40 || s.len() == 64) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    // Simple standard base64 decode without adding extra dependency to assay-cli.
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for b in s.bytes() {
        let val = match b {
            b'A'..=b'Z' => (b - b'A') as u32,
            b'a'..=b'z' => (b - b'a' + 26) as u32,
            b'0'..=b'9' => (b - b'0' + 52) as u32,
            b'+' => 62,
            b'/' => 63,
            b'=' | b'\n' | b'\r' | b' ' | b'\t' => continue,
            _ => return None,
        };
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}
