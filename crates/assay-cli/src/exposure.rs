use crate::pr::read_git_file;
use assay_core::digest::parse_sha512_sri;
use assay_core::lockfile::parse_lockfile_packages;
use assay_core::model::TransitionLedger;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone)]
pub enum ExposureQuery {
    PackageVersion { name: String, version: String },
    Sha512(String),
}

impl ExposureQuery {
    pub fn from_args(pkg_spec: Option<&str>, sha512: Option<&str>) -> Result<Self, String> {
        if let Some(s) = sha512 {
            let norm = parse_sha512_sri(s).unwrap_or_else(|| s.trim().to_ascii_lowercase());
            if norm.len() < 12 || !norm.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(format!("invalid --sha512 value '{s}'"));
            }
            return Ok(Self::Sha512(norm));
        }
        let Some(spec) = pkg_spec else {
            return Err("provide <name>@<version> or --sha512 <hex>".to_string());
        };
        let at_pos = spec
            .rfind('@')
            .filter(|&i| i > 0)
            .ok_or_else(|| format!("expected <name>@<version>, got '{spec}'"))?;
        Ok(Self::PackageVersion {
            name: spec[..at_pos].to_string(),
            version: spec[at_pos + 1..].to_string(),
        })
    }

    pub fn matches(&self, name: &str, version: Option<&str>, sha512: Option<&str>) -> bool {
        match self {
            Self::PackageVersion {
                name: qn,
                version: qv,
            } => name == qn && version == Some(qv.as_str()),
            Self::Sha512(qhex) => sha512
                .map(|s| s.to_ascii_lowercase().starts_with(qhex))
                .unwrap_or(false),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GitExposureHit {
    pub repo: String,
    pub lockfile: String,
    pub name: String,
    pub version: Option<String>,
    pub sha512: Option<String>,
    pub instance_path: String,
    pub first_commit: String,
    pub first_date: String,
    pub last_commit: String,
    pub last_date: String,
    pub still_present: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoreExposureHit {
    pub ledger_id: String,
    pub subject: String,
    pub name: String,
    pub version: String,
    pub sha512: String,
    pub published_at: Option<String>,
}

/// Walks Git history of `lockfile_rel_path` strictly via Git objects and reports every
/// admission window matching `query`.
pub fn search_git_lockfile_exposure(
    repo_dir: &Path,
    lockfile_rel_path: &str,
    query: &ExposureQuery,
) -> Result<Vec<GitExposureHit>, String> {
    let out = Command::new("git")
        .current_dir(repo_dir)
        .env("GIT_TERMINAL_PROMPT", "0")
        .args([
            "log",
            "--reverse",
            "--format=%H\t%aI",
            "--",
            lockfile_rel_path,
        ])
        .output()
        .map_err(|e| format!("failed running git log: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!("git log failed: {}", stderr.trim()));
    }

    let commits: Vec<(String, String)> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            let (sha, date) = line.split_once('\t')?;
            Some((sha.trim().to_string(), date.trim().to_string()))
        })
        .collect();

    let repo_label = repo_dir.display().to_string();
    let mut active: BTreeMap<String, GitExposureHit> = BTreeMap::new();
    let mut finished: Vec<GitExposureHit> = Vec::new();

    for (commit, date) in &commits {
        let matched_in_commit = match read_git_file(repo_dir, commit, lockfile_rel_path)? {
            Some(bytes) => match parse_lockfile_packages(&bytes) {
                Ok(pkgs) => pkgs
                    .into_iter()
                    .filter(|p| query.matches(&p.name, p.version.as_deref(), p.sha512.as_deref()))
                    .collect::<Vec<_>>(),
                Err(_) => Vec::new(),
            },
            None => Vec::new(),
        };

        let mut seen_keys = std::collections::BTreeSet::new();
        for pkg in matched_in_commit {
            let key = format!(
                "{}|{}|{}",
                pkg.instance_path,
                pkg.version.as_deref().unwrap_or(""),
                pkg.sha512.as_deref().unwrap_or("")
            );
            seen_keys.insert(key.clone());
            if let Some(hit) = active.get_mut(&key) {
                hit.last_commit = commit.clone();
                hit.last_date = date.clone();
            } else {
                active.insert(
                    key,
                    GitExposureHit {
                        repo: repo_label.clone(),
                        lockfile: lockfile_rel_path.to_string(),
                        name: pkg.name,
                        version: pkg.version,
                        sha512: pkg.sha512,
                        instance_path: pkg.instance_path,
                        first_commit: commit.clone(),
                        first_date: date.clone(),
                        last_commit: commit.clone(),
                        last_date: date.clone(),
                        still_present: true,
                    },
                );
            }
        }

        // Any active hit absent from this commit was removed here.
        let removed_keys: Vec<String> = active
            .keys()
            .filter(|k| !seen_keys.contains(*k))
            .cloned()
            .collect();
        for rk in removed_keys {
            if let Some(mut hit) = active.remove(&rk) {
                hit.still_present = false;
                finished.push(hit);
            }
        }
    }

    finished.extend(active.into_values());
    Ok(finished)
}

/// Scans `<store_dir>/ledgers/*.json` for any recorded transition admitting matching bytes.
pub fn search_store_exposure(
    store_dir: &Path,
    query: &ExposureQuery,
) -> Result<Vec<StoreExposureHit>, String> {
    let ledgers_dir = store_dir.join("ledgers");
    if !ledgers_dir.exists() {
        return Ok(Vec::new());
    }
    let mut hits = Vec::new();
    let entries = fs::read_dir(&ledgers_dir)
        .map_err(|e| format!("failed reading {}: {e}", ledgers_dir.display()))?;
    for entry in entries.flatten() {
        let p = entry.path();
        if p.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Ok(bytes) = fs::read(&p) else {
            continue;
        };
        let Ok(ledger) = serde_json::from_slice::<TransitionLedger>(&bytes) else {
            continue;
        };
        if query.matches(
            &ledger.name,
            Some(ledger.new.version.as_str()),
            Some(ledger.new.sha512.as_str()),
        ) {
            let ledger_id = p
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
            hits.push(StoreExposureHit {
                ledger_id,
                subject: ledger.subject,
                name: ledger.name,
                version: ledger.new.version,
                sha512: ledger.new.sha512,
                published_at: ledger.new.published_at,
            });
        }
    }
    Ok(hits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use assay_core::digest::{sha512_hex, sha512_sri};

    #[test]
    fn traces_exposure_window_in_git_history() {
        let tmp = std::env::temp_dir().join(format!("assay-exp-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let run = |args: &[&str]| {
            let out = Command::new("git")
                .current_dir(&tmp)
                .env("GIT_AUTHOR_NAME", "test")
                .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
                .env("GIT_COMMITTER_NAME", "test")
                .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
                .args(args)
                .output()
                .unwrap();
            assert!(out.status.success(), "git {:?} failed", args);
        };

        run(&["init", "-b", "main"]);
        let bad_sri = sha512_sri(b"bad-tarball");
        let bad_hex = sha512_hex(b"bad-tarball");
        let good_sri = sha512_sri(b"good-tarball");

        let lock1 = serde_json::json!({
            "lockfileVersion": 3,
            "packages": {
                "": {},
                "node_modules/evilpkg": {
                    "version": "1.2.3",
                    "resolved": "https://registry.npmjs.org/evilpkg/-/evilpkg-1.2.3.tgz",
                    "integrity": bad_sri
                }
            }
        });
        fs::write(tmp.join("package-lock.json"), serde_json::to_vec(&lock1).unwrap()).unwrap();
        run(&["add", "."]);
        run(&["commit", "-m", "add evilpkg"]);

        let lock2 = serde_json::json!({
            "lockfileVersion": 3,
            "packages": {
                "": {},
                "node_modules/evilpkg": {
                    "version": "1.2.4",
                    "resolved": "https://registry.npmjs.org/evilpkg/-/evilpkg-1.2.4.tgz",
                    "integrity": good_sri
                }
            }
        });
        fs::write(tmp.join("package-lock.json"), serde_json::to_vec(&lock2).unwrap()).unwrap();
        run(&["add", "."]);
        run(&["commit", "-m", "upgrade evilpkg"]);

        let q = ExposureQuery::from_args(None, Some(&bad_hex[..16])).unwrap();
        let hits = search_git_lockfile_exposure(&tmp, "package-lock.json", &q).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].name, "evilpkg");
        assert_eq!(hits[0].version.as_deref(), Some("1.2.3"));
        assert!(!hits[0].still_present);

        let _ = fs::remove_dir_all(&tmp);
    }
}
