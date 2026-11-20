use crate::canonical::{canonical_id, to_canonical_json};
use crate::model::{Anchor, ArtifactProfile, Decision, TransitionLedger};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalRecord {
    pub kind: String,
    pub schema: u32,
    pub subject: String,
    pub ledger_id: String,
    /// Exact concrete stop fact keys approved by the human (e.g. `break:provenance_lost`, `advisory:MAL-...`).
    /// Any new stop fact outside this set invalidates the approval under S10.
    pub approved_facts: BTreeSet<String>,
    pub approver: String,
    pub approved_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Self-contained offline input bundle for `carat replay`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InputBundle {
    pub schema: u32,
    pub ecosystem: String,
    pub name: String,
    pub reference_version: Option<String>,
    pub reference_tarball_file: Option<String>,
    pub reference_sha512: Option<String>,
    pub reference_published_at: Option<String>,
    pub reference_anchor: Option<Anchor>,
    #[serde(default)]
    pub reference_source_package_dir: Option<String>,
    #[serde(default)]
    pub reference_source_tree: BTreeMap<String, String>,
    #[serde(default)]
    pub reference_source_blobs_b64: BTreeMap<String, String>,
    pub new_version: String,
    pub new_tarball_file: String,
    pub new_sha512: String,
    pub new_published_at: Option<String>,
    pub new_anchor: Anchor,
    pub new_source_package_dir: Option<String>,
    pub new_source_tree: BTreeMap<String, String>,
    pub new_source_blobs_b64: BTreeMap<String, String>,
    pub registry_snapshot_file: Option<String>,
    pub history_slice_sha256: Option<String>,
    pub as_of: String,
    pub expected_ledger_id: String,
}

/// Validates that `id` is a strict ASCII hex digest (16..=128 chars, no path separators or traversal).
pub fn validate_hex_id(id: &str) -> Result<&str, String> {
    if !(16..=128).contains(&id.len()) || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("invalid digest id '{id}'"));
    }
    Ok(id)
}

/// Validates that `name` is a single normal filename with no directory traversal, separators, or NULs.
pub fn validate_safe_filename(name: &str) -> Result<&str, String> {
    if name.is_empty() || name.contains('/') || name.contains('\\') || name.contains('\0') {
        return Err(format!("unsafe filename '{name}'"));
    }
    let mut comps = Path::new(name).components();
    match (comps.next(), comps.next()) {
        (Some(Component::Normal(_)), None) => Ok(name),
        _ => Err(format!("unsafe filename '{name}'")),
    }
}

/// Rejects symlinks on `path` if it exists.
pub fn reject_symlink(path: &Path) -> Result<(), String> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(format!("refusing symlink at {}", path.display()));
        }
    }
    Ok(())
}

/// Writes bytes atomically via an exclusive sibling temp file (`O_CREAT | O_EXCL`) + rename,
/// refusing symlinks at target.
pub fn write_atomic_no_symlink(target: &Path, bytes: &[u8]) -> Result<(), String> {
    reject_symlink(target)?;
    let parent = target
        .parent()
        .ok_or_else(|| format!("target {} has no parent directory", target.display()))?;
    fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    let base_name = target
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("tmp");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp_path = parent.join(format!(".{base_name}.carat-tmp-{}-{nonce}", std::process::id()));
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)
        .map_err(|e| format!("create temp {}: {e}", tmp_path.display()))?;
    if let Err(e) = f.write_all(bytes) {
        let _ = fs::remove_file(&tmp_path);
        return Err(format!("write temp {}: {e}", tmp_path.display()));
    }
    drop(f);
    reject_symlink(target)?;
    if let Err(e) = fs::rename(&tmp_path, target) {
        let _ = fs::remove_file(&tmp_path);
        return Err(format!("rename into {}: {e}", target.display()));
    }
    Ok(())
}

/// Content-addressed JSON store on disk (`.carat/`), plus optional read-only extra stores.
#[derive(Debug, Clone)]
pub struct RecordStore {
    pub root: PathBuf,
    pub readonly_stores: Vec<PathBuf>,
}

impl RecordStore {
    pub fn open(root: PathBuf, readonly_stores: Vec<PathBuf>) -> Result<Self, String> {
        reject_symlink(&root)?;
        for sub in [
            "profiles",
            "ledgers",
            "decisions",
            "readings",
            "approvals",
            "inputs",
        ] {
            let dir = root.join(sub);
            reject_symlink(&dir)?;
            fs::create_dir_all(&dir)
                .map_err(|e| format!("failed creating store dir {}: {e}", dir.display()))?;
        }
        Ok(Self {
            root,
            readonly_stores,
        })
    }

    fn all_roots(&self) -> Vec<&Path> {
        let mut out = vec![self.root.as_path()];
        for r in &self.readonly_stores {
            out.push(r.as_path());
        }
        out
    }

    pub fn save_profile(&self, profile: &ArtifactProfile) -> Result<String, String> {
        let id = canonical_id(profile)?;
        validate_hex_id(&id)?;
        let canon = to_canonical_json(profile)?;
        let path = self.root.join("profiles").join(format!("{id}.json"));
        write_atomic_no_symlink(&path, canon.as_bytes())?;
        Ok(id)
    }

    pub fn save_ledger(&self, ledger: &TransitionLedger) -> Result<String, String> {
        let id = canonical_id(ledger)?;
        validate_hex_id(&id)?;
        let canon = to_canonical_json(ledger)?;
        let path = self.root.join("ledgers").join(format!("{id}.json"));
        write_atomic_no_symlink(&path, canon.as_bytes())?;
        Ok(id)
    }

    pub fn save_decision(&self, decision: &Decision) -> Result<String, String> {
        validate_hex_id(&decision.subject)?;
        let id = canonical_id(decision)?;
        validate_hex_id(&id)?;
        let canon = to_canonical_json(decision)?;
        let path = self
            .root
            .join("decisions")
            .join(format!("{}.json", decision.subject));
        write_atomic_no_symlink(&path, canon.as_bytes())?;
        Ok(id)
    }

    pub fn load_decision_for_subject(&self, subject: &str) -> Option<Decision> {
        validate_hex_id(subject).ok()?;
        for root in self.all_roots() {
            let p = root.join("decisions").join(format!("{subject}.json"));
            if reject_symlink(&p).is_err() {
                continue;
            }
            if let Ok(s) = fs::read_to_string(&p) {
                if let Ok(d) = serde_json::from_str::<Decision>(&s) {
                    if d.subject == subject {
                        return Some(d);
                    }
                }
            }
        }
        None
    }

    pub fn save_reading_json(&self, reading_key: &str, canonical_json: &str) -> Result<PathBuf, String> {
        validate_hex_id(reading_key)?;
        let path = self.root.join("readings").join(format!("{reading_key}.json"));
        write_atomic_no_symlink(&path, canonical_json.as_bytes())?;
        Ok(path)
    }

    pub fn load_reading_json(&self, reading_key: &str) -> Option<String> {
        validate_hex_id(reading_key).ok()?;
        for root in self.all_roots() {
            let p = root.join("readings").join(format!("{reading_key}.json"));
            if reject_symlink(&p).is_err() {
                continue;
            }
            if let Ok(s) = fs::read_to_string(&p) {
                return Some(s);
            }
        }
        None
    }

    pub fn save_approval(&self, approval: &ApprovalRecord) -> Result<PathBuf, String> {
        validate_hex_id(&approval.subject)?;
        validate_hex_id(&approval.ledger_id)?;
        let canon = to_canonical_json(approval)?;
        let path = self
            .root
            .join("approvals")
            .join(format!("{}.json", approval.subject));
        write_atomic_no_symlink(&path, canon.as_bytes())?;
        Ok(path)
    }

    pub fn find_approval(&self, subject: &str) -> Option<ApprovalRecord> {
        validate_hex_id(subject).ok()?;
        for root in self.all_roots() {
            let p = root.join("approvals").join(format!("{subject}.json"));
            if reject_symlink(&p).is_err() {
                continue;
            }
            if let Ok(s) = fs::read_to_string(&p) {
                if let Ok(rec) = serde_json::from_str::<ApprovalRecord>(&s) {
                    if rec.subject == subject && validate_hex_id(&rec.ledger_id).is_ok() {
                        return Some(rec);
                    }
                }
            }
        }
        None
    }

    /// Finds a unique ledger whose `subject` or `ledger_id` starts with `prefix` (min 8 hex chars).
    pub fn find_unique_ledger_for_subject(
        &self,
        prefix: &str,
    ) -> Result<(String, TransitionLedger), String> {
        let p = prefix.trim().to_ascii_lowercase();
        if p.len() < 8 || !p.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!(
                "approval subject '{prefix}' must be at least 8 lowercase hex characters"
            ));
        }

        let mut matches: BTreeMap<String, TransitionLedger> = BTreeMap::new();
        for root in self.all_roots() {
            let dir = root.join("ledgers");
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for ent in entries.flatten() {
                let path = ent.path();
                if path.extension().and_then(|e| e.to_str()) != Some("json") {
                    continue;
                }
                if reject_symlink(&path).is_err() {
                    continue;
                }
                let Ok(s) = fs::read_to_string(&path) else {
                    continue;
                };
                let Ok(ledger) = serde_json::from_str::<TransitionLedger>(&s) else {
                    continue;
                };
                let ledger_id = path
                    .file_stem()
                    .and_then(|st| st.to_str())
                    .unwrap_or("")
                    .to_string();
                if ledger.subject.starts_with(&p) || ledger_id.starts_with(&p) {
                    matches.insert(ledger_id, ledger);
                }
            }
        }

        if matches.is_empty() {
            return Err(format!("no stored transition ledger matches '{prefix}'"));
        }
        // Multiple ledgers may share the same subject (e.g. different history depth); verify unique subject.
        let subjects: BTreeSet<&str> = matches.values().map(|l| l.subject.as_str()).collect();
        if subjects.len() > 1 {
            return Err(format!(
                "prefix '{prefix}' is ambiguous across {} distinct subjects; provide more hex characters",
                subjects.len()
            ));
        }
        let (lid, ledger) = matches.into_iter().next().unwrap();
        Ok((lid, ledger))
    }

    pub fn save_input_bundle(
        &self,
        ledger_id: &str,
        bundle: &InputBundle,
        files: &[(&str, &[u8])],
    ) -> Result<PathBuf, String> {
        validate_hex_id(ledger_id)?;
        validate_safe_filename(&bundle.new_tarball_file)?;
        if let Some(ref rf) = bundle.reference_tarball_file {
            validate_safe_filename(rf)?;
        }
        if let Some(ref rs) = bundle.registry_snapshot_file {
            validate_safe_filename(rs)?;
        }
        let dir = self.root.join("inputs").join(ledger_id);
        reject_symlink(&dir)?;
        fs::create_dir_all(&dir).map_err(|e| format!("create bundle dir: {e}"))?;
        for (name, bytes) in files {
            validate_safe_filename(name)?;
            write_atomic_no_symlink(&dir.join(name), bytes)?;
        }
        let canon = to_canonical_json(bundle)?;
        write_atomic_no_symlink(&dir.join("bundle.json"), canon.as_bytes())?;
        Ok(dir)
    }

    pub fn load_input_bundle(bundle_dir: &Path) -> Result<InputBundle, String> {
        let p = bundle_dir.join("bundle.json");
        reject_symlink(&p)?;
        let s = fs::read_to_string(&p)
            .map_err(|e| format!("failed reading {}: {e}", p.display()))?;
        let bundle: InputBundle =
            serde_json::from_str(&s).map_err(|e| format!("invalid bundle.json: {e}"))?;
        validate_safe_filename(&bundle.new_tarball_file)?;
        if let Some(ref rf) = bundle.reference_tarball_file {
            validate_safe_filename(rf)?;
        }
        if let Some(ref rs) = bundle.registry_snapshot_file {
            validate_safe_filename(rs)?;
        }
        Ok(bundle)
    }

    pub fn list_all_ledgers(&self) -> Vec<(String, TransitionLedger)> {
        let mut out = Vec::new();
        for root in self.all_roots() {
            let dir = root.join("ledgers");
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for ent in entries.flatten() {
                let path = ent.path();
                if path.extension().and_then(|e| e.to_str()) != Some("json") {
                    continue;
                }
                if reject_symlink(&path).is_err() {
                    continue;
                }
                if let Ok(s) = fs::read_to_string(&path) {
                    if let Ok(ledger) = serde_json::from_str::<TransitionLedger>(&s) {
                        let lid = path
                            .file_stem()
                            .and_then(|st| st.to_str())
                            .unwrap_or("")
                            .to_string();
                        out.push((lid, ledger));
                    }
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saves_and_finds_approval_across_readonly_stores_and_rejects_traversal() {
        let base = std::env::temp_dir().join(format!("carat-store-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let ro = base.join("ro");
        let rw = base.join("rw");

        let s_ro = RecordStore::open(ro.clone(), vec![]).unwrap();
        let approval = ApprovalRecord {
            kind: "approval".into(),
            schema: 2,
            subject: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".into(),
            ledger_id: "1111111111111111111111111111111111111111111111111111111111111111".into(),
            approved_facts: ["break:provenance_lost".into()].into_iter().collect(),
            approver: "alice".into(),
            approved_at: "2026-11-19T23:00:00Z".into(),
            note: Some("verified".into()),
        };
        s_ro.save_approval(&approval).unwrap();

        let s_rw = RecordStore::open(rw, vec![ro]).unwrap();
        let found = s_rw.find_approval(&approval.subject).unwrap();
        assert_eq!(found.approver, "alice");
        assert!(found.approved_facts.contains("break:provenance_lost"));

        // Path traversal and non-hex IDs must be rejected.
        assert!(validate_hex_id("../etc/passwd").is_err());
        assert!(validate_hex_id("abcdef0123456789-model").is_err());
        assert!(validate_safe_filename("../escape.tgz").is_err());
        assert!(validate_safe_filename("sub/file.tgz").is_err());
        assert!(s_rw.find_approval("../../etc/passwd").is_none());
        assert!(s_rw.save_reading_json("../pwn", "{}").is_err());

        let _ = fs::remove_dir_all(&base);
    }
}
