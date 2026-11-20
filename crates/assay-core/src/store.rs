use crate::canonical::{canonical_id, to_canonical_json};
use crate::model::{Anchor, ArtifactProfile, Decision, TransitionLedger};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

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

/// Self-contained offline input bundle for `assay replay`.
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

#[derive(Debug, Clone)]
pub struct RecordStore {
    root: PathBuf,
    readonly_stores: Vec<PathBuf>,
}

impl RecordStore {
    pub fn open(root: PathBuf, readonly_stores: Vec<PathBuf>) -> Result<Self, String> {
        for sub in ["profiles", "ledgers", "decisions", "readings", "approvals", "inputs"] {
            fs::create_dir_all(root.join(sub))
                .map_err(|e| format!("failed creating store dir {sub}: {e}"))?;
        }
        Ok(Self {
            root,
            readonly_stores,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn save_profile(&self, profile: &ArtifactProfile) -> Result<String, String> {
        let id = canonical_id(profile)?;
        let json = to_canonical_json(profile)?;
        let path = self.root.join("profiles").join(format!("{id}.json"));
        fs::write(&path, json).map_err(|e| format!("write profile failed: {e}"))?;
        Ok(id)
    }

    pub fn load_profile(&self, id: &str) -> Option<ArtifactProfile> {
        self.read_from_any("profiles", &format!("{id}.json"))
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    }

    pub fn save_ledger(&self, ledger: &TransitionLedger) -> Result<String, String> {
        let id = canonical_id(ledger)?;
        let json = to_canonical_json(ledger)?;
        let path = self.root.join("ledgers").join(format!("{id}.json"));
        fs::write(&path, json).map_err(|e| format!("write ledger failed: {e}"))?;
        Ok(id)
    }

    pub fn load_ledger(&self, id: &str) -> Option<TransitionLedger> {
        self.read_from_any("ledgers", &format!("{id}.json"))
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    }

    /// Finds the unique subject matching `subject_prefix` (requiring >= 8 hex chars and rejecting ambiguity).
    pub fn find_unique_ledger_for_subject(
        &self,
        subject_prefix: &str,
    ) -> Result<(String, TransitionLedger), String> {
        let q = subject_prefix.trim().to_ascii_lowercase();
        if q.len() < 8 || !q.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!(
                "subject '{subject_prefix}' must be at least 8 hex characters"
            ));
        }

        let mut dirs = vec![self.root.join("ledgers")];
        for ro in &self.readonly_stores {
            dirs.push(ro.join("ledgers"));
        }

        let mut matches_by_subject: BTreeMap<String, (String, TransitionLedger)> = BTreeMap::new();
        for dir in dirs {
            let Ok(entries) = fs::read_dir(dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let p = entry.path();
                if p.extension().and_then(|e| e.to_str()) != Some("json") {
                    continue;
                }
                if let Ok(bytes) = fs::read(&p) {
                    if let Ok(ledger) = serde_json::from_slice::<TransitionLedger>(&bytes) {
                        if ledger.subject == q || ledger.subject.starts_with(&q) {
                            let id = p
                                .file_stem()
                                .and_then(|s| s.to_str())
                                .unwrap_or("")
                                .to_string();
                            matches_by_subject
                                .entry(ledger.subject.clone())
                                .or_insert((id, ledger));
                        }
                    }
                }
            }
        }

        match matches_by_subject.len() {
            0 => Err(format!(
                "no recorded ledger found in {} matching subject '{subject_prefix}'",
                self.root.display()
            )),
            1 => Ok(matches_by_subject.into_values().next().unwrap()),
            n => Err(format!(
                "ambiguous subject prefix '{subject_prefix}' matched {n} distinct subjects; pass a longer prefix"
            )),
        }
    }

    pub fn save_decision(&self, decision: &Decision) -> Result<(), String> {
        let json = to_canonical_json(decision)?;
        let path = self
            .root
            .join("decisions")
            .join(format!("{}.json", decision.subject));
        fs::write(&path, json).map_err(|e| format!("write decision failed: {e}"))
    }

    pub fn load_decision_for_subject(&self, subject: &str) -> Option<Decision> {
        self.read_from_any("decisions", &format!("{subject}.json"))
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    }

    pub fn save_reading_json(&self, reading_key: &str, canonical_json: &str) -> Result<(), String> {
        let path = self.root.join("readings").join(format!("{reading_key}.json"));
        fs::write(&path, canonical_json).map_err(|e| format!("write reading failed: {e}"))
    }

    pub fn load_reading_json(&self, reading_key: &str) -> Option<String> {
        self.read_from_any("readings", &format!("{reading_key}.json"))
            .and_then(|b| String::from_utf8(b).ok())
    }

    pub fn save_approval(&self, approval: &ApprovalRecord) -> Result<PathBuf, String> {
        let json = to_canonical_json(approval)?;
        let path = self
            .root
            .join("approvals")
            .join(format!("{}.json", approval.subject));
        fs::write(&path, json).map_err(|e| format!("write approval failed: {e}"))?;
        Ok(path)
    }

    pub fn find_approval(&self, subject: &str) -> Option<ApprovalRecord> {
        self.read_from_any("approvals", &format!("{subject}.json"))
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    }

    pub fn save_input_bundle(
        &self,
        ledger_id: &str,
        bundle: &InputBundle,
        files: &[(&str, &[u8])],
    ) -> Result<PathBuf, String> {
        let dir = self.root.join("inputs").join(ledger_id);
        fs::create_dir_all(&dir).map_err(|e| format!("create input bundle dir: {e}"))?;
        for (rel, bytes) in files {
            fs::write(dir.join(rel), bytes)
                .map_err(|e| format!("write bundle file {rel}: {e}"))?;
        }
        let manifest = to_canonical_json(bundle)?;
        fs::write(dir.join("bundle.json"), manifest)
            .map_err(|e| format!("write bundle.json: {e}"))?;
        Ok(dir)
    }

    pub fn load_input_bundle(bundle_dir: &Path) -> Result<InputBundle, String> {
        let bytes = fs::read(bundle_dir.join("bundle.json"))
            .map_err(|e| format!("failed reading bundle.json: {e}"))?;
        serde_json::from_slice(&bytes).map_err(|e| format!("invalid bundle.json: {e}"))
    }

    fn read_from_any(&self, subdir: &str, filename: &str) -> Option<Vec<u8>> {
        let primary = self.root.join(subdir).join(filename);
        if let Ok(b) = fs::read(primary) {
            return Some(b);
        }
        for ro in &self.readonly_stores {
            if let Ok(b) = fs::read(ro.join(subdir).join(filename)) {
                return Some(b);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saves_and_finds_approval_across_readonly_stores() {
        let tmp = std::env::temp_dir().join(format!("assay-store-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        let shared = tmp.join("shared");
        let local = tmp.join("local");

        let shared_store = RecordStore::open(shared.clone(), vec![]).unwrap();
        let rec = ApprovalRecord {
            kind: "approval".into(),
            schema: 1,
            subject: "abcdef1234567890".into(),
            ledger_id: "112233".into(),
            approved_facts: BTreeSet::from(["break:provenance_lost".into()]),
            approver: "alice".into(),
            approved_at: "2026-11-19T23:00:00Z".into(),
            note: Some("reviewed".into()),
        };
        shared_store.save_approval(&rec).unwrap();

        let local_store = RecordStore::open(local, vec![shared]).unwrap();
        let loaded = local_store.find_approval("abcdef1234567890").unwrap();
        assert_eq!(loaded, rec);
        let _ = fs::remove_dir_all(&tmp);
    }
}
