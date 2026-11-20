use crate::archive::{LoadedArchive, classify_file_role, strip_archive_root};
use crate::digest::sha256_hex;
use crate::model::{ClassTotal, FileOrigin, NormalizationKind, OriginClass};
use crate::normalize::{ManifestNormalization, compare_published_manifest, normalize_crlf_to_lf};
use std::collections::{BTreeMap, BTreeSet};

/// A deterministic view of a Git anchor commit's tree, produced by `fetch`
/// and verified by SHA-256 in the core.
#[derive(Debug, Clone, Default)]
pub struct SourceSnapshot {
    /// Repository-relative path -> git blob sha1 hex.
    pub tree_blob_sha1: BTreeMap<String, String>,
    /// Verified blob contents keyed by git blob sha1 hex.
    pub blobs_by_sha1: BTreeMap<String, Vec<u8>>,
    /// Package directory inside a monorepo (e.g. `"packages/vite"`), or `None` for root.
    pub package_dir: Option<String>,
}

impl SourceSnapshot {
    pub fn blob_at_path(&self, repo_path: &str) -> Option<&[u8]> {
        let sha1 = self.tree_blob_sha1.get(repo_path)?;
        self.blobs_by_sha1.get(sha1).map(|v| v.as_slice())
    }

    pub fn expected_repo_path(&self, archive_rel: &str) -> String {
        match &self.package_dir {
            Some(dir) if !dir.is_empty() => format!("{dir}/{archive_rel}"),
            _ => archive_rel.to_string(),
        }
    }
}

/// Classifies every file in `new_archive` against an optional `ref_archive` (for `carried`)
/// and an optional `source` snapshot (for `source`, `source_elsewhere`, `source_normalized`).
pub fn classify_files(
    new_archive: &LoadedArchive,
    ref_archive: Option<&LoadedArchive>,
    source: Option<&SourceSnapshot>,
) -> (Vec<FileOrigin>, Vec<String>, BTreeMap<OriginClass, ClassTotal>) {
    // Index reference files by path and by sha256 (for moved files).
    let mut ref_by_path: BTreeMap<&str, &str> = BTreeMap::new();
    let mut ref_paths_by_sha256: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    if let Some(ref_arch) = ref_archive {
        for entry in &ref_arch.inventory.entries {
            ref_by_path.insert(&entry.path, &entry.sha256);
            ref_paths_by_sha256
                .entry(&entry.sha256)
                .or_default()
                .push(&entry.path);
        }
    }

    // Index source tree by git blob sha1 -> sorted repo paths.
    let mut source_paths_by_sha1: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    if let Some(src) = source {
        for (repo_path, blob_sha1) in &src.tree_blob_sha1 {
            source_paths_by_sha1
                .entry(blob_sha1.as_str())
                .or_default()
                .push(repo_path.as_str());
        }
        for paths in source_paths_by_sha1.values_mut() {
            paths.sort();
        }
    }

    let mut origins = Vec::with_capacity(new_archive.inventory.entries.len());
    let mut totals: BTreeMap<OriginClass, ClassTotal> = BTreeMap::new();
    let mut new_paths: BTreeSet<&str> = BTreeSet::new();

    for entry in &new_archive.inventory.entries {
        new_paths.insert(&entry.path);
        let bytes = new_archive
            .contents
            .get(&entry.path)
            .map(|v| v.as_slice())
            .unwrap_or(&[]);
        let role = classify_file_role(&entry.path, bytes);

        // 1. Carried: identical bytes at same path in reference, or moved from another path in reference.
        if let Some(&ref_sha) = ref_by_path.get(entry.path.as_str()) {
            if ref_sha == entry.sha256 {
                origins.push(FileOrigin {
                    path: entry.path.clone(),
                    sha256: entry.sha256.clone(),
                    bytes: entry.size,
                    class: OriginClass::Carried,
                    role,
                    moved_from: None,
                    source_path: None,
                    normalization: None,
                    significant_manifest_diffs: Vec::new(),
                });
                add_total(&mut totals, OriginClass::Carried, entry.size);
                continue;
            }
        }
        if let Some(prev_paths) = ref_paths_by_sha256.get(entry.sha256.as_str()) {
            let moved_from = prev_paths.first().map(|s| (*s).to_string());
            origins.push(FileOrigin {
                path: entry.path.clone(),
                sha256: entry.sha256.clone(),
                bytes: entry.size,
                class: OriginClass::Carried,
                role,
                moved_from,
                source_path: None,
                normalization: None,
                significant_manifest_diffs: Vec::new(),
            });
            add_total(&mut totals, OriginClass::Carried, entry.size);
            continue;
        }

        // 2-4. Match against anchored source snapshot (confirming equality by SHA-256).
        let mut classified: Option<FileOrigin> = None;
        if let Some(src) = source {
            let rel = strip_archive_root(&entry.path);
            let expected_repo_path = src.expected_repo_path(rel);

            // 2a. Exact match at corresponding path in anchor tree.
            if let Some(src_bytes) = src.blob_at_path(&expected_repo_path) {
                if sha256_hex(src_bytes) == entry.sha256 {
                    classified = Some(FileOrigin {
                        path: entry.path.clone(),
                        sha256: entry.sha256.clone(),
                        bytes: entry.size,
                        class: OriginClass::Source,
                        role,
                        moved_from: None,
                        source_path: Some(expected_repo_path.clone()),
                        normalization: None,
                        significant_manifest_diffs: Vec::new(),
                    });
                }
            }

            // 2b. Exact match elsewhere in anchor tree via git blob sha1 lookup + SHA-256 confirmation.
            if classified.is_none() {
                if let Some(candidate_paths) = source_paths_by_sha1.get(entry.git_blob_sha1.as_str())
                {
                    if let Some(blob_bytes) = src.blobs_by_sha1.get(&entry.git_blob_sha1) {
                        if sha256_hex(blob_bytes) == entry.sha256 {
                            let matched_path = candidate_paths
                                .iter()
                                .find(|&&p| p == expected_repo_path)
                                .or_else(|| candidate_paths.first())
                                .map(|s| (*s).to_string());
                            let class = if matched_path.as_deref() == Some(expected_repo_path.as_str()) {
                                OriginClass::Source
                            } else {
                                OriginClass::SourceElsewhere
                            };
                            classified = Some(FileOrigin {
                                path: entry.path.clone(),
                                sha256: entry.sha256.clone(),
                                bytes: entry.size,
                                class,
                                role,
                                moved_from: None,
                                source_path: matched_path,
                                normalization: None,
                                significant_manifest_diffs: Vec::new(),
                            });
                        }
                    }
                }
            }

            // 3. Declared normalizations against the corresponding source path.
            if classified.is_none() {
                if let Some(src_bytes) = src.blob_at_path(&expected_repo_path) {
                    // Normalization #1: CRLF -> LF
                    if normalize_crlf_to_lf(src_bytes) == normalize_crlf_to_lf(bytes) {
                        classified = Some(FileOrigin {
                            path: entry.path.clone(),
                            sha256: entry.sha256.clone(),
                            bytes: entry.size,
                            class: OriginClass::SourceNormalized,
                            role,
                            moved_from: None,
                            source_path: Some(expected_repo_path.clone()),
                            normalization: Some(NormalizationKind::CrlfToLf),
                            significant_manifest_diffs: Vec::new(),
                        });
                    } else if rel == "package.json" {
                        // Normalization #2: Published package.json
                        match compare_published_manifest(src_bytes, bytes) {
                            ManifestNormalization::Benign => {
                                classified = Some(FileOrigin {
                                    path: entry.path.clone(),
                                    sha256: entry.sha256.clone(),
                                    bytes: entry.size,
                                    class: OriginClass::SourceNormalized,
                                    role,
                                    moved_from: None,
                                    source_path: Some(expected_repo_path.clone()),
                                    normalization: Some(NormalizationKind::PublishedPackageJson),
                                    significant_manifest_diffs: Vec::new(),
                                });
                            }
                            ManifestNormalization::Significant(diffs) => {
                                classified = Some(FileOrigin {
                                    path: entry.path.clone(),
                                    sha256: entry.sha256.clone(),
                                    bytes: entry.size,
                                    class: OriginClass::Unexplained,
                                    role,
                                    moved_from: None,
                                    source_path: Some(expected_repo_path.clone()),
                                    normalization: None,
                                    significant_manifest_diffs: diffs,
                                });
                            }
                            ManifestNormalization::Unparseable => {}
                        }
                    }
                }
            }
        }

        let origin = classified.unwrap_or_else(|| FileOrigin {
            path: entry.path.clone(),
            sha256: entry.sha256.clone(),
            bytes: entry.size,
            class: OriginClass::Unexplained,
            role,
            moved_from: None,
            source_path: None,
            normalization: None,
            significant_manifest_diffs: Vec::new(),
        });

        add_total(&mut totals, origin.class, origin.bytes);
        origins.push(origin);
    }

    let mut removed = Vec::new();
    if let Some(ref_arch) = ref_archive {
        for entry in &ref_arch.inventory.entries {
            if !new_paths.contains(entry.path.as_str()) {
                removed.push(entry.path.clone());
            }
        }
    }
    removed.sort();

    (origins, removed, totals)
}

fn add_total(totals: &mut BTreeMap<OriginClass, ClassTotal>, class: OriginClass, bytes: u64) {
    let entry = totals.entry(class).or_default();
    entry.files += 1;
    entry.bytes += bytes;
}
