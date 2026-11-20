use crate::model::{Anchor, ArtifactProfile, BreakKind, BreakSeverity, FileOrigin, FileRole, ManifestFacts, OriginClass};
use crate::normalize::canonicalize_repo_url;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Default)]
pub struct ReleaseMetaSummary {
    pub version: String,
    pub published_at: Option<String>,
    pub has_provenance: bool,
    pub has_trusted_publisher: bool,
    pub has_git_head: bool,
    pub repository_url: Option<String>,
    pub publisher_id: Option<String>,
    pub file_count: Option<u64>,
    pub unpacked_size: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct HistoryContext {
    pub prior_releases: Vec<ReleaseMetaSummary>,
    pub new_release: ReleaseMetaSummary,
    pub reference_had_anchor: Option<bool>,
    pub registry_manifest_diffs: Vec<String>,
    pub known_malicious_ids: Vec<String>,
    pub is_new_to_project: bool,
}

#[derive(Debug, Clone, Default)]
pub struct HistoryResult {
    pub breaks: BTreeSet<BreakKind>,
    pub flags: BTreeSet<BreakKind>,
    pub notes: BTreeMap<BreakKind, String>,
}

impl HistoryResult {
    fn record(&mut self, kind: BreakKind, note: impl Into<String>) {
        match kind.default_severity() {
            BreakSeverity::Stop => {
                self.breaks.insert(kind);
            }
            BreakSeverity::Flag => {
                self.flags.insert(kind);
            }
        }
        self.notes.insert(kind, note.into());
    }
}

pub fn evaluate_history(
    ctx: &HistoryContext,
    new_anchor: &Anchor,
    new_manifest: &ManifestFacts,
    new_files: &[FileOrigin],
    ref_profile: Option<&ArtifactProfile>,
) -> HistoryResult {
    let mut res = HistoryResult::default();
    let prior = &ctx.prior_releases;

    // 1. known_malicious (OSV)
    if !ctx.known_malicious_ids.is_empty() {
        res.record(
            BreakKind::KnownMalicious,
            format!("advisory: {}", ctx.known_malicious_ids.join(", ")),
        );
    }

    // 2. registry_manifest_differs
    if !ctx.registry_manifest_diffs.is_empty() {
        res.record(
            BreakKind::RegistryManifestDiffers,
            format!(
                "registry metadata differs from tarball package.json on: {}",
                ctx.registry_manifest_diffs.join(", ")
            ),
        );
    }

    // 3. anchor_lost
    if !new_anchor.found {
        let prior_had_anchor = ctx.reference_had_anchor.unwrap_or(false)
            || prior.iter().any(|r| r.has_provenance || r.has_git_head);
        if prior_had_anchor {
            res.record(
                BreakKind::AnchorLost,
                "no source anchor found, though prior releases had one",
            );
        }
    }

    // 4. anchor_unreachable
    if new_anchor.found && new_anchor.reachable_from_branch == Some(false) {
        res.record(
            BreakKind::AnchorUnreachable,
            "anchor commit is not reachable from the repository default or release branches",
        );
    }

    // 5. provenance_lost
    let prior_provenance_count = prior.iter().filter(|r| r.has_provenance).count();
    let prior_tp_count = prior.iter().filter(|r| r.has_trusted_publisher).count();
    let recent_window = prior.iter().rev().take(3).collect::<Vec<_>>();
    let recent_had_prov = !recent_window.is_empty()
        && recent_window.iter().all(|r| r.has_provenance);
    let recent_had_tp = !recent_window.is_empty()
        && recent_window.iter().all(|r| r.has_trusted_publisher);

    if (recent_had_prov || (prior.len() >= 3 && prior_provenance_count * 2 >= prior.len()))
        && !ctx.new_release.has_provenance
    {
        res.record(
            BreakKind::ProvenanceLost,
            format!(
                "prior releases carried provenance ({prior_provenance_count}/{}), this release does not",
                prior.len()
            ),
        );
    } else if (recent_had_tp || (prior.len() >= 3 && prior_tp_count * 2 >= prior.len()))
        && !ctx.new_release.has_trusted_publisher
    {
        res.record(
            BreakKind::ProvenanceLost,
            "prior releases used trusted publishing, this release does not",
        );
    }

    // 6. repo_changed
    let new_repo = new_anchor
        .repository_url
        .as_deref()
        .or(new_manifest.repository_url.as_deref())
        .map(canonicalize_repo_url);
    if let Some(ref nr) = new_repo {
        let prior_repos: BTreeSet<String> = prior
            .iter()
            .filter_map(|r| r.repository_url.as_deref().map(canonicalize_repo_url))
            .collect();
        let ref_repo = ref_profile
            .and_then(|p| {
                p.anchor
                    .repository_url
                    .as_deref()
                    .or(p.manifest.repository_url.as_deref())
            })
            .map(canonicalize_repo_url);
        let mut known_repos = prior_repos;
        if let Some(rr) = ref_repo {
            known_repos.insert(rr);
        }
        if !known_repos.is_empty() && !known_repos.contains(nr) {
            res.record(
                BreakKind::RepoChanged,
                format!("repository changed to {nr}"),
            );
        }
    }

    // 7. source_match_drop & unexplained_appeared (comparing against reference profile)
    if let Some(rp) = ref_profile {
        let ref_source_paths: BTreeSet<&str> = rp
            .files
            .iter()
            .filter(|f| {
                matches!(
                    f.class,
                    OriginClass::Source | OriginClass::SourceElsewhere | OriginClass::SourceNormalized
                )
            })
            .map(|f| f.path.as_str())
            .collect();

        let dropped: Vec<&str> = new_files
            .iter()
            .filter(|f| f.class == OriginClass::Unexplained && ref_source_paths.contains(f.path.as_str()))
            .map(|f| f.path.as_str())
            .collect();

        if !dropped.is_empty() {
            let preview = dropped.iter().take(3).copied().collect::<Vec<_>>().join(", ");
            res.record(
                BreakKind::SourceMatchDrop,
                format!(
                    "{} file(s) matched source in reference and are now unexplained ({preview})",
                    dropped.len()
                ),
            );
        }

        let ref_had_unexplained_exec = rp.files.iter().any(|f| {
            f.class == OriginClass::Unexplained
                && matches!(f.role, FileRole::Code | FileRole::Manifest | FileRole::Binary)
        });
        let new_has_unexplained_exec = new_files.iter().any(|f| {
            f.class == OriginClass::Unexplained
                && matches!(f.role, FileRole::Code | FileRole::Manifest | FileRole::Binary)
        });
        if rp.anchor.found && !ref_had_unexplained_exec && new_has_unexplained_exec && dropped.is_empty() {
            res.record(
                BreakKind::UnexplainedAppeared,
                "reference had zero unexplained executable files; new release introduced unexplained code",
            );
        }
    }

    // 8. install_script_new / install_script_changed
    if ctx.is_new_to_project {
        if new_manifest.has_install_exec {
            res.record(
                BreakKind::InstallScriptNew,
                "package new to project defines install-time execution",
            );
        }
    } else if let Some(rp) = ref_profile {
        if new_manifest.has_install_exec && !rp.manifest.has_install_exec {
            res.record(
                BreakKind::InstallScriptNew,
                "install-time execution appeared (absent in reference)",
            );
        } else if new_manifest.has_install_exec
            && rp.manifest.has_install_exec
            && (new_manifest.install_scripts != rp.manifest.install_scripts
                || new_manifest.has_binding_gyp != rp.manifest.has_binding_gyp
                || new_manifest.nested_install_scripts != rp.manifest.nested_install_scripts)
        {
            res.record(
                BreakKind::InstallScriptChanged,
                "install-time script or native build trigger changed",
            );
        }
    }

    // 9. native_or_binary_new
    if let Some(rp) = ref_profile {
        if new_manifest.has_native_or_binary && !rp.manifest.has_native_or_binary {
            res.record(
                BreakKind::NativeOrBinaryNew,
                "first appearance of native addon or executable binary",
            );
        }
    }

    // 10. publisher_changed (flag)
    if let Some(ref pub_id) = ctx.new_release.publisher_id {
        let prior_pubs: BTreeSet<&str> = prior
            .iter()
            .filter_map(|r| r.publisher_id.as_deref())
            .collect();
        if !prior_pubs.is_empty() && !prior_pubs.contains(pub_id.as_str()) {
            res.record(
                BreakKind::PublisherChanged,
                format!("publisher '{pub_id}' not seen in prior {} releases", prior.len()),
            );
        }
    }

    // 11. dependency_added (flag)
    if let Some(rp) = ref_profile {
        let added: Vec<&String> = new_manifest
            .runtime_dependencies
            .difference(&rp.manifest.runtime_dependencies)
            .collect();
        if !added.is_empty() {
            let names = added.iter().take(4).map(|s| s.as_str()).collect::<Vec<_>>().join(", ");
            res.record(
                BreakKind::DependencyAdded,
                format!("added runtime dependencies: {names}"),
            );
        }
    }

    // 12. size_jump (flag): unpacked size or file count > 2.5x max of prior K (with reasonable floor).
    if prior.len() >= 3 {
        let max_prior_size = prior.iter().filter_map(|r| r.unpacked_size).max();
        let max_prior_files = prior.iter().filter_map(|r| r.file_count).max();
        let size_spike = match (max_prior_size, ctx.new_release.unpacked_size) {
            (Some(max_s), Some(new_s)) if max_s > 0 => {
                new_s > max_s.saturating_mul(5) / 2 && new_s.saturating_sub(max_s) > 100_000
            }
            _ => false,
        };
        let file_spike = match (max_prior_files, ctx.new_release.file_count) {
            (Some(max_f), Some(new_f)) if max_f > 0 => {
                new_f > max_f.saturating_mul(5) / 2 && new_f.saturating_sub(max_f) > 25
            }
            _ => false,
        };
        if size_spike || file_spike {
            res.record(
                BreakKind::SizeJump,
                "unpacked size or file count jumped sharply above recent release band",
            );
        }
    }

    // 13. version_out_of_sequence (flag)
    if let Some(rp) = ref_profile {
        if is_version_jump_suspicious(&rp.version, &ctx.new_release.version) {
            res.record(
                BreakKind::VersionOutOfSequence,
                format!(
                    "version {} -> {} skipped unexpectedly on release line",
                    rp.version, ctx.new_release.version
                ),
            );
        }
    }

    res
}

fn parse_simple_semver(v: &str) -> Option<(u64, u64, u64, bool)> {
    let is_pre = v.contains('-');
    let core = v.split(['-', '+']).next()?;
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch, is_pre))
}

fn is_version_jump_suspicious(from: &str, to: &str) -> bool {
    let (Some((ma1, mi1, pa1, _)), Some((ma2, mi2, pa2, _))) =
        (parse_simple_semver(from), parse_simple_semver(to))
    else {
        return false;
    };
    // Huge single-step jumps like 1.2.3 -> 99.0.0 or 1.2.3 -> 1.2.999
    if ma2 > ma1 + 5 {
        return true;
    }
    if ma2 == ma1 && mi2 > mi1 + 20 {
        return true;
    }
    if ma2 == ma1 && mi2 == mi1 && pa2 > pa1 + 50 {
        return true;
    }
    false
}
