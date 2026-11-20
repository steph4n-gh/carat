mod fetch;
mod render;

use assay_core::canonical::{format_unix_rfc3339, to_canonical_json};
use assay_core::history::HistoryContext;
use assay_core::model::{
    ArchiveLimits, PolicyConfig, ReadingOutcome, ReferenceStanding, Verdict,
};
use assay_core::normalize::registry_manifest_differs;
use assay_core::policy::{
    TransitionInput, build_artifact_profile, build_transition_ledger, evaluate_decision,
};
use clap::{Parser, Subcommand};
use fetch::{Fetcher, build_release_history};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(name = "assay", version, about = "A balance sheet for dependency changes")]
struct Cli {
    /// Emit machine-readable JSON output
    #[arg(long, global = true)]
    json: bool,

    /// Cache directory (default: .assay/cache)
    #[arg(long, global = true)]
    cache_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Explain one npm package transition directly from the registry: <name>@<from>..<to>
    Explain {
        /// Package transition spec, e.g. vite@8.3.7..8.3.8 or @scope/pkg@1.0.0..1.0.1
        spec: String,

        /// Explicit RFC 3339 evaluation timestamp (default: now UTC)
        #[arg(long)]
        as_of: Option<String>,

        /// Skip OSV advisory lookup (useful for zero-day backtesting)
        #[arg(long)]
        no_osv: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let cache_dir = cli
        .cache_dir
        .unwrap_or_else(|| PathBuf::from(".assay/cache"));

    match cli.command {
        Commands::Explain {
            spec,
            as_of,
            no_osv,
        } => match run_explain(&spec, as_of, no_osv, &cache_dir, cli.json) {
            Ok(verdict) => match verdict {
                Verdict::Stop => ExitCode::from(1),
                Verdict::Explained | Verdict::Read => ExitCode::from(0),
            },
            Err(err) => {
                eprintln!("assay error: {err}");
                ExitCode::from(2)
            }
        },
    }
}

fn parse_transition_spec(spec: &str) -> Result<(String, String, String), String> {
    // Handle scoped packages like `@scope/name@1.0.0..1.0.1` by finding the LAST `@`.
    let at_pos = spec
        .rfind('@')
        .filter(|&i| i > 0)
        .ok_or_else(|| format!("invalid spec '{spec}': expected <name>@<from>..<to>"))?;
    let name = spec[..at_pos].to_string();
    let range = &spec[at_pos + 1..];
    let (from, to) = range
        .split_once("..")
        .ok_or_else(|| format!("invalid version range '{range}': expected <from>..<to>"))?;
    if from.is_empty() || to.is_empty() {
        return Err(format!("invalid version range '{range}': both versions required"));
    }
    Ok((name, from.to_string(), to.to_string()))
}

fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    format_unix_rfc3339(secs)
}

fn run_explain(
    spec: &str,
    as_of_opt: Option<String>,
    no_osv: bool,
    cache_dir: &PathBuf,
    json_output: bool,
) -> Result<Verdict, String> {
    let (name, from_ver, to_ver) = parse_transition_spec(spec)?;
    let as_of = as_of_opt.unwrap_or_else(now_rfc3339);
    let fetcher = Fetcher::new(cache_dir.clone())?;
    let limits = ArchiveLimits::default();
    let policy = PolicyConfig::default();

    // 1. Fetch registry metadata document
    let reg_doc = fetcher.fetch_registry_package(&name)?;
    let versions = reg_doc
        .json
        .get("versions")
        .and_then(|v| v.as_object())
        .ok_or_else(|| format!("registry doc for {name} missing versions map"))?;

    let ref_reg = versions
        .get(&from_ver)
        .ok_or_else(|| format!("version {from_ver} not found for {name}"))?;
    let new_reg = versions
        .get(&to_ver)
        .ok_or_else(|| format!("version {to_ver} not found for {name}"))?;

    let ref_tarball = ref_reg
        .pointer("/dist/tarball")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("missing dist.tarball for {name}@{from_ver}"))?;
    let ref_integrity = ref_reg.pointer("/dist/integrity").and_then(|v| v.as_str());

    let new_tarball = new_reg
        .pointer("/dist/tarball")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("missing dist.tarball for {name}@{to_ver}"))?;
    let new_integrity = new_reg.pointer("/dist/integrity").and_then(|v| v.as_str());

    // 2. Fetch and inspect both tarballs in memory (SHA-512 verified)
    let ref_archive = fetcher.fetch_and_inspect_tarball(ref_tarball, ref_integrity, limits)?;
    let new_archive = fetcher.fetch_and_inspect_tarball(new_tarball, new_integrity, limits)?;

    let ref_manifest = assay_core::archive::extract_manifest_facts(&ref_archive);
    let new_manifest = assay_core::archive::extract_manifest_facts(&new_archive);

    // 3. Resolve anchors and source snapshots (object-only git)
    let (ref_anchor, ref_source) = fetcher.resolve_anchor_and_source(
        &name,
        &from_ver,
        &ref_archive,
        &ref_manifest,
        ref_reg,
        None,
    );
    let (new_anchor, new_source) = fetcher.resolve_anchor_and_source(
        &name,
        &to_ver,
        &new_archive,
        &new_manifest,
        new_reg,
        Some(&ref_archive),
    );

    let ref_profile = build_artifact_profile(
        "npm",
        &name,
        &from_ver,
        &ref_archive,
        ref_anchor.clone(),
        ref_source.as_ref(),
    );
    let new_profile = build_artifact_profile(
        "npm",
        &name,
        &to_ver,
        &new_archive,
        new_anchor.clone(),
        new_source.as_ref(),
    );

    // 4. Build history context & optional OSV check
    let (prior_releases, new_release_summary) =
        build_release_history(&reg_doc.json, &to_ver, policy.history_depth);
    let ref_published_at = reg_doc
        .json
        .get("time")
        .and_then(|t| t.get(&from_ver))
        .and_then(|v| v.as_str())
        .map(String::from);

    let reg_manifest_diffs = new_archive
        .contents
        .iter()
        .find(|(p, _)| assay_core::archive::strip_archive_root(p) == "package.json")
        .map(|(_, bytes)| registry_manifest_differs(bytes, new_reg))
        .unwrap_or_default();

    let known_malicious_ids = if no_osv {
        Vec::new()
    } else {
        fetcher.query_osv(&name, &to_ver, Some(&as_of))
    };

    let history_ctx = HistoryContext {
        prior_releases,
        new_release: new_release_summary.clone(),
        reference_had_anchor: Some(ref_anchor.found),
        registry_manifest_diffs: reg_manifest_diffs,
        known_malicious_ids,
        is_new_to_project: false,
    };

    // 5. Build timeless TransitionLedger + evaluate Decision at `as_of`
    let (ledger, ledger_id) = build_transition_ledger(TransitionInput {
        ecosystem: "npm",
        name: &name,
        reference_archive: Some(&ref_archive),
        reference_profile: Some(&ref_profile),
        reference_standing: ReferenceStanding::Admitted,
        reference_published_at: ref_published_at,
        new_archive: &new_archive,
        new_profile: &new_profile,
        new_source: new_source.as_ref(),
        new_published_at: new_release_summary.published_at,
        lock_alarms: BTreeSet::new(),
        history_ctx,
        registry_snapshot_sha256: Some(reg_doc.raw_sha256),
    })?;

    let decision = evaluate_decision(
        &ledger,
        &ledger_id,
        &policy,
        &as_of,
        false,
        ReadingOutcome::NotRun,
        None,
    );

    if json_output {
        let out = serde_json::json!({
            "ledger_id": ledger_id,
            "ledger": ledger,
            "decision": decision,
        });
        println!("{}", to_canonical_json(&out)?);
    } else {
        print!("{}", render::render_explain_markdown(&ledger, &decision));
    }

    Ok(decision.verdict)
}
