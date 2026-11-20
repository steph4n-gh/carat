mod exposure;
mod fetch;
mod mcp;
mod pr;
mod reader_exec;
mod render;

use assay_core::archive::{LoadedArchive, extract_manifest_facts, inspect_tgz, strip_archive_root};
use assay_core::canonical::{canonical_id, format_unix_rfc3339, to_canonical_json};
use assay_core::config::AssayConfig;
use assay_core::digest::sha256_hex;
use assay_core::history::HistoryContext;
use assay_core::lockfile::{
    LockTransition, deduplicate_transitions, diff_lockfiles, parse_lockfile_packages,
};
use assay_core::model::{
    ArchiveLimits, LockAlarm, ReadingOutcome, ReferenceStanding, StopRule, Verdict,
};
use assay_core::normalize::registry_manifest_differs;
use assay_core::packet::{PacketBudgets, build_inline_residual_diffs, build_reading_packet};
use assay_core::policy::{
    TransitionInput, build_artifact_profile, build_transition_ledger, evaluate_decision,
};
use assay_core::reader::ReadingRecord;
use assay_core::source::SourceSnapshot;
use assay_core::store::{ApprovalRecord, InputBundle, RecordStore};
use clap::{Parser, Subcommand};
use exposure::{ExposureQuery, search_git_lockfile_exposure, search_store_exposure};
use fetch::{Fetcher, build_release_history};
use mcp::{McpDispatcher, run_mcp_server};
use pr::{
    PrComment, detect_protected_file_tampering, list_changed_paths, parse_approval_comments,
    read_git_file,
};
use reader_exec::{ReaderExecConfig, run_reading};
use render::{TransitionReportItem, render_change_summary, render_explain_markdown};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_CONFIG_TOML: &str = include_str!("../../../assay.toml.example");
const DEFAULT_GITHUB_WORKFLOW: &str = include_str!("../../../docs/workflows/assay-pr.yml");

#[derive(Parser)]
#[command(name = "assay", version, about = "A balance sheet for dependency changes")]
struct Cli {
    /// Emit machine-readable JSON output
    #[arg(long, global = true)]
    json: bool,

    /// Store directory (default: .assay)
    #[arg(long, global = true)]
    store_dir: Option<PathBuf>,

    /// Path to assay.toml configuration
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Explain one npm package transition straight from the registry: <name>@<from>..<to>
    Explain {
        /// Transition spec, e.g. vite@8.3.7..8.3.8 or @scope/pkg@1.0.0..1.0.1
        spec: String,
        /// Run the configured reader when unexplained code diffs or flags remain
        #[arg(long)]
        read: bool,
        /// Explicit RFC 3339 evaluation timestamp (for historical backtesting only)
        #[arg(long)]
        as_of: Option<String>,
        /// Skip OSV advisory lookup (for zero-day backtesting only)
        #[arg(long)]
        no_osv: bool,
        /// Save an offline input bundle under .assay/inputs/<ledger_id> for `assay replay`
        #[arg(long)]
        save_inputs: bool,
    },

    /// Check all changed packages between a base and head package-lock.json (v3)
    Check {
        #[arg(long)]
        base: PathBuf,
        #[arg(long)]
        head: PathBuf,
        #[arg(long)]
        base_pkg: Option<PathBuf>,
        #[arg(long)]
        head_pkg: Option<PathBuf>,
        #[arg(long)]
        read: bool,
        #[arg(long)]
        as_of: Option<String>,
    },

    /// Check a pull request reading both revisions strictly from Git objects (never executes PR head)
    Pr {
        #[arg(long)]
        base: String,
        #[arg(long)]
        head: String,
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        #[arg(long, default_value = "package-lock.json")]
        lockfile: String,
        #[arg(long, default_value = "package.json")]
        manifest: String,
        /// Optional JSON file of PR comments (`[{author, body, has_write_access, created_at}]`)
        #[arg(long)]
        comments_json: Option<PathBuf>,
        /// PR author username (prevented from self-approving)
        #[arg(long)]
        pr_author: Option<String>,
        #[arg(long)]
        read: bool,
    },

    /// Resolve, check, and optionally install an npm dependency (exact checked bytes only)
    Add {
        /// Package specifier, e.g. zod or zod@4.6.7
        package: String,
        /// Project directory containing package.json / package-lock.json
        #[arg(long, default_value = ".")]
        project_dir: PathBuf,
        /// Run the configured reader when unexplained code diffs or flags remain
        #[arg(long)]
        read: bool,
        /// If every transition passes, write the exact checked lockfile and run `npm ci --ignore-scripts`
        #[arg(long)]
        install: bool,
    },

    /// Record a human approval bound to a transition subject and exact stop facts
    Approve {
        /// Unique subject hex ID or prefix (>= 8 hex chars) from a stop report
        subject: String,
        /// Approver name (defaults to $USER)
        #[arg(long)]
        by: Option<String>,
        /// Optional approval rationale
        #[arg(long)]
        note: Option<String>,
        /// Allow running without an interactive terminal (for human-invoked scripts/tests only)
        #[arg(long)]
        non_interactive: bool,
    },

    /// Report where and when given package bytes were admitted (Git history + local store)
    Exposure {
        /// Package and version, e.g. flatmap-stream@0.1.1
        package: Option<String>,
        /// Exact SHA-512 hex (or prefix) or SRI (`sha512-...`)
        #[arg(long)]
        sha512: Option<String>,
        /// Git repository directory to scan (default: current directory)
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        #[arg(long, default_value = "package-lock.json")]
        lockfile: String,
    },

    /// Summarize all packages currently in a lockfile (never blocks; shows standing debt)
    Inventory {
        #[arg(long, default_value = "package-lock.json")]
        lock: PathBuf,
    },

    /// Recompute deterministic records 100% offline from a saved input bundle
    Replay {
        /// Path to saved input bundle directory (e.g. .assay/inputs/<ledger_id>)
        bundle: PathBuf,
        #[arg(long)]
        as_of: Option<String>,
    },

    /// Run Assay's stdio JSON-RPC 2.0 MCP server for coding agents
    Mcp,

    /// Bootstrap Assay in a project (writes assay.toml, optional GitHub workflow, and MCP snippet)
    Init {
        /// Target project directory (default: current directory)
        #[arg(long, default_value = ".")]
        dir: PathBuf,
        /// Also install .github/workflows/assay-pr.yml
        #[arg(long)]
        github: bool,
        /// Print ready-to-paste MCP server JSON config for coding agents
        #[arg(long)]
        mcp: bool,
        /// Overwrite existing files if present
        #[arg(long)]
        force: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let store_root = cli.store_dir.unwrap_or_else(|| PathBuf::from(".assay"));
    let cfg = match load_config(cli.config.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("assay config error: {e}");
            return ExitCode::from(2);
        }
    };

    match cli.command {
        Commands::Explain {
            spec,
            read,
            as_of,
            no_osv,
            save_inputs,
        } => match run_explain(&spec, read, as_of, no_osv, save_inputs, &store_root, &cfg, cli.json) {
            Ok(passed) => if passed { ExitCode::from(0) } else { ExitCode::from(1) },
            Err(e) => {
                eprintln!("assay error: {e}");
                ExitCode::from(2)
            }
        },
        Commands::Check {
            base,
            head,
            base_pkg,
            head_pkg,
            read,
            as_of,
        } => match run_check_files(
            &base,
            &head,
            base_pkg.as_deref(),
            head_pkg.as_deref(),
            read,
            as_of,
            &store_root,
            &cfg,
            cli.json,
        ) {
            Ok(passed) => if passed { ExitCode::from(0) } else { ExitCode::from(1) },
            Err(e) => {
                eprintln!("assay error: {e}");
                ExitCode::from(2)
            }
        },
        Commands::Pr {
            base,
            head,
            repo,
            lockfile,
            manifest,
            comments_json,
            pr_author,
            read,
        } => match run_pr(
            &repo,
            &base,
            &head,
            &lockfile,
            &manifest,
            comments_json.as_deref(),
            pr_author.as_deref(),
            read,
            &store_root,
            cli.json,
        ) {
            Ok(passed) => if passed { ExitCode::from(0) } else { ExitCode::from(1) },
            Err(e) => {
                eprintln!("assay error: {e}");
                ExitCode::from(2)
            }
        },
        Commands::Add {
            package,
            project_dir,
            read,
            install,
        } => match execute_add(&package, &project_dir, read, install, &store_root, &cfg) {
            Ok(res) => {
                if let Err(e) = emit_change_report(
                    &res.items,
                    &[],
                    &res.transition_errors,
                    res.passed,
                    cli.json,
                ) {
                    eprintln!("assay error: {e}");
                    return ExitCode::from(2);
                }
                if res.installed && !cli.json {
                    println!("Installed exact checked lockfile via `npm ci --ignore-scripts`.");
                }
                if res.passed {
                    ExitCode::from(0)
                } else {
                    ExitCode::from(1)
                }
            }
            Err(e) => {
                eprintln!("assay error: {e}");
                ExitCode::from(2)
            }
        },
        Commands::Approve {
            subject,
            by,
            note,
            non_interactive,
        } => match run_approve(&subject, by, note, non_interactive, &store_root, &cfg, cli.json) {
            Ok(()) => ExitCode::from(0),
            Err(e) => {
                eprintln!("assay error: {e}");
                ExitCode::from(2)
            }
        },
        Commands::Exposure {
            package,
            sha512,
            repo,
            lockfile,
        } => match run_exposure(
            package.as_deref(),
            sha512.as_deref(),
            &repo,
            &lockfile,
            &store_root,
            cli.json,
        ) {
            Ok(()) => ExitCode::from(0),
            Err(e) => {
                eprintln!("assay error: {e}");
                ExitCode::from(2)
            }
        },
        Commands::Inventory { lock } => match run_inventory(&lock, cli.json) {
            Ok(()) => ExitCode::from(0),
            Err(e) => {
                eprintln!("assay error: {e}");
                ExitCode::from(2)
            }
        },
        Commands::Replay { bundle, as_of } => match run_replay(&bundle, as_of, &cfg, cli.json) {
            Ok(passed) => if passed { ExitCode::from(0) } else { ExitCode::from(1) },
            Err(e) => {
                eprintln!("assay error: {e}");
                ExitCode::from(2)
            }
        },
        Commands::Mcp => {
            let dispatcher = CliMcpDispatcher { store_root, cfg };
            match run_mcp_server(&dispatcher) {
                Ok(()) => ExitCode::from(0),
                Err(e) => {
                    eprintln!("assay mcp error: {e}");
                    ExitCode::from(2)
                }
            }
        }
        Commands::Init {
            dir,
            github,
            mcp,
            force,
        } => match run_init(&dir, github, mcp, force, cli.json) {
            Ok(()) => ExitCode::from(0),
            Err(e) => {
                eprintln!("assay init error: {e}");
                ExitCode::from(2)
            }
        },
    }
}

fn load_config(explicit: Option<&Path>) -> Result<AssayConfig, String> {
    if let Some(p) = explicit {
        let s = fs::read_to_string(p)
            .map_err(|e| format!("failed reading config {}: {e}", p.display()))?;
        return AssayConfig::from_toml(&s);
    }
    for candidate in ["assay.toml", ".assay.toml"] {
        let p = Path::new(candidate);
        if p.exists() {
            let s = fs::read_to_string(p)
                .map_err(|e| format!("failed reading {}: {e}", p.display()))?;
            return AssayConfig::from_toml(&s);
        }
    }
    Ok(AssayConfig::default())
}

fn open_store(store_root: &Path, cfg: &AssayConfig) -> Result<RecordStore, String> {
    let readonly = cfg.stores.iter().map(PathBuf::from).collect();
    RecordStore::open(store_root.to_path_buf(), readonly)
}

fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    format_unix_rfc3339(secs)
}

fn parse_transition_spec(spec: &str) -> Result<(String, String, String), String> {
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

struct EvalOptions<'a> {
    read: bool,
    as_of: &'a str,
    no_osv: bool,
    save_inputs: bool,
    is_new_direct: bool,
    is_new_to_project: bool,
    lock_alarms: BTreeSet<LockAlarm>,
    pr_approvals: &'a [pr::ParsedPrApproval],
}

#[allow(clippy::too_many_arguments)]
fn evaluate_single_transition(
    fetcher: &Fetcher,
    store: &RecordStore,
    cfg: &AssayConfig,
    name: &str,
    ref_ver_opt: Option<&str>,
    ref_tarball_opt: Option<(&str, Option<&str>)>,
    new_ver: &str,
    new_tarball_opt: Option<(&str, Option<&str>)>,
    opts: EvalOptions<'_>,
) -> Result<TransitionReportItem, String> {
    let limits = ArchiveLimits::default();
    let reg_doc = fetcher.fetch_registry_package(name)?;
    let versions = reg_doc
        .json
        .get("versions")
        .and_then(|v| v.as_object())
        .ok_or_else(|| format!("registry doc for {name} missing versions map"))?;

    let new_reg = versions
        .get(new_ver)
        .ok_or_else(|| format!("version {new_ver} not found for {name}"))?;

    let (chosen_ref_ver, ref_standing) = match ref_ver_opt {
        Some(rv) => (Some(rv.to_string()), ReferenceStanding::Admitted),
        None => match fetcher.find_settled_reference_version(
            &reg_doc.json,
            new_ver,
            opts.as_of,
            cfg.policy.settled_age_days,
        ) {
            Some(sv) => (Some(sv), ReferenceStanding::Settled),
            None => (None, ReferenceStanding::None),
        },
    };

    let mut ref_archive: Option<LoadedArchive> = None;
    let mut ref_profile = None;
    let mut ref_source_snap: Option<SourceSnapshot> = None;
    let mut ref_anchor_found = None;
    let mut ref_anchor_commit = None;
    let mut ref_published_at = None;

    if let Some(ref rv) = chosen_ref_ver {
        if let Some(ref_reg) = versions.get(rv) {
            let (rt_url, rt_int) = match ref_tarball_opt {
                Some((u, i)) => (u, i),
                None => (
                    ref_reg
                        .pointer("/dist/tarball")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| format!("missing dist.tarball for {name}@{rv}"))?,
                    ref_reg.pointer("/dist/integrity").and_then(|v| v.as_str()),
                ),
            };
            let ra = fetcher.fetch_and_inspect_tarball(rt_url, rt_int, limits)?;
            let rm = extract_manifest_facts(&ra);
            let (r_anchor, r_source) =
                fetcher.resolve_anchor_and_source(name, rv, &ra, &rm, ref_reg, None);
            ref_anchor_found = Some(r_anchor.found);
            ref_anchor_commit = r_anchor.commit.clone();
            let rp = build_artifact_profile("npm", name, rv, &ra, r_anchor, r_source.as_ref());
            let _ = store.save_profile(&rp);
            ref_published_at = reg_doc
                .json
                .get("time")
                .and_then(|t| t.get(rv))
                .and_then(|v| v.as_str())
                .map(String::from);
            ref_archive = Some(ra);
            ref_profile = Some(rp);
            ref_source_snap = r_source;
        }
    }

    let (nt_url, nt_int) = match new_tarball_opt {
        Some((u, i)) => (u, i),
        None => (
            new_reg
                .pointer("/dist/tarball")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("missing dist.tarball for {name}@{new_ver}"))?,
            new_reg.pointer("/dist/integrity").and_then(|v| v.as_str()),
        ),
    };
    let new_archive = fetcher.fetch_and_inspect_tarball(nt_url, nt_int, limits)?;
    let new_manifest = extract_manifest_facts(&new_archive);
    let (new_anchor, new_source) = fetcher.resolve_anchor_and_source(
        name,
        new_ver,
        &new_archive,
        &new_manifest,
        new_reg,
        ref_archive.as_ref(),
    );
    let new_profile = build_artifact_profile(
        "npm",
        name,
        new_ver,
        &new_archive,
        new_anchor.clone(),
        new_source.as_ref(),
    );
    let _ = store.save_profile(&new_profile);

    let hist_slice = build_release_history(&reg_doc.json, new_ver, cfg.policy.history_depth);

    let reg_manifest_diffs = new_archive
        .contents
        .iter()
        .find(|(p, _)| strip_archive_root(p) == "package.json")
        .map(|(_, bytes)| registry_manifest_differs(bytes, new_reg, new_manifest.has_binding_gyp))
        .unwrap_or_default();

    let (known_malicious_ids, osv_unavailable) = if opts.no_osv {
        (Vec::new(), false)
    } else {
        fetcher.query_osv(name, new_ver, Some(opts.as_of))
    };

    let history_ctx = HistoryContext {
        prior_releases: hist_slice.prior_releases,
        total_prior_releases: hist_slice.total_prior_releases,
        package_first_published_at: hist_slice.first_published_at,
        new_release: hist_slice.new_release.clone(),
        reference_had_anchor: ref_anchor_found,
        registry_manifest_diffs: reg_manifest_diffs,
        known_malicious_ids,
        osv_unavailable,
        is_new_to_project: opts.is_new_to_project,
    };

    let (ledger, ledger_id) = build_transition_ledger(TransitionInput {
        ecosystem: "npm",
        name,
        reference_archive: ref_archive.as_ref(),
        reference_profile: ref_profile.as_ref(),
        reference_standing: ref_standing,
        reference_published_at: ref_published_at.clone(),
        new_archive: &new_archive,
        new_profile: &new_profile,
        new_source: new_source.as_ref(),
        new_published_at: hist_slice.new_release.published_at.clone(),
        lock_alarms: opts.lock_alarms,
        history_ctx,
        history_slice_sha256: Some(hist_slice.slice_sha256.clone()),
    })?;
    let _ = store.save_ledger(&ledger);

    // Inline leftover code diffs (the 30-second wedge!)
    let residual_diffs =
        build_inline_residual_diffs(&ledger, ref_archive.as_ref(), &new_archive, 4, 40);

    // Optional offline replay input bundle
    if opts.save_inputs {
        let mut bundle_files: Vec<(String, Vec<u8>)> = Vec::new();
        let new_tgz_name = format!("{}.tgz", new_archive.inventory.sha512);
        if let Some(b) = fetcher.read_cached_tarball(&new_archive.inventory.sha512) {
            bundle_files.push((new_tgz_name.clone(), b));
        }
        let ref_tgz_name = ref_archive.as_ref().and_then(|ra| {
            let fname = format!("{}.tgz", ra.inventory.sha512);
            fetcher.read_cached_tarball(&ra.inventory.sha512).map(|b| {
                bundle_files.push((fname.clone(), b));
                fname
            })
        });
        bundle_files.push(("registry.json".into(), reg_doc.raw_bytes.clone()));

        let mut ref_source_blobs_b64 = BTreeMap::new();
        if let Some(ref src) = ref_source_snap {
            for (k, v) in &src.blobs_by_sha1 {
                ref_source_blobs_b64.insert(k.clone(), base64_encode(v));
            }
        }
        let mut source_blobs_b64 = BTreeMap::new();
        if let Some(ref src) = new_source {
            for (k, v) in &src.blobs_by_sha1 {
                source_blobs_b64.insert(k.clone(), base64_encode(v));
            }
        }

        let bundle = InputBundle {
            schema: 1,
            ecosystem: "npm".into(),
            name: name.into(),
            reference_version: chosen_ref_ver.clone(),
            reference_tarball_file: ref_tgz_name,
            reference_sha512: ref_archive.as_ref().map(|a| a.inventory.sha512.clone()),
            reference_published_at: ref_published_at,
            reference_anchor: ref_profile.as_ref().map(|p| p.anchor.clone()),
            reference_source_package_dir: ref_source_snap
                .as_ref()
                .and_then(|s| s.package_dir.clone()),
            reference_source_tree: ref_source_snap
                .as_ref()
                .map(|s| s.tree_blob_sha1.clone())
                .unwrap_or_default(),
            reference_source_blobs_b64: ref_source_blobs_b64,
            new_version: new_ver.into(),
            new_tarball_file: new_tgz_name,
            new_sha512: new_archive.inventory.sha512.clone(),
            new_published_at: hist_slice.new_release.published_at,
            new_anchor: new_anchor.clone(),
            new_source_package_dir: new_source.as_ref().and_then(|s| s.package_dir.clone()),
            new_source_tree: new_source
                .as_ref()
                .map(|s| s.tree_blob_sha1.clone())
                .unwrap_or_default(),
            new_source_blobs_b64: source_blobs_b64,
            registry_snapshot_file: Some("registry.json".into()),
            history_slice_sha256: Some(hist_slice.slice_sha256),
            as_of: opts.as_of.into(),
            expected_ledger_id: ledger_id.clone(),
        };

        let refs: Vec<(&str, &[u8])> = bundle_files
            .iter()
            .map(|(n, b)| (n.as_str(), b.as_slice()))
            .collect();
        let _ = store.save_input_bundle(&ledger_id, &bundle, &refs);
    }

    let prelim = evaluate_decision(
        &ledger,
        &ledger_id,
        &cfg.policy,
        opts.as_of,
        opts.is_new_direct,
        ReadingOutcome::NotRun,
        None,
    );

    let mut reading_record: Option<ReadingRecord> = None;
    let mut reading_outcome = ReadingOutcome::NotRun;

    let should_read = opts.read
        && prelim.reading_required
        && (cfg.read_on_stop
            || prelim
                .stop_rules
                .iter()
                .all(|&r| r == StopRule::S8 || r == StopRule::S9));

    if should_read {
        let reading_cache_key = format!(
            "{}-{}",
            &ledger_id[..24],
            cfg.reader.model.replace('/', "_")
        );
        // Only reuse cached COMPLETED assessments (never reuse cached Unavailable / Invalid outages!).
        if let Some(cached_json) = store.load_reading_json(&reading_cache_key) {
            if let Ok(rec) = serde_json::from_str::<ReadingRecord>(&cached_json) {
                if matches!(
                    rec.outcome,
                    ReadingOutcome::Passed | ReadingOutcome::Concern | ReadingOutcome::Refused
                ) {
                    reading_outcome = rec.outcome;
                    reading_record = Some(rec);
                }
            }
        }
        if reading_record.is_none() {
            let (commit_subjects, source_diff) = match (
                new_anchor.repository_url.as_deref(),
                ref_anchor_commit.as_deref(),
                new_anchor.commit.as_deref(),
            ) {
                (Some(url), Some(fc), Some(tc)) => fetcher.fetch_commit_subjects_and_source_diff(
                    url,
                    fc,
                    tc,
                    new_anchor.repository_directory.as_deref(),
                ),
                _ => (Vec::new(), None),
            };
            let packet = build_reading_packet(
                &ledger,
                ref_archive.as_ref(),
                &new_archive,
                commit_subjects,
                source_diff,
                PacketBudgets::default(),
            )?;

            let exec_cfg = ReaderExecConfig {
                command: cfg.reader.command.clone(),
                model: cfg.reader.model.clone(),
                effort: cfg.reader.effort.clone(),
                timeout_secs: cfg.reader.timeout_secs,
            };
            let rec = run_reading(&packet, &ledger_id, &exec_cfg);
            reading_outcome = rec.outcome;
            // Persist ONLY completed assessments so an API outage never poisons the cache.
            if matches!(
                rec.outcome,
                ReadingOutcome::Passed | ReadingOutcome::Concern | ReadingOutcome::Refused
            ) {
                if let Ok(canon) = to_canonical_json(&rec) {
                    let _ = store.save_reading_json(&reading_cache_key, &canon);
                }
            }
            reading_record = Some(rec);
        }
    }

    // Check granular approval in store (exact approved_facts) or PR comments.
    let store_approval = store.find_approval(&ledger.subject);
    let pr_approval = opts
        .pr_approvals
        .iter()
        .find(|a| ledger.subject.starts_with(&a.subject));

    let prior_facts = store_approval.as_ref().map(|a| &a.approved_facts);
    let decision = evaluate_decision(
        &ledger,
        &ledger_id,
        &cfg.policy,
        opts.as_of,
        opts.is_new_direct,
        reading_outcome,
        prior_facts,
    );
    let _ = store.save_decision(&decision);

    let approved_by =
        if decision.verdict == Verdict::Stop && !decision.stop_rules.contains(&StopRule::S10) {
            if let Some(ref sa) = store_approval {
                Some(sa.approver.clone())
            } else {
                // PR comment approval: disallow silently approving known_malicious advisories without explicit store record
                if ledger.advisory_ids.is_empty() {
                    pr_approval.map(|pa| pa.approver.clone())
                } else {
                    None
                }
            }
        } else {
            None
        };

    Ok(TransitionReportItem {
        ledger,
        decision,
        reading: reading_record,
        residual_diffs,
        route: Vec::new(),
        approved_by,
    })
}

#[allow(clippy::too_many_arguments)]
fn run_explain(
    spec: &str,
    read: bool,
    as_of_opt: Option<String>,
    no_osv: bool,
    save_inputs: bool,
    store_root: &Path,
    cfg: &AssayConfig,
    json_output: bool,
) -> Result<bool, String> {
    let (name, from_ver, to_ver) = parse_transition_spec(spec)?;
    let as_of = as_of_opt.unwrap_or_else(now_rfc3339);
    let fetcher = Fetcher::new(store_root.join("cache"))?;
    let store = open_store(store_root, cfg)?;

    let item = evaluate_single_transition(
        &fetcher,
        &store,
        cfg,
        &name,
        Some(&from_ver),
        None,
        &to_ver,
        None,
        EvalOptions {
            read,
            as_of: &as_of,
            no_osv,
            save_inputs,
            is_new_direct: false,
            is_new_to_project: false,
            lock_alarms: BTreeSet::new(),
            pr_approvals: &[],
        },
    )?;

    if json_output {
        let out = json!({
            "ledger_id": item.decision.ledger_id,
            "ledger": item.ledger,
            "decision": item.decision,
            "residual_diffs": item.residual_diffs,
            "reading": item.reading,
            "approved_by": item.approved_by,
        });
        println!("{}", to_canonical_json(&out)?);
    } else {
        print!("{}", render_explain_markdown(&item));
    }

    Ok(item.decision.verdict != Verdict::Stop || item.approved_by.is_some())
}

#[allow(clippy::too_many_arguments)]
fn run_check_bytes(
    base_lock: &[u8],
    head_lock: &[u8],
    base_pkg: Option<&[u8]>,
    head_pkg: Option<&[u8]>,
    read: bool,
    as_of: &str,
    store_root: &Path,
    cfg: &AssayConfig,
    tampered_files: &[String],
    pr_approvals: &[pr::ParsedPrApproval],
) -> Result<(Vec<TransitionReportItem>, Vec<String>, bool), String> {
    let diff = diff_lockfiles(base_lock, head_lock, base_pkg, head_pkg)?;
    let unique = deduplicate_transitions(&diff.transitions);
    let fetcher = Fetcher::new(store_root.join("cache"))?;
    let store = open_store(store_root, cfg)?;

    let mut items = Vec::with_capacity(unique.len());
    let mut transition_errors = Vec::new();
    for (t, _paths) in unique {
        if t.in_bundle && t.new_resolved.is_none() {
            continue;
        }
        // Per-transition isolation: one unfetchable/private/non-registry package stops that transition
        // instead of crashing the entire check with exit 2.
        match eval_lock_transition(&fetcher, &store, cfg, &t, read, as_of, pr_approvals) {
            Ok(item) => items.push(item),
            Err(e) => transition_errors.push(format!(
                "{}@{} ({}): {e}",
                t.name,
                t.new_version.as_deref().unwrap_or("?"),
                t.instance_path
            )),
        }
    }

    let all_passed = tampered_files.is_empty()
        && transition_errors.is_empty()
        && items
            .iter()
            .all(|i| i.decision.verdict != Verdict::Stop || i.approved_by.is_some());
    Ok((items, transition_errors, all_passed))
}

#[allow(clippy::too_many_arguments)]
fn eval_lock_transition(
    fetcher: &Fetcher,
    store: &RecordStore,
    cfg: &AssayConfig,
    t: &LockTransition,
    read: bool,
    as_of: &str,
    pr_approvals: &[pr::ParsedPrApproval],
) -> Result<TransitionReportItem, String> {
    let new_ver = t
        .new_version
        .as_deref()
        .ok_or_else(|| format!("transition for {} missing version", t.name))?;
    let ref_tarball = t
        .ref_resolved
        .as_deref()
        .map(|u| (u, t.ref_integrity.as_deref()));
    let new_tarball = t
        .new_resolved
        .as_deref()
        .map(|u| (u, t.new_integrity.as_deref()));

    let mut item = evaluate_single_transition(
        fetcher,
        store,
        cfg,
        &t.name,
        t.ref_version.as_deref(),
        ref_tarball,
        new_ver,
        new_tarball,
        EvalOptions {
            read,
            as_of,
            no_osv: false,
            save_inputs: false,
            is_new_direct: t.is_new_direct,
            is_new_to_project: t.ref_version.is_none(),
            lock_alarms: t.lock_alarms.clone(),
            pr_approvals,
        },
    )?;
    item.route = t.route.clone();
    Ok(item)
}

#[allow(clippy::too_many_arguments)]
fn run_check_files(
    base: &Path,
    head: &Path,
    base_pkg: Option<&Path>,
    head_pkg: Option<&Path>,
    read: bool,
    as_of_opt: Option<String>,
    store_root: &Path,
    cfg: &AssayConfig,
    json_output: bool,
) -> Result<bool, String> {
    let base_lock = fs::read(base).map_err(|e| format!("read {}: {e}", base.display()))?;
    let head_lock = fs::read(head).map_err(|e| format!("read {}: {e}", head.display()))?;
    let bp = base_pkg.and_then(|p| fs::read(p).ok());
    let hp = head_pkg.and_then(|p| fs::read(p).ok());
    let as_of = as_of_opt.unwrap_or_else(now_rfc3339);

    let (items, transition_errors, passed) = run_check_bytes(
        &base_lock,
        &head_lock,
        bp.as_deref(),
        hp.as_deref(),
        read,
        &as_of,
        store_root,
        cfg,
        &[],
        &[],
    )?;

    emit_change_report(&items, &[], &transition_errors, passed, json_output)?;
    Ok(passed)
}

fn emit_change_report(
    items: &[TransitionReportItem],
    tampered_files: &[String],
    transition_errors: &[String],
    passed: bool,
    json_output: bool,
) -> Result<(), String> {
    if json_output {
        let out = change_report_json(items, tampered_files, transition_errors, passed);
        println!("{}", to_canonical_json(&out)?);
    } else {
        print!("{}", render_change_summary(items, tampered_files, transition_errors));
    }
    Ok(())
}

fn change_report_json(
    items: &[TransitionReportItem],
    tampered_files: &[String],
    transition_errors: &[String],
    passed: bool,
) -> Value {
    let transitions_json: Vec<Value> = items
        .iter()
        .map(|i| {
            json!({
                "ledger_id": i.decision.ledger_id,
                "ledger": i.ledger,
                "decision": i.decision,
                "residual_diffs": i.residual_diffs,
                "reading": i.reading,
                "route": i.route,
                "approved_by": i.approved_by,
            })
        })
        .collect();
    json!({
        "passed": passed,
        "tampered_protected_files": tampered_files,
        "transition_errors": transition_errors,
        "transitions": transitions_json,
    })
}

#[allow(clippy::too_many_arguments)]
fn run_pr(
    repo: &Path,
    base: &str,
    head: &str,
    lockfile: &str,
    manifest: &str,
    comments_json: Option<&Path>,
    pr_author: Option<&str>,
    read: bool,
    store_root: &Path,
    json_output: bool,
) -> Result<bool, String> {
    let as_of = now_rfc3339();
    let changed_paths = list_changed_paths(repo, base, head)?;
    let mut tampered = detect_protected_file_tampering(&changed_paths);

    // Policy MUST come strictly from protected base revision (SPEC 8 & 10.3).
    let base_cfg = match read_git_file(repo, base, "assay.toml")?
        .or(read_git_file(repo, base, ".assay.toml")?)
    {
        Some(bytes) => {
            let s = String::from_utf8(bytes)
                .map_err(|_| "base assay.toml is not valid UTF-8".to_string())?;
            AssayConfig::from_toml(&s)?
        }
        None => AssayConfig::default(),
    };

    let pr_approvals = match (comments_json, pr_author) {
        (Some(path), Some(author)) => {
            let raw = fs::read_to_string(path)
                .map_err(|e| format!("read {}: {e}", path.display()))?;
            let comments: Vec<PrComment> = serde_json::from_str(&raw)
                .map_err(|e| format!("invalid comments json: {e}"))?;
            parse_approval_comments(&comments, author)
        }
        _ => Vec::new(),
    };

    let base_lock_opt = read_git_file(repo, base, lockfile)?;
    let head_lock_opt = read_git_file(repo, head, lockfile)?;

    // Security fix: deleting the lockfile in a PR MUST hard-stop rather than silently passing!
    if base_lock_opt.is_some() && head_lock_opt.is_none() {
        tampered.push(format!("{lockfile} (deleted in PR)"));
        emit_change_report(&[], &tampered, &[], false, json_output)?;
        return Ok(false);
    }

    let Some(head_lock) = head_lock_opt else {
        emit_change_report(&[], &tampered, &[], tampered.is_empty(), json_output)?;
        return Ok(tampered.is_empty());
    };
    let base_lock =
        base_lock_opt.unwrap_or_else(|| br#"{"lockfileVersion":3,"packages":{"":{}}}"#.to_vec());
    let base_pkg = read_git_file(repo, base, manifest)?;
    let head_pkg = read_git_file(repo, head, manifest)?;

    let (items, transition_errors, passed) = run_check_bytes(
        &base_lock,
        &head_lock,
        base_pkg.as_deref(),
        head_pkg.as_deref(),
        read,
        &as_of,
        store_root,
        &base_cfg,
        &tampered,
        &pr_approvals,
    )?;

    emit_change_report(&items, &tampered, &transition_errors, passed, json_output)?;
    Ok(passed)
}

struct AddResult {
    items: Vec<TransitionReportItem>,
    transition_errors: Vec<String>,
    passed: bool,
    installed: bool,
}

/// Shared "resolve once, check once, install those exact bytes" engine used by BOTH CLI and MCP!
fn execute_add(
    package: &str,
    project_dir: &Path,
    read: bool,
    install: bool,
    store_root: &Path,
    cfg: &AssayConfig,
) -> Result<AddResult, String> {
    let as_of = now_rfc3339();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp_dir = std::env::temp_dir().join(format!("assay-add-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&tmp_dir).map_err(|e| format!("create temp dir: {e}"))?;

    let base_pkg_path = project_dir.join("package.json");
    let base_lock_path = project_dir.join("package-lock.json");
    let had_base_pkg = base_pkg_path.exists();
    let had_base_lock = base_lock_path.exists();

    let base_pkg_bytes = if had_base_pkg {
        fs::read(&base_pkg_path).map_err(|e| format!("read package.json: {e}"))?
    } else {
        br#"{"name":"assay-project","version":"0.0.0","private":true}"#.to_vec()
    };
    let base_lock_bytes = if had_base_lock {
        fs::read(&base_lock_path).map_err(|e| format!("read package-lock.json: {e}"))?
    } else {
        br#"{"lockfileVersion":3,"packages":{"":{}}}"#.to_vec()
    };

    let base_pkg_hash = sha256_hex(&base_pkg_bytes);
    let base_lock_hash = sha256_hex(&base_lock_bytes);

    // Copy .npmrc if present so private/custom registry configs are surfaced honestly rather than silently dropped.
    if project_dir.join(".npmrc").exists() {
        let _ = fs::copy(project_dir.join(".npmrc"), tmp_dir.join(".npmrc"));
    }

    fs::write(tmp_dir.join("package.json"), &base_pkg_bytes)
        .map_err(|e| format!("write temp package.json: {e}"))?;
    if had_base_lock {
        fs::write(tmp_dir.join("package-lock.json"), &base_lock_bytes)
            .map_err(|e| format!("write temp package-lock.json: {e}"))?;
    }

    // Resolve ONCE in isolated temp dir with scripts disabled.
    let npm_out = Command::new("npm")
        .current_dir(&tmp_dir)
        .args([
            "install",
            "--package-lock-only",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
            package,
        ])
        .output()
        .map_err(|e| format!("failed spawning npm: {e}"))?;

    if !npm_out.status.success() {
        let stderr = String::from_utf8_lossy(&npm_out.stderr);
        let _ = fs::remove_dir_all(&tmp_dir);
        return Err(format!("npm lockfile resolution failed: {}", stderr.trim()));
    }

    let head_lock_bytes = fs::read(tmp_dir.join("package-lock.json"))
        .map_err(|e| format!("read resolved package-lock.json: {e}"))?;
    let head_pkg_bytes = fs::read(tmp_dir.join("package.json"))
        .map_err(|e| format!("read resolved package.json: {e}"))?;
    let _ = fs::remove_dir_all(&tmp_dir);

    let (items, transition_errors, passed) = run_check_bytes(
        &base_lock_bytes,
        &head_lock_bytes,
        Some(&base_pkg_bytes),
        Some(&head_pkg_bytes),
        read,
        &as_of,
        store_root,
        cfg,
        &[],
        &[],
    )?;

    let mut installed = false;
    if passed && install {
        // Verify project manifest & lockfile were not modified concurrently during check (zero TOCTOU!).
        if had_base_pkg {
            let cur = fs::read(&base_pkg_path)
                .map_err(|e| format!("re-read package.json before install: {e}"))?;
            if sha256_hex(&cur) != base_pkg_hash {
                return Err(
                    "package.json changed on disk during Assay check; refusing to overwrite".into(),
                );
            }
        }
        if had_base_lock {
            let cur = fs::read(&base_lock_path)
                .map_err(|e| format!("re-read package-lock.json before install: {e}"))?;
            if sha256_hex(&cur) != base_lock_hash {
                return Err(
                    "package-lock.json changed on disk during Assay check; refusing to overwrite"
                        .into(),
                );
            }
        }

        // Write the EXACT checked manifest & lockfile, then install strictly from that lockfile (`npm ci --ignore-scripts`).
        fs::write(&base_pkg_path, &head_pkg_bytes)
            .map_err(|e| format!("write checked package.json: {e}"))?;
        fs::write(&base_lock_path, &head_lock_bytes)
            .map_err(|e| format!("write checked package-lock.json: {e}"))?;

        let ci_out = Command::new("npm")
            .current_dir(project_dir)
            .args(["ci", "--ignore-scripts", "--no-audit", "--no-fund"])
            .output()
            .map_err(|e| format!("failed spawning npm ci: {e}"))?;
        if !ci_out.status.success() {
            return Err(format!(
                "npm ci --ignore-scripts failed: {}",
                String::from_utf8_lossy(&ci_out.stderr).trim()
            ));
        }
        installed = true;
    }

    Ok(AddResult {
        items,
        transition_errors,
        passed,
        installed,
    })
}

fn run_approve(
    subject_query: &str,
    by: Option<String>,
    note: Option<String>,
    non_interactive: bool,
    store_root: &Path,
    cfg: &AssayConfig,
    json_output: bool,
) -> Result<(), String> {
    if !non_interactive && !std::io::stdin().is_terminal() {
        return Err(
            "assay approve requires an interactive human terminal (refusing non-TTY agent call; humans scripting approvals may pass --non-interactive)".into(),
        );
    }

    let store = open_store(store_root, cfg)?;
    let (ledger_id, ledger) = store.find_unique_ledger_for_subject(subject_query)?;

    let now = now_rfc3339();
    let approved_facts = match store.load_decision_for_subject(&ledger.subject) {
        Some(prev_dec) => prev_dec.stop_facts,
        None => evaluate_decision(
            &ledger,
            &ledger_id,
            &cfg.policy,
            &now,
            false,
            ReadingOutcome::NotRun,
            None,
        )
        .stop_facts,
    };

    let approver = by
        .or_else(|| std::env::var("USER").ok())
        .unwrap_or_else(|| "human".to_string());

    let approval = ApprovalRecord {
        kind: "approval".to_string(),
        schema: 2,
        subject: ledger.subject.clone(),
        ledger_id,
        approved_facts,
        approver,
        approved_at: now,
        note,
    };

    let saved_path = store.save_approval(&approval)?;
    if json_output {
        println!("{}", to_canonical_json(&approval)?);
    } else {
        println!(
            "Approved {} ({} -> {}) by {} for {} fact(s) -> {}",
            &approval.subject[..16],
            ledger.name,
            ledger.new.version,
            approval.approver,
            approval.approved_facts.len(),
            saved_path.display()
        );
    }
    Ok(())
}

fn run_exposure(
    pkg: Option<&str>,
    sha512: Option<&str>,
    repo: &Path,
    lockfile: &str,
    store_root: &Path,
    json_output: bool,
) -> Result<(), String> {
    let query = ExposureQuery::from_args(pkg, sha512)?;
    let git_hits = if repo.join(".git").exists() {
        search_git_lockfile_exposure(repo, lockfile, &query)?
    } else {
        Vec::new()
    };
    let store_hits = search_store_exposure(store_root, &query)?;

    if json_output {
        let out = json!({
            "git_hits": git_hits,
            "store_hits": store_hits,
        });
        println!("{}", to_canonical_json(&out)?);
    } else if git_hits.is_empty() && store_hits.is_empty() {
        println!(
            "No exposure found in {} or {}.",
            repo.display(),
            store_root.display()
        );
    } else {
        for h in &git_hits {
            println!(
                "GIT   {} {} ({}) in {} [{}..{}] still_present={}",
                h.name,
                h.version.as_deref().unwrap_or("?"),
                h.instance_path,
                h.lockfile,
                h.first_date,
                h.last_date,
                h.still_present
            );
        }
        for s in &store_hits {
            println!(
                "STORE {} {} subject={} ledger={}",
                s.name,
                s.version,
                &s.subject[..16],
                &s.ledger_id[..16]
            );
        }
    }
    Ok(())
}

fn run_inventory(lock: &Path, json_output: bool) -> Result<(), String> {
    let bytes = fs::read(lock).map_err(|e| format!("read {}: {e}", lock.display()))?;
    let pkgs = parse_lockfile_packages(&bytes)?;
    let missing_integrity = pkgs
        .iter()
        .filter(|p| p.sha512.is_none() && !p.in_bundle)
        .count();
    let non_registry = pkgs
        .iter()
        .filter(|p| p.source_kind != assay_core::lockfile::SourceKind::Registry && !p.in_bundle)
        .count();

    if json_output {
        let out = json!({
            "total_packages": pkgs.len(),
            "missing_integrity": missing_integrity,
            "non_registry": non_registry,
            "packages": pkgs,
        });
        println!("{}", to_canonical_json(&out)?);
    } else {
        println!("Assay inventory for {}", lock.display());
        println!("  total package instances: {}", pkgs.len());
        println!("  missing SHA-512 integrity: {missing_integrity}");
        println!("  non-registry sources (git/url/file): {non_registry}");
    }
    Ok(())
}

fn run_replay(
    bundle_dir: &Path,
    as_of_opt: Option<String>,
    cfg: &AssayConfig,
    json_output: bool,
) -> Result<bool, String> {
    let bundle = RecordStore::load_input_bundle(bundle_dir)?;
    let limits = ArchiveLimits::default();

    let new_bytes = fs::read(bundle_dir.join(&bundle.new_tarball_file))
        .map_err(|e| format!("read bundle tarball {}: {e}", bundle.new_tarball_file))?;
    let new_archive = inspect_tgz(&new_bytes, Some(&bundle.new_sha512), limits)?;
    let new_manifest = extract_manifest_facts(&new_archive);

    let mut blobs_by_sha1 = BTreeMap::new();
    for (k, b64) in &bundle.new_source_blobs_b64 {
        let decoded = base64_decode(b64)
            .ok_or_else(|| format!("invalid base64 in bundle blob {k}"))?;
        blobs_by_sha1.insert(k.clone(), decoded);
    }
    let new_source = if bundle.new_source_tree.is_empty() {
        None
    } else {
        Some(SourceSnapshot {
            tree_blob_sha1: bundle.new_source_tree.clone(),
            blobs_by_sha1,
            package_dir: bundle.new_source_package_dir.clone(),
        })
    };

    let new_profile = build_artifact_profile(
        &bundle.ecosystem,
        &bundle.name,
        &bundle.new_version,
        &new_archive,
        bundle.new_anchor.clone(),
        new_source.as_ref(),
    );

    let (ref_archive, ref_profile, ref_standing) = match (
        &bundle.reference_version,
        &bundle.reference_tarball_file,
        &bundle.reference_sha512,
        &bundle.reference_anchor,
    ) {
        (Some(rv), Some(rf), Some(rs), Some(ra)) => {
            let rb = fs::read(bundle_dir.join(rf))
                .map_err(|e| format!("read ref bundle tarball {rf}: {e}"))?;
            let r_arch = inspect_tgz(&rb, Some(rs), limits)?;
            let mut ref_blobs_by_sha1 = BTreeMap::new();
            for (k, b64) in &bundle.reference_source_blobs_b64 {
                let decoded = base64_decode(b64)
                    .ok_or_else(|| format!("invalid base64 in ref bundle blob {k}"))?;
                ref_blobs_by_sha1.insert(k.clone(), decoded);
            }
            let r_source = if bundle.reference_source_tree.is_empty() {
                None
            } else {
                Some(SourceSnapshot {
                    tree_blob_sha1: bundle.reference_source_tree.clone(),
                    blobs_by_sha1: ref_blobs_by_sha1,
                    package_dir: bundle.reference_source_package_dir.clone(),
                })
            };
            let r_prof = build_artifact_profile(
                &bundle.ecosystem,
                &bundle.name,
                rv,
                &r_arch,
                ra.clone(),
                r_source.as_ref(),
            );
            (Some(r_arch), Some(r_prof), ReferenceStanding::Admitted)
        }
        _ => (None, None, ReferenceStanding::None),
    };

    let (history_ctx, hist_sha) = match &bundle.registry_snapshot_file {
        Some(rf) => {
            let raw = fs::read(bundle_dir.join(rf))
                .map_err(|e| format!("read registry snapshot {rf}: {e}"))?;
            let val: Value = serde_json::from_slice(&raw)
                .map_err(|e| format!("parse registry snapshot: {e}"))?;
            let hs = build_release_history(&val, &bundle.new_version, cfg.policy.history_depth);
            let new_reg = val
                .pointer(&format!("/versions/{}", bundle.new_version))
                .cloned()
                .unwrap_or(Value::Null);
            let diffs = new_archive
                .contents
                .iter()
                .find(|(p, _)| strip_archive_root(p) == "package.json")
                .map(|(_, bytes)| {
                    registry_manifest_differs(bytes, &new_reg, new_manifest.has_binding_gyp)
                })
                .unwrap_or_default();
            (
                HistoryContext {
                    prior_releases: hs.prior_releases,
                    total_prior_releases: hs.total_prior_releases,
                    package_first_published_at: hs.first_published_at,
                    new_release: hs.new_release,
                    reference_had_anchor: bundle.reference_anchor.as_ref().map(|a| a.found),
                    registry_manifest_diffs: diffs,
                    known_malicious_ids: Vec::new(),
                    osv_unavailable: false,
                    is_new_to_project: ref_archive.is_none(),
                },
                Some(hs.slice_sha256),
            )
        }
        None => (
            HistoryContext {
                reference_had_anchor: bundle.reference_anchor.as_ref().map(|a| a.found),
                is_new_to_project: ref_archive.is_none(),
                ..Default::default()
            },
            bundle.history_slice_sha256.clone(),
        ),
    };

    let (ledger, ledger_id) = build_transition_ledger(TransitionInput {
        ecosystem: &bundle.ecosystem,
        name: &bundle.name,
        reference_archive: ref_archive.as_ref(),
        reference_profile: ref_profile.as_ref(),
        reference_standing: ref_standing,
        reference_published_at: bundle.reference_published_at.clone(),
        new_archive: &new_archive,
        new_profile: &new_profile,
        new_source: new_source.as_ref(),
        new_published_at: bundle.new_published_at.clone(),
        lock_alarms: BTreeSet::new(),
        history_ctx,
        history_slice_sha256: hist_sha,
    })?;

    let residual_diffs =
        build_inline_residual_diffs(&ledger, ref_archive.as_ref(), &new_archive, 4, 40);
    let as_of = as_of_opt.unwrap_or(bundle.as_of);
    let decision = evaluate_decision(
        &ledger,
        &ledger_id,
        &cfg.policy,
        &as_of,
        false,
        ReadingOutcome::NotRun,
        None,
    );

    let matches_expected = ledger_id == bundle.expected_ledger_id;
    let _ = canonical_id(&ledger)?;

    let item = TransitionReportItem {
        ledger,
        decision,
        reading: None,
        residual_diffs,
        route: Vec::new(),
        approved_by: None,
    };

    if json_output {
        let out = json!({
            "offline_replay": true,
            "ledger_id": ledger_id,
            "expected_ledger_id": bundle.expected_ledger_id,
            "byte_identical": matches_expected,
            "ledger": item.ledger,
            "decision": item.decision,
            "residual_diffs": item.residual_diffs,
        });
        println!("{}", to_canonical_json(&out)?);
    } else {
        println!(
            "Offline replay: ledger={} expected={} byte_identical={}",
            &ledger_id[..16],
            &bundle.expected_ledger_id[..16],
            matches_expected
        );
        print!("{}", render_explain_markdown(&item));
    }
    Ok(matches_expected && item.decision.verdict != Verdict::Stop)
}

fn run_init(
    dir: &Path,
    github: bool,
    mcp: bool,
    force: bool,
    json_output: bool,
) -> Result<(), String> {
    let mut created: Vec<String> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();

    let cfg_path = dir.join("assay.toml");
    if cfg_path.exists() && !force {
        skipped.push(cfg_path.display().to_string());
    } else {
        fs::create_dir_all(dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
        fs::write(&cfg_path, DEFAULT_CONFIG_TOML)
            .map_err(|e| format!("write {}: {e}", cfg_path.display()))?;
        created.push(cfg_path.display().to_string());
    }

    if github {
        let wf_dir = dir.join(".github").join("workflows");
        let wf_path = wf_dir.join("assay-pr.yml");
        if wf_path.exists() && !force {
            skipped.push(wf_path.display().to_string());
        } else {
            fs::create_dir_all(&wf_dir).map_err(|e| format!("mkdir {}: {e}", wf_dir.display()))?;
            fs::write(&wf_path, DEFAULT_GITHUB_WORKFLOW)
                .map_err(|e| format!("write {}: {e}", wf_path.display()))?;
            created.push(wf_path.display().to_string());
        }
    }

    let exe_path = std::env::current_exe()
        .ok()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "assay".to_string());
    let mcp_config = json!({
        "mcpServers": {
            "assay": {
                "command": exe_path,
                "args": ["mcp"],
                "env": {
                    "ANTHROPIC_API_KEY": "${ANTHROPIC_API_KEY}"
                }
            }
        }
    });

    if json_output {
        let out = json!({
            "created": created,
            "skipped": skipped,
            "mcp_config": mcp_config,
        });
        println!("{}", to_canonical_json(&out)?);
    } else {
        for p in &created {
            println!("Created {p}");
        }
        for p in &skipped {
            println!("Skipped {p} (already exists; pass --force to overwrite)");
        }
        if mcp {
            println!("\nMCP config (paste into your coding agent settings):");
            println!(
                "{}",
                serde_json::to_string_pretty(&mcp_config).unwrap_or_default()
            );
        }
    }
    Ok(())
}

struct CliMcpDispatcher {
    store_root: PathBuf,
    cfg: AssayConfig,
}

impl McpDispatcher for CliMcpDispatcher {
    fn call_tool(&self, name: &str, arguments: &Value) -> Result<Value, String> {
        let as_of = now_rfc3339();
        let read = arguments
            .get("read")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let fetcher = Fetcher::new(self.store_root.join("cache"))?;
        let store = open_store(&self.store_root, &self.cfg)?;

        match name {
            "assay_explain" => {
                let spec = arguments
                    .get("spec")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| "missing required argument 'spec'".to_string())?;
                let (pkg, from, to) = parse_transition_spec(spec)?;
                let item = evaluate_single_transition(
                    &fetcher,
                    &store,
                    &self.cfg,
                    &pkg,
                    Some(&from),
                    None,
                    &to,
                    None,
                    EvalOptions {
                        read,
                        as_of: &as_of,
                        no_osv: false,
                        save_inputs: false,
                        is_new_direct: false,
                        is_new_to_project: false,
                        lock_alarms: BTreeSet::new(),
                        pr_approvals: &[],
                    },
                )?;
                Ok(json!({
                    "ledger_id": item.decision.ledger_id,
                    "subject": item.ledger.subject,
                    "verdict": item.decision.verdict,
                    "stop_rules": item.decision.stop_rules,
                    "stop_facts": item.decision.stop_facts,
                    "stop_reasons": item.decision.stop_reasons,
                    "residual_diffs": item.residual_diffs,
                    "ledger": item.ledger,
                    "reading": item.reading,
                }))
            }
            "assay_check" => {
                let base = PathBuf::from(
                    arguments
                        .get("base_lock")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'base_lock'".to_string())?,
                );
                let head = PathBuf::from(
                    arguments
                        .get("head_lock")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'head_lock'".to_string())?,
                );
                let base_lock = fs::read(&base).map_err(|e| format!("read base_lock: {e}"))?;
                let head_lock = fs::read(&head).map_err(|e| format!("read head_lock: {e}"))?;
                let base_pkg = arguments
                    .get("base_pkg")
                    .and_then(|v| v.as_str())
                    .and_then(|p| fs::read(p).ok());
                let head_pkg = arguments
                    .get("head_pkg")
                    .and_then(|v| v.as_str())
                    .and_then(|p| fs::read(p).ok());
                let (items, transition_errors, passed) = run_check_bytes(
                    &base_lock,
                    &head_lock,
                    base_pkg.as_deref(),
                    head_pkg.as_deref(),
                    read,
                    &as_of,
                    &self.store_root,
                    &self.cfg,
                    &[],
                    &[],
                )?;
                Ok(change_report_json(&items, &[], &transition_errors, passed))
            }
            "assay_add" => {
                let pkg = arguments
                    .get("package")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| "missing 'package'".to_string())?;
                let project_dir = PathBuf::from(
                    arguments
                        .get("project_dir")
                        .and_then(|v| v.as_str())
                        .unwrap_or("."),
                );
                let install = arguments
                    .get("install")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let res = execute_add(pkg, &project_dir, read, install, &self.store_root, &self.cfg)?;
                let mut report = change_report_json(&res.items, &[], &res.transition_errors, res.passed);
                if let Some(obj) = report.as_object_mut() {
                    obj.insert("installed".into(), Value::Bool(res.installed));
                    obj.insert(
                        "note".into(),
                        Value::String(
                            "Agents cannot approve stops. If passed is false, report stop_reasons, route, residual_diffs, and approval subject to the user.".into(),
                        ),
                    );
                }
                Ok(report)
            }
            other => Err(format!("unknown tool {other}")),
        }
    }
}

fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((triple >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((triple >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(triple & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
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
