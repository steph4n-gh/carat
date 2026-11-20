use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchiveLimits {
    pub max_compressed_bytes: u64,
    pub max_expanded_bytes: u64,
    pub max_entries: usize,
    pub max_manifest_bytes: usize,
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            max_compressed_bytes: 64 * 1024 * 1024,
            max_expanded_bytes: 256 * 1024 * 1024,
            max_entries: 10_000,
            max_manifest_bytes: 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveFact {
    ArchiveDuplicatePath,
    ArchiveLinkEntry,
    ArchiveSpecialEntry,
    ArchivePathEscape,
    ArchiveOverLimit,
    ArchiveCorrupt,
}

impl ArchiveFact {
    pub fn fact_key(self) -> &'static str {
        match self {
            Self::ArchiveDuplicatePath => "archive:duplicate_path",
            Self::ArchiveLinkEntry => "archive:link_entry",
            Self::ArchiveSpecialEntry => "archive:special_entry",
            Self::ArchivePathEscape => "archive:path_escape",
            Self::ArchiveOverLimit => "archive:over_limit",
            Self::ArchiveCorrupt => "archive:corrupt",
        }
    }

    pub fn human_label(self) -> &'static str {
        match self {
            Self::ArchiveDuplicatePath => "duplicate or case-colliding archive paths",
            Self::ArchiveLinkEntry => "symlink or hardlink entry in archive",
            Self::ArchiveSpecialEntry => "special device/FIFO entry in archive",
            Self::ArchivePathEscape => "path traversal or absolute path in archive",
            Self::ArchiveOverLimit => "archive exceeded safety size or entry limit",
            Self::ArchiveCorrupt => "malformed tar framing or trailing data after zero block",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EntryType {
    File,
    Directory,
    Symlink,
    Hardlink,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchiveEntry {
    pub path: String,
    pub entry_type: EntryType,
    pub mode: u32,
    pub size: u64,
    pub sha256: String,
    pub git_blob_sha1: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchiveInventory {
    pub compressed_bytes: u64,
    pub expanded_bytes: u64,
    pub sha512: String,
    pub entries: Vec<ArchiveEntry>,
    pub facts: BTreeSet<ArchiveFact>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AnchorMethod {
    ProvenanceAsserted,
    ProvenanceVerified,
    GitHead,
    Tag,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Anchor {
    pub found: bool,
    pub commit: Option<String>,
    pub method: Option<AnchorMethod>,
    pub methods_tried: Vec<String>,
    pub conflict: bool,
    pub conflict_details: Vec<String>,
    pub repository_url: Option<String>,
    pub repository_directory: Option<String>,
    pub workflow_path: Option<String>,
    pub workflow_ref: Option<String>,
    pub reachable_from_branch: Option<bool>,
    /// Populated when a network/git error prevented checking the repository (never masquerades as `anchor_lost`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lookup_error: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum OriginClass {
    Carried,
    Source,
    SourceElsewhere,
    SourceNormalized,
    Rebuilt,
    Unexplained,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum NormalizationKind {
    CrlfToLf,
    PublishedPackageJson,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum FileRole {
    Code,
    Manifest,
    Declaration,
    SourceMap,
    Binary,
    Doc,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileOrigin {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
    pub class: OriginClass,
    pub role: FileRole,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub moved_from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub normalization: Option<NormalizationKind>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub significant_manifest_diffs: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClassTotal {
    pub files: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum BreakKind {
    AnchorLost,
    ProvenanceLost,
    RepoChanged,
    SourceMatchDrop,
    UnexplainedAppeared,
    InstallScriptNew,
    InstallScriptChanged,
    NativeOrBinaryNew,
    RegistryManifestDiffers,
    KnownMalicious,
    PublisherChanged,
    DependencyAdded,
    AnchorUnreachable,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BreakSeverity {
    Stop,
    Flag,
}

impl BreakKind {
    pub fn default_severity(self) -> BreakSeverity {
        match self {
            Self::AnchorLost
            | Self::ProvenanceLost
            | Self::RepoChanged
            | Self::SourceMatchDrop
            | Self::InstallScriptNew
            | Self::InstallScriptChanged
            | Self::NativeOrBinaryNew
            | Self::RegistryManifestDiffers
            | Self::KnownMalicious => BreakSeverity::Stop,
            Self::UnexplainedAppeared
            | Self::PublisherChanged
            | Self::DependencyAdded
            | Self::AnchorUnreachable => BreakSeverity::Flag,
        }
    }

    pub fn fact_key(self) -> &'static str {
        match self {
            Self::AnchorLost => "break:anchor_lost",
            Self::ProvenanceLost => "break:provenance_lost",
            Self::RepoChanged => "break:repo_changed",
            Self::SourceMatchDrop => "break:source_match_drop",
            Self::UnexplainedAppeared => "flag:unexplained_appeared",
            Self::InstallScriptNew => "break:install_script_new",
            Self::InstallScriptChanged => "break:install_script_changed",
            Self::NativeOrBinaryNew => "break:native_or_binary_new",
            Self::RegistryManifestDiffers => "break:registry_manifest_differs",
            Self::KnownMalicious => "break:known_malicious",
            Self::PublisherChanged => "flag:publisher_changed",
            Self::DependencyAdded => "flag:dependency_added",
            Self::AnchorUnreachable => "flag:anchor_unreachable",
        }
    }

    pub fn human_label(self) -> &'static str {
        match self {
            Self::AnchorLost => "source anchor disappeared",
            Self::ProvenanceLost => "build provenance or trusted publishing dropped",
            Self::RepoChanged => "source repository changed",
            Self::SourceMatchDrop => "previously source-matched executable file is now unexplained",
            Self::UnexplainedAppeared => "unexplained executable code appeared for the first time",
            Self::InstallScriptNew => "install-time execution script added",
            Self::InstallScriptChanged => "install-time execution script changed",
            Self::NativeOrBinaryNew => "native addon or executable binary appeared",
            Self::RegistryManifestDiffers => "registry metadata disagrees with tarball package.json",
            Self::KnownMalicious => "listed as malicious in OSV",
            Self::PublisherChanged => "publishing account changed",
            Self::DependencyAdded => "new runtime dependency added",
            Self::AnchorUnreachable => "anchor commit is not reachable from a repository branch or tag",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ReachToken {
    Net,
    Fs,
    Env,
    HostInfo,
    BrowserSensitive,
    Proc,
    DynCode,
    Native,
    InstallExec,
    EncodedBlob,
    ShellLiteral,
    MinifiedNew,
}

impl ReachToken {
    pub fn is_high(self) -> bool {
        matches!(
            self,
            Self::Proc
                | Self::DynCode
                | Self::Native
                | Self::InstallExec
                | Self::EncodedBlob
                | Self::ShellLiteral
                | Self::MinifiedNew
        )
    }

    pub fn key(self) -> &'static str {
        match self {
            Self::Net => "net",
            Self::Fs => "fs",
            Self::Env => "env",
            Self::HostInfo => "host_info",
            Self::BrowserSensitive => "browser_sensitive",
            Self::Proc => "proc",
            Self::DynCode => "dyn_code",
            Self::Native => "native",
            Self::InstallExec => "install_exec",
            Self::EncodedBlob => "encoded_blob",
            Self::ShellLiteral => "shell_literal",
            Self::MinifiedNew => "minified_new",
        }
    }

    pub fn human_label(self) -> &'static str {
        match self {
            Self::Net => "network access",
            Self::Fs => "filesystem access",
            Self::Env => "environment variable access",
            Self::HostInfo => "host/user metadata access",
            Self::BrowserSensitive => "browser cookies/storage/wallet access",
            Self::Proc => "process execution (child_process)",
            Self::DynCode => "dynamic code evaluation (eval/Function/vm/dynamic import)",
            Self::Native => "native addon / binary loading",
            Self::InstallExec => "install-time script execution",
            Self::EncodedBlob => "large encoded/high-entropy string literal",
            Self::ShellLiteral => "shell download-and-execute pattern",
            Self::MinifiedNew => "previously readable file became minified",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestFacts {
    pub name: Option<String>,
    pub version: Option<String>,
    pub repository_url: Option<String>,
    pub repository_directory: Option<String>,
    pub install_scripts: BTreeMap<String, String>,
    pub has_binding_gyp: bool,
    pub has_install_exec: bool,
    pub runtime_dependencies: BTreeSet<String>,
    pub optional_dependencies: BTreeSet<String>,
    pub peer_dependencies: BTreeSet<String>,
    pub bundled_dependencies: BTreeSet<String>,
    pub bin_paths: BTreeSet<String>,
    pub entry_paths: BTreeSet<String>,
    pub has_native_or_binary: bool,
    pub nested_install_scripts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactProfile {
    pub kind: String,
    pub schema: u32,
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub sha512: String,
    pub compressed_bytes: u64,
    pub expanded_bytes: u64,
    pub file_count: u64,
    pub archive_facts: BTreeSet<ArchiveFact>,
    pub anchor: Anchor,
    pub manifest: ManifestFacts,
    pub reach: BTreeSet<ReachToken>,
    pub hostnames: BTreeSet<String>,
    pub files: Vec<FileOrigin>,
    pub tool_version: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceStanding {
    Admitted,
    Settled,
    None,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum LockAlarm {
    SameVersionBytesChanged,
    SourceKindChanged,
    RegistryHostChanged,
    IntegrityMissing,
}

impl LockAlarm {
    pub fn fact_key(self) -> &'static str {
        match self {
            Self::SameVersionBytesChanged => "lock:same_version_bytes_changed",
            Self::SourceKindChanged => "lock:source_kind_changed",
            Self::RegistryHostChanged => "lock:registry_host_changed",
            Self::IntegrityMissing => "lock:integrity_missing",
        }
    }

    pub fn human_label(self) -> &'static str {
        match self {
            Self::SameVersionBytesChanged => "same package version has different tarball bytes",
            Self::SourceKindChanged => "dependency source changed between registry and git/url/file",
            Self::RegistryHostChanged => "registry host changed",
            Self::IntegrityMissing => "lockfile entry is missing SHA-512 integrity",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LedgerEndpoint {
    pub version: String,
    pub sha512: String,
    pub profile_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub standing: Option<ReferenceStanding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published_at: Option<String>,
}

/// Compact inline diff preview for one unexplained executable/manifest file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResidualDiff {
    pub path: String,
    pub bytes: u64,
    pub total_lines: usize,
    pub truncated: bool,
    pub diff: String,
}

/// Timeless deterministic transition ledger (no wall-clock timestamps or relative ages).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransitionLedger {
    pub kind: String,
    pub schema: u32,
    pub subject: String,
    pub ecosystem: String,
    pub name: String,
    pub reference: Option<LedgerEndpoint>,
    pub new: LedgerEndpoint,
    pub anchor: Anchor,
    pub lock_alarms: BTreeSet<LockAlarm>,
    pub archive_facts: BTreeSet<ArchiveFact>,
    pub files: Vec<FileOrigin>,
    pub removed_files: Vec<String>,
    pub totals: BTreeMap<OriginClass, ClassTotal>,
    pub unexplained_code_bytes: u64,
    pub unexplained_non_exec_bytes: u64,
    pub breaks: BTreeSet<BreakKind>,
    pub flags: BTreeSet<BreakKind>,
    pub break_notes: BTreeMap<BreakKind, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub advisory_ids: Vec<String>,
    #[serde(default)]
    pub osv_unavailable: bool,
    pub new_reach: BTreeSet<ReachToken>,
    pub new_reach_in_unexplained: BTreeSet<ReachToken>,
    pub new_reach_files: BTreeMap<ReachToken, Vec<String>>,
    pub new_hostnames: BTreeSet<String>,
    /// Number of prior releases strictly older than `new.published_at` (used for thin-history direct dep gating).
    #[serde(default)]
    pub prior_release_count: usize,
    /// Earliest known release timestamp for this package (RFC 3339, from historical slice).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_first_published_at: Option<String>,
    /// Hash of the deterministic historical metadata slice (not the mutable full packument).
    pub history_slice_sha256: Option<String>,
    pub tool_version: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StopRule {
    S1,
    S2,
    S3,
    S4,
    S5,
    S6,
    S7,
    S8,
    S9,
    S10,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Explained,
    Read,
    Stop,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseAgeBand {
    Fresh,
    Recent,
    Settled,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NewDirectPolicy {
    /// Stop only if the package has thin history (< 30 days old or < 3 prior releases).
    ThinHistory,
    /// Stop on every brand-new direct dependency for explicit human confirmation.
    Confirm,
    /// Treat new direct dependencies identically to transitive ones.
    Check,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReadPassPolicy {
    Allow,
    RequireHuman,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyConfig {
    pub policy_version: u32,
    pub min_age_hours: i64,
    pub settled_age_days: i64,
    pub new_direct_dependency: NewDirectPolicy,
    pub read_pass: ReadPassPolicy,
    pub history_depth: usize,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            policy_version: 2,
            min_age_hours: 24,
            settled_age_days: 30,
            new_direct_dependency: NewDirectPolicy::ThinHistory,
            read_pass: ReadPassPolicy::Allow,
            history_depth: 20,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReadingOutcome {
    NotRequired,
    NotRun,
    Passed,
    Concern,
    Invalid,
    Unread,
    Refused,
    Unavailable,
}

/// Policy evaluation of a timeless `TransitionLedger` at an explicit `as_of` timestamp.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Decision {
    pub kind: String,
    pub schema: u32,
    pub ledger_id: String,
    pub subject: String,
    pub as_of: String,
    pub policy_version: u32,
    pub published_age_hours: Option<i64>,
    pub age_band: ReleaseAgeBand,
    pub reading_required: bool,
    pub reading_outcome: ReadingOutcome,
    pub stop_rules: BTreeSet<StopRule>,
    /// Concrete fact keys that caused stops; approvals bind to these exact facts (fixing S10 granularity).
    pub stop_facts: BTreeSet<String>,
    pub stop_reasons: Vec<String>,
    pub verdict: Verdict,
}
