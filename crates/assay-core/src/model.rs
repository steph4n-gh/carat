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
    TagMoved,
    PublisherChanged,
    DependencyAdded,
    SizeJump,
    VersionOutOfSequence,
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
            | Self::KnownMalicious
            | Self::TagMoved => BreakSeverity::Stop,
            Self::UnexplainedAppeared
            | Self::PublisherChanged
            | Self::DependencyAdded
            | Self::SizeJump
            | Self::VersionOutOfSequence
            | Self::AnchorUnreachable => BreakSeverity::Flag,
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

/// Timeless deterministic transition ledger (no relative ages or current-clock timestamps).
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
    pub new_reach: BTreeSet<ReachToken>,
    pub new_reach_in_unexplained: BTreeSet<ReachToken>,
    pub new_reach_files: BTreeMap<ReachToken, Vec<String>>,
    pub new_hostnames: BTreeSet<String>,
    pub registry_snapshot_sha256: Option<String>,
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
    Confirm,
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
            policy_version: 1,
            min_age_hours: 24,
            settled_age_days: 30,
            new_direct_dependency: NewDirectPolicy::Confirm,
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
    pub stop_reasons: Vec<String>,
    pub verdict: Verdict,
}
