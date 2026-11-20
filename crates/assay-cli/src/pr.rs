use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrComment {
    pub author: String,
    pub body: String,
    pub has_write_access: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParsedPrApproval {
    pub subject: String,
    pub approver: String,
    pub approved_at: String,
}

fn hardened_git(repo_dir: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.current_dir(repo_dir);
    cmd.env("GIT_TERMINAL_PROMPT", "0");
    cmd.env("GIT_CONFIG_NOSYSTEM", "1");
    cmd.env("GIT_CONFIG_GLOBAL", "/dev/null");
    cmd.args([
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.symlinks=false",
        "-c",
        "submodule.recurse=false",
        "-c",
        "protocol.file.allow=never",
    ]);
    cmd
}

/// Reads `<rev>:<rel_path>` strictly from Git object storage (never touches working tree).
pub fn read_git_file(repo_dir: &Path, rev: &str, rel_path: &str) -> Result<Option<Vec<u8>>, String> {
    let spec = format!("{rev}:{rel_path}");
    let out = hardened_git(repo_dir)
        .args(["show", &spec])
        .output()
        .map_err(|e| format!("failed spawning git show {spec}: {e}"))?;
    if out.status.success() {
        return Ok(Some(out.stdout));
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    if stderr.contains("does not exist")
        || stderr.contains("exists on disk, but not in")
        || stderr.contains("path '")
    {
        return Ok(None);
    }
    Err(format!("git show {spec} failed: {}", stderr.trim()))
}

/// Lists paths modified between `base_rev` and `head_rev` using Git objects only.
pub fn list_changed_paths(
    repo_dir: &Path,
    base_rev: &str,
    head_rev: &str,
) -> Result<Vec<String>, String> {
    let out = hardened_git(repo_dir)
        .args(["diff", "--name-only", base_rev, head_rev])
        .output()
        .map_err(|e| format!("failed spawning git diff: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!("git diff --name-only failed: {}", stderr.trim()));
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect())
}

/// Flags PR edits to Assay policy or workflow files as hard stops (SPEC section 10.3).
pub fn detect_protected_file_tampering(changed_paths: &[String]) -> Vec<String> {
    changed_paths
        .iter()
        .filter(|p| {
            let lower = p.to_ascii_lowercase();
            lower == "assay.toml"
                || lower == ".assay.toml"
                || (lower.starts_with(".github/workflows/")
                    && lower.contains("assay")
                    && (lower.ends_with(".yml") || lower.ends_with(".yaml")))
        })
        .cloned()
        .collect()
}

/// Parses exact `assay approve <subject>` lines from PR comments.
/// Enforces SPEC section 10.3: approver must have write access and MUST NOT be the PR author.
pub fn parse_approval_comments(
    comments: &[PrComment],
    pr_author: &str,
) -> Vec<ParsedPrApproval> {
    let mut out = Vec::new();
    for c in comments {
        if !c.has_write_access || c.author.eq_ignore_ascii_case(pr_author) {
            continue;
        }
        for line in c.body.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("assay approve ") {
                let subj = rest.trim();
                if subj.len() >= 12
                    && subj.len() <= 64
                    && subj.bytes().all(|b| b.is_ascii_hexdigit())
                {
                    out.push(ParsedPrApproval {
                        subject: subj.to_ascii_lowercase(),
                        approver: c.author.clone(),
                        approved_at: c.created_at.clone(),
                    });
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_policy_and_workflow_tampering() {
        let changed = vec![
            "package-lock.json".into(),
            "assay.toml".into(),
            ".github/workflows/assay-pr.yml".into(),
            "src/index.ts".into(),
        ];
        let tampered = detect_protected_file_tampering(&changed);
        assert_eq!(
            tampered,
            vec!["assay.toml", ".github/workflows/assay-pr.yml"]
        );
    }

    #[test]
    fn parses_valid_maintainer_approval_and_rejects_self_approval() {
        let comments = vec![
            PrComment {
                author: "renovate".into(),
                body: "assay approve 7f3c1234abcd5678".into(),
                has_write_access: true,
                created_at: "2026-11-19T23:00:00Z".into(),
            },
            PrComment {
                author: "random-user".into(),
                body: "assay approve 7f3c1234abcd5678".into(),
                has_write_access: false,
                created_at: "2026-11-19T23:01:00Z".into(),
            },
            PrComment {
                author: "maintainer".into(),
                body: "Looks fine.\nassay approve 7f3c1234abcd5678\n".into(),
                has_write_access: true,
                created_at: "2026-11-19T23:02:00Z".into(),
            },
        ];
        let parsed = parse_approval_comments(&comments, "renovate");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].approver, "maintainer");
        assert_eq!(parsed[0].subject, "7f3c1234abcd5678");
    }

    #[test]
    fn reads_git_objects_without_touching_worktree() {
        let tmp = std::env::temp_dir().join(format!("assay-pr-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let run = |args: &[&str]| {
            let out = Command::new("git")
                .current_dir(&tmp)
                .env("GIT_AUTHOR_NAME", "test")
                .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
                .env("GIT_COMMITTER_NAME", "test")
                .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
                .args(args)
                .output()
                .unwrap();
            assert!(out.status.success(), "git {:?} failed", args);
        };

        run(&["init", "-b", "main"]);
        std::fs::write(tmp.join("package.json"), r#"{"name":"t","version":"1.0.0"}"#).unwrap();
        run(&["add", "."]);
        run(&["commit", "-m", "base"]);
        let base = String::from_utf8(
            Command::new("git")
                .current_dir(&tmp)
                .args(["rev-parse", "HEAD"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_string();

        std::fs::write(tmp.join("assay.toml"), "min_age = \"0h\"\n").unwrap();
        run(&["add", "."]);
        run(&["commit", "-m", "tamper"]);

        let changed = list_changed_paths(&tmp, &base, "HEAD").unwrap();
        assert_eq!(detect_protected_file_tampering(&changed), vec!["assay.toml"]);
        assert!(read_git_file(&tmp, &base, "assay.toml").unwrap().is_none());
        assert!(read_git_file(&tmp, "HEAD", "assay.toml").unwrap().is_some());

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
