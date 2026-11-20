use crate::model::{NewDirectPolicy, PolicyConfig, ReadPassPolicy};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReaderConfig {
    pub command: Option<String>,
    pub model: String,
    pub effort: String,
    pub timeout_secs: u64,
}

impl Default for ReaderConfig {
    fn default() -> Self {
        Self {
            command: None,
            model: "claude-opus-5-5".to_string(),
            effort: "high".to_string(),
            timeout_secs: 90,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaratConfig {
    pub policy: PolicyConfig,
    /// Only run the reader on already-stopped transitions when explicitly enabled (default: false).
    pub read_on_stop: bool,
    pub reader: ReaderConfig,
    pub stores: Vec<String>,
}

impl Default for CaratConfig {
    fn default() -> Self {
        Self {
            policy: PolicyConfig::default(),
            read_on_stop: false,
            reader: ReaderConfig::default(),
            stores: Vec::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCaratToml {
    min_age: Option<String>,
    settled_age: Option<String>,
    new_direct_dependency: Option<String>,
    read_pass: Option<String>,
    read_on_stop: Option<bool>,
    history_depth: Option<usize>,
    stores: Option<Vec<String>>,
    reader: Option<RawReaderToml>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawReaderToml {
    command: Option<String>,
    model: Option<String>,
    effort: Option<String>,
    timeout_secs: Option<u64>,
}

impl CaratConfig {
    pub fn from_toml(input: &str) -> Result<Self, String> {
        let raw: RawCaratToml =
            toml::from_str(input).map_err(|e| format!("invalid carat.toml: {e}"))?;
        let mut cfg = Self::default();

        if let Some(s) = raw.min_age {
            cfg.policy.min_age_hours = parse_duration_hours(&s)?;
        }
        if let Some(s) = raw.settled_age {
            let hours = parse_duration_hours(&s)?;
            cfg.policy.settled_age_days = (hours + 23) / 24;
        }
        if let Some(s) = raw.new_direct_dependency {
            cfg.policy.new_direct_dependency = match s.as_str() {
                "thin_history" => NewDirectPolicy::ThinHistory,
                "confirm" => NewDirectPolicy::Confirm,
                "check" => NewDirectPolicy::Check,
                other => {
                    return Err(format!(
                        "invalid new_direct_dependency '{other}': expected 'thin_history', 'confirm', or 'check'"
                    ));
                }
            };
        }
        if let Some(s) = raw.read_pass {
            cfg.policy.read_pass = match s.as_str() {
                "allow" => ReadPassPolicy::Allow,
                "require_human" => ReadPassPolicy::RequireHuman,
                other => {
                    return Err(format!(
                        "invalid read_pass '{other}': expected 'allow' or 'require_human'"
                    ));
                }
            };
        }
        if let Some(ros) = raw.read_on_stop {
            cfg.read_on_stop = ros;
        }
        if let Some(k) = raw.history_depth {
            cfg.policy.history_depth = k;
        }
        if let Some(stores) = raw.stores {
            cfg.stores = stores;
        }
        if let Some(rc) = raw.reader {
            if rc.command.is_some() {
                cfg.reader.command = rc.command;
            }
            if let Some(m) = rc.model {
                cfg.reader.model = m;
            }
            if let Some(e) = rc.effort {
                cfg.reader.effort = e;
            }
            if let Some(t) = rc.timeout_secs {
                cfg.reader.timeout_secs = t;
            }
        }

        Ok(cfg)
    }
}

pub fn parse_duration_hours(raw: &str) -> Result<i64, String> {
    let s = raw.trim();
    if let Some(num) = s.strip_suffix('d') {
        let days: i64 = num
            .parse()
            .map_err(|_| format!("invalid day duration '{raw}'"))?;
        return Ok(days * 24);
    }
    if let Some(num) = s.strip_suffix('h') {
        let hours: i64 = num
            .parse()
            .map_err(|_| format!("invalid hour duration '{raw}'"))?;
        return Ok(hours);
    }
    if let Some(num) = s.strip_suffix('m') {
        let mins: i64 = num
            .parse()
            .map_err(|_| format!("invalid minute duration '{raw}'"))?;
        return Ok(mins / 60);
    }
    Err(format!(
        "invalid duration '{raw}': use suffix 'h', 'd', or 'm' (e.g. '24h', '30d')"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_carat_toml_correctly() {
        let toml_str = r#"
min_age = "48h"
settled_age = "14d"
new_direct_dependency = "confirm"
read_pass = "require_human"
read_on_stop = true
history_depth = 15
stores = ["/var/lib/carat-shared"]

[reader]
model = "claude-opus-5-5"
effort = "max"
timeout_secs = 120
"#;
        let cfg = CaratConfig::from_toml(toml_str).unwrap();
        assert_eq!(cfg.policy.min_age_hours, 48);
        assert_eq!(cfg.policy.settled_age_days, 14);
        assert_eq!(cfg.policy.new_direct_dependency, NewDirectPolicy::Confirm);
        assert_eq!(cfg.policy.read_pass, ReadPassPolicy::RequireHuman);
        assert!(cfg.read_on_stop);
        assert_eq!(cfg.policy.history_depth, 15);
        assert_eq!(cfg.reader.effort, "max");
        assert_eq!(cfg.stores, vec!["/var/lib/carat-shared"]);
    }
}
