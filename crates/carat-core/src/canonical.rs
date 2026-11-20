use crate::digest::sha256_hex;
use serde::Serialize;
use serde_json::{Map, Value};

/// Serializes any `Serialize` value into Carat canonical JSON:
/// UTF-8, object keys sorted lexicographically (UTF-8 / Unicode code point order),
/// no insignificant whitespace.
pub fn to_canonical_json<T: Serialize>(value: &T) -> Result<String, String> {
    let v = serde_json::to_value(value).map_err(|e| format!("json serialize error: {e}"))?;
    let sorted = sort_value(v);
    serde_json::to_string(&sorted).map_err(|e| format!("canonical json error: {e}"))
}

pub fn canonical_id<T: Serialize>(value: &T) -> Result<String, String> {
    let json = to_canonical_json(value)?;
    Ok(sha256_hex(json.as_bytes()))
}

/// Computes the approval/transition subject:
/// SHA-256 of canonical `[ecosystem, name, reference_sha512_or_null, new_sha512]`.
pub fn transition_subject(
    ecosystem: &str,
    name: &str,
    reference_sha512: Option<&str>,
    new_sha512: &str,
) -> String {
    let tuple = Value::Array(vec![
        Value::String(ecosystem.to_string()),
        Value::String(name.to_string()),
        match reference_sha512 {
            Some(s) => Value::String(s.to_string()),
            None => Value::Null,
        },
        Value::String(new_sha512.to_string()),
    ]);
    let json = serde_json::to_string(&tuple).expect("json tuple serialization cannot fail");
    sha256_hex(json.as_bytes())
}

fn sort_value(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            let mut sorted = Map::with_capacity(entries.len());
            for (k, v) in entries {
                sorted.insert(k, sort_value(v));
            }
            Value::Object(sorted)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(sort_value).collect()),
        other => other,
    }
}

/// Parses an RFC 3339 timestamp (`YYYY-MM-DDTHH:MM:SS(.frac)?(Z|±HH:MM)`) into Unix epoch seconds.
pub fn parse_rfc3339_unix(input: &str) -> Option<i64> {
    let s = input.trim();
    if s.len() < 20 {
        return None;
    }
    let bytes = s.as_bytes();
    if bytes[4] != b'-' || bytes[7] != b'-' || (bytes[10] != b'T' && bytes[10] != b't') {
        return None;
    }
    if bytes[13] != b':' || bytes[16] != b':' {
        return None;
    }
    let year: i64 = s[0..4].parse().ok()?;
    let month: u32 = s[5..7].parse().ok()?;
    let day: u32 = s[8..10].parse().ok()?;
    let hour: i64 = s[11..13].parse().ok()?;
    let minute: i64 = s[14..16].parse().ok()?;
    let second: i64 = s[17..19].parse().ok()?;

    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return None;
    }

    let mut rest = &s[19..];
    if let Some(after_dot) = rest.strip_prefix('.') {
        let digits = after_dot.bytes().take_while(|b| b.is_ascii_digit()).count();
        if digits == 0 {
            return None;
        }
        rest = &after_dot[digits..];
    }

    let offset_secs: i64 = if rest == "Z" || rest == "z" {
        0
    } else if rest.len() == 6 && (rest.starts_with('+') || rest.starts_with('-')) {
        let sign = if rest.starts_with('+') { 1 } else { -1 };
        if rest.as_bytes()[3] != b':' {
            return None;
        }
        let oh: i64 = rest[1..3].parse().ok()?;
        let om: i64 = rest[4..6].parse().ok()?;
        if !(0..=23).contains(&oh) || !(0..=59).contains(&om) {
            return None;
        }
        sign * (oh * 3600 + om * 60)
    } else {
        return None;
    };

    let days = days_from_civil(year, month, day);
    Some(days * 86_400 + hour * 3600 + minute * 60 + second - offset_secs)
}

/// Formats Unix epoch seconds as an RFC 3339 UTC string (`YYYY-MM-DDTHH:MM:SSZ`).
pub fn format_unix_rfc3339(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let hour = rem / 3600;
    let minute = (rem % 3600) / 60;
    let second = rem % 60;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

// Howard Hinnant's civil calendar algorithms (exact across all Gregorian dates).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400; // [0, 399]
    let m = m as i64;
    let d = d as i64;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_json_sorts_nested_keys() {
        let a = json!({"b": 1, "a": {"z": 2, "m": 3}});
        let b = json!({"a": {"m": 3, "z": 2}, "b": 1});
        assert_eq!(to_canonical_json(&a).unwrap(), to_canonical_json(&b).unwrap());
        assert_eq!(
            to_canonical_json(&a).unwrap(),
            r#"{"a":{"m":3,"z":2},"b":1}"#
        );
    }

    #[test]
    fn rfc3339_roundtrip() {
        let ts = "2026-11-19T19:00:00.123Z";
        let unix = parse_rfc3339_unix(ts).unwrap();
        assert_eq!(format_unix_rfc3339(unix), "2026-11-19T19:00:00Z");
        let with_offset = parse_rfc3339_unix("2026-11-19T14:00:00-05:00").unwrap();
        assert_eq!(unix, with_offset);
    }
}
