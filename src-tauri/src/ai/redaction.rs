//! Structured redaction for HTTP material before it can enter an AI prompt.
//!
//! The redactor never stores original secret values in its manifest.  It first
//! understands URL/header/body structure and only falls back to conservative
//! text scanning when the declared representation cannot be parsed.

use regex::{Captures, Regex};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

const REDACTED_QUERY: &str = "[REDACTED:query_value]";
const REDACTED_HEADER: &str = "[REDACTED:sensitive_header]";
const REDACTED_FIELD: &str = "[REDACTED:sensitive_field]";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedactionRecord {
    pub location: String,
    pub kind: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OmissionRecord {
    pub location: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BodyDecision {
    pub location: String,
    pub capture_status: String,
    pub included: bool,
    pub reason: String,
    pub source_bytes: usize,
    pub sent_bytes: usize,
    pub truncated_by_policy: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedactionManifest {
    pub redactions: Vec<RedactionRecord>,
    pub omissions: Vec<OmissionRecord>,
    /// Policy relaxations are recorded without echoing the disclosed value.
    pub disclosures: Vec<String>,
    pub body_decisions: Vec<BodyDecision>,
    pub notes: Vec<String>,
    pub total_input_bytes: usize,
}

impl RedactionManifest {
    pub fn record_redaction(&mut self, location: &str, kind: &str) {
        if let Some(record) = self
            .redactions
            .iter_mut()
            .find(|record| record.location == location && record.kind == kind)
        {
            record.count += 1;
        } else {
            self.redactions.push(RedactionRecord {
                location: location.to_string(),
                kind: kind.to_string(),
                count: 1,
            });
        }
    }

    pub fn omit(&mut self, location: &str, reason: impl Into<String>) {
        self.omissions.push(OmissionRecord {
            location: location.to_string(),
            reason: reason.into(),
        });
    }

    pub fn disclose(&mut self, description: impl Into<String>) {
        let description = description.into();
        if !self.disclosures.contains(&description) {
            self.disclosures.push(description);
        }
    }

    pub fn note(&mut self, note: impl Into<String>) {
        let note = note.into();
        if !self.notes.contains(&note) {
            self.notes.push(note);
        }
    }
}

fn normalized_name(name: &str) -> String {
    name.chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

pub fn is_sensitive_field_name(name: &str) -> bool {
    let normalized = normalized_name(name);
    matches!(
        normalized.as_str(),
        "authorization"
            | "proxyauthorization"
            | "cookie"
            | "setcookie"
            | "password"
            | "passwd"
            | "pwd"
            | "secret"
            | "token"
            | "apikey"
            | "xapikey"
            | "authtoken"
            | "xauthtoken"
            | "accesstoken"
            | "xaccesstoken"
            | "refreshtoken"
            | "clientsecret"
            | "privatekey"
            | "credential"
            | "credentials"
            | "session"
            | "sessionid"
    ) || normalized.ends_with("token")
        || normalized.ends_with("secret")
        || normalized.ends_with("secretkey")
        || normalized.contains("password")
        || normalized.contains("clientsecret")
        || normalized.contains("accesskey")
        || normalized.contains("privatekey")
}

fn looks_like_hex_hash(value: &str) -> bool {
    matches!(value.len(), 32 | 40 | 64 | 96 | 128)
        && value.chars().all(|character| character.is_ascii_hexdigit())
}

fn looks_like_uuid(value: &str) -> bool {
    let groups: Vec<&str> = value.split('-').collect();
    groups.len() == 5
        && groups.iter().zip([8, 4, 4, 4, 12]).all(|(group, length)| {
            group.len() == length && group.chars().all(|character| character.is_ascii_hexdigit())
        })
}

fn shannon_entropy(value: &str) -> f64 {
    let mut counts = [0_u32; 256];
    let bytes = value.as_bytes();
    for byte in bytes {
        counts[*byte as usize] += 1;
    }
    let length = bytes.len() as f64;
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let probability = *count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}

fn secret_value_kind(value: &str) -> Option<&'static str> {
    let trimmed = value.trim().trim_matches(['"', '\'']);
    if trimmed.is_empty()
        || trimmed.chars().all(|character| character.is_ascii_digit())
        || looks_like_hex_hash(trimmed)
        || looks_like_uuid(trimmed)
    {
        return None;
    }
    let upper = trimmed.to_ascii_uppercase();
    if trimmed.starts_with("-----BEGIN ") && upper.contains("PRIVATE KEY-----") {
        return Some("pem_private_key");
    }
    if upper.starts_with("AKIA")
        && trimmed.len() == 20
        && trimmed
            .chars()
            .all(|character| character.is_ascii_alphanumeric())
    {
        return Some("cloud_credential");
    }
    let lower = trimmed.to_ascii_lowercase();
    if trimmed.len() >= 20
        && (trimmed.starts_with("AIza")
            || lower.starts_with("sk-")
            || lower.starts_with("sk_live_")
            || lower.starts_with("rk_live_")
            || lower.starts_with("ghp_")
            || lower.starts_with("gho_")
            || lower.starts_with("ghu_")
            || lower.starts_with("ghs_")
            || lower.starts_with("github_pat_")
            || lower.starts_with("xoxb-")
            || lower.starts_with("xoxp-")
            || lower.starts_with("xoxa-")
            || lower.starts_with("xoxr-"))
    {
        return Some("service_credential");
    }
    let jwt_parts: Vec<&str> = trimmed.split('.').collect();
    if jwt_parts.len() == 3
        && jwt_parts[0].starts_with("eyJ")
        && jwt_parts.iter().all(|part| part.len() >= 8)
    {
        return Some("jwt");
    }
    if lower.starts_with("bearer ") || lower.starts_with("basic ") {
        return Some("authorization");
    }
    if trimmed.len() >= 24
        && trimmed
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_-+/=.~".contains(character))
    {
        let has_upper = trimmed
            .chars()
            .any(|character| character.is_ascii_uppercase());
        let has_lower = trimmed
            .chars()
            .any(|character| character.is_ascii_lowercase());
        let has_digit = trimmed.chars().any(|character| character.is_ascii_digit());
        let has_symbol = trimmed
            .chars()
            .any(|character| "_-+/=.~".contains(character));
        let classes = [has_upper, has_lower, has_digit, has_symbol]
            .into_iter()
            .filter(|present| *present)
            .count();
        if classes >= 3 && shannon_entropy(trimmed) >= 4.0 {
            return Some("high_entropy");
        }
    }
    None
}

fn redact_or_disclose_value(
    value: &str,
    location: &str,
    enabled: bool,
    manifest: &mut RedactionManifest,
) -> String {
    let Some(kind) = secret_value_kind(value) else {
        return value.to_string();
    };
    if enabled {
        manifest.record_redaction(location, kind);
        format!("[REDACTED:{kind}]")
    } else {
        manifest.disclose(format!("{location}: 用户明确允许发送检测到的 {kind} 值"));
        value.to_string()
    }
}

pub fn redact_url(
    raw: &str,
    redact_query_values: bool,
    manifest: &mut RedactionManifest,
) -> String {
    let Ok(mut parsed) = url::Url::parse(raw) else {
        manifest.note("URL 无法结构化解析，已保守移除查询字符串与片段");
        let without_fragment = raw.split_once('#').map_or(raw, |(prefix, _)| prefix);
        if without_fragment.len() != raw.len() {
            manifest.omit("request.url.fragment", "URL fragment 默认不进入 AI 上下文");
        }
        if let Some((prefix, _)) = without_fragment.split_once('?') {
            manifest.record_redaction("request.url.query", "unparsed_query");
            return prefix.to_string();
        }
        return without_fragment.to_string();
    };
    if parsed.fragment().is_some() {
        parsed.set_fragment(None);
        manifest.omit("request.url.fragment", "URL fragment 默认不进入 AI 上下文");
    }
    if parsed.query().is_none() {
        return parsed.to_string();
    }
    let pairs: Vec<(String, String)> = parsed
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    parsed.set_query(None);
    {
        let mut query = parsed.query_pairs_mut();
        for (key, value) in pairs {
            if redact_query_values {
                query.append_pair(&key, REDACTED_QUERY);
                manifest.record_redaction(&format!("request.url.query.{key}"), "query_value");
            } else {
                query.append_pair(&key, &value);
            }
        }
    }
    if !redact_query_values {
        manifest.disclose("request.url.query: 用户明确允许发送查询参数值");
    }
    parsed.to_string()
}

fn value_strings(value: &Value) -> Vec<String> {
    match value {
        Value::String(value) => vec![value.clone()],
        Value::Array(values) => values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

/// Returns `(pretty JSON, content-type)` while preserving repeated headers.
pub fn redact_headers(
    headers_json: &str,
    location: &str,
    redact_sensitive_headers: bool,
    manifest: &mut RedactionManifest,
) -> (String, Option<String>) {
    let Ok(headers) = serde_json::from_str::<Map<String, Value>>(headers_json) else {
        manifest.note(format!(
            "{location}: Header JSON 无法解析，已使用保守文本扫描"
        ));
        return (
            redact_fallback_text(headers_json, location, redact_sensitive_headers, manifest),
            None,
        );
    };
    let content_type = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .and_then(|(_, value)| value_strings(value).into_iter().next());
    let mut output = Map::new();
    for (name, value) in headers {
        let field_location = format!("{location}.{}", name.to_ascii_lowercase());
        let sensitive = is_sensitive_field_name(&name);
        let mut redact_one = |input: &str| {
            if sensitive {
                if redact_sensitive_headers {
                    manifest.record_redaction(&field_location, "sensitive_header");
                    REDACTED_HEADER.to_string()
                } else {
                    manifest.disclose(format!("{field_location}: 用户明确允许发送敏感 Header"));
                    input.to_string()
                }
            } else {
                redact_or_disclose_value(input, &field_location, redact_sensitive_headers, manifest)
            }
        };
        let redacted = match value {
            Value::String(value) => Value::String(redact_one(&value)),
            Value::Array(values) => Value::Array(
                values
                    .into_iter()
                    .map(|value| Value::String(redact_one(value.as_str().unwrap_or_default())))
                    .collect(),
            ),
            _ => Value::String(String::new()),
        };
        output.insert(name, redacted);
    }
    (
        serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string()),
        content_type,
    )
}

fn redact_json_value(
    value: &mut Value,
    location: &str,
    key: Option<&str>,
    enabled: bool,
    manifest: &mut RedactionManifest,
) {
    if key.is_some_and(is_sensitive_field_name) {
        if enabled {
            *value = Value::String(REDACTED_FIELD.to_string());
            manifest.record_redaction(location, "sensitive_field");
        } else {
            manifest.disclose(format!("{location}: 用户明确允许发送敏感字段"));
        }
        return;
    }
    match value {
        Value::Object(map) => {
            for (child_key, child) in map {
                let child_location = format!("{location}.{child_key}");
                redact_json_value(child, &child_location, Some(child_key), enabled, manifest);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter_mut().enumerate() {
                redact_json_value(
                    child,
                    &format!("{location}[{index}]"),
                    None,
                    enabled,
                    manifest,
                );
            }
        }
        Value::String(text) => {
            *text = redact_or_disclose_value(text, location, enabled, manifest);
        }
        _ => {}
    }
}

fn redact_form(
    text: &str,
    location: &str,
    enabled: bool,
    manifest: &mut RedactionManifest,
) -> String {
    let pairs: Vec<(String, String)> = url::form_urlencoded::parse(text.as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    let mut output = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in pairs {
        let field_location = format!("{location}.{key}");
        let redacted = if is_sensitive_field_name(&key) {
            if enabled {
                manifest.record_redaction(&field_location, "sensitive_field");
                REDACTED_FIELD.to_string()
            } else {
                manifest.disclose(format!("{field_location}: 用户明确允许发送敏感字段"));
                value
            }
        } else {
            redact_or_disclose_value(&value, &field_location, enabled, manifest)
        };
        output.append_pair(&key, &redacted);
    }
    output.finish()
}

fn multipart_boundary(content_type: &str) -> Option<String> {
    content_type.split(';').find_map(|piece| {
        let (name, value) = piece.trim().split_once('=')?;
        if !name.trim().eq_ignore_ascii_case("boundary") {
            return None;
        }
        let value = value.trim().trim_matches('"');
        (!value.is_empty()).then(|| value.to_string())
    })
}

fn split_header_parameters(value: &str) -> Vec<String> {
    let mut pieces = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for character in value.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        match character {
            '\\' if quoted => {
                current.push(character);
                escaped = true;
            }
            '"' => {
                quoted = !quoted;
                current.push(character);
            }
            ';' if !quoted => {
                pieces.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(character),
        }
    }
    pieces.push(current.trim().to_string());
    pieces
}

fn unquote_header_parameter(value: &str) -> String {
    let value = value.trim();
    let Some(inner) = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    else {
        return value.to_string();
    };
    let mut unescaped = String::with_capacity(inner.len());
    let mut escaped = false;
    for character in inner.chars() {
        if escaped {
            unescaped.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else {
            unescaped.push(character);
        }
    }
    if escaped {
        unescaped.push('\\');
    }
    unescaped
}

fn content_disposition_parameters(headers: &str) -> Vec<(String, String)> {
    let Some(value) = headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("content-disposition")
            .then_some(value.trim())
    }) else {
        return Vec::new();
    };
    split_header_parameters(value)
        .into_iter()
        .skip(1)
        .filter_map(|piece| {
            let (name, value) = piece.split_once('=')?;
            let name = name.trim().to_ascii_lowercase();
            (!name.is_empty()).then(|| (name, unquote_header_parameter(value)))
        })
        .collect()
}

fn redact_multipart(
    text: &str,
    content_type: &str,
    location: &str,
    enabled: bool,
    manifest: &mut RedactionManifest,
) -> Option<String> {
    let boundary = multipart_boundary(content_type)?;
    let mut fields = Vec::new();
    for (index, raw_part) in text.split(&format!("--{boundary}")).enumerate() {
        if index == 0 {
            continue;
        }
        let part = raw_part.strip_prefix("\r\n").unwrap_or(raw_part);
        let part = part.strip_suffix("\r\n").unwrap_or(part);
        if part.is_empty() || part == "--" || part.starts_with("--\r\n") {
            continue;
        }
        let (headers, body) = part.split_once("\r\n\r\n")?;
        let parameters = content_disposition_parameters(headers);
        let name = parameters
            .iter()
            .find(|(name, _)| name == "name")
            .map(|(_, value)| value.clone())
            .unwrap_or_else(|| format!("part_{index}"));
        let is_file = parameters
            .iter()
            .any(|(name, _)| name == "filename" || name == "filename*");
        let field_location = format!("{location}.{name}");
        let value = if is_file {
            manifest.omit(&field_location, "multipart 文件内容默认不进入 AI 上下文");
            "[OMITTED:file_content]".to_string()
        } else if is_sensitive_field_name(&name) {
            if enabled {
                manifest.record_redaction(&field_location, "sensitive_field");
                REDACTED_FIELD.to_string()
            } else {
                manifest.disclose(format!("{field_location}: 用户明确允许发送敏感字段"));
                body.to_string()
            }
        } else {
            redact_or_disclose_value(body, &field_location, enabled, manifest)
        };
        fields.push(serde_json::json!({ "name": name, "value": value }));
    }
    serde_json::to_string_pretty(&fields).ok()
}

fn replace_regex(
    input: &str,
    pattern: &str,
    replacement: &str,
    location: &str,
    kind: &str,
    manifest: &mut RedactionManifest,
) -> String {
    let Ok(regex) = Regex::new(pattern) else {
        return input.to_string();
    };
    regex
        .replace_all(input, |_captures: &Captures<'_>| {
            manifest.record_redaction(location, kind);
            replacement.to_string()
        })
        .into_owned()
}

pub fn redact_fallback_text(
    text: &str,
    location: &str,
    enabled: bool,
    manifest: &mut RedactionManifest,
) -> String {
    if !enabled {
        if secret_value_kind(text).is_some() {
            manifest.disclose(format!("{location}: 用户明确允许发送保守扫描识别到的秘密"));
        }
        return text.to_string();
    }
    let mut output = replace_regex(
        text,
        r"(?is)-----BEGIN [^-\r\n]*PRIVATE KEY-----.*?-----END [^-\r\n]*PRIVATE KEY-----",
        "[REDACTED:pem_private_key]",
        location,
        "pem_private_key",
        manifest,
    );
    output = replace_regex(
        &output,
        r"(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}",
        "[REDACTED:authorization]",
        location,
        "authorization",
        manifest,
    );
    output = replace_regex(
        &output,
        r"(?im)^\s*(?:Authorization|Proxy-Authorization|Cookie|Set-Cookie|X-Api-Key|X-Auth-Token|X-Access-Token)\s*:[^\r\n]*$",
        "[REDACTED:sensitive_header]",
        location,
        "sensitive_header",
        manifest,
    );
    let sensitive_assignment = Regex::new(
        r#"(?i)(["']?(?:authorization|proxy-authorization|cookie|set-cookie|password|passwd|pwd|secret|token|api[_-]?key|x-api-key|auth[_-]?token|x-auth-token|access[_-]?token|x-access-token|refresh[_-]?token|client[_-]?secret|session(?:id)?)["']?\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^,\s}\r\n]+)"#,
    )
    .expect("static sensitive assignment regex");
    output = sensitive_assignment
        .replace_all(&output, |captures: &Captures<'_>| {
            manifest.record_redaction(location, "sensitive_field");
            format!("{}{}", &captures[1], REDACTED_FIELD)
        })
        .into_owned();
    output = replace_regex(
        &output,
        r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
        "[REDACTED:jwt]",
        location,
        "jwt",
        manifest,
    );
    output = replace_regex(
        &output,
        r"\bAKIA[0-9A-Z]{16}\b",
        "[REDACTED:cloud_credential]",
        location,
        "cloud_credential",
        manifest,
    );
    output = replace_regex(
        &output,
        r"\b(?:AIza[0-9A-Za-z_-]{16,}|sk-(?:proj-)?[0-9A-Za-z_-]{16,}|(?:sk|rk)_live_[0-9A-Za-z]{16,}|gh[pousr]_[0-9A-Za-z]{16,}|github_pat_[0-9A-Za-z_]{16,}|xox[bpar]-[0-9A-Za-z-]{16,})\b",
        "[REDACTED:service_credential]",
        location,
        "service_credential",
        manifest,
    );

    let key_value = Regex::new(
        r#"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|session(?:id)?)\b(\s*[:=]\s*)[\"']?[A-Za-z0-9._~+/=-]{3,}[\"']?"#,
    )
    .expect("static key/value regex");
    output = key_value
        .replace_all(&output, |captures: &Captures<'_>| {
            manifest.record_redaction(location, "sensitive_field");
            format!("{}{}{}", &captures[1], &captures[2], REDACTED_FIELD)
        })
        .into_owned();

    // Excluding `=` prevents a normal `hash=<hex>` pair from becoming one
    // mixed high-entropy candidate. Dedicated passes already cover key/value,
    // Authorization, JWT, and cloud credential formats.
    let candidate =
        Regex::new(r"\b[A-Za-z0-9_+/.-]{24,}\b").expect("static high entropy candidate regex");
    candidate
        .replace_all(&output, |captures: &Captures<'_>| {
            let value = &captures[0];
            if let Some(kind) = secret_value_kind(value) {
                manifest.record_redaction(location, kind);
                format!("[REDACTED:{kind}]")
            } else {
                value.to_string()
            }
        })
        .into_owned()
}

pub fn redact_text_body(
    text: &str,
    content_type: Option<&str>,
    location: &str,
    enabled: bool,
    manifest: &mut RedactionManifest,
) -> String {
    let original_content_type = content_type.unwrap_or_default();
    let normalized = original_content_type.to_ascii_lowercase();
    let trimmed = text.trim_start();
    if normalized.contains("json") || trimmed.starts_with('{') || trimmed.starts_with('[') {
        match serde_json::from_str::<Value>(text) {
            Ok(mut json) => {
                redact_json_value(&mut json, location, None, enabled, manifest);
                return serde_json::to_string_pretty(&json).unwrap_or_default();
            }
            Err(_) => manifest.note(format!("{location}: JSON 解析失败，已改用保守文本扫描")),
        }
    } else if normalized.contains("application/x-www-form-urlencoded") {
        return redact_form(text, location, enabled, manifest);
    } else if normalized.contains("multipart/form-data") {
        if let Some(redacted) =
            redact_multipart(text, original_content_type, location, enabled, manifest)
        {
            return redacted;
        }
        manifest.note(format!(
            "{location}: multipart 解析失败，已改用保守文本扫描"
        ));
    }
    redact_fallback_text(text, location, enabled, manifest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_keeps_route_and_redacts_every_query_value() {
        let mut manifest = RedactionManifest::default();
        let output = redact_url(
            "https://example.test/login?token=secret&next=%2Fhome#local-state",
            true,
            &mut manifest,
        );
        assert!(output.starts_with("https://example.test/login?"));
        assert!(!output.contains("secret"));
        assert!(!output.contains("%2Fhome"));
        assert!(!output.contains("local-state"));
        assert_eq!(manifest.redactions.len(), 2);
        assert!(manifest
            .omissions
            .iter()
            .any(|record| record.location == "request.url.fragment"));
    }

    #[test]
    fn headers_preserve_repeated_safe_values_and_hide_credentials() {
        let mut manifest = RedactionManifest::default();
        let (output, _) = redact_headers(
            r#"{"Authorization":"Bearer top-secret","Set-Cookie":["a=1","b=2"],"X-Test":["one","two"]}"#,
            "request.headers",
            true,
            &mut manifest,
        );
        assert!(!output.contains("top-secret"));
        assert!(!output.contains("a=1"));
        assert!(output.contains("one"));
        assert!(output.contains("two"));
    }

    #[test]
    fn nested_json_and_common_secret_formats_are_redacted() {
        let mut manifest = RedactionManifest::default();
        let input = r#"{"profile":{"password":"p@ss","id":"ORD-2026-0042"},"id_token":"opaque-short-token","jwt":"eyJ12345678.eyJabcdefgh.abcdefghi","sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}"#;
        let output = redact_text_body(
            input,
            Some("application/json"),
            "request.body",
            true,
            &mut manifest,
        );
        assert!(!output.contains("p@ss"));
        assert!(!output.contains("eyJ12345678"));
        assert!(!output.contains("opaque-short-token"));
        assert!(output.contains("ORD-2026-0042"));
        assert!(output.contains("0123456789abcdef0123456789abcdef"));
    }

    #[test]
    fn form_and_multipart_are_parsed_before_redaction() {
        let mut form_manifest = RedactionManifest::default();
        let form = redact_text_body(
            "user=alice&password=hunter2",
            Some("application/x-www-form-urlencoded"),
            "request.body",
            true,
            &mut form_manifest,
        );
        assert!(form.contains("user=alice"));
        assert!(!form.contains("hunter2"));

        let mut multipart_manifest = RedactionManifest::default();
        let multipart = "--abc\r\nContent-Disposition: form-data; name=\"token\"\r\n\r\nsecret-value\r\n--abc--\r\n";
        let output = redact_text_body(
            multipart,
            Some("multipart/form-data; Boundary=abc"),
            "request.body",
            true,
            &mut multipart_manifest,
        );
        assert!(!output.contains("secret-value"));
    }

    #[test]
    fn common_secret_suffixes_are_redacted_in_structured_data() {
        for field in [
            "api_secret",
            "consumer-secret",
            "signingSecret",
            "secret_key",
        ] {
            assert!(
                is_sensitive_field_name(field),
                "{field} should be sensitive"
            );
        }
        let mut manifest = RedactionManifest::default();
        let output = redact_text_body(
            r#"{"api_secret":"hunter2","safe":"visible"}"#,
            Some("application/json"),
            "request.body",
            true,
            &mut manifest,
        );
        assert!(!output.contains("hunter2"));
        assert!(output.contains("visible"));
    }

    #[test]
    fn multipart_token_parameters_and_extended_filenames_are_safe() {
        let cases = [
            "--abc\r\nContent-Disposition: form-data; name=api_secret\r\n\r\nhunter2\r\n--abc--\r\n",
            "--abc\r\nContent-Disposition: form-data; name=upload; filename=secrets.txt\r\n\r\nprivate file text\r\n--abc--\r\n",
            "--abc\r\nContent-Disposition: form-data; name=\"upload\"; filename*=UTF-8''secrets.txt\r\n\r\nprivate file text\r\n--abc--\r\n",
        ];
        for multipart in cases {
            let mut manifest = RedactionManifest::default();
            let output = redact_text_body(
                multipart,
                Some("multipart/form-data; boundary=abc"),
                "request.body",
                true,
                &mut manifest,
            );
            assert!(!output.contains("hunter2"));
            assert!(!output.contains("private file text"));
        }
    }

    #[test]
    fn multipart_parser_preserves_field_hyphens() {
        let mut manifest = RedactionManifest::default();
        let multipart =
            "--abc\r\nContent-Disposition: form-data; name=value\r\n\r\nkeep--\r\n--abc--\r\n";
        let output = redact_text_body(
            multipart,
            Some("multipart/form-data; boundary=abc"),
            "request.body",
            true,
            &mut manifest,
        );
        assert!(output.contains("keep--"));
    }

    #[test]
    fn fallback_redacts_private_keys_cloud_keys_and_authorization() {
        let mut manifest = RedactionManifest::default();
        let input = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz\nAKIAABCDEFGHIJKLMNOP\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----";
        let output = redact_fallback_text(input, "request.body", true, &mut manifest);
        assert!(!output.contains("abcdefghijklmnopqrstuvwxyz"));
        assert!(!output.contains("AKIAABCDEFGHIJKLMNOP"));
        assert!(!output.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn fallback_redacts_common_service_credentials() {
        let mut manifest = RedactionManifest::default();
        let input = "github=ghp_abcdefghijklmnopqrstuvwxyz123456 openai=sk-proj-abcdefghijklmnopqrstuvwxyz123456";
        let output = redact_fallback_text(input, "request.body", true, &mut manifest);
        assert!(!output.contains("ghp_abcdefghijklmnopqrstuvwxyz123456"));
        assert!(!output.contains("sk-proj-abcdefghijklmnopqrstuvwxyz123456"));
        assert!(manifest
            .redactions
            .iter()
            .any(|record| record.kind == "service_credential"));
    }

    #[test]
    fn fallback_redacts_basic_auth_cookie_and_high_entropy_random_values() {
        let mut manifest = RedactionManifest::default();
        let random = "dG9wU2VjcmV0LTIwMjYtQWxwaGEvKzEyMzQ1Njc4OTA=";
        let input = format!(
            "Authorization: Basic dXNlcjpwYXNzd29yZA==\nCookie: sid=secret\nnonce={random}"
        );
        let output = redact_fallback_text(&input, "request.body", true, &mut manifest);
        assert!(!output.contains("dXNlcjpwYXNzd29yZA"));
        assert!(!output.contains("sid=secret"));
        assert!(!output.contains(random));
        assert!(manifest
            .redactions
            .iter()
            .any(|record| record.kind == "high_entropy"));
    }

    #[test]
    fn malformed_structures_use_conservative_sensitive_assignment_scanning() {
        let mut manifest = RedactionManifest::default();
        let input = r#"{"Cookie":"sid=x; role=admin","Authorization":"Custom short credential","password":"secret value with spaces", BROKEN"#;
        let output = redact_fallback_text(input, "request.headers", true, &mut manifest);
        assert!(!output.contains("sid=x"));
        assert!(!output.contains("Custom short credential"));
        assert!(!output.contains("secret value with spaces"));
        assert!(manifest
            .redactions
            .iter()
            .any(|record| record.kind == "sensitive_field"));
    }

    #[test]
    fn normal_ids_uuids_and_hashes_are_not_over_redacted() {
        let mut manifest = RedactionManifest::default();
        let input = "order=ORD-2026-0042 uuid=550e8400-e29b-41d4-a716-446655440000 hash=0123456789abcdef0123456789abcdef";
        let output = redact_fallback_text(input, "request.body", true, &mut manifest);
        assert_eq!(output, input);
        assert!(manifest.redactions.is_empty());
    }
}
