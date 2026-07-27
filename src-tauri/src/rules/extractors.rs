//! 结构化提取器：把已捕获的 HTTP 字段解析成可比较的标量。
//!
//! 这里的每个函数都只做"读已有字节"这一件事——没有文件、网络、进程和脚本
//! 能力，所有输入都是代理已经落库的文本。提取失败一律退化为"没有候选值"，
//! 绝不 panic，也不会让规则引擎中断。

use crate::rules::schema::{
    CookieField, FormField, JwtMetadataField, QueryField, MAX_CANDIDATES_PER_SELECTOR,
    MAX_EVIDENCE_SNIPPET_CHARS, MAX_JSON_PATH_SEGMENTS,
};
use base64::Engine as _;
use regex::Regex;
use serde_json::{Map, Value};
use std::sync::LazyLock;

/// 解析后的单条 Cookie（`Set-Cookie` 或请求 `Cookie` 里的一项）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCookie {
    pub name: String,
    pub value: String,
    /// 属性名统一小写；flag 型属性（HttpOnly/Secure）值为 None。
    pub attributes: Vec<(String, Option<String>)>,
}

impl ParsedCookie {
    pub fn has_attribute(&self, name: &str) -> bool {
        self.attributes
            .iter()
            .any(|(attribute, _)| attribute.eq_ignore_ascii_case(name))
    }

    pub fn attribute_value(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(attribute, _)| attribute.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_deref().unwrap_or_default())
    }

    /// 证据形态：Cookie 值永远不出现，只保留名字与属性。
    pub fn redacted(&self) -> String {
        let mut rendered = format!("{}=[REDACTED]", self.name);
        for (attribute, value) in &self.attributes {
            match value {
                Some(_) => rendered.push_str(&format!("; {attribute}=[REDACTED]")),
                None => rendered.push_str(&format!("; {attribute}")),
            }
        }
        rendered
    }
}

/// 解析单条 `Set-Cookie`。第一段是 `name=value`，其余是属性。
pub fn parse_set_cookie(raw: &str) -> ParsedCookie {
    let mut pieces = raw.split(';');
    let (name, value) = pieces
        .next()
        .map(split_cookie_pair)
        .unwrap_or_else(|| (String::new(), String::new()));
    let attributes = pieces
        .filter_map(|piece| {
            let piece = piece.trim();
            if piece.is_empty() {
                return None;
            }
            Some(match piece.split_once('=') {
                Some((attribute, value)) => (
                    attribute.trim().to_ascii_lowercase(),
                    Some(value.trim().to_string()),
                ),
                None => (piece.to_ascii_lowercase(), None),
            })
        })
        .take(MAX_CANDIDATES_PER_SELECTOR)
        .collect();
    ParsedCookie {
        name,
        value,
        attributes,
    }
}

/// 解析请求侧 `Cookie` 头，返回逐项 Cookie（请求 Cookie 没有属性）。
pub fn parse_cookie_header(raw: &str) -> Vec<ParsedCookie> {
    raw.split(';')
        .filter(|piece| !piece.trim().is_empty())
        .take(MAX_CANDIDATES_PER_SELECTOR)
        .map(|piece| {
            let (name, value) = split_cookie_pair(piece);
            ParsedCookie {
                name,
                value,
                attributes: Vec::new(),
            }
        })
        .collect()
}

fn split_cookie_pair(piece: &str) -> (String, String) {
    match piece.split_once('=') {
        Some((name, value)) => (name.trim().to_string(), value.trim().to_string()),
        None => (piece.trim().to_string(), String::new()),
    }
}

/// 解析 URL 查询串。URL 无法结构化解析时退化为手工按 `?` 切分。
pub fn parse_query(url: &str) -> Vec<(String, String)> {
    let query = match url::Url::parse(url) {
        Ok(parsed) => parsed.query().map(str::to_string),
        Err(_) => url
            .split_once('?')
            .map(|(_, rest)| rest.split('#').next().unwrap_or_default().to_string()),
    };
    let Some(query) = query else {
        return Vec::new();
    };
    url::form_urlencoded::parse(query.as_bytes())
        .take(MAX_CANDIDATES_PER_SELECTOR)
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect()
}

/// 解析 `application/x-www-form-urlencoded` 正文。
pub fn parse_form(body: &str) -> Vec<(String, String)> {
    url::form_urlencoded::parse(body.as_bytes())
        .take(MAX_CANDIDATES_PER_SELECTOR)
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect()
}

pub fn query_scalar(field: QueryFieldLike, name: &str, value: &str) -> String {
    match field {
        QueryFieldLike::Name => name.to_string(),
        QueryFieldLike::Value => value.to_string(),
        QueryFieldLike::Pair => format!("{name}={value}"),
    }
}

/// `QueryField` 与 `FormField` 语义相同，统一成一个内部枚举避免重复分支。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryFieldLike {
    Name,
    Value,
    Pair,
}

impl From<QueryField> for QueryFieldLike {
    fn from(field: QueryField) -> Self {
        match field {
            QueryField::Name => Self::Name,
            QueryField::Value => Self::Value,
            QueryField::Pair => Self::Pair,
        }
    }
}

impl From<FormField> for QueryFieldLike {
    fn from(field: FormField) -> Self {
        match field {
            FormField::Name => Self::Name,
            FormField::Value => Self::Value,
            FormField::Pair => Self::Pair,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonPathSegment {
    Key(String),
    Index(usize),
}

/// JSONPath 子集：只支持 `$.a.b` 与 `$.a[0].b`，不支持递归 `..`、通配与过滤。
pub fn parse_json_path(path: &str) -> Result<Vec<JsonPathSegment>, String> {
    let rest = path
        .strip_prefix('$')
        .ok_or_else(|| format!("JSONPath `{path}` 必须以 `$` 开头"))?;
    if rest.contains("..")
        || rest.contains('*')
        || rest.contains('?')
        || rest.contains('(')
        || rest.contains('@')
    {
        return Err(format!(
            "JSONPath `{path}` 使用了子集不支持的递归/通配/过滤语法"
        ));
    }
    let mut segments = Vec::new();
    let mut characters = rest.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '.' => {
                let mut key = String::new();
                while let Some(next) = characters.peek() {
                    if *next == '.' || *next == '[' {
                        break;
                    }
                    key.push(*next);
                    characters.next();
                }
                if key.is_empty() {
                    return Err(format!("JSONPath `{path}` 含空字段名"));
                }
                segments.push(JsonPathSegment::Key(key));
            }
            '[' => {
                let mut digits = String::new();
                let mut closed = false;
                for next in characters.by_ref() {
                    if next == ']' {
                        closed = true;
                        break;
                    }
                    digits.push(next);
                }
                if !closed {
                    return Err(format!("JSONPath `{path}` 的 `[` 未闭合"));
                }
                let index = digits
                    .parse::<usize>()
                    .map_err(|_| format!("JSONPath `{path}` 只支持非负整数下标"))?;
                segments.push(JsonPathSegment::Index(index));
            }
            other => {
                return Err(format!("JSONPath `{path}` 含非法字符 `{other}`"));
            }
        }
    }
    if segments.is_empty() {
        return Err(format!("JSONPath `{path}` 未指向任何字段"));
    }
    if segments.len() > MAX_JSON_PATH_SEGMENTS {
        return Err(format!(
            "JSONPath `{path}` 层级 {} 超过上限 {MAX_JSON_PATH_SEGMENTS}",
            segments.len()
        ));
    }
    Ok(segments)
}

/// 按已解析路径取值，取不到返回 None。
pub fn json_path_lookup<'a>(root: &'a Value, segments: &[JsonPathSegment]) -> Option<&'a Value> {
    let mut current = root;
    for segment in segments {
        current = match segment {
            JsonPathSegment::Key(key) => current.as_object()?.get(key)?,
            JsonPathSegment::Index(index) => current.as_array()?.get(*index)?,
        };
    }
    Some(current)
}

/// JSON 值转成规则可比较的标量文本。
pub fn json_scalar(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => "null".to_string(),
        other => other.to_string(),
    }
}

static JWT_TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}(?:\.[A-Za-z0-9_-]*)?")
        .expect("static JWT token regex")
});

/// 从任意文本里取出第一个 JWT 形态的串（`Bearer ` 前缀会被自动跳过）。
pub fn find_jwt(text: &str) -> Option<&str> {
    JWT_TOKEN.find(text).map(|found| found.as_str())
}

fn decode_base64url(segment: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segment)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(segment))
        .ok()
}

fn jwt_claim(object: &Map<String, Value>, key: &str) -> Option<String> {
    let value = object.get(key)?;
    Some(match value {
        Value::Array(items) => items.iter().map(json_scalar).collect::<Vec<_>>().join(","),
        other => json_scalar(other),
    })
}

/// 只解码 JWT 的 header/payload 元数据，不做任何签名校验。
pub fn jwt_metadata(token: &str, field: JwtMetadataField) -> Option<String> {
    let token = find_jwt(token)?;
    let mut parts = token.split('.');
    let header = parts.next()?;
    let payload = parts.next()?;
    let source = match field {
        JwtMetadataField::Alg | JwtMetadataField::Typ | JwtMetadataField::Kid => header,
        _ => payload,
    };
    let decoded = decode_base64url(source)?;
    let object = serde_json::from_slice::<Value>(&decoded).ok()?;
    let object = object.as_object()?;
    let key = match field {
        JwtMetadataField::Alg => "alg",
        JwtMetadataField::Typ => "typ",
        JwtMetadataField::Kid => "kid",
        JwtMetadataField::Iss => "iss",
        JwtMetadataField::Aud => "aud",
        JwtMetadataField::Exp => "exp",
        JwtMetadataField::Nbf => "nbf",
        JwtMetadataField::Iat => "iat",
    };
    jwt_claim(object, key)
}

/// Header JSON（字符串或有序数组）解析成 `(小写名, 值列表)`。
/// 解析失败返回空表——规则宁可少命中，也不能对脏数据瞎猜。
pub fn parse_headers(headers_json: &str) -> Vec<(String, Vec<String>)> {
    let Ok(Value::Object(map)) = serde_json::from_str::<Value>(headers_json) else {
        return Vec::new();
    };
    let mut remaining = MAX_CANDIDATES_PER_SELECTOR;
    let mut headers = Vec::new();
    for (name, value) in map {
        if remaining == 0 {
            break;
        }
        let values: Vec<String> = match value {
            Value::String(single) => vec![single],
            Value::Array(items) => items
                .into_iter()
                .map(|item| match item {
                    Value::String(text) => text,
                    other => json_scalar(&other),
                })
                .take(remaining)
                .collect(),
            other => vec![json_scalar(&other)],
        };
        if values.is_empty() {
            continue;
        }
        remaining -= values.len();
        headers.push((name.to_ascii_lowercase(), values));
    }
    headers
}

fn cookie_field_scalar(cookie: &ParsedCookie, field: CookieField) -> Option<String> {
    match field {
        CookieField::Name => Some(cookie.name.clone()),
        CookieField::Value => Some(cookie.value.clone()),
        CookieField::Attribute => None,
    }
}

/// Cookie 提取器的标量取值；`attribute` 为空时枚举全部属性名。
pub fn cookie_candidates(
    cookie: &ParsedCookie,
    field: CookieField,
    attribute: Option<&str>,
) -> Vec<(String, String)> {
    if field != CookieField::Attribute {
        return cookie_field_scalar(cookie, field)
            .map(|value| vec![(field_suffix(field).to_string(), value)])
            .unwrap_or_default();
    }
    match attribute {
        Some(attribute) => cookie
            .attribute_value(attribute)
            .map(|value| vec![(attribute.to_ascii_lowercase(), value.to_string())])
            .unwrap_or_default(),
        None => cookie
            .attributes
            .iter()
            .map(|(name, value)| (name.clone(), value.clone().unwrap_or_default()))
            .collect(),
    }
}

fn field_suffix(field: CookieField) -> &'static str {
    match field {
        CookieField::Name => "name",
        CookieField::Value => "value",
        CookieField::Attribute => "attribute",
    }
}

// ---- 证据脱敏 ----

static SENSITIVE_ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(["']?(?:authorization|proxy-authorization|cookie|set-cookie|password|passwd|pwd|secret|token|api[_-]?key|x-api-key|auth[_-]?token|x-auth-token|access[_-]?token|x-access-token|refresh[_-]?token|client[_-]?secret|session(?:[_-]?id)?)["']?\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^,;&\s}\r\n]+)"#,
    )
    .expect("static sensitive assignment regex")
});

static JWT_IN_TEXT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}(?:\.[A-Za-z0-9_-]*)?")
        .expect("static JWT redaction regex")
});

/// 证据片段脱敏：先套用全局秘密过滤，再抹掉 JWT 与 `键=值` 形态的凭据，
/// 最后压成单行并按字符数截断。命中证据永远不携带原始秘密。
pub fn redact_evidence(raw: &str) -> String {
    let redacted = crate::secrets::redact_sensitive(raw, &[]);
    let redacted = JWT_IN_TEXT.replace_all(&redacted, "[REDACTED:jwt]");
    let redacted = SENSITIVE_ASSIGNMENT.replace_all(&redacted, "${1}[REDACTED]");
    let single_line = redacted
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>();
    truncate_chars(single_line.trim(), MAX_EVIDENCE_SNIPPET_CHARS)
}

pub fn truncate_chars(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_string();
    }
    let mut truncated: String = text.chars().take(limit.saturating_sub(1)).collect();
    truncated.push('…');
    truncated
}

fn floor_char_boundary(text: &str, index: usize) -> usize {
    let mut index = index.min(text.len());
    while index > 0 && !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn ceil_char_boundary(text: &str, index: usize) -> usize {
    let mut index = index.min(text.len());
    while index < text.len() && !text.is_char_boundary(index) {
        index += 1;
    }
    index
}

/// 命中位置周边的上下文窗口，避免把整段正文当证据。
pub fn evidence_window(text: &str, start: usize, end: usize) -> String {
    const CONTEXT_BYTES: usize = 48;
    let from = floor_char_boundary(text, start.saturating_sub(CONTEXT_BYTES));
    let to = ceil_char_boundary(text, end.saturating_add(CONTEXT_BYTES));
    let mut snippet = String::new();
    if from > 0 {
        snippet.push('…');
    }
    snippet.push_str(&text[from..to]);
    if to < text.len() {
        snippet.push('…');
    }
    snippet
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_cookie_is_split_into_name_value_and_attributes() {
        let cookie = parse_set_cookie("session=abc123; Path=/; Secure; HttpOnly");
        assert_eq!(cookie.name, "session");
        assert_eq!(cookie.value, "abc123");
        assert!(cookie.has_attribute("httponly"));
        assert!(cookie.has_attribute("SECURE"));
        assert_eq!(cookie.attribute_value("path"), Some("/"));
        assert!(!cookie.has_attribute("samesite"));
    }

    #[test]
    fn cookie_evidence_never_contains_the_value() {
        let cookie = parse_set_cookie("session=super-secret-value; Path=/; Secure");
        let evidence = cookie.redacted();
        assert!(!evidence.contains("super-secret-value"));
        assert_eq!(evidence, "session=[REDACTED]; path=[REDACTED]; secure");
    }

    #[test]
    fn attribute_named_secure_is_not_matched_by_substring() {
        // 老实现用 `(?i)secure` 扫全文，Cookie 值里出现 secure 就误判有 Secure 属性
        let cookie = parse_set_cookie("token=this-is-secure-looking; Path=/");
        assert!(!cookie.has_attribute("secure"));
    }

    #[test]
    fn query_and_form_are_percent_decoded() {
        let query = parse_query("https://t.cn/a?token=x%20y&next=/home");
        assert_eq!(query[0], ("token".into(), "x y".into()));
        assert_eq!(query[1], ("next".into(), "/home".into()));

        let form = parse_form("user=alice&password=hunter%202");
        assert_eq!(form[1], ("password".into(), "hunter 2".into()));
    }

    #[test]
    fn query_falls_back_when_url_is_not_absolute() {
        let query = parse_query("/api/list?page=2#frag");
        assert_eq!(query, vec![("page".to_string(), "2".to_string())]);
    }

    #[test]
    fn json_path_subset_rejects_recursion_wildcard_and_filters() {
        assert!(parse_json_path("$..name").is_err());
        assert!(parse_json_path("$.items[*]").is_err());
        assert!(parse_json_path("$.items[?(@.id==1)]").is_err());
        assert!(parse_json_path("items.name").is_err());
        assert!(parse_json_path("$.a.b.c.d.e.f.g.h.i.j.k.l.m").is_err());
    }

    #[test]
    fn json_path_reads_nested_objects_and_array_indexes() {
        let root: Value =
            serde_json::from_str(r#"{"data":{"users":[{"role":"admin"},{"role":"guest"}]}}"#)
                .unwrap();
        let segments = parse_json_path("$.data.users[1].role").unwrap();
        assert_eq!(
            json_path_lookup(&root, &segments).map(json_scalar),
            Some("guest".to_string())
        );
        let missing = parse_json_path("$.data.users[9].role").unwrap();
        assert!(json_path_lookup(&root, &missing).is_none());
    }

    #[test]
    fn jwt_metadata_decodes_header_and_payload_without_verifying_signature() {
        // {"alg":"none","typ":"JWT","kid":"k1"} / {"iss":"acme","aud":["a","b"],"exp":123}
        let token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIiwia2lkIjoiazEifQ.eyJpc3MiOiJhY21lIiwiYXVkIjpbImEiLCJiIl0sImV4cCI6MTIzfQ.";
        assert_eq!(
            jwt_metadata(token, JwtMetadataField::Alg),
            Some("none".into())
        );
        assert_eq!(
            jwt_metadata(token, JwtMetadataField::Kid),
            Some("k1".into())
        );
        assert_eq!(
            jwt_metadata(token, JwtMetadataField::Aud),
            Some("a,b".into())
        );
        assert_eq!(
            jwt_metadata(token, JwtMetadataField::Exp),
            Some("123".into())
        );
        assert_eq!(jwt_metadata(token, JwtMetadataField::Nbf), None);
        assert_eq!(jwt_metadata("not-a-token", JwtMetadataField::Alg), None);
    }

    #[test]
    fn headers_json_supports_single_and_repeated_values() {
        let headers = parse_headers(r#"{"Set-Cookie":["a=1","b=2"],"Server":"nginx/1.2"}"#);
        let cookies = headers
            .iter()
            .find(|(name, _)| name == "set-cookie")
            .unwrap();
        assert_eq!(cookies.1, vec!["a=1".to_string(), "b=2".to_string()]);
        assert!(headers.iter().any(|(name, _)| name == "server"));
        assert!(parse_headers("not json").is_empty());
    }

    #[test]
    fn header_values_and_cookie_attributes_share_hard_candidate_limits() {
        let values: Vec<Value> = (0..=MAX_CANDIDATES_PER_SELECTOR)
            .map(|index| Value::String(format!("v{index}")))
            .collect();
        let headers = parse_headers(
            &serde_json::json!({
                "x-a": values,
                "x-b": ["must-not-expand"]
            })
            .to_string(),
        );
        assert_eq!(
            headers
                .iter()
                .map(|(_, values)| values.len())
                .sum::<usize>(),
            MAX_CANDIDATES_PER_SELECTOR
        );

        let raw_cookie = std::iter::once("sid=value".to_string())
            .chain(
                (0..=MAX_CANDIDATES_PER_SELECTOR).map(|index| format!("attribute-{index}=value")),
            )
            .collect::<Vec<_>>()
            .join("; ");
        assert_eq!(
            parse_set_cookie(&raw_cookie).attributes.len(),
            MAX_CANDIDATES_PER_SELECTOR
        );
    }

    #[test]
    fn evidence_redaction_hides_credentials_and_bounds_length() {
        let evidence = redact_evidence(
            r#"authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature-value"#,
        );
        assert!(!evidence.contains("eyJhbGciOiJIUzI1NiJ9"));
        assert!(evidence.contains("[REDACTED"));

        let long = "a".repeat(1000);
        assert!(redact_evidence(&long).chars().count() <= MAX_EVIDENCE_SNIPPET_CHARS);
    }

    #[test]
    fn evidence_window_is_char_boundary_safe() {
        let text = format!("{}错误信息{}", "x".repeat(300), "y".repeat(300));
        let start = text.find("错误").unwrap();
        let window = evidence_window(&text, start, start + "错误信息".len());
        assert!(window.contains("错误信息"));
        assert!(window.starts_with('…'));
        assert!(window.ends_with('…'));
    }
}
