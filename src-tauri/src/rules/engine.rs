//! Declarative passive-rule evaluator.
//!
//! Evaluation is local and read-only. Regexes are compiled under loader limits,
//! candidate expansion is bounded by the extractors, and the whole pack has a
//! wall-clock budget. A disabled pack produces diagnostics and zero hits.

use super::builtin::{LegacyRule, LegacyTarget};
use super::extractors::{
    cookie_candidates, evidence_window, json_path_lookup, json_scalar, jwt_metadata,
    parse_cookie_header, parse_form, parse_headers, parse_query, parse_set_cookie, query_scalar,
    redact_evidence, ParsedCookie, QueryFieldLike,
};
use super::fingerprint::fingerprint_for_url;
use super::loader::{
    CompiledCondition, CompiledExtractor, CompiledPack, CompiledRule, CompiledSelector, PackStatus,
};
use super::schema::{
    CookieField, Target, MAX_CANDIDATES_PER_SELECTOR, MAX_EVALUATION_MILLIS,
    TRUNCATED_HIT_MAX_CONFIDENCE,
};
use crate::ai::redaction::{redact_url, RedactionManifest};
use std::ops::Range;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

pub use super::schema::Severity;

#[derive(Debug)]
pub struct TrafficView<'a> {
    pub method: &'a str,
    pub url: &'a str,
    pub req_headers: &'a str,
    pub resp_headers: Option<&'a str>,
    pub req_body: &'a [u8],
    pub resp_body: Option<&'a [u8]>,
    pub status: Option<u16>,
    pub content_type: Option<&'a str>,
    pub req_truncated: bool,
    pub resp_truncated: bool,
    pub req_decode_status: &'a str,
    pub resp_decode_status: &'a str,
}

#[derive(Debug, Clone, Copy)]
pub struct EvaluationLimits {
    pub max_duration: Duration,
}

impl Default for EvaluationLimits {
    fn default() -> Self {
        Self {
            max_duration: Duration::from_millis(MAX_EVALUATION_MILLIS),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationDiagnostic {
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug)]
pub struct RuleHit<'a> {
    pub rule: &'a CompiledRule,
    pub field_path: String,
    pub evidence: String,
    pub incomplete_evidence: bool,
    pub confidence: u8,
    pub fingerprint: String,
}

#[derive(Debug, Default)]
pub struct EvaluationReport<'a> {
    pub hits: Vec<RuleHit<'a>>,
    pub diagnostics: Vec<EvaluationDiagnostic>,
    pub timed_out: bool,
}

#[derive(Debug, Clone)]
struct Candidate {
    field_path: String,
    value: String,
    safe_evidence: Option<String>,
    incomplete: bool,
}

#[derive(Debug, Clone)]
struct ScopedCookie {
    target: Target,
    index: usize,
    cookie: ParsedCookie,
}

struct Budget {
    started: Instant,
    max_duration: Duration,
}

impl Budget {
    fn new(limits: EvaluationLimits) -> Self {
        Self {
            started: Instant::now(),
            max_duration: limits.max_duration,
        }
    }

    fn checkpoint(&self) -> Result<(), ()> {
        (self.started.elapsed() < self.max_duration)
            .then_some(())
            .ok_or(())
    }
}

#[derive(Debug)]
struct ConditionMatch {
    field_path: String,
    evidence: String,
    incomplete: bool,
}

fn body_text<'a>(body: &'a [u8], decode_status: &str) -> Option<std::borrow::Cow<'a, str>> {
    matches!(decode_status, "empty" | "identity_text" | "decoded_text")
        .then(|| String::from_utf8_lossy(body))
}

fn header_source<'a>(view: &'a TrafficView<'a>, target: Target) -> Option<&'a str> {
    match target {
        Target::RequestHeader | Target::RequestCookie => Some(view.req_headers),
        Target::ResponseHeader | Target::ResponseCookie => view.resp_headers,
        _ => None,
    }
}

fn cookie_instances(view: &TrafficView<'_>, target: Target) -> Vec<ScopedCookie> {
    let header_name = match target {
        Target::RequestCookie => "cookie",
        Target::ResponseCookie => "set-cookie",
        _ => return Vec::new(),
    };
    let Some(headers) = header_source(view, target) else {
        return Vec::new();
    };
    let values = parse_headers(headers)
        .into_iter()
        .filter(|(name, _)| name == header_name)
        .flat_map(|(_, values)| values);
    let mut cookies = Vec::new();
    for raw in values {
        match target {
            Target::RequestCookie => {
                for cookie in parse_cookie_header(&raw) {
                    if cookies.len() == MAX_CANDIDATES_PER_SELECTOR {
                        return cookies;
                    }
                    cookies.push(ScopedCookie {
                        target,
                        index: cookies.len(),
                        cookie,
                    });
                }
            }
            Target::ResponseCookie => {
                if cookies.len() == MAX_CANDIDATES_PER_SELECTOR {
                    return cookies;
                }
                cookies.push(ScopedCookie {
                    target,
                    index: cookies.len(),
                    cookie: parse_set_cookie(&raw),
                });
            }
            _ => {}
        }
    }
    cookies
}

fn cookie_base_path(target: Target, index: usize) -> String {
    match target {
        Target::RequestCookie => format!("request.cookie.cookie[{index}]"),
        Target::ResponseCookie => format!("response.cookie.set-cookie[{index}]"),
        _ => format!("{}.instance[{index}]", target.path_prefix()),
    }
}

fn redacted_url(raw: &str) -> String {
    let mut manifest = RedactionManifest::default();
    redact_url(raw, true, &mut manifest)
}

fn cookie_raw(cookie: &ParsedCookie) -> String {
    let mut value = format!("{}={}", cookie.name, cookie.value);
    for (attribute, attribute_value) in &cookie.attributes {
        value.push_str("; ");
        value.push_str(attribute);
        if let Some(attribute_value) = attribute_value {
            value.push('=');
            value.push_str(attribute_value);
        }
    }
    value
}

fn selector_missing_path(selector: &CompiledSelector, scope: Option<&ScopedCookie>) -> String {
    if let Some(scope) = scope.filter(|scope| scope.target == selector.target) {
        let base = cookie_base_path(scope.target, scope.index);
        return match &selector.extractor {
            CompiledExtractor::Cookie {
                field: CookieField::Attribute,
                attribute,
            } => format!("{base}.attribute.{}", attribute.as_deref().unwrap_or("*")),
            CompiledExtractor::Cookie { field, .. } => {
                format!("{base}.{}", cookie_field_name(*field))
            }
            _ => base,
        };
    }
    let base = selector.target.path_prefix();
    let named = selector
        .name
        .as_deref()
        .map(|name| format!(".{name}"))
        .unwrap_or_default();
    match &selector.extractor {
        CompiledExtractor::JsonPath { path, .. } => format!("{base}.json{path}"),
        CompiledExtractor::Cookie {
            field: CookieField::Attribute,
            attribute,
        } => format!(
            "{base}{named}.attribute.{}",
            attribute.as_deref().unwrap_or("*")
        ),
        _ => format!("{base}{named}"),
    }
}

fn cookie_field_name(field: CookieField) -> &'static str {
    match field {
        CookieField::Name => "name",
        CookieField::Value => "value",
        CookieField::Attribute => "attribute",
    }
}

fn scalar_candidate(
    field_path: impl Into<String>,
    value: impl Into<String>,
    safe_evidence: Option<String>,
    incomplete: bool,
) -> Candidate {
    Candidate {
        field_path: field_path.into(),
        value: value.into(),
        safe_evidence,
        incomplete,
    }
}

fn body_source<'a>(
    view: &'a TrafficView<'a>,
    target: Target,
) -> (Option<std::borrow::Cow<'a, str>>, bool, &'static str) {
    match target {
        Target::RequestBody => (
            body_text(view.req_body, view.req_decode_status),
            view.req_truncated,
            "request.body",
        ),
        Target::ResponseBody => (
            view.resp_body
                .and_then(|body| body_text(body, view.resp_decode_status)),
            view.resp_truncated,
            "response.body",
        ),
        _ => (None, false, "unsupported.body"),
    }
}

fn candidates_for_cookie(
    selector: &CompiledSelector,
    cookie_scope: &ScopedCookie,
) -> Vec<Candidate> {
    let cookie = &cookie_scope.cookie;
    if selector
        .name
        .as_deref()
        .is_some_and(|name| name != cookie.name)
    {
        return Vec::new();
    }
    let base = cookie_base_path(cookie_scope.target, cookie_scope.index);
    let safe = Some(cookie.redacted());
    match &selector.extractor {
        CompiledExtractor::Text => vec![scalar_candidate(base, cookie_raw(cookie), safe, false)],
        CompiledExtractor::Cookie { field, attribute } => {
            cookie_candidates(cookie, *field, attribute.as_deref())
                .into_iter()
                .map(|(suffix, value)| {
                    scalar_candidate(format!("{base}.{suffix}"), value, safe.clone(), false)
                })
                .collect()
        }
        CompiledExtractor::JwtMetadata(field) => jwt_metadata(&cookie.value, *field)
            .map(|value| {
                scalar_candidate(
                    format!("{base}.jwt.{field:?}").to_ascii_lowercase(),
                    value.clone(),
                    Some(format!("JWT {field:?}={value}")),
                    false,
                )
            })
            .into_iter()
            .collect(),
        _ => Vec::new(),
    }
}

fn candidates_for_selector(
    selector: &CompiledSelector,
    view: &TrafficView<'_>,
    scope: Option<&ScopedCookie>,
) -> Vec<Candidate> {
    if selector.target.is_cookie() {
        if let Some(scope) = scope.filter(|scope| scope.target == selector.target) {
            return candidates_for_cookie(selector, scope);
        }
        return cookie_instances(view, selector.target)
            .iter()
            .flat_map(|cookie| candidates_for_cookie(selector, cookie))
            .take(MAX_CANDIDATES_PER_SELECTOR)
            .collect();
    }

    match selector.target {
        Target::Method => vec![scalar_candidate(
            "request.method",
            view.method,
            Some(view.method.to_string()),
            false,
        )],
        Target::Url => vec![scalar_candidate(
            "request.url",
            view.url,
            Some(redacted_url(view.url)),
            false,
        )],
        Target::Query => parse_query(view.url)
            .into_iter()
            .enumerate()
            .filter(|(_, (name, _))| selector.name.as_deref().is_none_or(|wanted| wanted == name))
            .filter_map(|(index, (name, value))| {
                let (scalar, suffix) = match selector.extractor {
                    CompiledExtractor::Text => (format!("{name}={value}"), "pair"),
                    CompiledExtractor::Query(field) => (
                        query_scalar(field.into(), &name, &value),
                        query_field_name(field.into()),
                    ),
                    CompiledExtractor::JwtMetadata(field) => {
                        return jwt_metadata(&value, field).map(|metadata| {
                            scalar_candidate(
                                format!("request.query.{name}[{index}].jwt.{field:?}")
                                    .to_ascii_lowercase(),
                                metadata.clone(),
                                Some(format!("query {name}=[REDACTED]; JWT {field:?}={metadata}")),
                                false,
                            )
                        });
                    }
                    _ => return None,
                };
                Some(scalar_candidate(
                    format!("request.query.{name}[{index}].{suffix}"),
                    scalar,
                    Some(format!("{name}=[REDACTED]")),
                    false,
                ))
            })
            .collect(),
        Target::RequestHeader | Target::ResponseHeader => {
            let Some(headers) = header_source(view, selector.target) else {
                return Vec::new();
            };
            let prefix = selector.target.path_prefix();
            parse_headers(headers)
                .into_iter()
                .filter(|(name, _)| selector.name.as_deref().is_none_or(|wanted| wanted == name))
                .flat_map(|(name, values)| {
                    values
                        .into_iter()
                        .enumerate()
                        .filter_map(move |(index, value)| match selector.extractor {
                            CompiledExtractor::Text => Some(scalar_candidate(
                                format!("{prefix}.{name}[{index}]"),
                                value.clone(),
                                Some(redact_evidence(&format!("{name}: {value}"))),
                                false,
                            )),
                            CompiledExtractor::JwtMetadata(field) => jwt_metadata(&value, field)
                                .map(|metadata| {
                                    scalar_candidate(
                                        format!("{prefix}.{name}[{index}].jwt.{field:?}")
                                            .to_ascii_lowercase(),
                                        metadata.clone(),
                                        Some(format!("JWT {field:?}={metadata}")),
                                        false,
                                    )
                                }),
                            _ => None,
                        })
                })
                .collect()
        }
        Target::RequestBody | Target::ResponseBody => {
            let (body, capture_incomplete, base) = body_source(view, selector.target);
            let Some(body) = body.filter(|body| !body.is_empty()) else {
                return Vec::new();
            };
            match &selector.extractor {
                CompiledExtractor::Text => vec![scalar_candidate(
                    base,
                    body.to_string(),
                    None,
                    capture_incomplete,
                )],
                CompiledExtractor::Form(field) => parse_form(&body)
                    .into_iter()
                    .enumerate()
                    .filter(|(_, (name, _))| {
                        selector.name.as_deref().is_none_or(|wanted| wanted == name)
                    })
                    .map(|(index, (name, value))| {
                        scalar_candidate(
                            format!(
                                "{base}.form.{name}[{index}].{}",
                                query_field_name((*field).into())
                            ),
                            query_scalar((*field).into(), &name, &value),
                            Some(format!("{name}=[REDACTED]")),
                            capture_incomplete,
                        )
                    })
                    .collect(),
                CompiledExtractor::JsonPath { path, segments } => {
                    let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) else {
                        return Vec::new();
                    };
                    json_path_lookup(&json, segments)
                        .map(|value| {
                            let value = json_scalar(value);
                            let last_name = path
                                .rsplit(['.', '['])
                                .next()
                                .unwrap_or_default()
                                .trim_end_matches(']');
                            let evidence =
                                if crate::ai::redaction::is_sensitive_field_name(last_name) {
                                    format!("{path}=[REDACTED]")
                                } else {
                                    redact_evidence(&format!("{path}={value}"))
                                };
                            scalar_candidate(
                                format!("{base}.json{path}"),
                                value,
                                Some(evidence),
                                capture_incomplete,
                            )
                        })
                        .into_iter()
                        .collect()
                }
                CompiledExtractor::JwtMetadata(field) => jwt_metadata(&body, *field)
                    .map(|value| {
                        scalar_candidate(
                            format!("{base}.jwt.{field:?}").to_ascii_lowercase(),
                            value.clone(),
                            Some(format!("JWT {field:?}={value}")),
                            capture_incomplete,
                        )
                    })
                    .into_iter()
                    .collect(),
                _ => Vec::new(),
            }
        }
        Target::Status => view
            .status
            .map(|status| {
                scalar_candidate(
                    "response.status",
                    status.to_string(),
                    Some(status.to_string()),
                    false,
                )
            })
            .into_iter()
            .collect(),
        Target::ContentType => view
            .content_type
            .map(|content_type| {
                scalar_candidate(
                    "response.content_type",
                    content_type,
                    Some(content_type.to_string()),
                    false,
                )
            })
            .into_iter()
            .collect(),
        Target::RequestCookie | Target::ResponseCookie => unreachable!("handled above"),
    }
}

fn query_field_name(field: QueryFieldLike) -> &'static str {
    match field {
        QueryFieldLike::Name => "name",
        QueryFieldLike::Value => "value",
        QueryFieldLike::Pair => "pair",
    }
}

fn candidate_evidence(candidate: &Candidate, range: Option<Range<usize>>) -> String {
    if let Some(safe) = &candidate.safe_evidence {
        return redact_evidence(safe);
    }
    let raw = range.map_or_else(
        || candidate.value.clone(),
        |range| evidence_window(&candidate.value, range.start, range.end),
    );
    redact_evidence(&raw)
}

fn matched_candidate(candidate: &Candidate, range: Option<Range<usize>>) -> ConditionMatch {
    ConditionMatch {
        field_path: candidate.field_path.clone(),
        evidence: candidate_evidence(candidate, range),
        incomplete: candidate.incomplete,
    }
}

fn condition_selector(condition: &CompiledCondition) -> Option<&CompiledSelector> {
    match condition {
        CompiledCondition::Equals { selector, .. }
        | CompiledCondition::Contains { selector, .. }
        | CompiledCondition::Regex { selector, .. }
        | CompiledCondition::Exists { selector }
        | CompiledCondition::Missing { selector }
        | CompiledCondition::Numeric { selector, .. } => Some(selector),
        CompiledCondition::All(conditions) | CompiledCondition::Any(conditions) => {
            conditions.iter().find_map(condition_selector)
        }
        CompiledCondition::Not(condition) | CompiledCondition::ForEach { condition, .. } => {
            condition_selector(condition)
        }
    }
}

fn missing_match(
    selector: &CompiledSelector,
    scope: Option<&ScopedCookie>,
    view: &TrafficView<'_>,
) -> ConditionMatch {
    let field_path = selector_missing_path(selector, scope);
    let incomplete = match selector.target {
        Target::RequestBody => view.req_truncated,
        Target::ResponseBody => view.resp_truncated,
        _ => false,
    };
    let evidence = scope
        .map(|scope| scope.cookie.redacted())
        .unwrap_or_else(|| {
            if incomplete {
                format!("{field_path}：捕获正文已截断，未观察到该字段")
            } else {
                format!("{field_path}：字段不存在")
            }
        });
    ConditionMatch {
        field_path,
        evidence: redact_evidence(&evidence),
        incomplete,
    }
}

fn ascii_find(haystack: &str, needle: &str, case_sensitive: bool) -> Option<Range<usize>> {
    if case_sensitive {
        return haystack
            .find(needle)
            .map(|start| start..start.saturating_add(needle.len()));
    }
    let haystack = haystack.to_ascii_lowercase();
    let needle = needle.to_ascii_lowercase();
    haystack
        .find(&needle)
        .map(|start| start..start.saturating_add(needle.len()))
}

fn evaluate_condition(
    condition: &CompiledCondition,
    view: &TrafficView<'_>,
    scope: Option<&ScopedCookie>,
    budget: &Budget,
) -> Result<Option<ConditionMatch>, ()> {
    budget.checkpoint()?;
    match condition {
        CompiledCondition::Equals {
            selector,
            value,
            case_sensitive,
        } => {
            for candidate in candidates_for_selector(selector, view, scope) {
                budget.checkpoint()?;
                let actual = candidate.value.trim();
                let expected = value.trim();
                let matched = if *case_sensitive {
                    actual == expected
                } else {
                    actual.eq_ignore_ascii_case(expected)
                };
                if matched {
                    return Ok(Some(matched_candidate(
                        &candidate,
                        Some(0..candidate.value.len()),
                    )));
                }
            }
            Ok(None)
        }
        CompiledCondition::Contains {
            selector,
            value,
            case_sensitive,
        } => {
            for candidate in candidates_for_selector(selector, view, scope) {
                budget.checkpoint()?;
                if let Some(range) = ascii_find(&candidate.value, value, *case_sensitive) {
                    return Ok(Some(matched_candidate(&candidate, Some(range))));
                }
            }
            Ok(None)
        }
        CompiledCondition::Regex { selector, pattern } => {
            for candidate in candidates_for_selector(selector, view, scope) {
                budget.checkpoint()?;
                if let Some(matched) = pattern.find(&candidate.value) {
                    return Ok(Some(matched_candidate(&candidate, Some(matched.range()))));
                }
                budget.checkpoint()?;
            }
            Ok(None)
        }
        CompiledCondition::Exists { selector } => {
            let candidates = candidates_for_selector(selector, view, scope);
            Ok(candidates
                .first()
                .map(|candidate| matched_candidate(candidate, None)))
        }
        CompiledCondition::Missing { selector } => {
            let candidates = candidates_for_selector(selector, view, scope);
            Ok(candidates
                .is_empty()
                .then(|| missing_match(selector, scope, view)))
        }
        CompiledCondition::Numeric {
            selector,
            comparison,
            value,
        } => {
            for candidate in candidates_for_selector(selector, view, scope) {
                budget.checkpoint()?;
                if candidate
                    .value
                    .trim()
                    .parse::<f64>()
                    .ok()
                    .is_some_and(|actual| comparison.matches(actual, *value))
                {
                    return Ok(Some(matched_candidate(&candidate, None)));
                }
            }
            Ok(None)
        }
        CompiledCondition::All(conditions) => {
            let mut first = None;
            let mut incomplete = false;
            for condition in conditions {
                let Some(matched) = evaluate_condition(condition, view, scope, budget)? else {
                    return Ok(None);
                };
                incomplete |= matched.incomplete;
                if first.is_none() {
                    first = Some(matched);
                }
            }
            if let Some(first) = &mut first {
                first.incomplete |= incomplete;
            }
            Ok(first)
        }
        CompiledCondition::Any(conditions) => {
            for condition in conditions {
                if let Some(matched) = evaluate_condition(condition, view, scope, budget)? {
                    return Ok(Some(matched));
                }
            }
            Ok(None)
        }
        CompiledCondition::Not(condition) => {
            if evaluate_condition(condition, view, scope, budget)?.is_some() {
                return Ok(None);
            }
            let Some(selector) = condition_selector(condition) else {
                return Ok(Some(ConditionMatch {
                    field_path: "condition.not".to_string(),
                    evidence: "否定条件成立".to_string(),
                    incomplete: false,
                }));
            };
            Ok(Some(missing_match(selector, scope, view)))
        }
        CompiledCondition::ForEach {
            target,
            name,
            condition,
        } => {
            for instance in cookie_instances(view, *target)
                .into_iter()
                .filter(|instance| {
                    name.as_deref()
                        .is_none_or(|name| name == instance.cookie.name)
                })
            {
                budget.checkpoint()?;
                if let Some(matched) = evaluate_condition(condition, view, Some(&instance), budget)?
                {
                    return Ok(Some(matched));
                }
            }
            Ok(None)
        }
    }
}

/// 一条规则在一条流量上的全部命中。
///
/// 顶层 `for_each` 会为每个满足条件的实例各产出一条命中：三条 Set-Cookie 里
/// 有两条缺 HttpOnly 就是两条命中，字段路径与指纹互不相同，UI 能逐条定位，
/// Task 3.3 也能按指纹独立去重。其它算子最多一条命中。
fn evaluate_rule_matches(
    rule: &CompiledRule,
    view: &TrafficView<'_>,
    budget: &Budget,
) -> Result<Vec<ConditionMatch>, ()> {
    let CompiledCondition::ForEach {
        target,
        name,
        condition,
    } = &rule.condition
    else {
        return Ok(evaluate_condition(&rule.condition, view, None, budget)?
            .into_iter()
            .collect());
    };
    let mut matches = Vec::new();
    for instance in cookie_instances(view, *target)
        .into_iter()
        .filter(|instance| {
            name.as_deref()
                .is_none_or(|name| name == instance.cookie.name)
        })
    {
        budget.checkpoint()?;
        if let Some(matched) = evaluate_condition(condition, view, Some(&instance), budget)? {
            matches.push(matched);
        }
    }
    Ok(matches)
}

pub fn evaluate_pack_with_limits<'a>(
    pack: &'a CompiledPack,
    view: &TrafficView<'_>,
    limits: EvaluationLimits,
) -> EvaluationReport<'a> {
    let mut report = EvaluationReport::default();
    let budget = Budget::new(limits);
    for rule in &pack.rules {
        let matches = match evaluate_rule_matches(rule, view, &budget) {
            Ok(matches) => matches,
            Err(()) => {
                report.timed_out = true;
                report.diagnostics.push(EvaluationDiagnostic {
                    code: "evaluation_timeout",
                    message: format!(
                        "规则包 {}@{} 达到 {:?} 执行上限，已停止于规则 {}@{}",
                        pack.pack_id, pack.version, limits.max_duration, rule.rule_id, rule.version
                    ),
                });
                break;
            }
        };
        for matched in matches {
            let confidence = if matched.incomplete {
                rule.confidence.min(TRUNCATED_HIT_MAX_CONFIDENCE)
            } else {
                rule.confidence
            };
            report.hits.push(RuleHit {
                fingerprint: fingerprint_for_url(
                    &rule.rule_id,
                    &rule.version,
                    view.method,
                    view.url,
                    &matched.field_path,
                ),
                rule,
                field_path: matched.field_path,
                evidence: matched.evidence,
                incomplete_evidence: matched.incomplete,
                confidence,
            });
        }
    }
    report
}

pub fn evaluate_pack<'a>(pack: &'a CompiledPack, view: &TrafficView<'_>) -> EvaluationReport<'a> {
    evaluate_pack_with_limits(pack, view, EvaluationLimits::default())
}

/// 对任意加载结果求值。被禁用的包只产出一条诊断和零条命中——调用方
/// （代理）照常写库、照常继续，不会因为规则包坏了而中断。
pub fn evaluate_status<'a>(status: &'a PackStatus, view: &TrafficView<'_>) -> EvaluationReport<'a> {
    match status {
        PackStatus::Loaded(pack) => evaluate_pack(pack, view),
        PackStatus::Disabled { pack_id, reason } => EvaluationReport {
            diagnostics: vec![EvaluationDiagnostic {
                code: "rule_pack_disabled",
                message: format!("规则包 `{pack_id}` 已禁用：{reason}"),
            }],
            ..EvaluationReport::default()
        },
    }
}

pub fn evaluate(view: &TrafficView<'_>) -> EvaluationReport<'static> {
    evaluate_status(super::loader::builtin_pack(), view)
}

// ---- 旧版正则实现：只留给 Task 3.3 做新旧影子对比 ----

/// 旧版（v1）命中结果。
pub struct LegacyRuleHit {
    pub rule: &'static LegacyRule,
    /// 命中的目标段（如 "resp_body"）
    pub location: &'static str,
    pub incomplete_evidence: bool,
}

static LEGACY_RULES: LazyLock<Vec<LegacyRule>> = LazyLock::new(super::builtin::legacy_rules);

/// 旧版"整段文本跑正则"的求值实现，语义上带已知缺陷：`must_absent` 作用于
/// 整个 Header JSON，任意一条合规 Cookie 都会掩盖其它 Cookie 的属性缺失。
/// 保留它只为让 Task 3.3 能用同一批输入做新旧对比，不要再用于生产判定。
pub fn legacy_evaluate(view: &TrafficView<'_>) -> Vec<LegacyRuleHit> {
    let req_body = body_text(view.req_body, view.req_decode_status);
    let resp_body = view
        .resp_body
        .and_then(|body| body_text(body, view.resp_decode_status));
    let empty = String::new();
    let req_body = req_body.as_deref().unwrap_or(&empty);
    let resp_body = resp_body.as_deref().unwrap_or(&empty);

    let mut hits = Vec::new();
    for rule in LEGACY_RULES.iter() {
        for &target in rule.targets {
            let (text, location, incomplete_evidence): (&str, &'static str, bool) = match target {
                LegacyTarget::Url => (view.url, "url", false),
                LegacyTarget::ReqHeaders => (view.req_headers, "req_headers", false),
                LegacyTarget::ReqBody => (req_body, "req_body", view.req_truncated),
                LegacyTarget::RespHeaders => {
                    (view.resp_headers.unwrap_or(""), "resp_headers", false)
                }
                LegacyTarget::RespBody => (resp_body, "resp_body", view.resp_truncated),
            };
            if text.is_empty() {
                continue;
            }
            if rule.pattern.is_match(text)
                && rule
                    .must_absent
                    .as_ref()
                    .is_none_or(|neg| !neg.is_match(text))
            {
                hits.push(LegacyRuleHit {
                    rule,
                    location,
                    incomplete_evidence,
                });
                break; // 同一规则命中一次即可
            }
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::loader::{builtin_pack, load_pack, load_pack_status};

    fn view<'a>(
        url: &'a str,
        req_headers: &'a str,
        req_body: &'a [u8],
        resp_headers: Option<&'a str>,
        resp_body: Option<&'a [u8]>,
    ) -> TrafficView<'a> {
        TrafficView {
            method: "GET",
            url,
            req_headers,
            resp_headers,
            req_body,
            resp_body,
            status: Some(200),
            content_type: Some("text/html"),
            req_truncated: false,
            resp_truncated: false,
            req_decode_status: "identity_text",
            resp_decode_status: "identity_text",
        }
    }

    fn hit<'a>(report: &'a EvaluationReport<'a>, id: &str) -> Option<&'a RuleHit<'a>> {
        report.hits.iter().find(|hit| hit.rule.rule_id == id)
    }

    #[test]
    fn multiple_set_cookie_values_are_evaluated_independently() {
        let view = view(
            "https://t.cn/login",
            "{}",
            b"",
            Some(r#"{"set-cookie":["safe=1; Secure; HttpOnly","unsafe=secret; Secure; Path=/"]}"#),
            None,
        );
        let report = evaluate(&view);
        let cookie_hit = hit(&report, "cookie-no-httponly").unwrap();
        assert!(cookie_hit.field_path.contains("set-cookie[1]"));
        assert!(!cookie_hit.evidence.contains("secret"));
        assert!(cookie_hit.evidence.contains("[REDACTED]"));
        assert!(hit(&report, "cookie-no-secure").is_none());
    }

    #[test]
    fn every_offending_cookie_gets_its_own_hit_and_fingerprint() {
        let view = view(
            "https://t.cn/login",
            "{}",
            b"",
            Some(r#"{"set-cookie":["a=1; Path=/","b=2; Path=/; HttpOnly","c=3; Path=/"]}"#),
            None,
        );
        let report = evaluate(&view);
        let hits: Vec<&RuleHit<'_>> = report
            .hits
            .iter()
            .filter(|hit| hit.rule.rule_id == "cookie-no-httponly")
            .collect();
        assert_eq!(hits.len(), 2);
        assert!(hits[0].field_path.contains("set-cookie[0]"));
        assert!(hits[1].field_path.contains("set-cookie[2]"));
        assert_ne!(hits[0].fingerprint, hits[1].fingerprint);
    }

    #[test]
    fn cookie_selector_candidate_expansion_has_one_global_limit() {
        let attributes = (0..200)
            .map(|index| format!("attribute-{index}=value"))
            .collect::<Vec<_>>()
            .join("; ");
        let response_headers = serde_json::json!({
            "set-cookie": [
                format!("a=1; {attributes}"),
                format!("b=2; {attributes}")
            ]
        })
        .to_string();
        let view = view(
            "https://t.cn/login",
            "{}",
            b"",
            Some(&response_headers),
            None,
        );
        let selector = CompiledSelector {
            target: Target::ResponseCookie,
            name: None,
            extractor: CompiledExtractor::Cookie {
                field: CookieField::Attribute,
                attribute: None,
            },
        };
        assert_eq!(
            candidates_for_selector(&selector, &view, None).len(),
            MAX_CANDIDATES_PER_SELECTOR
        );
    }

    #[test]
    fn per_cookie_evaluation_fixes_the_legacy_global_must_absent_bug() {
        let view = view(
            "https://t.cn/login",
            "{}",
            b"",
            Some(
                r#"{"set-cookie":["session=abc; Path=/; Secure","theme=dark; Path=/; Secure; HttpOnly"]}"#,
            ),
            None,
        );
        // 旧实现：theme 带了 HttpOnly，全局 must_absent 就认定整条响应没问题
        assert!(!legacy_evaluate(&view)
            .iter()
            .any(|hit| hit.rule.id == "cookie-no-httponly"));
        // 新实现：逐条判定，session 缺 HttpOnly 被单独识别出来
        let report = evaluate(&view);
        let hit = hit(&report, "cookie-no-httponly").unwrap();
        assert!(hit.field_path.contains("set-cookie[0]"));
        assert!(!hit.evidence.contains("abc"));
    }

    #[test]
    fn cookie_value_spelling_secure_is_not_mistaken_for_the_attribute() {
        let view = view(
            "https://t.cn/login",
            "{}",
            b"",
            Some(r#"{"set-cookie":"sid=very-secure-token; Path=/; HttpOnly"}"#),
            None,
        );
        // 旧实现对整段 Header JSON 跑 `(?i)secure`，Cookie 值里的 secure 会掩盖缺失
        assert!(!legacy_evaluate(&view)
            .iter()
            .any(|hit| hit.rule.id == "cookie-no-secure"));
        assert!(hit(&evaluate(&view), "cookie-no-secure").is_some());
    }

    #[test]
    fn truncated_body_hit_is_explicitly_low_confidence() {
        let mut view = view(
            "https://t.cn/item?id=1",
            "{}",
            b"",
            Some(r#"{"content-type":"text/plain"}"#),
            Some(b"You have an error in your SQL syntax"),
        );
        view.resp_truncated = true;
        let report = evaluate(&view);
        let hit = hit(&report, "sql-error-leak").unwrap();
        assert!(hit.incomplete_evidence);
        assert!(hit.confidence <= TRUNCATED_HIT_MAX_CONFIDENCE);
    }

    #[test]
    fn missing_on_truncated_body_is_never_treated_as_complete_evidence() {
        let raw = r#"{
          "schema_version":1,"pack_id":"truncated-missing","version":"1","source":"test",
          "description":"truncated missing","rules":[{
            "rule_id":"missing-json","version":"1","source":"test","name":"missing json",
            "description":"missing json","verify_hint":"verify","severity":"low","confidence":90,
            "tag":"missing-json","vuln_type":"missing-json",
            "references":[{"framework":"cwe","version":"4.20","id":"CWE-200"}],
            "condition":{"operator":"missing","selector":{
              "target":"response_body",
              "extractor":{"kind":"json_path","path":"$.secret"}
            }}
          }]}"#;
        let pack = load_pack("truncated-missing.json", raw).unwrap();
        let mut view = view(
            "https://t.cn/",
            "{}",
            b"",
            Some(r#"{"content-type":"application/json"}"#),
            Some(br#"{"sec"#),
        );
        view.resp_truncated = true;
        let report = evaluate_pack(&pack, &view);
        let hit = report.hits.first().unwrap();
        assert!(hit.incomplete_evidence);
        assert!(hit.evidence.contains("已截断"));
        assert_eq!(hit.confidence, TRUNCATED_HIT_MAX_CONFIDENCE);
    }

    #[test]
    fn disabled_pack_has_a_visible_reason_and_zero_hits() {
        let status = load_pack_status("broken.json", "{ nope");
        assert!(status.pack().is_none());
        assert!(status.disabled_reason().unwrap().contains("不是有效 JSON"));
    }

    #[test]
    fn zero_duration_budget_stops_before_regex_evaluation() {
        let PackStatus::Loaded(pack) = builtin_pack() else {
            panic!("builtin pack disabled")
        };
        let view = view("https://t.cn/", "{}", b"", None, None);
        let report = evaluate_pack_with_limits(
            pack,
            &view,
            EvaluationLimits {
                max_duration: Duration::ZERO,
            },
        );
        assert!(report.timed_out);
        assert!(report.hits.is_empty());
        assert_eq!(report.diagnostics[0].code, "evaluation_timeout");
    }

    #[test]
    fn logical_and_numeric_operators_share_the_same_bounded_evaluator() {
        let raw = r#"{
          "schema_version":1,"pack_id":"ops","version":"1","source":"test",
          "description":"operators","rules":[{
            "rule_id":"ops","version":"1","source":"test","name":"ops",
            "description":"ops","verify_hint":"ops","severity":"low","confidence":50,
            "tag":"ops","vuln_type":"ops",
            "references":[{"framework":"cwe","version":"4.20","id":"CWE-200"}],
            "condition":{"operator":"all","conditions":[
              {"operator":"greater_than","selector":{"target":"status"},"value":199},
              {"operator":"greater_or_equal","selector":{"target":"status"},"value":200},
              {"operator":"less_than","selector":{"target":"status"},"value":300},
              {"operator":"less_or_equal","selector":{"target":"status"},"value":200},
              {"operator":"contains","selector":{"target":"content_type"},"value":"html"},
              {"operator":"any","conditions":[
                {"operator":"equals","selector":{"target":"method"},"value":"POST"},
                {"operator":"equals","selector":{"target":"method"},"value":"GET"}
              ]},
              {"operator":"not","condition":{
                "operator":"exists","selector":{"target":"response_header","name":"x-missing"}
              }}
            ]}
          }]}"#;
        let pack = load_pack("operators.json", raw).unwrap();
        let view = view("https://t.cn/", "{}", b"", None, None);
        assert_eq!(evaluate_pack(&pack, &view).hits.len(), 1);
    }
}
