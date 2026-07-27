//! 规则包加载器：JSON → 校验 → 编译。
//!
//! 三条硬约束：
//! 1. 所有上限（规则数、正则长度/体积、条件深度）都在加载期检查，运行期不再冒险；
//! 2. 标准引用必须能在内置知识包里查到，否则规则不允许上线；
//! 3. 任何失败都只把这个包标成 `Disabled` 并带上原因，绝不 panic、绝不拖垮代理。

use crate::knowledge::{self, StandardReference};
use crate::rules::extractors::{self, JsonPathSegment};
use crate::rules::schema::{
    ConditionDefinition, CookieField, ExtractorDefinition, FormField, JwtMetadataField, QueryField,
    RuleDefinition, RulePackDefinition, SelectorDefinition, Severity, Target, MAX_CONDITION_DEPTH,
    MAX_REGEX_PATTERN_BYTES, MAX_RULES_PER_PACK, REGEX_DFA_SIZE_LIMIT_BYTES, REGEX_NEST_LIMIT,
    REGEX_SIZE_LIMIT_BYTES, RULE_SCHEMA_VERSION,
};
use crate::secrets::redact_sensitive;
use regex::{Regex, RegexBuilder};
use std::collections::HashSet;
use std::sync::LazyLock;

pub const BUILTIN_PACK_ID: &str = "builtin";
pub const BUILTIN_PACK_FILE: &str = "packs/builtin-v1.json";
pub const BUILTIN_PACK_JSON: &str = include_str!("packs/builtin-v1.json");

#[derive(Debug, thiserror::Error)]
pub enum RulePackError {
    #[error("规则包 `{pack}` 不是有效 JSON: {reason}")]
    InvalidJson { pack: String, reason: String },
    #[error("规则包 `{pack}` 校验失败: {reason}")]
    InvalidPack { pack: String, reason: String },
    #[error("规则包 `{pack}` 的规则 `{rule}` 校验失败: {reason}")]
    InvalidRule {
        pack: String,
        rule: String,
        reason: String,
    },
}

#[derive(Debug, Clone)]
pub enum CompiledExtractor {
    Text,
    Query(QueryField),
    Form(FormField),
    JsonPath {
        path: String,
        segments: Vec<JsonPathSegment>,
    },
    Cookie {
        field: CookieField,
        attribute: Option<String>,
    },
    JwtMetadata(JwtMetadataField),
}

#[derive(Debug, Clone)]
pub struct CompiledSelector {
    pub target: Target,
    /// Header 名已规范成小写；查询参数与 Cookie 名保持原样（大小写敏感）。
    pub name: Option<String>,
    pub extractor: CompiledExtractor,
}

#[derive(Debug, Clone)]
pub enum CompiledCondition {
    Equals {
        selector: CompiledSelector,
        value: String,
        case_sensitive: bool,
    },
    Contains {
        selector: CompiledSelector,
        value: String,
        case_sensitive: bool,
    },
    Regex {
        selector: CompiledSelector,
        pattern: Regex,
    },
    Exists {
        selector: CompiledSelector,
    },
    Missing {
        selector: CompiledSelector,
    },
    Numeric {
        selector: CompiledSelector,
        comparison: NumericComparison,
        value: f64,
    },
    All(Vec<CompiledCondition>),
    Any(Vec<CompiledCondition>),
    Not(Box<CompiledCondition>),
    ForEach {
        target: Target,
        name: Option<String>,
        condition: Box<CompiledCondition>,
    },
}

impl CompiledCondition {
    /// 结构上第一个选择器；否定命中（missing/not）没有正向证据时用它定位字段。
    pub fn primary_selector(&self) -> Option<&CompiledSelector> {
        match self {
            Self::Equals { selector, .. }
            | Self::Contains { selector, .. }
            | Self::Regex { selector, .. }
            | Self::Exists { selector }
            | Self::Missing { selector }
            | Self::Numeric { selector, .. } => Some(selector),
            Self::All(conditions) | Self::Any(conditions) => {
                conditions.iter().find_map(Self::primary_selector)
            }
            Self::Not(condition) | Self::ForEach { condition, .. } => condition.primary_selector(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumericComparison {
    GreaterThan,
    GreaterOrEqual,
    LessThan,
    LessOrEqual,
}

impl NumericComparison {
    pub fn matches(self, left: f64, right: f64) -> bool {
        match self {
            Self::GreaterThan => left > right,
            Self::GreaterOrEqual => left >= right,
            Self::LessThan => left < right,
            Self::LessOrEqual => left <= right,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub rule_id: String,
    pub version: String,
    pub source: String,
    pub name: String,
    pub description: String,
    pub verify_hint: String,
    pub severity: Severity,
    pub confidence: u8,
    pub tag: String,
    pub vuln_type: String,
    /// 已经过内置知识包校验并规范化的版本化标准引用。
    pub references: Vec<StandardReference>,
    pub condition: CompiledCondition,
}

#[derive(Debug, Clone)]
pub struct CompiledPack {
    pub pack_id: String,
    pub version: String,
    pub source: String,
    pub description: String,
    pub rules: Vec<CompiledRule>,
}

/// 加载结果。被禁用的包在求值时等价于"零条规则"，原因保留给 UI 与日志。
#[derive(Debug, Clone)]
pub enum PackStatus {
    Loaded(CompiledPack),
    Disabled { pack_id: String, reason: String },
}

impl PackStatus {
    pub fn pack(&self) -> Option<&CompiledPack> {
        match self {
            Self::Loaded(pack) => Some(pack),
            Self::Disabled { .. } => None,
        }
    }

    pub fn is_loaded(&self) -> bool {
        matches!(self, Self::Loaded(_))
    }

    pub fn disabled_reason(&self) -> Option<&str> {
        match self {
            Self::Loaded(_) => None,
            Self::Disabled { reason, .. } => Some(reason),
        }
    }

    pub fn pack_id(&self) -> &str {
        match self {
            Self::Loaded(pack) => &pack.pack_id,
            Self::Disabled { pack_id, .. } => pack_id,
        }
    }
}

/// 严格加载：任何问题都返回错误，交给调用方决定是禁用还是上报。
pub fn load_pack(name: &str, raw: &str) -> Result<CompiledPack, RulePackError> {
    let definition: RulePackDefinition =
        serde_json::from_str(raw).map_err(|error| RulePackError::InvalidJson {
            pack: name.to_string(),
            reason: error.to_string(),
        })?;
    compile_pack(name, definition)
}

/// 容错加载：失败不会传播，只把这个包禁用并附上原因。
pub fn load_pack_status(name: &str, raw: &str) -> PackStatus {
    match load_pack(name, raw) {
        Ok(pack) => PackStatus::Loaded(pack),
        Err(error) => PackStatus::Disabled {
            pack_id: pack_id_hint(name, raw),
            reason: redact_sensitive(&error.to_string(), &[]),
        },
    }
}

/// 加载失败时也要给出一个可展示的包标识，尽量从原始 JSON 里捞。
fn pack_id_hint(name: &str, raw: &str) -> String {
    serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|value| {
            value
                .get("pack_id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        })
        .filter(|pack_id| !pack_id.trim().is_empty())
        .unwrap_or_else(|| name.to_string())
}

fn compile_pack(name: &str, definition: RulePackDefinition) -> Result<CompiledPack, RulePackError> {
    let invalid = |reason: String| RulePackError::InvalidPack {
        pack: name.to_string(),
        reason,
    };
    if definition.schema_version != RULE_SCHEMA_VERSION {
        return Err(invalid(format!(
            "schema_version 应为 {RULE_SCHEMA_VERSION}，实际为 {}",
            definition.schema_version
        )));
    }
    for (value, field) in [
        (&definition.pack_id, "pack_id"),
        (&definition.version, "version"),
        (&definition.source, "source"),
        (&definition.description, "description"),
    ] {
        if value.trim().is_empty() {
            return Err(invalid(format!("`{field}` 不能为空")));
        }
    }
    if definition.rules.is_empty() {
        return Err(invalid("rules 不能为空".to_string()));
    }
    if definition.rules.len() > MAX_RULES_PER_PACK {
        return Err(invalid(format!(
            "规则数 {} 超过上限 {MAX_RULES_PER_PACK}",
            definition.rules.len()
        )));
    }

    let mut seen = HashSet::new();
    let mut rules = Vec::with_capacity(definition.rules.len());
    for rule in &definition.rules {
        if !seen.insert(rule.rule_id.as_str()) {
            return Err(invalid(format!("rule_id `{}` 重复", rule.rule_id)));
        }
        rules.push(
            compile_rule(rule).map_err(|reason| RulePackError::InvalidRule {
                pack: name.to_string(),
                rule: rule.rule_id.clone(),
                reason,
            })?,
        );
    }

    Ok(CompiledPack {
        pack_id: definition.pack_id,
        version: definition.version,
        source: definition.source,
        description: definition.description,
        rules,
    })
}

fn compile_rule(definition: &RuleDefinition) -> Result<CompiledRule, String> {
    for (value, field) in [
        (&definition.rule_id, "rule_id"),
        (&definition.version, "version"),
        (&definition.source, "source"),
        (&definition.name, "name"),
        (&definition.description, "description"),
        (&definition.verify_hint, "verify_hint"),
        (&definition.tag, "tag"),
        (&definition.vuln_type, "vuln_type"),
    ] {
        if value.trim().is_empty() {
            return Err(format!("`{field}` 不能为空"));
        }
    }
    if !(1..=100).contains(&definition.confidence) {
        return Err(format!(
            "confidence 必须落在 1..=100，实际为 {}",
            definition.confidence
        ));
    }
    if definition.references.is_empty() {
        return Err("references 不能为空——规则结论必须能追溯到版本化标准".to_string());
    }
    let references = knowledge::validate_references(&definition.references)?;

    let depth = definition.condition.depth();
    if depth > MAX_CONDITION_DEPTH {
        return Err(format!("条件树深度 {depth} 超过上限 {MAX_CONDITION_DEPTH}"));
    }
    let condition = compile_condition(&definition.condition)?;

    Ok(CompiledRule {
        rule_id: definition.rule_id.clone(),
        version: definition.version.clone(),
        source: definition.source.clone(),
        name: definition.name.clone(),
        description: definition.description.clone(),
        verify_hint: definition.verify_hint.clone(),
        severity: definition.severity,
        confidence: definition.confidence,
        tag: definition.tag.clone(),
        vuln_type: definition.vuln_type.clone(),
        references,
        condition,
    })
}

fn compile_condition(definition: &ConditionDefinition) -> Result<CompiledCondition, String> {
    Ok(match definition {
        ConditionDefinition::Equals {
            selector,
            value,
            case_sensitive,
        } => CompiledCondition::Equals {
            selector: compile_selector(selector)?,
            value: value.clone(),
            case_sensitive: *case_sensitive,
        },
        ConditionDefinition::Contains {
            selector,
            value,
            case_sensitive,
        } => {
            if value.is_empty() {
                return Err("contains 的 value 不能为空".to_string());
            }
            CompiledCondition::Contains {
                selector: compile_selector(selector)?,
                value: value.clone(),
                case_sensitive: *case_sensitive,
            }
        }
        ConditionDefinition::Regex { selector, pattern } => CompiledCondition::Regex {
            selector: compile_selector(selector)?,
            pattern: compile_regex(pattern)?,
        },
        ConditionDefinition::Exists { selector } => CompiledCondition::Exists {
            selector: compile_selector(selector)?,
        },
        ConditionDefinition::Missing { selector } => CompiledCondition::Missing {
            selector: compile_selector(selector)?,
        },
        ConditionDefinition::GreaterThan { selector, value } => CompiledCondition::Numeric {
            selector: compile_selector(selector)?,
            comparison: NumericComparison::GreaterThan,
            value: *value,
        },
        ConditionDefinition::GreaterOrEqual { selector, value } => CompiledCondition::Numeric {
            selector: compile_selector(selector)?,
            comparison: NumericComparison::GreaterOrEqual,
            value: *value,
        },
        ConditionDefinition::LessThan { selector, value } => CompiledCondition::Numeric {
            selector: compile_selector(selector)?,
            comparison: NumericComparison::LessThan,
            value: *value,
        },
        ConditionDefinition::LessOrEqual { selector, value } => CompiledCondition::Numeric {
            selector: compile_selector(selector)?,
            comparison: NumericComparison::LessOrEqual,
            value: *value,
        },
        ConditionDefinition::All { conditions } => {
            CompiledCondition::All(compile_children("all", conditions)?)
        }
        ConditionDefinition::Any { conditions } => {
            CompiledCondition::Any(compile_children("any", conditions)?)
        }
        ConditionDefinition::Not { condition } => {
            CompiledCondition::Not(Box::new(compile_condition(condition)?))
        }
        ConditionDefinition::ForEach {
            target,
            name,
            condition,
        } => {
            if !target.is_cookie() {
                return Err(
                    "首版 `for_each` 只允许逐项评价 request_cookie/response_cookie".to_string(),
                );
            }
            CompiledCondition::ForEach {
                target: *target,
                name: normalized_name(*target, name.as_deref()),
                condition: Box::new(compile_condition(condition)?),
            }
        }
    })
}

fn compile_children(
    operator: &str,
    conditions: &[ConditionDefinition],
) -> Result<Vec<CompiledCondition>, String> {
    if conditions.is_empty() {
        return Err(format!("`{operator}` 至少需要一个子条件"));
    }
    conditions.iter().map(compile_condition).collect()
}

fn normalized_name(target: Target, name: Option<&str>) -> Option<String> {
    name.map(str::trim)
        .filter(|name| !name.is_empty())
        .map(|name| {
            if target.is_header() {
                name.to_ascii_lowercase()
            } else {
                name.to_string()
            }
        })
}

fn compile_selector(selector: &SelectorDefinition) -> Result<CompiledSelector, String> {
    let target = selector.target;
    let extractor = match &selector.extractor {
        ExtractorDefinition::Text => CompiledExtractor::Text,
        ExtractorDefinition::Query { field } => {
            if target != Target::Query {
                return Err("`query` 提取器只能用于 `query` 目标".to_string());
            }
            CompiledExtractor::Query(*field)
        }
        ExtractorDefinition::Form { field } => {
            if !target.is_body() {
                return Err("`form` 提取器只能用于请求/响应正文".to_string());
            }
            CompiledExtractor::Form(*field)
        }
        ExtractorDefinition::JsonPath { path } => {
            if !target.is_body() {
                return Err("`json_path` 提取器只能用于请求/响应正文".to_string());
            }
            CompiledExtractor::JsonPath {
                path: path.clone(),
                segments: extractors::parse_json_path(path)?,
            }
        }
        ExtractorDefinition::Cookie { field, attribute } => {
            if !target.is_cookie() {
                return Err("`cookie` 提取器只能用于 cookie 目标".to_string());
            }
            if *field == CookieField::Attribute && target == Target::RequestCookie {
                return Err("请求 Cookie 不携带属性，无法用 attribute 提取".to_string());
            }
            if *field != CookieField::Attribute && attribute.is_some() {
                return Err("只有 `attribute` 字段才允许配 `attribute` 名".to_string());
            }
            CompiledExtractor::Cookie {
                field: *field,
                attribute: attribute
                    .as_deref()
                    .map(str::trim)
                    .filter(|attribute| !attribute.is_empty())
                    .map(str::to_ascii_lowercase),
            }
        }
        ExtractorDefinition::JwtMetadata { field } => CompiledExtractor::JwtMetadata(*field),
    };
    Ok(CompiledSelector {
        target,
        name: normalized_name(target, selector.name.as_deref()),
        extractor,
    })
}

/// 正则编译：源码长度、程序体积、DFA 缓存和语法嵌套四道闸门全部前置。
pub fn compile_regex(pattern: &str) -> Result<Regex, String> {
    if pattern.len() > MAX_REGEX_PATTERN_BYTES {
        return Err(format!(
            "正则长度 {} 字节超过上限 {MAX_REGEX_PATTERN_BYTES}",
            pattern.len()
        ));
    }
    RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT_BYTES)
        .dfa_size_limit(REGEX_DFA_SIZE_LIMIT_BYTES)
        .nest_limit(REGEX_NEST_LIMIT)
        .build()
        .map_err(|error| format!("正则编译被拒绝: {error}"))
}

static BUILTIN_PACK: LazyLock<PackStatus> = LazyLock::new(|| {
    let status = load_pack_status(BUILTIN_PACK_FILE, BUILTIN_PACK_JSON);
    if let PackStatus::Disabled { pack_id, reason } = &status {
        eprintln!("[rules] 规则包 `{pack_id}` 加载失败，已禁用该包: {reason}");
    }
    status
});

/// 内置规则包。加载失败时返回 `Disabled`，调用方拿到零条规则而不是崩溃。
pub fn builtin_pack() -> &'static PackStatus {
    &BUILTIN_PACK
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pack_json(rules: &str) -> String {
        format!(
            r#"{{"schema_version":1,"pack_id":"test","version":"1.0.0","source":"unit-test",
                 "description":"测试包","rules":[{rules}]}}"#
        )
    }

    fn rule_json(rule_id: &str, condition: &str) -> String {
        format!(
            r#"{{"rule_id":"{rule_id}","version":"1.0.0","source":"unit-test","name":"n",
                 "description":"d","verify_hint":"v","severity":"low","confidence":50,
                 "tag":"t","vuln_type":"vt",
                 "references":[{{"framework":"cwe","version":"4.20","id":"CWE-200"}}],
                 "condition":{condition}}}"#
        )
    }

    #[test]
    fn builtin_pack_loads_and_carries_every_legacy_rule_id() {
        let pack = builtin_pack()
            .pack()
            .expect("内置规则包必须加载成功，否则代理会静默失去初筛能力");
        assert_eq!(pack.pack_id, BUILTIN_PACK_ID);
        assert_eq!(pack.version, "1.0.0");
        assert_eq!(pack.source, "rustforge-builtin");
        let ids: Vec<&str> = pack.rules.iter().map(|r| r.rule_id.as_str()).collect();
        for legacy in crate::rules::builtin::legacy_rules() {
            assert!(ids.contains(&legacy.id), "缺少迁移规则 {}", legacy.id);
        }
        assert_eq!(pack.rules.len(), 14);
    }

    #[test]
    fn every_builtin_rule_references_a_known_versioned_standard() {
        let pack = builtin_pack().pack().unwrap();
        for rule in &pack.rules {
            assert!(!rule.references.is_empty(), "{}", rule.rule_id);
            knowledge::validate_references(&rule.references)
                .unwrap_or_else(|error| panic!("{}: {error}", rule.rule_id));
        }
    }

    #[test]
    fn reloading_the_same_pack_produces_identical_rule_metadata() {
        let first = load_pack("builtin", BUILTIN_PACK_JSON).unwrap();
        let second = load_pack("builtin", BUILTIN_PACK_JSON).unwrap();
        let describe = |pack: &CompiledPack| {
            pack.rules
                .iter()
                .map(|rule| {
                    format!(
                        "{}|{}|{}|{}|{:?}",
                        rule.rule_id,
                        rule.version,
                        rule.confidence,
                        rule.severity.as_str(),
                        rule.references
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(describe(&first), describe(&second));
    }

    #[test]
    fn overlong_regex_is_rejected_at_load_time() {
        let pattern = format!("(?i){}", "a".repeat(MAX_REGEX_PATTERN_BYTES));
        let raw = pack_json(&rule_json(
            "big",
            &format!(
                r#"{{"operator":"regex","selector":{{"target":"url"}},"pattern":"{pattern}"}}"#
            ),
        ));
        let status = load_pack_status("oversized.json", &raw);
        assert!(!status.is_loaded());
        assert!(status.disabled_reason().unwrap().contains("超过上限"));
    }

    #[test]
    fn regex_exceeding_the_compiled_size_budget_is_rejected() {
        // 源码很短但展开后极其庞大，正是需要 size_limit 拦住的形态
        let raw = pack_json(&rule_json(
            "bomb",
            r#"{"operator":"regex","selector":{"target":"url"},"pattern":"((a{1000}){1000}){1000}"}"#,
        ));
        let status = load_pack_status("bomb.json", &raw);
        assert!(!status.is_loaded());
        assert!(status.disabled_reason().unwrap().contains("正则"));
    }

    #[test]
    fn deeply_nested_conditions_are_rejected() {
        let mut condition = r#"{"operator":"exists","selector":{"target":"url"}}"#.to_string();
        for _ in 0..MAX_CONDITION_DEPTH {
            condition = format!(r#"{{"operator":"not","condition":{condition}}}"#);
        }
        let raw = pack_json(&rule_json("deep", &condition));
        let status = load_pack_status("deep.json", &raw);
        assert!(!status.is_loaded());
        assert!(status.disabled_reason().unwrap().contains("深度"));
    }

    #[test]
    fn malformed_json_disables_the_pack_with_a_reason_instead_of_panicking() {
        let status = load_pack_status("broken.json", "{ not json");
        assert_eq!(status.pack_id(), "broken.json");
        assert!(status.disabled_reason().unwrap().contains("不是有效 JSON"));
        assert!(status.pack().is_none());
    }

    #[test]
    fn unknown_standard_reference_disables_the_pack() {
        let raw = pack_json(
            &rule_json(
                "bad-ref",
                r#"{"operator":"exists","selector":{"target":"url"}}"#,
            )
            .replace("CWE-200", "CWE-999999"),
        );
        let status = load_pack_status("bad-ref.json", &raw);
        assert!(status.disabled_reason().unwrap().contains("CWE-999999"));
    }

    #[test]
    fn duplicate_rule_ids_and_out_of_range_confidence_are_rejected() {
        let duplicated = pack_json(&format!(
            "{},{}",
            rule_json(
                "dup",
                r#"{"operator":"exists","selector":{"target":"url"}}"#
            ),
            rule_json(
                "dup",
                r#"{"operator":"exists","selector":{"target":"url"}}"#
            )
        ));
        assert!(load_pack_status("dup.json", &duplicated)
            .disabled_reason()
            .unwrap()
            .contains("重复"));

        let bad_confidence = pack_json(
            &rule_json("c", r#"{"operator":"exists","selector":{"target":"url"}}"#)
                .replace("\"confidence\":50", "\"confidence\":0"),
        );
        assert!(load_pack_status("c.json", &bad_confidence)
            .disabled_reason()
            .unwrap()
            .contains("confidence"));
    }

    #[test]
    fn extractors_must_match_their_target_family() {
        let cases = [
            (
                r#"{"operator":"exists","selector":{"target":"url","extractor":{"kind":"cookie","field":"name"}}}"#,
                "cookie",
            ),
            (
                r#"{"operator":"exists","selector":{"target":"url","extractor":{"kind":"json_path","path":"$.a"}}}"#,
                "json_path",
            ),
            (
                r#"{"operator":"exists","selector":{"target":"response_body","extractor":{"kind":"query"}}}"#,
                "query",
            ),
            (
                r#"{"operator":"exists","selector":{"target":"request_cookie","extractor":{"kind":"cookie","field":"attribute","attribute":"secure"}}}"#,
                "属性",
            ),
        ];
        for (condition, expected) in cases {
            let raw = pack_json(&rule_json("x", condition));
            let status = load_pack_status("x.json", &raw);
            assert!(
                status.disabled_reason().unwrap().contains(expected),
                "{condition}"
            );
        }
    }

    #[test]
    fn schema_version_mismatch_disables_the_pack() {
        let raw = pack_json(&rule_json(
            "v",
            r#"{"operator":"exists","selector":{"target":"url"}}"#,
        ))
        .replace("\"schema_version\":1", "\"schema_version\":2");
        assert!(load_pack_status("v.json", &raw)
            .disabled_reason()
            .unwrap()
            .contains("schema_version"));
    }

    #[test]
    fn rule_count_limit_is_enforced() {
        let rules: Vec<String> = (0..=MAX_RULES_PER_PACK)
            .map(|index| {
                rule_json(
                    &format!("r{index}"),
                    r#"{"operator":"exists","selector":{"target":"url"}}"#,
                )
            })
            .collect();
        let raw = pack_json(&rules.join(","));
        assert!(load_pack_status("many.json", &raw)
            .disabled_reason()
            .unwrap()
            .contains("规则数"));
    }
}
