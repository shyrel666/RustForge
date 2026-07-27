//! Strict, declarative schema for passive rule packs.
//!
//! The schema intentionally has no action, script, file, process, or network
//! primitive. A rule can only select already-captured HTTP fields and compare
//! the extracted scalar values with bounded operators.

use crate::knowledge::StandardReference;
use serde::{Deserialize, Serialize};

pub const RULE_SCHEMA_VERSION: u32 = 1;

/// 单个规则包最多容纳的规则数，避免一次加载吃掉不可控的内存与时间。
pub const MAX_RULES_PER_PACK: usize = 256;
/// 正则源码长度上限，超长即视为不可审计的规则，加载期直接拒绝。
pub const MAX_REGEX_PATTERN_BYTES: usize = 512;
/// 条件树最大嵌套层数，防止深层嵌套导致的递归求值代价。
pub const MAX_CONDITION_DEPTH: usize = 16;
/// 证据片段最大字符数（按 char 计，避免截断多字节字符）。
pub const MAX_EVIDENCE_SNIPPET_CHARS: usize = 160;
/// 正文被截断时命中结果的置信度上限——不完整证据不允许高置信度。
pub const TRUNCATED_HIT_MAX_CONFIDENCE: u8 = 40;
/// 编译后正则程序的内存上限（regex crate 的 size_limit）。默认值是 10 MiB，
/// 收紧到 1 MiB 足以拦住 `((a{1000}){1000}){1000}` 这类展开爆炸的构造，
/// 又留得下带 `\b` 边界的多分支 IP/报错特征正则。
pub const REGEX_SIZE_LIMIT_BYTES: usize = 1024 * 1024;
/// 惰性 DFA 缓存上限，限制单条正则在长文本上的空间放大。
pub const REGEX_DFA_SIZE_LIMIT_BYTES: usize = 1024 * 1024;
/// 正则语法树嵌套上限，拒绝 `(((((...)))))` 式的病态构造。
pub const REGEX_NEST_LIMIT: u32 = 24;
/// JSONPath 子集允许的最大层级。
pub const MAX_JSON_PATH_SEGMENTS: usize = 12;
/// 单个选择器最多展开的候选值数量（如超多 Set-Cookie / 查询参数）。
pub const MAX_CANDIDATES_PER_SELECTOR: usize = 256;
/// 单条流量跑完整个规则包的时间预算，超时后停止求值并返回已有命中。
pub const MAX_EVALUATION_MILLIS: u64 = 50;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RulePackDefinition {
    pub schema_version: u32,
    pub pack_id: String,
    pub version: String,
    pub source: String,
    pub description: String,
    pub rules: Vec<RuleDefinition>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuleDefinition {
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
    pub references: Vec<StandardReference>,
    pub condition: ConditionDefinition,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "operator", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConditionDefinition {
    Equals {
        selector: SelectorDefinition,
        value: String,
        #[serde(default)]
        case_sensitive: bool,
    },
    Contains {
        selector: SelectorDefinition,
        value: String,
        #[serde(default)]
        case_sensitive: bool,
    },
    Regex {
        selector: SelectorDefinition,
        pattern: String,
    },
    Exists {
        selector: SelectorDefinition,
    },
    Missing {
        selector: SelectorDefinition,
    },
    GreaterThan {
        selector: SelectorDefinition,
        value: f64,
    },
    GreaterOrEqual {
        selector: SelectorDefinition,
        value: f64,
    },
    LessThan {
        selector: SelectorDefinition,
        value: f64,
    },
    LessOrEqual {
        selector: SelectorDefinition,
        value: f64,
    },
    All {
        conditions: Vec<ConditionDefinition>,
    },
    Any {
        conditions: Vec<ConditionDefinition>,
    },
    Not {
        condition: Box<ConditionDefinition>,
    },
    /// 逐实例求值：把目标展开成互相独立的实例（如每一条 `Set-Cookie`），
    /// 在每个实例内部单独判定内层条件。内层同 target 的选择器只能看到
    /// 当前实例，其余 target 仍按整条流量解析。
    ///
    /// 这是修正"全局 must_absent"语义的关键：只要有任意一个 Cookie 带了
    /// HttpOnly 就掩盖掉其它缺失项的老写法在这里不可能出现。
    ForEach {
        target: Target,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        condition: Box<ConditionDefinition>,
    },
}

impl ConditionDefinition {
    /// 条件树深度（叶子为 1）。
    pub fn depth(&self) -> usize {
        match self {
            Self::All { conditions } | Self::Any { conditions } => {
                1 + conditions.iter().map(Self::depth).max().unwrap_or(0)
            }
            Self::Not { condition } | Self::ForEach { condition, .. } => 1 + condition.depth(),
            _ => 1,
        }
    }

    /// 结构上第一个选择器，用于在无正向证据（missing/not）时给出字段路径。
    pub fn first_selector(&self) -> Option<&SelectorDefinition> {
        match self {
            Self::Equals { selector, .. }
            | Self::Contains { selector, .. }
            | Self::Regex { selector, .. }
            | Self::Exists { selector }
            | Self::Missing { selector }
            | Self::GreaterThan { selector, .. }
            | Self::GreaterOrEqual { selector, .. }
            | Self::LessThan { selector, .. }
            | Self::LessOrEqual { selector, .. } => Some(selector),
            Self::All { conditions } | Self::Any { conditions } => {
                conditions.iter().find_map(Self::first_selector)
            }
            Self::Not { condition } | Self::ForEach { condition, .. } => condition.first_selector(),
        }
    }

    pub fn visit(&self, visitor: &mut impl FnMut(&ConditionDefinition)) {
        visitor(self);
        match self {
            Self::All { conditions } | Self::Any { conditions } => {
                for condition in conditions {
                    condition.visit(visitor);
                }
            }
            Self::Not { condition } | Self::ForEach { condition, .. } => condition.visit(visitor),
            _ => {}
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(deny_unknown_fields)]
pub struct SelectorDefinition {
    pub target: Target,
    /// Header, query parameter, or cookie name. Matching is ASCII
    /// case-insensitive for headers and cookies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default)]
    pub extractor: ExtractorDefinition,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Target {
    Method,
    Url,
    Query,
    RequestHeader,
    ResponseHeader,
    RequestCookie,
    ResponseCookie,
    RequestBody,
    ResponseBody,
    Status,
    ContentType,
}

impl Target {
    /// 粗粒度命中位置，供列表/Finding 展示。
    pub fn location(self) -> &'static str {
        match self {
            Self::Method => "request.method",
            Self::Url => "request.url",
            Self::Query => "request.query",
            Self::RequestHeader => "request.headers",
            Self::ResponseHeader => "response.headers",
            Self::RequestCookie => "request.cookie",
            Self::ResponseCookie => "response.cookie",
            Self::RequestBody => "request.body",
            Self::ResponseBody => "response.body",
            Self::Status => "response.status",
            Self::ContentType => "response.content_type",
        }
    }

    /// 字段路径前缀，命中结果在其后追加具体字段名/下标。
    pub fn path_prefix(self) -> &'static str {
        match self {
            Self::RequestHeader => "request.header",
            Self::ResponseHeader => "response.header",
            other => other.location(),
        }
    }

    pub fn is_body(self) -> bool {
        matches!(self, Self::RequestBody | Self::ResponseBody)
    }

    pub fn is_cookie(self) -> bool {
        matches!(self, Self::RequestCookie | Self::ResponseCookie)
    }

    pub fn is_header(self) -> bool {
        matches!(self, Self::RequestHeader | Self::ResponseHeader)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExtractorDefinition {
    #[default]
    Text,
    Query {
        #[serde(default)]
        field: QueryField,
    },
    Form {
        #[serde(default)]
        field: FormField,
    },
    JsonPath {
        path: String,
    },
    Cookie {
        #[serde(default)]
        field: CookieField,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        attribute: Option<String>,
    },
    JwtMetadata {
        field: JwtMetadataField,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum QueryField {
    Name,
    #[default]
    Value,
    Pair,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum FormField {
    Name,
    #[default]
    Value,
    Pair,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum CookieField {
    Name,
    #[default]
    Value,
    Attribute,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum JwtMetadataField {
    Alg,
    Typ,
    Kid,
    Iss,
    Aud,
    Exp,
    Nbf,
    Iat,
}
