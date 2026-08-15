use serde::Serialize;
use sha2::{Digest, Sha256};

pub const TOOL_REGISTRY_VERSION: &str = "2026.08.03-v2";
/// Compatibility name retained for v3 contracts and reports.
pub const TEMPLATE_REGISTRY_VERSION: &str = TOOL_REGISTRY_VERSION;

/// Version-pinned capability exposed to the mission planner. A ToolSpec is
/// metadata only: request construction and approval are always enforced by the
/// backend implementation selected by `id + version`.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ToolSpec {
    pub id: &'static str,
    pub version: &'static str,
    pub display_name: &'static str,
    pub description: &'static str,
    pub execution_kind: &'static str,
    pub risk_level: &'static str,
    pub verifier_id: &'static str,
    pub verifier_version: &'static str,
    pub allowed_identity_modes: &'static [&'static str],
    pub requires_parameter: bool,
    /// JSON Schema text is static and hashable. It never contains target data.
    pub parameter_schema: &'static str,
    pub request_cost: u8,
    pub default_permission: &'static str,
    pub can_auto_confirm: bool,
    /// Only v3 runner implementations may appear in the legacy check planner.
    pub legacy_template: bool,
}

/// Existing materialization code keeps this name while using the richer spec.
pub type SafeTemplate = ToolSpec;

const NO_PARAMETERS: &str = r#"{"type":"object","additionalProperties":false}"#;
const OPTIONAL_PARAMETER_NAME: &str = r#"{"type":"object","additionalProperties":false,"properties":{"parameterName":{"type":"string","maxLength":240}}}"#;
const MANUAL_RECIPE_PARAMETERS: &str = r#"{"type":"object","additionalProperties":false,"properties":{"surfaceId":{"type":"string","maxLength":120},"parameterName":{"type":"string","maxLength":240},"identityMode":{"enum":["anonymous","a","b","a_vs_b"]}}}"#;

pub const TOOL_SPECS: &[ToolSpec] = &[
    ToolSpec {
        id: "security_headers_cookie",
        version: "2.0.0",
        display_name: "响应安全基线",
        description: "复用完整响应，确定性检查安全 Header、Cookie、缓存、CSP、Frame 与 MIME。",
        execution_kind: "observe",
        risk_level: "local",
        verifier_id: "security_headers_cookie",
        verifier_version: "2.0.0",
        allowed_identity_modes: &["anonymous", "a", "b"],
        requires_parameter: false,
        parameter_schema: NO_PARAMETERS,
        request_cost: 0,
        default_permission: "execute",
        can_auto_confirm: true,
        legacy_template: true,
    },
    ToolSpec {
        id: "credentialed_cors",
        version: "1.2.0",
        display_name: "凭据化 CORS 边界",
        description: "比较匿名、身份与受控 Origin 预检响应，不构造任意 Header。",
        execution_kind: "safe_probe",
        risk_level: "guarded",
        verifier_id: "credentialed_cors",
        verifier_version: "1.2.0",
        allowed_identity_modes: &["a", "b"],
        requires_parameter: false,
        parameter_schema: NO_PARAMETERS,
        request_cost: 2,
        default_permission: "ask",
        can_auto_confirm: true,
        legacy_template: true,
    },
    ToolSpec {
        id: "jwt_integrity",
        version: "1.1.0",
        display_name: "JWT 完整性边界",
        description: "使用版本固定的非破坏性 JWT 变体比较授权结果。",
        execution_kind: "safe_probe",
        risk_level: "guarded",
        verifier_id: "jwt_integrity",
        verifier_version: "1.1.0",
        allowed_identity_modes: &["a", "b"],
        requires_parameter: false,
        parameter_schema: NO_PARAMETERS,
        request_cost: 4,
        default_permission: "ask",
        can_auto_confirm: true,
        legacy_template: true,
    },
    ToolSpec {
        id: "open_redirect",
        version: "1.1.0",
        display_name: "开放重定向探针",
        description: "仅在已有参数名上使用固定外部标记并观察 Location，不跟随跨源跳转。",
        execution_kind: "safe_probe",
        risk_level: "guarded",
        verifier_id: "open_redirect",
        verifier_version: "1.1.0",
        allowed_identity_modes: &["anonymous", "a", "b"],
        requires_parameter: true,
        parameter_schema: OPTIONAL_PARAMETER_NAME,
        request_cost: 1,
        default_permission: "ask",
        can_auto_confirm: true,
        legacy_template: true,
    },
    ToolSpec {
        id: "lazy_reflection",
        version: "1.1.0",
        display_name: "受控反射观察",
        description: "在已有参数上放置固定惰性标记；语义不足时只能进入 suspected。",
        execution_kind: "safe_probe",
        risk_level: "guarded",
        verifier_id: "lazy_reflection",
        verifier_version: "1.1.0",
        allowed_identity_modes: &["anonymous", "a", "b"],
        requires_parameter: true,
        parameter_schema: OPTIONAL_PARAMETER_NAME,
        request_cost: 1,
        default_permission: "ask",
        can_auto_confirm: false,
        legacy_template: true,
    },
    ToolSpec {
        id: "readonly_idor",
        version: "1.1.0",
        display_name: "只读身份差异",
        description: "在明确资源归属声明上串行比较身份 A/B 的 GET 响应。",
        execution_kind: "safe_probe",
        risk_level: "guarded",
        verifier_id: "readonly_idor",
        verifier_version: "1.1.0",
        allowed_identity_modes: &["a_vs_b"],
        requires_parameter: false,
        parameter_schema: NO_PARAMETERS,
        request_cost: 2,
        default_permission: "ask",
        can_auto_confirm: true,
        legacy_template: true,
    },
    ToolSpec {
        id: "html_surface_inventory",
        version: "1.0.0",
        display_name: "HTML 与表单清单",
        description: "本地解析 anchor、form、input、script/resource；表单只登记不提交。",
        execution_kind: "observe",
        risk_level: "local",
        verifier_id: "inventory_only",
        verifier_version: "1.0.0",
        allowed_identity_modes: &["anonymous", "a", "b"],
        requires_parameter: false,
        parameter_schema: NO_PARAMETERS,
        request_cost: 0,
        default_permission: "execute",
        can_auto_confirm: false,
        legacy_template: false,
    },
    ToolSpec {
        id: "static_route_inventory",
        version: "1.0.0",
        display_name: "静态脚本路由清单",
        description: "有界提取同源脚本文本中的静态路由字面量，不执行 JavaScript。",
        execution_kind: "observe",
        risk_level: "local",
        verifier_id: "inventory_only",
        verifier_version: "1.0.0",
        allowed_identity_modes: &["anonymous", "a", "b"],
        requires_parameter: false,
        parameter_schema: NO_PARAMETERS,
        request_cost: 0,
        default_permission: "execute",
        can_auto_confirm: false,
        legacy_template: false,
    },
    ToolSpec {
        id: "openapi_inventory",
        version: "1.0.0",
        display_name: "OpenAPI 结构导入",
        description: "本地读取有界 JSON/YAML 摘要，只保留路径形状、方法、参数名与 Schema key。",
        execution_kind: "observe",
        risk_level: "local",
        verifier_id: "inventory_only",
        verifier_version: "1.0.0",
        allowed_identity_modes: &["anonymous"],
        requires_parameter: false,
        parameter_schema: NO_PARAMETERS,
        request_cost: 0,
        default_permission: "execute",
        can_auto_confirm: false,
        legacy_template: false,
    },
    ToolSpec {
        id: "options_capabilities",
        version: "1.0.0",
        display_name: "OPTIONS 能力边界",
        description: "对精确 origin 的已知 surface 发送单次 OPTIONS 并观察 Allow/CORS 能力。",
        execution_kind: "safe_probe",
        risk_level: "low",
        verifier_id: "options_capabilities",
        verifier_version: "1.0.0",
        allowed_identity_modes: &["anonymous", "a", "b"],
        requires_parameter: false,
        parameter_schema: NO_PARAMETERS,
        request_cost: 1,
        default_permission: "execute",
        can_auto_confirm: false,
        legacy_template: true,
    },
    ToolSpec {
        id: "anonymous_authenticated_diff",
        version: "1.0.0",
        display_name: "匿名/登录可见性差异",
        description: "串行比较同一 GET surface 的匿名与已选身份响应结构。",
        execution_kind: "safe_probe",
        risk_level: "guarded",
        verifier_id: "identity_visibility",
        verifier_version: "1.0.0",
        allowed_identity_modes: &["a", "b"],
        requires_parameter: false,
        parameter_schema: NO_PARAMETERS,
        request_cost: 2,
        default_permission: "ask",
        can_auto_confirm: false,
        legacy_template: true,
    },
    ToolSpec {
        id: "manual_sqli_recipe",
        version: "1.0.0",
        display_name: "SQL 注入人工配方",
        description: "生成版本固定的 Repeater 差异草稿；只能由用户在手动会话点击发送。",
        execution_kind: "manual_recipe",
        risk_level: "manual",
        verifier_id: "human_evidence_review",
        verifier_version: "1.0.0",
        allowed_identity_modes: &["anonymous", "a", "b"],
        requires_parameter: true,
        parameter_schema: MANUAL_RECIPE_PARAMETERS,
        request_cost: 0,
        default_permission: "ask",
        can_auto_confirm: false,
        legacy_template: false,
    },
    ToolSpec {
        id: "manual_ssrf_recipe",
        version: "1.0.0",
        display_name: "SSRF 人工配方",
        description: "生成无发送的 Repeater 草稿，并要求用户审阅目标差异。",
        execution_kind: "manual_recipe",
        risk_level: "manual",
        verifier_id: "human_evidence_review",
        verifier_version: "1.0.0",
        allowed_identity_modes: &["anonymous", "a", "b"],
        requires_parameter: true,
        parameter_schema: MANUAL_RECIPE_PARAMETERS,
        request_cost: 0,
        default_permission: "ask",
        can_auto_confirm: false,
        legacy_template: false,
    },
    ToolSpec {
        id: "manual_xss_recipe",
        version: "1.0.0",
        display_name: "XSS 人工配方",
        description: "生成惰性标记差异草稿；评估引擎不执行脚本且不发送草稿。",
        execution_kind: "manual_recipe",
        risk_level: "manual",
        verifier_id: "human_evidence_review",
        verifier_version: "1.0.0",
        allowed_identity_modes: &["anonymous", "a", "b"],
        requires_parameter: true,
        parameter_schema: MANUAL_RECIPE_PARAMETERS,
        request_cost: 0,
        default_permission: "ask",
        can_auto_confirm: false,
        legacy_template: false,
    },
    ToolSpec {
        id: "manual_business_logic_recipe",
        version: "1.0.0",
        display_name: "业务逻辑人工配方",
        description: "仅生成审核清单和 Repeater 草稿，不自动修改状态或重放请求。",
        execution_kind: "manual_recipe",
        risk_level: "manual",
        verifier_id: "human_evidence_review",
        verifier_version: "1.0.0",
        allowed_identity_modes: &["anonymous", "a", "b", "a_vs_b"],
        requires_parameter: false,
        parameter_schema: MANUAL_RECIPE_PARAMETERS,
        request_cost: 0,
        default_permission: "ask",
        can_auto_confirm: false,
        legacy_template: false,
    },
];

/// v3 runner lookup: unimplemented v2 tools fail closed even if a forged planner
/// response references them.
pub fn template(id: &str) -> Option<&'static SafeTemplate> {
    TOOL_SPECS
        .iter()
        .find(|tool| tool.id == id && tool.legacy_template)
}

pub fn tool(id: &str) -> Option<&'static ToolSpec> {
    TOOL_SPECS.iter().find(|tool| tool.id == id)
}

pub fn planner_tools() -> impl Iterator<Item = &'static ToolSpec> {
    TOOL_SPECS.iter().filter(|tool| tool.legacy_template)
}

/// Tools exposed to a v2 mission planner. Manual recipes are selectable only
/// when the mission-specific allowlist also contains their ID; they still have
/// no executable template and can therefore never reach the network runner.
pub fn mission_planner_tools() -> impl Iterator<Item = &'static ToolSpec> {
    TOOL_SPECS
        .iter()
        .filter(|tool| tool.legacy_template || tool.execution_kind == "manual_recipe")
}

pub fn registry_hash() -> String {
    let canonical = serde_json::to_vec(&(TOOL_REGISTRY_VERSION, TOOL_SPECS))
        .expect("static tool registry serializes");
    let digest = Sha256::digest(canonical);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_unique_versioned_and_bounded() {
        let mut ids = std::collections::HashSet::new();
        for tool in TOOL_SPECS {
            assert!(ids.insert(tool.id));
            assert!(tool.request_cost <= 8);
            assert!(!tool.allowed_identity_modes.is_empty());
            assert!(serde_json::from_str::<serde_json::Value>(tool.parameter_schema).is_ok());
            if tool.execution_kind == "manual_recipe" {
                assert_eq!(tool.default_permission, "ask");
                assert!(!tool.can_auto_confirm);
                assert!(!tool.legacy_template);
            }
        }
        assert_eq!(registry_hash().len(), 64);
        assert!(planner_tools().all(|tool| template(tool.id).is_some()));
        assert!(mission_planner_tools().any(|tool| tool.id == "manual_xss_recipe"));
        assert!(template("manual_sqli_recipe").is_none());
        assert!(tool("manual_sqli_recipe").is_some());
    }
}
