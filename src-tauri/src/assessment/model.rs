use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentStatus {
    Queued,
    Discovering,
    Planning,
    Executing,
    Verifying,
    Completed,
    Stopped,
    Cancelled,
    Failed,
    Interrupted,
}

impl AssessmentStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Discovering => "discovering",
            Self::Planning => "planning",
            Self::Executing => "executing",
            Self::Verifying => "verifying",
            Self::Completed => "completed",
            Self::Stopped => "stopped",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
            Self::Interrupted => "interrupted",
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "queued" => Ok(Self::Queued),
            "discovering" => Ok(Self::Discovering),
            "planning" => Ok(Self::Planning),
            "executing" => Ok(Self::Executing),
            "verifying" => Ok(Self::Verifying),
            "completed" => Ok(Self::Completed),
            "stopped" => Ok(Self::Stopped),
            "cancelled" => Ok(Self::Cancelled),
            "failed" => Ok(Self::Failed),
            "interrupted" => Ok(Self::Interrupted),
            _ => Err(format!("未知评估状态: {value}")),
        }
    }

    pub const fn is_active(self) -> bool {
        matches!(
            self,
            Self::Queued | Self::Discovering | Self::Planning | Self::Executing | Self::Verifying
        )
    }

    pub const fn is_terminal(self) -> bool {
        !self.is_active()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentVerdict {
    Confirmed,
    Suspected,
    NotObserved,
    Inconclusive,
    Skipped,
}

impl AssessmentVerdict {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::Suspected => "suspected",
            Self::NotObserved => "not_observed",
            Self::Inconclusive => "inconclusive",
            Self::Skipped => "skipped",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AssessmentAuthProfile {
    pub id: i64,
    pub project_id: i64,
    pub label: String,
    pub source_traffic_id: Option<i64>,
    pub header_name: String,
    pub secret_revision: i64,
    pub has_secret: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// Traffic 中可提取指定鉴权 Header 的候选请求元数据。
/// 只描述"存在性"，绝不携带 Header 值；值仅在用户选中后由
/// import_auth_profile_from_traffic 提取并写入系统凭据库。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AssessmentAuthCandidate {
    pub traffic_id: i64,
    pub method: String,
    pub url: String,
    pub status: Option<u16>,
    pub created_at: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateAssessmentAuthProfileInput {
    pub project_id: i64,
    pub label: String,
    pub header_name: String,
    pub secret: String,
    pub source_traffic_id: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SetAssessmentAuthProfileInput {
    pub project_id: i64,
    pub profile_id: i64,
    pub header_name: String,
    pub secret: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportAssessmentAuthProfileInput {
    pub project_id: i64,
    pub traffic_id: i64,
    pub label: String,
    pub header_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceOwnershipClaim {
    pub path: String,
    pub owner_profile_id: i64,
}

fn default_request_budget() -> u32 {
    120
}

fn default_requests_per_second() -> f64 {
    1.0
}

fn default_max_rounds() -> u8 {
    3
}

fn default_tls_policy() -> String {
    "strict".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssessmentContractInput {
    pub project_id: i64,
    pub start_url: String,
    #[serde(default)]
    pub excluded_paths: Vec<String>,
    #[serde(default = "default_tls_policy")]
    pub tls_policy: String,
    #[serde(default = "default_request_budget")]
    pub request_budget: u32,
    #[serde(default = "default_requests_per_second")]
    pub requests_per_second: f64,
    #[serde(default)]
    pub identity_a_profile_id: Option<i64>,
    #[serde(default)]
    pub identity_b_profile_id: Option<i64>,
    #[serde(default)]
    pub resource_ownership: Vec<ResourceOwnershipClaim>,
    #[serde(default)]
    pub include_recent_traffic: bool,
    pub provider_id: String,
    pub model: String,
    #[serde(default = "default_max_rounds")]
    pub max_rounds: u8,
    #[serde(default)]
    pub written_authorization_confirmed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AssessmentContractPreview {
    pub project_id: i64,
    pub normalized_start_url: String,
    pub exact_origin: String,
    pub normalized_scope: Vec<String>,
    pub excluded_paths: Vec<String>,
    pub builtin_excluded_segments: Vec<String>,
    pub tls_policy: String,
    pub request_budget: u32,
    pub discovery_budget: u32,
    pub requests_per_second: f64,
    pub identity_a_profile_id: Option<i64>,
    pub identity_a_label: Option<String>,
    pub identity_a_secret_revision: Option<i64>,
    pub identity_b_profile_id: Option<i64>,
    pub identity_b_label: Option<String>,
    pub identity_b_secret_revision: Option<i64>,
    pub resource_ownership: Vec<ResourceOwnershipClaim>,
    pub include_recent_traffic: bool,
    pub provider_id: String,
    pub model: String,
    pub max_rounds: u8,
    pub data_disclosure: Vec<String>,
    pub template_registry_version: String,
    pub template_registry_hash: String,
    pub contract_hash: String,
    pub written_authorization_confirmed: bool,
    pub residual_risk_notice: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AssessmentRun {
    pub id: i64,
    pub project_id: i64,
    pub status: AssessmentStatus,
    pub start_url: String,
    pub exact_origin: String,
    pub contract_hash: String,
    pub template_registry_hash: String,
    pub provider_id: String,
    pub model: String,
    pub tls_policy: String,
    pub request_budget: u32,
    pub request_count: u32,
    pub discovery_budget: u32,
    pub requests_per_second: f64,
    pub response_byte_budget: u64,
    pub response_bytes_read: u64,
    pub max_rounds: u8,
    pub completed_rounds: u8,
    pub stop_reason: String,
    pub created_at: String,
    pub started_at: Option<String>,
    pub ended_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AssessmentRound {
    pub id: i64,
    pub run_id: i64,
    pub round_number: u8,
    pub status: String,
    pub analysis_run_id: Option<i64>,
    pub input_hash: String,
    pub output_hash: Option<String>,
    pub selected_checks: u8,
    pub rejection_json: serde_json::Value,
    pub created_at: String,
    pub completed_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AssessmentEndpoint {
    pub id: i64,
    pub run_id: i64,
    /// Opaque identifier exposed to the model. The actual URL is never part of AI input.
    pub endpoint_id: String,
    pub method: String,
    pub url: String,
    pub path: String,
    pub query_parameter_names: Vec<String>,
    pub source_kind: String,
    pub status: Option<u16>,
    pub content_type: String,
    pub has_authentication: bool,
    pub passive_tags: Vec<String>,
    pub response_complete: bool,
    pub resource_owner_profile_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AssessmentCheck {
    pub id: i64,
    pub run_id: i64,
    pub round_id: Option<i64>,
    pub endpoint_id: Option<i64>,
    pub requested_endpoint_id: String,
    pub template_id: String,
    pub template_version: String,
    pub parameter_name: Option<String>,
    pub identity_mode: String,
    pub rationale: String,
    pub policy_result: String,
    pub policy_reason: String,
    pub status: String,
    pub request_cost: u8,
    pub created_at: String,
    pub completed_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AssessmentVerification {
    pub id: i64,
    pub check_id: i64,
    pub verifier_id: String,
    pub verifier_version: String,
    pub verdict: AssessmentVerdict,
    pub observations: serde_json::Value,
    pub content_hash: String,
    pub finding_id: Option<i64>,
    pub finding_relation: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AssessmentCoverageGap {
    pub id: i64,
    pub run_id: i64,
    pub check_id: Option<i64>,
    pub category: String,
    pub reason_code: String,
    pub detail: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AssessmentEvent {
    pub id: i64,
    pub run_id: i64,
    pub check_id: Option<i64>,
    pub event_type: String,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    pub details: serde_json::Value,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AssessmentDetail {
    pub run: AssessmentRun,
    pub rounds: Vec<AssessmentRound>,
    pub endpoints: Vec<AssessmentEndpoint>,
    pub checks: Vec<AssessmentCheck>,
    pub verifications: Vec<AssessmentVerification>,
    pub coverage_gaps: Vec<AssessmentCoverageGap>,
    pub events: Vec<AssessmentEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AssessmentProgress {
    pub project_id: i64,
    pub run_id: i64,
    pub status: AssessmentStatus,
    pub phase: String,
    pub message: String,
    pub request_count: u32,
    pub request_budget: u32,
    pub completed_checks: u32,
    pub total_checks: u32,
    pub occurred_at: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StartAssessmentInput {
    pub contract: AssessmentContractInput,
    pub contract_hash: String,
}
