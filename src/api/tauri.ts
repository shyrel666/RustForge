import { invoke } from "@tauri-apps/api/core";

export interface Project {
  id: number;
  name: string;
  target_host: string;
  scope: string[];
  created_at: string;
}

// ---------- 设置 ----------
export const getSetting = (key: string) =>
  invoke<string | null>("get_setting", { key });

export const setSetting = (key: string, value: string) =>
  invoke<void>("set_setting", { key, value });

export const getAllSettings = () =>
  invoke<Record<string, string>>("get_all_settings");

export interface AiDataPolicy {
  redact_query_values: boolean;
  redact_sensitive_headers: boolean;
  redact_body_secrets: boolean;
  include_truncated_bodies: boolean;
  include_binary_bodies: boolean;
  include_decode_failed_bodies: boolean;
  request_body_max_bytes: number;
  response_body_max_bytes: number;
  total_context_max_bytes: number;
}

export const getAiDataPolicy = () =>
  invoke<AiDataPolicy>("get_ai_data_policy");

export const setAiDataPolicy = (policy: AiDataPolicy) =>
  invoke<AiDataPolicy>("set_ai_data_policy", { policy });

export interface ApiKeyStatus {
  provider_id: string;
  has_api_key: boolean;
}

/** 专用秘密写入命令；返回值只包含是否已配置，不回传 Key。 */
export const setProviderApiKey = (providerId: string, apiKey: string) =>
  invoke<ApiKeyStatus>("set_provider_api_key", { providerId, apiKey });

export const deleteProviderApiKey = (providerId: string) =>
  invoke<ApiKeyStatus>("delete_provider_api_key", { providerId });

/** Key 由 Rust 后端按 providerId 从系统凭据库读取。 */
export const fetchModels = (providerId: string) =>
  invoke<string[]>("fetch_models", { providerId });

/** 使用未保存的表单值获取模型；Key 仅用于本次请求，不会写入凭据库。 */
export const fetchModelsForDraft = (baseUrl: string, apiKey: string) =>
  invoke<string[]>("fetch_models_for_draft", { baseUrl, apiKey });

/** 系统浏览器打开外链 */
export const openUrl = (url: string) => invoke<void>("open_url", { url });

// ---------- 项目 ----------
export const listProjects = () => invoke<Project[]>("list_projects");

export const createProject = (
  name: string,
  targetHost: string,
  scope: string[]
) => invoke<number>("create_project", { name, targetHost, scope });

export const deleteProject = (id: number) =>
  invoke<void>("delete_project", { id });

export const getCurrentProject = () =>
  invoke<Project | null>("get_current_project");

export const setCurrentProject = (id: number) =>
  invoke<void>("set_current_project", { id });

export const updateProjectScope = (id: number, scope: string[]) =>
  invoke<void>("update_project_scope", { id, scope });

// ---------- 代理 ----------

export interface ProxyStatus {
  running: boolean;
  port: number;
}

export const startProxy = (port: number) =>
  invoke<ProxyStatus>("start_proxy", { port });

export const stopProxy = () => invoke<ProxyStatus>("stop_proxy");

export const proxyStatus = () => invoke<ProxyStatus>("proxy_status");

// ---------- CA 证书 ----------

export interface CaInfo {
  cert_path: string;
  fingerprint: string;
  trusted: boolean;
}

export const getCaInfo = () => invoke<CaInfo>("get_ca_info");

/** 导出到下载目录，返回保存路径 */
export const exportCaCert = () => invoke<string>("export_ca_cert");

/** 一键安装到当前用户根证书 store，返回 certutil 输出 */
export const installCaCert = () => invoke<string>("install_ca_cert");

export const revealCaCert = () => invoke<void>("reveal_ca_cert");

// ---------- 运行环境（关于页） ----------

export interface RuntimeInfo {
  os: string;
  arch: string;
  app_data_dir: string;
}

export const getRuntimeInfo = () => invoke<RuntimeInfo>("get_runtime_info");

export const revealAppDataDir = () => invoke<void>("reveal_app_data_dir");

// ---------- 流量 ----------

export type BodyDecodeStatus =
  | "not_received"
  | "empty"
  | "identity_text"
  | "identity_binary"
  | "decoded_text"
  | "decoded_binary"
  | "decode_failed"
  | "unsupported_encoding"
  | "encoded_truncated"
  | "decode_truncated"
  | "stream_error"
  | "stream_incomplete";

export interface TrafficSummary {
  id: number;
  project_id: number;
  method: string;
  scheme: string;
  host: string;
  port: number;
  path: string;
  url: string;
  status: number | null;
  content_type: string | null;
  req_wire_size: number;
  resp_wire_size: number;
  req_captured_size: number;
  resp_captured_size: number;
  req_truncated: boolean;
  resp_truncated: boolean;
  req_decode_status: BodyDecodeStatus;
  resp_decode_status: BodyDecodeStatus;
  duration_ms: number;
  rule_tags: string[];
  created_at: string;
}

export interface TrafficTagsUpdate {
  id: number;
  project_id: number;
  rule_tags: string[];
}

export interface TrafficDetail extends TrafficSummary {
  req_headers: string;
  req_body_text: string | null;
  req_body_base64: string | null;
  resp_headers: string | null;
  resp_body_text: string | null;
  resp_body_base64: string | null;
}

export interface TrafficFilter {
  method?: string;
  statusClass?: string;
  search?: string;
  limit?: number;
  offset?: number;
}

export const listTraffic = (projectId: number, f: TrafficFilter = {}) =>
  invoke<TrafficSummary[]>("list_traffic", {
    projectId,
    method: f.method || null,
    statusClass: f.statusClass || null,
    search: f.search || null,
    limit: f.limit ?? 200,
    offset: f.offset ?? 0,
  });

export const getTrafficDetail = (id: number) =>
  invoke<TrafficDetail>("get_traffic_detail", { id });

export const clearTraffic = (projectId: number) =>
  invoke<void>("clear_traffic", { projectId });

// ---------- AI 分析 ----------

export interface StandardReference {
  framework: "owasp-top10" | "owasp-api-top10" | "asvs" | "wstg" | "cwe";
  version: string;
  id: string;
}

export function formatStandardReference(reference: StandardReference): string {
  if (
    reference.framework === "owasp-top10" ||
    reference.framework === "owasp-api-top10"
  ) {
    return `${reference.id}:${reference.version}`;
  }
  if (reference.framework === "asvs") {
    return `ASVS v${reference.version}-${reference.id}`;
  }
  if (reference.framework === "wstg") {
    return `WSTG-v${reference.version.split(".").join("")}-${reference.id.replace(
      /^WSTG-/,
      ""
    )}`;
  }
  if (reference.framework === "cwe") {
    return `${reference.id} (v${reference.version})`;
  }
  return `${reference.framework}@${reference.version}/${reference.id}`;
}

export interface VulnHypothesis {
  vuln_type: string;
  param: string;
  standard_references: StandardReference[];
  severity: string;
  /** 0-100，AI 自评，必须人工复核 */
  confidence: number;
  reasoning: string;
  verify_steps: string;
  evidence_refs: string[];
  grounding_status: "grounded" | "ungrounded";
  validation_notes: string[];
}

export interface AnalysisResult {
  purpose: string;
  suspicious_params: string[];
  hypotheses: VulnHypothesis[];
  summary: string;
  analysis_run_id: number | null;
}

export type AnalysisProgressStage =
  | "preparing"
  | "generating"
  | "validating"
  | "saving"
  | "completed"
  | "failed";

export interface AnalysisProgress {
  request_id: string;
  traffic_id: number;
  stage: AnalysisProgressStage;
  percentage: number;
  message: string;
}

export interface RedactionRecord {
  location: string;
  kind: string;
  count: number;
}

export interface OmissionRecord {
  location: string;
  reason: string;
}

export interface BodyDecision {
  location: string;
  capture_status: string;
  included: boolean;
  reason: string;
  source_bytes: number;
  sent_bytes: number;
  truncated_by_policy: boolean;
}

export interface RedactionManifest {
  redactions: RedactionRecord[];
  omissions: OmissionRecord[];
  disclosures: string[];
  body_decisions: BodyDecision[];
  notes: string[];
  total_input_bytes: number;
}

export interface AiContextPreview {
  traffic_id: number;
  provider_id: string;
  provider_base_url: string;
  model: string;
  prompt_id: string;
  prompt_version: number;
  prompt_source: "builtin" | "custom";
  system_prompt: string;
  user_prompt: string;
  retry_user_prompt: string;
  response_schema: Record<string, unknown> | null;
  input_hash: string;
  policy: AiDataPolicy;
  manifest: RedactionManifest;
  evidence_refs: string[];
  is_relaxed: boolean;
}

export const previewAiContext = (
  trafficId: number,
  policy: AiDataPolicy | null = null
) => invoke<AiContextPreview>("preview_ai_context", { trafficId, policy });

/** 只允许发送与预览哈希完全一致的上下文。 */
export const analyzeTraffic = (
  trafficId: number,
  policy: AiDataPolicy,
  expectedInputHash: string,
  requestId: string
) =>
  invoke<AnalysisResult>("analyze_traffic", {
    trafficId,
    policy,
    expectedInputHash,
    requestId,
  });

/** 读缓存的分析结果（没有则 null） */
export const getAnalysis = (trafficId: number) =>
  invoke<AnalysisResult | null>("get_analysis", { trafficId });

export interface ValidationReport {
  status: "valid" | "invalid";
  errors: string[];
  warnings: string[];
  attempts: number;
  hypotheses_total: number;
  grounded_hypotheses: number;
  ungrounded_hypotheses: number;
}

export interface AnalysisRun {
  id: number;
  project_id: number;
  traffic_id: number | null;
  provider_id: string;
  provider_base_url: string;
  model: string;
  prompt_id: string;
  prompt_version: number;
  input_hash: string;
  policy: AiDataPolicy;
  manifest: RedactionManifest;
  prompt_tokens: number;
  cached_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  schema_applied: boolean;
  validation: ValidationReport;
  raw_output_hash: string;
  created_at: string;
}

export const getAnalysisRun = (runId: number) =>
  invoke<AnalysisRun>("get_analysis_run", { runId });

// ---------- Findings ----------

export interface Finding {
  id: number;
  project_id: number;
  traffic_id: number | null;
  analysis_run_id: number | null;
  source: "ai" | "rule";
  producer: "ai" | "passive_rule" | "safe_verifier";
  title: string;
  vuln_type: string;
  standard_references: StandardReference[];
  severity: string;
  confidence: number;
  reasoning: string;
  verify_steps: string;
  /** pending=待验证 confirmed=已确认 rejected=误报 */
  status: string;
  analyst_notes: string;
  /** 项目 + 规则 + 规范化端点 + 字段的稳定身份；AI Finding 暂为空。 */
  fingerprint: string | null;
  /** 累计关联到该规则 Finding 的不同流量数。 */
  occurrences: number;
  last_seen_at: string;
  created_at: string;
  updated_at: string;
}

export interface FindingTrafficRef {
  traffic_id: number;
  method: string;
  url: string;
  status: number | null;
  first_seen_at: string;
}

export interface FindingRuleHit {
  id: number;
  finding_id: number;
  evaluation_id: number;
  traffic_id: number;
  pack_id: string;
  pack_version: string;
  rule_id: string;
  rule_version: string;
  field_path: string;
  evidence: string;
  confidence: number;
  incomplete_evidence: boolean;
  hit_fingerprint: string;
  created_at: string;
}

export type EvidenceSourceType = "traffic" | "analysis_run" | "replay_run";

export interface Evidence {
  id: number;
  project_id: number;
  source_type: EvidenceSourceType;
  source_id: number;
  source_available: boolean;
  observation: string;
  redacted_snapshot: unknown;
  content_hash: string;
  qualifies_for_confirmation: boolean;
  created_by: string;
  created_at: string;
  linked_at: string;
  accepted: boolean;
  acceptance_note: string;
  accepted_by: string | null;
  accepted_at: string | null;
  acceptance_kind: "human" | "safe_verifier";
  verification_id: number | null;
}

export interface FindingEvent {
  id: number;
  finding_id: number;
  event_type:
    | "created"
    | "status_changed"
    | "severity_changed"
    | "notes_changed"
    | "evidence_accepted"
    | "evidence_revoked";
  old_value: string | null;
  new_value: string | null;
  reason: string;
  actor: string;
  created_at: string;
}

export interface RulePackStatusInfo {
  pack_id: string;
  version: string;
  rule_count: number;
  loaded: boolean;
  disabled_reason: string | null;
}

export interface RuleEvaluationInfo {
  id: number;
  project_id: number;
  traffic_id: number;
  pack_id: string;
  pack_version: string;
  status: "completed" | "timed_out" | "pack_disabled";
  hit_count: number;
  finding_count: number;
  duration_ms: number;
  diagnostics: string[];
  created_at: string;
}

export interface RuleDiagnostics {
  packs: RulePackStatusInfo[];
  submitted_evaluations: number;
  completed_evaluations: number;
  dropped_evaluations: number;
  timed_out_evaluations: number;
  failed_evaluations: number;
  queue_capacity: number;
  queue_depth: number;
  last_error: string | null;
  recent_evaluations: RuleEvaluationInfo[];
  worker_running: boolean;
}

export const listFindings = (
  projectId: number,
  opts: { status?: string; severity?: string; source?: string } = {}
) =>
  invoke<Finding[]>("list_findings", {
    projectId,
    status: opts.status || null,
    severity: opts.severity || null,
    source: opts.source || null,
  });

export const updateFindingStatus = (
  id: number,
  status: string,
  reason?: string | null
) =>
  invoke<Finding>("update_finding_status", {
    id,
    status,
    reason: reason?.trim() || null,
  });

export const updateFindingReview = (
  id: number,
  severity: string,
  analystNotes: string,
  reason?: string | null
) =>
  invoke<Finding>("update_finding_review", {
    id,
    severity,
    analystNotes,
    reason: reason?.trim() || null,
  });

export const listFindingTraffic = (id: number) =>
  invoke<FindingTrafficRef[]>("list_finding_traffic", { id });

export const listFindingRuleHits = (id: number) =>
  invoke<FindingRuleHit[]>("list_finding_rule_hits", { id });

export const listFindingEvidence = (id: number) =>
  invoke<Evidence[]>("list_finding_evidence", { id });

export const listFindingEvents = (id: number) =>
  invoke<FindingEvent[]>("list_finding_events", { id });

export const createFindingEvidence = (
  findingId: number,
  sourceType: EvidenceSourceType,
  sourceId: number,
  observation: string
) =>
  invoke<Evidence>("create_finding_evidence", {
    findingId,
    sourceType,
    sourceId,
    observation,
  });

export const createTaskEvidence = (
  taskId: number,
  sourceType: EvidenceSourceType,
  sourceId: number,
  observation: string
) =>
  invoke<number>("create_task_evidence", {
    taskId,
    sourceType,
    sourceId,
    observation,
  });

export const setFindingEvidenceAccepted = (
  findingId: number,
  evidenceId: number,
  accepted: boolean,
  reason: string
) =>
  invoke<Evidence>("set_finding_evidence_accepted", {
    findingId,
    evidenceId,
    accepted,
    reason,
  });

export const getRuleDiagnostics = (projectId: number) =>
  invoke<RuleDiagnostics>("get_rule_diagnostics", { projectId });

export const deleteFinding = (id: number) =>
  invoke<void>("delete_finding", { id });

// ---------- 提示词模板 ----------

export interface PromptTemplateVersion {
  id: number | null;
  prompt_id: string;
  version: number;
  source: "builtin" | "custom";
  content: string;
  based_on_id: number | null;
  operation: "builtin" | "save" | "copy" | "rollback";
  created_at: string | null;
  active: boolean;
}

export const getPromptTemplate = () =>
  invoke<PromptTemplateVersion>("get_prompt_template");

export const listPromptVersions = () =>
  invoke<PromptTemplateVersion[]>("list_prompt_versions");

export const setPromptTemplate = (content: string) =>
  invoke<PromptTemplateVersion>("set_prompt_template", { content });

export const copyPromptTemplate = (sourceId: number | null) =>
  invoke<PromptTemplateVersion>("copy_prompt_template", { sourceId });

export const rollbackPromptTemplate = (sourceId: number | null) =>
  invoke<PromptTemplateVersion>("rollback_prompt_template", { sourceId });

export const resetPromptTemplate = () =>
  invoke<PromptTemplateVersion>("reset_prompt_template");

// ---------- 版本化测试计划 ----------

export type TaskNodeType = "hypothesis" | "test" | "decision" | "manual_note";
export type TaskStatus =
  | "todo"
  | "in_progress"
  | "done"
  | "blocked"
  | "skipped"
  | "not_applicable";
export type TaskSource = "ai" | "rule" | "manual";

export interface TaskNode {
  id: number;
  project_id: number;
  parent_id: number | null;
  stable_key: string;
  node_type: TaskNodeType;
  title: string;
  /** 做什么 */
  description: string;
  /** 为什么做这步 */
  why: string;
  /** 怎么做 */
  how_to: string;
  /** 完成判定标准 */
  verify_criteria: string;
  /** 0 为最高优先级 */
  priority: number;
  required_role: string;
  required_session: string;
  expected_observation: string;
  actual_observation: string;
  blocker_reason: string;
  source: TaskSource;
  locked_fields: string[];
  status: TaskStatus;
  sort_order: number;
  archived: boolean;
  archived_at: string | null;
  created_revision: number;
  updated_revision: number;
  created_at: string;
  updated_at: string;
  standard_references: StandardReference[];
  finding_ids: number[];
  prerequisite_ids: number[];
  evidence_ids: number[];
  risk_rank: number;
}

export interface TestPlan {
  project_id: number;
  revision: number;
  needs_update: boolean;
  update_reason: string;
  last_applied_proposal_id: number | null;
  created_at: string;
  updated_at: string;
}

export interface TaskPlanDiffItem {
  stable_key: string;
  node_id: number | null;
  title: string;
  changed_fields: string[];
  reason: string;
}

export interface TaskPlanDiff {
  additions: TaskPlanDiffItem[];
  updates: TaskPlanDiffItem[];
  preserved: TaskPlanDiffItem[];
  archives: TaskPlanDiffItem[];
}

export interface TaskPlanProposal {
  id: number;
  project_id: number;
  proposal_key: string;
  operation: TaskAiOperation;
  target_node_id: number | null;
  base_revision: number;
  analysis_run_id: number | null;
  status: "pending" | "applied" | "rejected" | "superseded";
  diff: TaskPlanDiff;
  created_at: string;
  applied_at: string | null;
}

export interface TaskPlanApplyResult {
  proposal_id: number;
  revision: number;
  applied: boolean;
  diff: TaskPlanDiff;
}

export interface TaskPlanEvent {
  id: number;
  project_id: number;
  revision: number;
  event_type: string;
  proposal_id: number | null;
  node_id: number | null;
  details: Record<string, unknown>;
  actor: string;
  created_at: string;
}

export interface CreateTaskNodeInput {
  project_id: number;
  parent_id: number | null;
  node_type: TaskNodeType;
  title: string;
  description: string;
  why: string;
  how_to: string;
  verify_criteria: string;
  priority: number;
  required_role: string;
  required_session: string;
  expected_observation: string;
  actual_observation: string;
  prerequisite_ids: number[];
}

export interface UpdateTaskNodeInput {
  node_id: number;
  node_type: TaskNodeType;
  title: string;
  description: string;
  why: string;
  how_to: string;
  verify_criteria: string;
  priority: number;
  required_role: string;
  required_session: string;
  expected_observation: string;
  actual_observation: string;
  prerequisite_ids: number[];
  locked_fields: string[];
}

export const getTaskTree = (projectId: number) =>
  invoke<TaskNode[]>("get_task_tree", { projectId });

export type TaskAiOperation = "generate" | "expand" | "alternative";

export interface TaskAiExecution {
  analysis_run_id: number;
  proposal: TaskPlanProposal;
}

export type TaskAiProgressStage =
  | "preparing"
  | "generating"
  | "validating"
  | "saving"
  | "proposal"
  | "completed"
  | "failed";

export interface TaskAiProgress {
  request_id: string;
  project_id: number;
  operation: TaskAiOperation;
  stage: TaskAiProgressStage;
  percentage: number;
  message: string;
}

export const getTestPlan = (projectId: number) =>
  invoke<TestPlan>("get_test_plan", { projectId });

export const listTaskPlanEvents = (projectId: number) =>
  invoke<TaskPlanEvent[]>("list_task_plan_events", { projectId });

export const previewTaskAi = (
  operation: TaskAiOperation,
  projectId: number | null,
  nodeId: number | null
) =>
  invoke<AiContextPreview>("preview_task_ai", {
    operation,
    projectId,
    nodeId,
  });

/** AI 只生成 proposal/diff，不直接修改当前测试计划。 */
export const generateTaskTree = (
  projectId: number,
  expectedInputHash: string,
  requestId: string
) =>
  invoke<TaskAiExecution>("generate_task_tree", {
    projectId,
    expectedInputHash,
    requestId,
  });

export const expandTaskNode = (nodeId: number, expectedInputHash: string) =>
  invoke<TaskAiExecution>("expand_task_node", { nodeId, expectedInputHash });

export const alternativeTaskNode = (nodeId: number, expectedInputHash: string) =>
  invoke<TaskAiExecution>("alternative_task_node", { nodeId, expectedInputHash });

export const nextTask = (projectId: number) =>
  invoke<TaskNode | null>("next_task", { projectId });

export const applyTaskPlanProposal = (projectId: number, proposalId: number) =>
  invoke<TaskPlanApplyResult>("apply_task_plan_proposal", {
    projectId,
    proposalId,
  });

export const rejectTaskPlanProposal = (proposalId: number) =>
  invoke<void>("reject_task_plan_proposal", { proposalId });

export const updateTaskStatus = (
  nodeId: number,
  status: TaskStatus,
  reason: string | null
) => invoke<TaskNode>("update_task_status", { nodeId, status, reason });

export const createTaskNode = (input: CreateTaskNodeInput) =>
  invoke<number>("create_task_node", { input });

export const updateTaskNode = (input: UpdateTaskNodeInput) =>
  invoke<TaskNode>("update_task_node", { input });

export const deleteTaskNode = (nodeId: number) =>
  invoke<void>("delete_task_node", { nodeId });

export const getTaskFindings = (nodeId: number) =>
  invoke<Finding[]>("get_task_findings", { nodeId });

// ---------- 知识库（OWASP/CWE 卡片） ----------

export interface KnowledgeCard {
  reference: StandardReference;
  key: string;
  framework_label: string;
  pack_title: string;
  title: string;
  /** 原理 */
  principle: string;
  /** 危害 */
  impact: string;
  /** 常见成因 */
  cause: string;
  /** 修复建议 */
  remediation: string;
  source_url: string;
  published_at: string;
  license_name: string;
  license_url: string;
}

/** 未能解析成知识卡的引用，绝不会退回成某个近似条目。 */
export interface UnresolvedReference {
  reference: StandardReference;
  key: string;
  framework_label: string;
  /** not_in_pack=编号合法但精选包未收录；invalid=编号本身不成立 */
  state: "not_in_pack" | "invalid";
  reason: string;
}

export interface KnowledgeLookup {
  cards: KnowledgeCard[];
  unresolved: UnresolvedReference[];
}

export const getKnowledgeCards = (references: StandardReference[]) =>
  invoke<KnowledgeLookup>("get_knowledge_cards", { references });

// ---------- Repeater（手动改包重发） ----------

export interface ReplayHeader {
  name: string;
  value: string;
}

export type TlsPolicy = "strict" | "ignore_invalid";

export interface ScopeDecision {
  normalized_host: string;
  matched_scope: string;
  match_kind: "exact" | "wildcard";
}

export interface ReplayScopeSnapshot {
  allowed: boolean;
  normalized_host: string | null;
  matched_scope: string | null;
  match_kind: "exact" | "wildcard" | null;
  reason_code: string | null;
  reason: string | null;
}

export interface ReplaySession {
  id: number;
  project_id: number;
  title: string;
  source_traffic_id: number | null;
  tls_policy: TlsPolicy;
  is_selected: boolean;
  run_count: number;
  last_run_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface ReplayRun {
  id: number;
  attempt_id: number | null;
  session_id: number;
  project_id: number;
  method: string;
  url: string;
  request_headers: ReplayHeader[];
  request_wire_body_text: string | null;
  request_wire_body_base64: string | null;
  req_wire_captured_size: number;
  req_wire_truncated: boolean;
  request_input: ReplayRequestInputSnapshot;
  request_body_text: string | null;
  request_body_base64: string | null;
  req_wire_size: number;
  req_captured_size: number;
  req_truncated: boolean;
  req_decode_status: BodyDecodeStatus;
  tls_policy: TlsPolicy;
  scope_decision: ReplayScopeSnapshot;
  outcome:
    | "completed"
    | "scope_rejected"
    | "request_failed"
    | "response_incomplete";
  error_code: string | null;
  error_message: string | null;
  status: number | null;
  status_text: string;
  response_headers: ReplayHeader[];
  response_body_text: string | null;
  response_body_base64: string | null;
  resp_wire_size: number;
  resp_captured_size: number;
  resp_truncated: boolean;
  resp_decode_status: BodyDecodeStatus;
  duration_ms: number;
  request_hash: string;
  req_body_hash: string | null;
  response_hash: string | null;
  resp_body_hash: string | null;
  created_at: string;
}

export interface ReplayRequestInputSnapshot {
  encoding: "none" | "text" | "base64" | "ambiguous";
  text: string | null;
  base64: string | null;
  original_size: number;
  captured_size: number;
  truncated: boolean;
  content_hash: string;
}

export interface ReplayRunSummary {
  id: number;
  session_id: number;
  project_id: number;
  method: string;
  url: string;
  tls_policy: TlsPolicy;
  outcome: ReplayRun["outcome"];
  error_code: string | null;
  error_message: string | null;
  status: number | null;
  status_text: string;
  req_wire_size: number;
  req_wire_captured_size: number;
  req_wire_truncated: boolean;
  req_decode_status: BodyDecodeStatus;
  resp_wire_size: number;
  resp_captured_size: number;
  resp_truncated: boolean;
  resp_decode_status: BodyDecodeStatus;
  duration_ms: number;
  request_hash: string;
  response_hash: string | null;
  created_at: string;
}

export interface ReplayRunPage {
  runs: ReplayRunSummary[];
  next_before_id: number | null;
}

export interface ReplayBodySnapshot {
  encoding: "text" | "base64" | "empty";
  text: string | null;
  base64: string | null;
  wire_size: number;
  captured_size: number;
  truncated: boolean;
  decode_status: BodyDecodeStatus;
  captured_hash: string;
  /** 完整 wire 正文哈希；构造失败时为规范化原始输入哈希。 */
  full_hash: string | null;
}

export interface ReplayValueDiff<T> {
  changed: boolean;
  indeterminate: boolean;
  left: T;
  right: T;
}

export interface ReplayRunDiff {
  left_run_id: number;
  right_run_id: number;
  method: ReplayValueDiff<string>;
  url: ReplayValueDiff<string>;
  request_headers: ReplayValueDiff<ReplayHeader[]>;
  request_body: ReplayValueDiff<ReplayBodySnapshot>;
  tls_policy: ReplayValueDiff<TlsPolicy>;
  scope_decision: ReplayValueDiff<ReplayScopeSnapshot>;
  outcome: ReplayValueDiff<ReplayRun["outcome"]>;
  status: ReplayValueDiff<number | null>;
  duration_ms: ReplayValueDiff<number>;
  response_headers: ReplayValueDiff<ReplayHeader[]>;
  response_body: ReplayValueDiff<ReplayBodySnapshot>;
}

/** 只做后端 ScopePolicy 判定，不建立网络连接。真正发送时后端会再次校验。 */
export const authorizeReplayTarget = (
  projectId: number | null,
  url: string
) =>
  invoke<ScopeDecision>("authorize_replay_target", { projectId, url });

export const listReplaySessions = (projectId: number) =>
  invoke<ReplaySession[]>("list_replay_sessions", { projectId });

export const createReplaySession = (
  projectId: number,
  title: string,
  sourceTrafficId: number | null,
  tlsPolicy: TlsPolicy
) =>
  invoke<ReplaySession>("create_replay_session", {
    projectId,
    title,
    sourceTrafficId,
    tlsPolicy,
  });

export const updateReplaySession = (
  sessionId: number,
  title: string,
  tlsPolicy: TlsPolicy
) =>
  invoke<ReplaySession>("update_replay_session", {
    sessionId,
    title,
    tlsPolicy,
  });

export const selectReplaySession = (sessionId: number) =>
  invoke<ReplaySession>("select_replay_session", { sessionId });

export const deleteReplaySession = (sessionId: number) =>
  invoke<void>("delete_replay_session", { sessionId });

export const listReplayRuns = (
  sessionId: number,
  beforeId: number | null = null,
  limit = 50
) =>
  invoke<ReplayRunPage>("list_replay_runs", { sessionId, beforeId, limit });

export const getReplayRun = (projectId: number, runId: number) =>
  invoke<ReplayRun>("get_replay_run", { projectId, runId });

export const compareReplayRuns = (
  projectId: number,
  leftRunId: number,
  rightRunId: number
) =>
  invoke<ReplayRunDiff>("compare_replay_runs", {
    projectId,
    leftRunId,
    rightRunId,
  });

export const replayRequest = (
  projectId: number,
  sessionId: number,
  method: string,
  url: string,
  headers: ReplayHeader[],
  bodyText: string | null,
  bodyBase64: string | null
) =>
  invoke<ReplayRun>("replay_request", {
    projectId,
    sessionId,
    request: {
      method,
      url,
      headers,
      bodyText,
      bodyBase64,
    },
  });

// ---------- AI 非破坏式安全评估 ----------

export type AssessmentStatus =
  | "queued"
  | "discovering"
  | "planning"
  | "executing"
  | "verifying"
  | "completed"
  | "stopped"
  | "cancelled"
  | "failed"
  | "interrupted";

export type AssessmentVerdict =
  | "confirmed"
  | "suspected"
  | "not_observed"
  | "inconclusive"
  | "skipped";

export interface AssessmentAuthProfile {
  id: number;
  projectId: number;
  label: string;
  sourceTrafficId: number | null;
  headerName: "Authorization" | "Cookie" | "X-API-Key" | "X-Auth-Token";
  secretRevision: number;
  hasSecret: boolean;
  createdAt: string;
  updatedAt: string;
}

/** Traffic 中可提取指定鉴权 Header 的候选请求；只含元数据，不含 Header 值。 */
export interface AssessmentAuthCandidate {
  trafficId: number;
  method: string;
  url: string;
  status: number | null;
  createdAt: string;
}

export interface ResourceOwnershipClaim {
  path: string;
  ownerProfileId: number;
}

export interface AssessmentContractInput {
  projectId: number;
  startUrl: string;
  excludedPaths: string[];
  tlsPolicy: TlsPolicy;
  requestBudget: number;
  requestsPerSecond: number;
  identityAProfileId: number | null;
  identityBProfileId: number | null;
  resourceOwnership: ResourceOwnershipClaim[];
  includeRecentTraffic: boolean;
  /** 留空时由后端绑定当前活动 provider/model。 */
  providerId: string;
  model: string;
  maxRounds: number;
  writtenAuthorizationConfirmed: boolean;
}

export interface AssessmentContractPreview {
  projectId: number;
  normalizedStartUrl: string;
  exactOrigin: string;
  normalizedScope: string[];
  excludedPaths: string[];
  builtinExcludedSegments: string[];
  tlsPolicy: TlsPolicy;
  requestBudget: number;
  discoveryBudget: number;
  requestsPerSecond: number;
  identityAProfileId: number | null;
  identityALabel: string | null;
  identityASecretRevision: number | null;
  identityBProfileId: number | null;
  identityBLabel: string | null;
  identityBSecretRevision: number | null;
  resourceOwnership: ResourceOwnershipClaim[];
  includeRecentTraffic: boolean;
  providerId: string;
  model: string;
  maxRounds: number;
  dataDisclosure: string[];
  templateRegistryVersion: string;
  templateRegistryHash: string;
  contractHash: string;
  writtenAuthorizationConfirmed: boolean;
  residualRiskNotice: string;
}

export interface AssessmentRun {
  id: number;
  projectId: number;
  status: AssessmentStatus;
  startUrl: string;
  exactOrigin: string;
  contractHash: string;
  templateRegistryHash: string;
  providerId: string;
  model: string;
  tlsPolicy: TlsPolicy;
  requestBudget: number;
  requestCount: number;
  discoveryBudget: number;
  requestsPerSecond: number;
  responseByteBudget: number;
  responseBytesRead: number;
  maxRounds: number;
  completedRounds: number;
  stopReason: string;
  createdAt: string;
  startedAt: string | null;
  endedAt: string | null;
}

export interface AssessmentRound {
  id: number;
  runId: number;
  roundNumber: number;
  status: string;
  analysisRunId: number | null;
  inputHash: string;
  outputHash: string | null;
  selectedChecks: number;
  rejectionJson: unknown;
  createdAt: string;
  completedAt: string | null;
}

export interface AssessmentEndpoint {
  id: number;
  runId: number;
  endpointId: string;
  method: "GET" | "HEAD";
  url: string;
  path: string;
  queryParameterNames: string[];
  sourceKind: "start_url" | "crawl" | "redirect" | "traffic";
  status: number | null;
  contentType: string;
  hasAuthentication: boolean;
  passiveTags: string[];
  responseComplete: boolean;
  resourceOwnerProfileId: number | null;
}

export interface AssessmentCheck {
  id: number;
  runId: number;
  roundId: number | null;
  endpointId: number | null;
  requestedEndpointId: string;
  templateId: string;
  templateVersion: string;
  parameterName: string | null;
  identityMode: "anonymous" | "a" | "b" | "a_vs_b";
  rationale: string;
  policyResult: "allowed" | "rejected" | "skipped";
  policyReason: string;
  status: string;
  requestCost: number;
  createdAt: string;
  completedAt: string | null;
}

export interface AssessmentVerification {
  id: number;
  checkId: number;
  verifierId: string;
  verifierVersion: string;
  verdict: AssessmentVerdict;
  observations: unknown;
  contentHash: string;
  findingId: number | null;
  findingRelation: "supports" | "human_conflict" | null;
  createdAt: string;
}

export interface AssessmentCoverageGap {
  id: number;
  runId: number;
  checkId: number | null;
  category: string;
  reasonCode: string;
  detail: string;
  createdAt: string;
}

export interface AssessmentEvent {
  id: number;
  runId: number;
  checkId: number | null;
  eventType: string;
  oldValue: string | null;
  newValue: string | null;
  details: unknown;
  createdAt: string;
}

export interface AssessmentDetail {
  run: AssessmentRun;
  rounds: AssessmentRound[];
  endpoints: AssessmentEndpoint[];
  checks: AssessmentCheck[];
  verifications: AssessmentVerification[];
  coverageGaps: AssessmentCoverageGap[];
  events: AssessmentEvent[];
}

export interface AssessmentProgress {
  projectId: number;
  runId: number;
  status: AssessmentStatus;
  phase: string;
  message: string;
  requestCount: number;
  requestBudget: number;
  completedChecks: number;
  totalChecks: number;
  occurredAt: string;
}

export const listAssessmentAuthProfiles = (projectId: number) =>
  invoke<AssessmentAuthProfile[]>("list_assessment_auth_profiles", { projectId });

export const createAssessmentAuthProfile = (input: {
  projectId: number;
  label: string;
  headerName: AssessmentAuthProfile["headerName"];
  secret: string;
  sourceTrafficId: number | null;
}) => invoke<AssessmentAuthProfile>("create_assessment_auth_profile", { input });

export const setAssessmentAuthProfile = (input: {
  projectId: number;
  profileId: number;
  headerName: AssessmentAuthProfile["headerName"];
  secret: string;
}) => invoke<AssessmentAuthProfile>("set_assessment_auth_profile", { input });

export const importAssessmentAuthProfile = (input: {
  projectId: number;
  trafficId: number;
  label: string;
  headerName: AssessmentAuthProfile["headerName"];
}) => invoke<AssessmentAuthProfile>("import_assessment_auth_profile", { input });

export const listAssessmentAuthCandidates = (
  projectId: number,
  headerName: AssessmentAuthProfile["headerName"]
) =>
  invoke<AssessmentAuthCandidate[]>("list_assessment_auth_candidates", {
    projectId,
    headerName,
  });

export const deleteAssessmentAuthProfile = (projectId: number, profileId: number) =>
  invoke<void>("delete_assessment_auth_profile", { projectId, profileId });

export const previewAssessmentContract = (input: AssessmentContractInput) =>
  invoke<AssessmentContractPreview>("preview_assessment_contract", { input });

export const startAssessment = (
  contract: AssessmentContractInput,
  contractHash: string
) => invoke<AssessmentRun>("start_assessment", { input: { contract, contractHash } });

export const cancelAssessment = (projectId: number, runId: number) =>
  invoke<void>("cancel_assessment", { projectId, runId });

export const listAssessmentRuns = (projectId: number) =>
  invoke<AssessmentRun[]>("list_assessment_runs", { projectId });

export const getAssessmentDetail = (projectId: number, runId: number) =>
  invoke<AssessmentDetail>("get_assessment_detail", { projectId, runId });

// ---------- AI 安全评估 Mission v2 ----------

export type AssessmentMissionStatus =
  | "draft"
  | "awaiting_context_approval"
  | "queued"
  | "discovering"
  | "planning"
  | "awaiting_action_approval"
  | "executing"
  | "verifying"
  | "awaiting_manual_handoff"
  | "completed"
  | "stopped"
  | "cancelled"
  | "failed"
  | "interrupted";

export type AssessmentAutonomyMode = "manual" | "smart" | "automatic";
export type AssessmentBudgetProfile = "quick" | "standard" | "deep";
export type AssessmentToolPermissionDecision = "disabled" | "ask" | "execute";

export interface MissionToolDescriptor {
  id: string;
  version: string;
  displayName: string;
  description: string;
  executionKind: "observe" | "safe_probe" | "manual_recipe";
  riskLevel: string;
  parameterSchema: unknown;
  allowedIdentityModes: string[];
  requestCost: number;
  defaultPermission: AssessmentToolPermissionDecision;
  effectivePermission: AssessmentToolPermissionDecision;
  canAutoConfirm: boolean;
}

export interface AssessmentMission {
  id: number;
  projectId: number;
  title: string;
  goal: string;
  startUrl: string;
  exactOrigin: string;
  status: AssessmentMissionStatus;
  autonomyMode: AssessmentAutonomyMode;
  budgetProfile: AssessmentBudgetProfile;
  requestBudget: number;
  requestCount: number;
  maxPlanningCycles: number;
  completedCycles: number;
  requestsPerSecond: number;
  identityAProfileId: number | null;
  identityBProfileId: number | null;
  providerId: string;
  model: string;
  tlsPolicy: TlsPolicy;
  includeRecentTraffic: boolean;
  contractHash: string;
  toolRegistryHash: string;
  permissionHash: string;
  contextHash: string | null;
  contextApprovedHash: string | null;
  activeRunId: number | null;
  legacyRunId: number | null;
  legacy: boolean;
  revision: number;
  pendingSteering: boolean;
  stopReason: string;
  createdAt: string;
  updatedAt: string;
  startedAt: string | null;
  endedAt: string | null;
}

export interface AssessmentMissionMessage {
  id: number;
  missionId: number;
  role: "user" | "assistant" | "system" | "action";
  messageKind: string;
  content: string;
  contentHash: string;
  oldValue: string | null;
  newValue: string | null;
  details: unknown;
  redactionManifest: string[];
  revision: number;
  createdAt: string;
}

export interface AssessmentWorkstream {
  id: number;
  missionId: number;
  parentId: number | null;
  stableKey: string;
  title: string;
  objective: string;
  status: string;
  sortOrder: number;
  createdAt: string;
  updatedAt: string;
}

export interface AssessmentAction {
  id: number;
  missionId: number;
  workstreamId: number | null;
  toolId: string;
  toolVersion: string;
  executionKind: "observe" | "safe_probe" | "manual_recipe";
  riskLevel: string;
  surfaceId: string | null;
  identityMode: string;
  parameters: unknown;
  rationale: string;
  expectedSignal: string;
  requestCost: number;
  permissionSnapshot: AssessmentToolPermissionDecision;
  permissionHash: string;
  approvalStatus: string;
  approvalSource: string;
  status: string;
  policyReason: string;
  redactedRequest: unknown | null;
  requestHash: string | null;
  redactedResponse: unknown | null;
  responseHash: string | null;
  result: unknown | null;
  resultHash: string | null;
  revision: number;
  createdAt: string;
  approvedAt: string | null;
  startedAt: string | null;
  completedAt: string | null;
}

export interface AssessmentMissionResource {
  id: number;
  missionId: number;
  resourceType: "traffic" | "finding" | "assessment_run" | "openapi";
  sourceId: number | null;
  displayName: string;
  mediaType: string;
  summary: unknown;
  contentHash: string;
  createdAt: string;
}

export interface AssessmentSurface {
  id: number;
  runId: number;
  surfaceId: string;
  surfaceKind: string;
  method: string;
  pathShape: string;
  queryParameterNames: string[];
  formFields: unknown[];
  contentTypes: string[];
  identityVisibility: unknown;
  responseStructureHash: string | null;
  sourceKinds: string[];
  safeToRequest: boolean;
  concreteCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface AssessmentToolPermission {
  projectId: number;
  toolId: string;
  decision: AssessmentToolPermissionDecision;
  revision: number;
  updatedAt: string;
}

export interface AssessmentManualHandoff {
  id: number;
  actionId: number;
  recipeId: string;
  recipeVersion: string;
  draft: unknown;
  draftHash: string;
  replaySessionId: number | null;
  replayRunId: number | null;
  evidenceId: number | null;
  status: string;
  createdAt: string;
  updatedAt: string;
}

export interface AssessmentHandoffReplayDraft {
  handoffId: number;
  missionId: number;
  actionId: number;
  recipeId: string;
  recipeVersion: string;
  draft: {
    sendAutomatically?: boolean;
    requiresUserClick?: boolean;
    request?: {
      method: string;
      url: string;
      headers: ReplayHeader[];
      bodyText: string | null;
      bodyBase64: string | null;
    };
    proposedDifference?: {
      field?: string | null;
      reviewMarker?: string;
      instructions?: string;
    };
    [key: string]: unknown;
  };
  draftHash: string;
  status: string;
}

export interface MissionCoverageSummary {
  confirmed: number;
  suspected: number;
  notObserved: number;
  coverageGap: number;
}

export interface AssessmentMissionDetail {
  mission: AssessmentMission;
  messages: AssessmentMissionMessage[];
  workstreams: AssessmentWorkstream[];
  actions: AssessmentAction[];
  resources: AssessmentMissionResource[];
  surfaces: AssessmentSurface[];
  toolPermissions: AssessmentToolPermission[];
  handoffs: AssessmentManualHandoff[];
  coverage: MissionCoverageSummary;
}

export interface MissionContextPreview {
  projectId: number;
  missionId: number;
  revision: number;
  contextHash: string;
  contractHash: string;
  toolRegistryHash: string;
  permissionHash: string;
  disclosureManifest: string[];
  contextSummary: unknown;
  tools: MissionToolDescriptor[];
  requiresApproval: boolean;
  approved: boolean;
}

export interface AssessmentMissionEvent {
  projectId: number;
  missionId: number;
  runId: number | null;
  actionId: number | null;
  revision: number;
  eventType: string;
  status: AssessmentMissionStatus;
  phase: string;
  message: string;
  requestCount: number;
  requestBudget: number;
  completedChecks: number;
  totalChecks: number;
  occurredAt: string;
}

export interface CreateAssessmentMissionInput {
  projectId: number;
  title?: string | null;
  goal: string;
  startUrl: string;
  excludedPaths?: string[];
  tlsPolicy?: TlsPolicy;
  identityAProfileId?: number | null;
  identityBProfileId?: number | null;
  includeRecentTraffic?: boolean;
  autonomyMode?: AssessmentAutonomyMode;
  budgetProfile?: AssessmentBudgetProfile;
  writtenAuthorizationConfirmed: boolean;
}

export const createAssessmentMission = (input: CreateAssessmentMissionInput) =>
  invoke<AssessmentMissionDetail>("create_assessment_mission", { input });

export const listAssessmentMissions = (projectId: number) =>
  invoke<AssessmentMission[]>("list_assessment_missions", { projectId });

export const getAssessmentMissionDetail = (projectId: number, missionId: number) =>
  invoke<AssessmentMissionDetail>("get_assessment_mission_detail", {
    projectId,
    missionId,
  });

export const previewAssessmentMissionContext = (
  projectId: number,
  missionId: number
) =>
  invoke<MissionContextPreview>("preview_assessment_mission_context", {
    projectId,
    missionId,
  });

export const confirmAssessmentMissionContext = (input: {
  projectId: number;
  missionId: number;
  expectedRevision: number;
  contextHash: string;
}) =>
  invoke<AssessmentMissionDetail>("confirm_assessment_mission_context", { input });

export const attachAssessmentMissionResource = (input: {
  projectId: number;
  missionId: number;
  expectedRevision: number;
  resourceType: "traffic" | "finding" | "assessment_run";
  sourceId: number;
}) => invoke<AssessmentMissionDetail>("attach_assessment_mission_resource", { input });

export const pickAssessmentOpenApiFile = () =>
  invoke<string | null>("pick_assessment_openapi_file");

export const importAssessmentMissionOpenApi = (input: {
  projectId: number;
  missionId: number;
  expectedRevision: number;
  path: string;
}) => invoke<AssessmentMissionDetail>("import_assessment_mission_openapi", { input });

export const sendAssessmentMissionMessage = (input: {
  projectId: number;
  missionId: number;
  expectedRevision: number;
  content: string;
}) => invoke<AssessmentMissionDetail>("send_assessment_mission_message", { input });

export const decideAssessmentAction = (input: {
  projectId: number;
  missionId: number;
  actionId: number;
  expectedMissionRevision: number;
  expectedActionRevision: number;
  approve: boolean;
  applyToSameTool?: boolean;
}) => invoke<AssessmentMissionDetail>("decide_assessment_action", { input });

export const getAssessmentActionDetail = (
  projectId: number,
  missionId: number,
  actionId: number
) =>
  invoke<AssessmentAction>("get_assessment_action_detail", {
    projectId,
    missionId,
    actionId,
  });

export const setAssessmentToolPermission = (input: {
  projectId: number;
  toolId: string;
  decision: AssessmentToolPermissionDecision;
  expectedRevision?: number | null;
}) => invoke<AssessmentToolPermission[]>("set_assessment_tool_permission", { input });

export const createAssessmentMissionHandoff = (input: {
  projectId: number;
  missionId: number;
  actionId: number;
  expectedActionRevision: number;
}) => invoke<AssessmentManualHandoff>("create_assessment_mission_handoff", { input });

export const linkAssessmentMissionHandoffReplay = (input: {
  projectId: number;
  missionId: number;
  handoffId: number;
  replayRunId: number;
}) =>
  invoke<AssessmentManualHandoff>("link_assessment_mission_handoff_replay", { input });

export const getReplaySessionAssessmentHandoff = (
  projectId: number,
  sessionId: number
) =>
  invoke<AssessmentHandoffReplayDraft | null>(
    "get_replay_session_assessment_handoff",
    { projectId, sessionId }
  );

export const startAssessmentMission = (input: {
  projectId: number;
  missionId: number;
  expectedRevision: number;
}) => invoke<AssessmentMissionDetail>("start_assessment_mission", { input });

export const stopAssessmentMission = (input: {
  projectId: number;
  missionId: number;
  expectedRevision: number;
}) => invoke<AssessmentMissionDetail>("stop_assessment_mission", { input });

// ---------- 证据化报告 ----------

/** 生成 Markdown 报告文本（预览用） */
export const buildReport = (
  projectId: number,
  assessmentRunId: number | null = null
) => invoke<string>("build_report", { projectId, assessmentRunId });

export const buildAssessmentMissionReport = (projectId: number, missionId: number) =>
  invoke<string>("build_assessment_mission_report", { projectId, missionId });

export interface ReportExportResult {
  markdown_path: string;
  json_path: string;
  contains_sensitive_evidence: boolean;
}

/** 同时导出 Markdown 主报告与 JSON 机器可读备份。 */
export const exportReport = (
  projectId: number,
  includeSensitiveEvidence = false,
  assessmentRunId: number | null = null
) =>
  invoke<ReportExportResult>("export_report", {
    projectId,
    includeSensitiveEvidence,
    assessmentRunId,
  });

export const exportAssessmentMissionReport = (projectId: number, missionId: number) =>
  invoke<ReportExportResult>("export_assessment_mission_report", {
    projectId,
    missionId,
  });

// ---------- 用量统计 & 计数（Phase 5） ----------

export interface TokenUsage {
  calls: number;
  prompt_tokens: number;
  cached_tokens: number;
  completion_tokens: number;
  total_tokens: number;
}

/** 本机累计 AI token 用量 */
export const getTokenUsage = () => invoke<TokenUsage>("get_token_usage");

export const resetTokenUsage = () => invoke<void>("reset_token_usage");

export interface UsageTrendPoint {
  period: string;
  calls: number;
  prompt_tokens: number;
  cached_tokens: number;
  completion_tokens: number;
  total_tokens: number;
}

export function getUsageTrend(
  granularity: 'day' | 'month',
): Promise<UsageTrendPoint[]> {
  return invoke('get_usage_trend', { granularity });
}

/** 按筛选条件统计流量总条数（分页用） */
export const countTraffic = (projectId: number, f: TrafficFilter = {}) =>
  invoke<number>("count_traffic", {
    projectId,
    method: f.method || null,
    statusClass: f.statusClass || null,
    search: f.search || null,
  });
