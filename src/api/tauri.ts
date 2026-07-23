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

/** 从供应商 /models 端点拉取可用模型（CC-switch 风格「获取模型」） */
export const fetchModels = (baseUrl: string, apiKey: string) =>
  invoke<string[]>("fetch_models", { baseUrl, apiKey });

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

// ---------- 流量 ----------

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
  req_size: number;
  resp_size: number;
  duration_ms: number;
  rule_tags: string[];
  created_at: string;
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

export interface VulnHypothesis {
  vuln_type: string;
  param: string;
  owasp: string;
  cwe: string;
  severity: string;
  /** 0-100，AI 自评，必须人工复核 */
  confidence: number;
  reasoning: string;
  verify_steps: string;
}

export interface AnalysisResult {
  purpose: string;
  suspicious_params: string[];
  hypotheses: VulnHypothesis[];
  summary: string;
}

/** 触发 AI 分析（后端会落缓存 + 生成 Finding） */
export const analyzeTraffic = (trafficId: number) =>
  invoke<AnalysisResult>("analyze_traffic", { trafficId });

/** 读缓存的分析结果（没有则 null） */
export const getAnalysis = (trafficId: number) =>
  invoke<AnalysisResult | null>("get_analysis", { trafficId });

// ---------- Findings ----------

export interface Finding {
  id: number;
  project_id: number;
  traffic_id: number | null;
  source: "ai" | "rule";
  title: string;
  vuln_type: string;
  owasp: string;
  cwe: string;
  severity: string;
  confidence: number;
  reasoning: string;
  verify_steps: string;
  /** pending=待验证 confirmed=已确认 rejected=误报 */
  status: string;
  created_at: string;
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

export const updateFindingStatus = (id: number, status: string) =>
  invoke<void>("update_finding_status", { id, status });

export const deleteFinding = (id: number) =>
  invoke<void>("delete_finding", { id });

// ---------- 提示词模板 ----------

export const getPromptTemplate = () =>
  invoke<string>("get_prompt_template");

export const setPromptTemplate = (content: string) =>
  invoke<void>("set_prompt_template", { content });

export const resetPromptTemplate = () =>
  invoke<void>("reset_prompt_template");

// ---------- 渗透任务树 ----------

export interface TaskNode {
  id: number;
  project_id: number;
  parent_id: number | null;
  title: string;
  /** 做什么 */
  description: string;
  /** 为什么做这步 */
  why: string;
  /** 怎么做 */
  how_to: string;
  /** 完成判定标准 */
  verify_criteria: string;
  /** todo / in_progress / done / blocked */
  status: string;
  sort_order: number;
  created_at: string;
  updated_at: string;
  finding_ids: number[];
}

export const getTaskTree = (projectId: number) =>
  invoke<TaskNode[]>("get_task_tree", { projectId });

/** AI 生成整树；replace=true 时先清空现有树。返回节点数 */
export const generateTaskTree = (projectId: number, replace: boolean) =>
  invoke<number>("generate_task_tree", { projectId, replace });

export const expandTaskNode = (nodeId: number) =>
  invoke<number>("expand_task_node", { nodeId });

export const alternativeTaskNode = (nodeId: number) =>
  invoke<void>("alternative_task_node", { nodeId });

export const nextTask = (projectId: number) =>
  invoke<TaskNode | null>("next_task", { projectId });

export const updateTaskStatus = (nodeId: number, status: string) =>
  invoke<void>("update_task_status", { nodeId, status });

export const createTaskNode = (
  projectId: number,
  parentId: number | null,
  fields: {
    title: string;
    description: string;
    why: string;
    how_to: string;
    verify_criteria: string;
  }
) =>
  invoke<number>("create_task_node", {
    projectId,
    parentId,
    ...fields,
  });

export const deleteTaskNode = (nodeId: number) =>
  invoke<void>("delete_task_node", { nodeId });

export const getTaskFindings = (nodeId: number) =>
  invoke<Finding[]>("get_task_findings", { nodeId });

// ---------- 知识库（OWASP/CWE 卡片） ----------

export interface KnowledgeCard {
  key: string;
  kind: "owasp" | "cwe";
  title: string;
  /** 原理 */
  principle: string;
  /** 危害 */
  impact: string;
  /** 常见成因 */
  cause: string;
  /** 修复建议 */
  remediation: string;
}

export const getKnowledgeCards = (owasp: string, cwe: string) =>
  invoke<KnowledgeCard[]>("get_knowledge_cards", { owasp, cwe });

// ---------- Repeater（手动改包重发） ----------

export interface ReplayHeader {
  name: string;
  value: string;
}

export interface ReplayResponse {
  status: number;
  status_text: string;
  headers: ReplayHeader[];
  body_text: string | null;
  body_base64: string | null;
  resp_size: number;
  duration_ms: number;
}

export const replayRequest = (
  method: string,
  url: string,
  headers: ReplayHeader[],
  body: string | null
) => invoke<ReplayResponse>("replay_request", { method, url, headers, body });

// ---------- 学习报告 ----------

/** 生成 Markdown 报告文本（预览用） */
export const buildReport = (projectId: number) =>
  invoke<string>("build_report", { projectId });

/** 导出报告到下载目录，返回保存路径 */
export const exportReport = (projectId: number) =>
  invoke<string>("export_report", { projectId });

// ---------- 用量统计 & 计数（Phase 5） ----------

export interface TokenUsage {
  calls: number;
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
}

/** 本机累计 AI token 用量 */
export const getTokenUsage = () => invoke<TokenUsage>("get_token_usage");

export const resetTokenUsage = () => invoke<void>("reset_token_usage");

/** 按筛选条件统计流量总条数（分页用） */
export const countTraffic = (projectId: number, f: TrafficFilter = {}) =>
  invoke<number>("count_traffic", {
    projectId,
    method: f.method || null,
    statusClass: f.statusClass || null,
    search: f.search || null,
  });
