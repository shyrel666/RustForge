import type {
  AssessmentHandoffReplayDraft,
  ReplayHeader,
  ReplayRun,
  ReplayRunSummary,
  TrafficDetail,
} from "../api/tauri";

export interface ReplayDraft {
  method: string;
  url: string;
  /** 原始头部编辑区：每行 "Name: Value"。 */
  headersRaw: string;
  body: string;
  /** 编辑区按 UTF-8 文本或 Base64 原始字节解释。 */
  bodyEncoding: "text" | "base64";
}

export interface ReplayDraftState {
  draft: ReplayDraft;
  sourceTrafficId: number | null;
  sourceProjectId: number | null;
  decodeStatus: string;
  bodyTruncated: boolean;
  /** 非空时必须在发送前由用户明确确认。 */
  replayWarning: string;
}

export interface ReplayWarningConfirmation {
  projectId: number;
  sessionId: number;
  warning: string;
}

export function emptyReplayDraftState(): ReplayDraftState {
  return {
    draft: {
      method: "GET",
      url: "",
      headersRaw: "",
      body: "",
      bodyEncoding: "text",
    },
    sourceTrafficId: null,
    sourceProjectId: null,
    decodeStatus: "",
    bodyTruncated: false,
    replayWarning: "",
  };
}

export function cloneReplayDraftState(state: ReplayDraftState): ReplayDraftState {
  return {
    ...state,
    draft: { ...state.draft },
  };
}

/** headers JSON 对象字符串 → 逐行文本，重复值逐项保留。 */
function headersJsonToRaw(json: string | null, omittedNames: string[] = []): string {
  if (!json) return "";
  try {
    const obj = JSON.parse(json) as Record<string, string | string[]>;
    const omitted = new Set(omittedNames.map((name) => name.toLowerCase()));
    return Object.entries(obj)
      .filter(([name]) => !omitted.has(name.toLowerCase()))
      .flatMap(([key, value]) =>
        (Array.isArray(value) ? value : [value]).map((item) => `${key}: ${item}`)
      )
      .join("\n");
  } catch {
    return "";
  }
}

function headersToRaw(headers: ReplayHeader[]): string {
  return headers.map((header) => `${header.name}: ${header.value}`).join("\n");
}

export function draftStateFromTraffic(detail: TrafficDetail): ReplayDraftState {
  const decoded = detail.req_decode_status.startsWith("decoded_");
  const decodeTruncated = detail.req_decode_status === "decode_truncated";
  const warning = decodeTruncated
    ? "来源正文在多层解码中被截断，当前字节不能精确还原原始编码；发送前必须确认。"
    : detail.req_truncated
      ? "来源请求体只保留了捕获前缀，发送前必须确认。"
      : "";
  return {
    draft: {
      method: detail.method,
      url: detail.url,
      // 只有明确完成解码的正文才可移除 Content-Encoding 后作为明文发送。
      // decode_truncated 可能仍是中间编码层，保留头并强制确认。
      headersRaw: headersJsonToRaw(
        detail.req_headers,
        decoded ? ["content-encoding"] : []
      ),
      body: detail.req_body_text ?? detail.req_body_base64 ?? "",
      bodyEncoding: detail.req_body_base64 !== null ? "base64" : "text",
    },
    sourceTrafficId: detail.id,
    sourceProjectId: detail.project_id,
    decodeStatus: detail.req_decode_status,
    bodyTruncated: detail.req_truncated,
    replayWarning: warning,
  };
}

export function draftStateFromRun(run: ReplayRun): ReplayDraftState {
  let body = "";
  let bodyEncoding: ReplayDraft["bodyEncoding"] = "text";
  let replayWarning = "";

  // Prefer the exact bytes supplied to reqwest. The decoded request_body is
  // intentionally only an inspection/Evidence preview.
  if (run.request_wire_body_text !== null) {
    body = run.request_wire_body_text;
  } else if (run.request_wire_body_base64 !== null) {
    body = run.request_wire_body_base64;
    bodyEncoding = "base64";
  } else if (run.request_input.encoding === "base64") {
    body = run.request_input.base64 ?? "";
    bodyEncoding = "base64";
  } else if (run.request_input.encoding === "ambiguous") {
    body = run.request_input.base64 ?? run.request_input.text ?? "";
    bodyEncoding = run.request_input.base64 !== null ? "base64" : "text";
    replayWarning =
      "原失败请求同时提交了文本与 Base64 正文，编辑器只能恢复其中一项；发送前必须确认。";
  } else {
    body = run.request_input.text ?? "";
  }

  if (run.req_wire_truncated) {
    replayWarning = "Run 只保留了实际发送正文的 wire 前缀，发送前必须确认。";
  } else if (run.request_input.truncated && run.request_wire_body_base64 === null) {
    replayWarning = "失败 Run 只保留了原始输入前缀，发送前必须确认。";
  }

  return {
    draft: {
      method: run.method,
      url: run.url,
      headersRaw: headersToRaw(run.request_headers),
      body,
      bodyEncoding,
    },
    sourceTrafficId: null,
    sourceProjectId: run.project_id,
    decodeStatus: run.req_decode_status,
    bodyTruncated: run.req_wire_truncated || run.request_input.truncated,
    replayWarning,
  };
}

export function draftStateFromAssessmentHandoff(
  handoff: AssessmentHandoffReplayDraft,
  projectId: number
): ReplayDraftState {
  const request = handoff.draft.request;
  if (!request || !request.url || !request.method) {
    const empty = emptyReplayDraftState();
    empty.sourceProjectId = projectId;
    empty.decodeStatus = "assessment_manual_recipe_invalid";
    empty.replayWarning = "人工配方草稿缺少请求结构，已拒绝自动填充；请返回任务重新创建。";
    return empty;
  }
  const bodyBase64 = request.bodyBase64;
  return {
    draft: {
      method: request.method,
      url: request.url,
      headersRaw: headersToRaw(request.headers ?? []),
      body: bodyBase64 ?? request.bodyText ?? "",
      bodyEncoding: bodyBase64 !== null ? "base64" : "text",
    },
    sourceTrafficId: null,
    sourceProjectId: projectId,
    decodeStatus: "assessment_manual_recipe",
    bodyTruncated: false,
    replayWarning:
      "这是 AI 安全评估生成的版本化人工配方草稿。请先核对 Scope、身份与差异，再亲自确认发送。",
  };
}

export function replayRunSummary(run: ReplayRun): ReplayRunSummary {
  return {
    id: run.id,
    session_id: run.session_id,
    project_id: run.project_id,
    method: run.method,
    url: run.url,
    tls_policy: run.tls_policy,
    outcome: run.outcome,
    error_code: run.error_code,
    error_message: run.error_message,
    status: run.status,
    status_text: run.status_text,
    req_wire_size: run.req_wire_size,
    req_wire_captured_size: run.req_wire_captured_size,
    req_wire_truncated: run.req_wire_truncated,
    req_decode_status: run.req_decode_status,
    resp_wire_size: run.resp_wire_size,
    resp_captured_size: run.resp_captured_size,
    resp_truncated: run.resp_truncated,
    resp_decode_status: run.resp_decode_status,
    duration_ms: run.duration_ms,
    request_hash: run.request_hash,
    response_hash: run.response_hash,
    created_at: run.created_at,
  };
}

export function shouldApplyReplayResult(
  workspaceProjectId: number | null,
  activeSessionId: number | null,
  resultProjectId: number,
  resultSessionId: number
): boolean {
  return (
    workspaceProjectId === resultProjectId && activeSessionId === resultSessionId
  );
}

export function replayWarningIsConfirmed(
  warning: string,
  workspaceProjectId: number | null,
  activeSessionId: number | null,
  confirmation: ReplayWarningConfirmation | null
): boolean {
  return (
    warning.length === 0 ||
    (confirmation !== null &&
      confirmation.projectId === workspaceProjectId &&
      confirmation.sessionId === activeSessionId &&
      confirmation.warning === warning)
  );
}
