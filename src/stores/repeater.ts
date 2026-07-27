import { defineStore } from "pinia";
import {
  authorizeReplayTarget,
  replayRequest,
  type ReplayHeader,
  type ReplayResponse,
  type ScopeDecision,
  type TrafficDetail,
} from "../api/tauri";
import { useProjectStore } from "./project";

interface Draft {
  method: string;
  url: string;
  /** 原始头部编辑区：每行 "Name: Value" */
  headersRaw: string;
  body: string;
  /** 编辑区按 UTF-8 文本或 Base64 原始字节解释。 */
  bodyEncoding: "text" | "base64";
}

/** headers JSON 对象字符串 → "Name: Value" 逐行文本，重复值逐项保留。 */
function headersJsonToRaw(json: string | null, omittedNames: string[] = []): string {
  if (!json) return "";
  try {
    const obj = JSON.parse(json) as Record<string, string | string[]>;
    const omitted = new Set(omittedNames.map((name) => name.toLowerCase()));
    return Object.entries(obj)
      .filter(([name]) => !omitted.has(name.toLowerCase()))
      .flatMap(([k, value]) =>
        (Array.isArray(value) ? value : [value]).map((v) => `${k}: ${v}`)
      )
      .join("\n");
  } catch {
    return "";
  }
}

/** "Name: Value" 逐行文本 → 头部数组（忽略空行/无冒号行） */
function parseHeaders(raw: string): ReplayHeader[] {
  return raw
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && line.includes(":"))
    .map((line) => {
      const idx = line.indexOf(":");
      return { name: line.slice(0, idx).trim(), value: line.slice(idx + 1).trim() };
    });
}

export const useRepeaterStore = defineStore("repeater", {
  state: () => ({
    draft: {
      method: "GET",
      url: "",
      headersRaw: "",
      body: "",
      bodyEncoding: "text",
    } as Draft,
    resp: null as ReplayResponse | null,
    sending: false,
    error: "",
    /** 来自哪条流量（仅提示用） */
    loadedFrom: null as number | null,
    loadedFromProject: null as number | null,
    sourceBodyTruncated: false,
    sourceDecodeStatus: "" as string,
    /** 无网络预检结果；真正发送时后端仍会再次执行 ScopePolicy。 */
    authorization: null as ScopeDecision | null,
    authorizationError: "",
    authorizationProjectId: null as number | null,
    authorizationUrl: "",
    checkingAuthorization: false,
    authorizationCheckId: 0,
  }),
  actions: {
    /** 从流量详情载入到 Repeater（TrafficView「发送到 Repeater」调用） */
    loadFromDetail(detail: TrafficDetail) {
      this.draft = {
        method: detail.method,
        url: detail.url,
        // The stored body is decoded evidence. Keeping Content-Encoding here
        // would make Repeater claim that plaintext is still compressed.
        headersRaw: headersJsonToRaw(
          detail.req_headers,
          detail.req_decode_status.startsWith("decoded_") ? ["content-encoding"] : []
        ),
        body: detail.req_body_text ?? detail.req_body_base64 ?? "",
        bodyEncoding: detail.req_body_base64 !== null ? "base64" : "text",
      };
      this.resp = null;
      this.error = "";
      this.loadedFrom = detail.id;
      this.loadedFromProject = detail.project_id;
      this.sourceBodyTruncated = detail.req_truncated;
      this.sourceDecodeStatus = detail.req_decode_status;
      this.clearAuthorization();
    },

    clearAuthorization() {
      this.authorizationCheckId += 1;
      this.authorization = null;
      this.authorizationError = "";
      this.authorizationProjectId = null;
      this.authorizationUrl = "";
      this.checkingAuthorization = false;
    },

    /** 调用后端做无网络 Scope 预检，旧的异步结果不会覆盖较新的 URL。 */
    async checkAuthorization(projectId: number | null) {
      const checkId = ++this.authorizationCheckId;
      const url = this.draft.url.trim();
      this.authorization = null;
      this.authorizationError = "";
      this.authorizationProjectId = null;
      this.authorizationUrl = "";
      this.checkingAuthorization = true;
      try {
        const decision = await authorizeReplayTarget(projectId, url);
        if (checkId !== this.authorizationCheckId) return;
        this.authorization = decision;
        this.authorizationProjectId = projectId;
        this.authorizationUrl = url;
      } catch (e) {
        if (checkId !== this.authorizationCheckId) return;
        this.authorizationError = String(e);
      } finally {
        if (checkId === this.authorizationCheckId) {
          this.checkingAuthorization = false;
        }
      }
    },

    async send(allowTruncatedBody = false) {
      if (this.sending) return;
      if (this.sourceBodyTruncated && !allowTruncatedBody) {
        this.error =
          "[TRUNCATED_BODY] 来源请求体只保留了捕获前缀，必须明确确认后才能发送";
        return;
      }
      const current = useProjectStore().current;
      const projectId = current?.id ?? null;
      const url = this.draft.url.trim();

      if (
        !this.authorization ||
        this.authorizationProjectId !== projectId ||
        this.authorizationUrl !== url
      ) {
        await this.checkAuthorization(projectId);
      }
      if (!this.authorization || projectId === null) {
        return;
      }

      this.sending = true;
      this.error = "";
      try {
        const headers = parseHeaders(this.draft.headersRaw);
        this.resp = await replayRequest(
          projectId,
          this.draft.method,
          url,
          headers,
          this.draft.bodyEncoding === "text" ? this.draft.body || null : null,
          this.draft.bodyEncoding === "base64" ? this.draft.body || null : null
        );
      } catch (e) {
        const message = String(e);
        this.error = message;
        this.resp = null;
        // Scope 可能在预检后被修改；后端二次校验失败时立即撤销 UI 授权状态。
        if (
          message.includes("[OUT_OF_SCOPE]") ||
          message.includes("[EMPTY_SCOPE]") ||
          message.includes("[PROJECT_NOT_FOUND]") ||
          message.includes("[INVALID_URL]")
        ) {
          this.clearAuthorization();
          this.authorizationError = message;
        }
      } finally {
        this.sending = false;
      }
    },
  },
});
