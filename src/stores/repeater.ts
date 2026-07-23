import { defineStore } from "pinia";
import {
  replayRequest,
  type ReplayHeader,
  type ReplayResponse,
  type TrafficDetail,
} from "../api/tauri";

interface Draft {
  method: string;
  url: string;
  /** 原始头部编辑区：每行 "Name: Value" */
  headersRaw: string;
  body: string;
}

/** headers JSON 对象字符串 → "Name: Value" 逐行文本 */
function headersJsonToRaw(json: string | null): string {
  if (!json) return "";
  try {
    const obj = JSON.parse(json) as Record<string, string>;
    return Object.entries(obj)
      .map(([k, v]) => `${k}: ${v}`)
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
    draft: { method: "GET", url: "", headersRaw: "", body: "" } as Draft,
    resp: null as ReplayResponse | null,
    sending: false,
    error: "",
    /** 来自哪条流量（仅提示用） */
    loadedFrom: null as number | null,
  }),
  actions: {
    /** 从流量详情载入到 Repeater（TrafficView「发送到 Repeater」调用） */
    loadFromDetail(detail: TrafficDetail) {
      this.draft = {
        method: detail.method,
        url: detail.url,
        headersRaw: headersJsonToRaw(detail.req_headers),
        body: detail.req_body_text ?? "",
      };
      this.resp = null;
      this.error = "";
      this.loadedFrom = detail.id;
    },

    async send() {
      if (!this.draft.url.trim()) {
        this.error = "请填写请求 URL";
        return;
      }
      this.sending = true;
      this.error = "";
      try {
        const headers = parseHeaders(this.draft.headersRaw);
        this.resp = await replayRequest(
          this.draft.method,
          this.draft.url,
          headers,
          this.draft.body || null
        );
      } catch (e) {
        this.error = String(e);
        this.resp = null;
      } finally {
        this.sending = false;
      }
    },
  },
});
