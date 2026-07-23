import { defineStore } from "pinia";
import { getAllSettings, setSetting } from "../api/tauri";

export interface AppSettings {
  // AI 接入（OpenAI 兼容接口）
  ai_enabled: boolean;
  api_key: string;
  base_url: string;
  model: string;
  // 代理
  proxy_port: number;
  // 成本提示：每百万 token 单价（货币自定，0=不估算）
  price_per_mtok: number;
  // 首次启动授权声明
  consent_accepted: boolean;
}

const DEFAULTS: AppSettings = {
  ai_enabled: true,
  api_key: "",
  base_url: "https://api.deepseek.com",
  model: "deepseek-chat",
  proxy_port: 8080,
  price_per_mtok: 0,
  consent_accepted: false,
};

export const useSettingsStore = defineStore("settings", {
  state: (): AppSettings => ({ ...DEFAULTS }),
  actions: {
    async load() {
      const all = await getAllSettings();
      this.ai_enabled = all.ai_enabled !== "false";
      this.api_key = all.api_key ?? DEFAULTS.api_key;
      this.base_url = all.base_url || DEFAULTS.base_url;
      this.model = all.model || DEFAULTS.model;
      this.proxy_port = Number(all.proxy_port) || DEFAULTS.proxy_port;
      this.price_per_mtok = Number(all.price_per_mtok) || DEFAULTS.price_per_mtok;
      this.consent_accepted = all.consent_accepted === "true";
    },
    async save() {
      await Promise.all([
        setSetting("ai_enabled", String(this.ai_enabled)),
        setSetting("api_key", this.api_key),
        setSetting("base_url", this.base_url),
        setSetting("model", this.model),
        setSetting("proxy_port", String(this.proxy_port)),
        setSetting("price_per_mtok", String(this.price_per_mtok)),
        setSetting("consent_accepted", String(this.consent_accepted)),
      ]);
    },
    async acceptConsent() {
      this.consent_accepted = true;
      await setSetting("consent_accepted", "true");
    },
  },
});
