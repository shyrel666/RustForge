import { defineStore } from "pinia";
import { getAllSettings, setSetting } from "../api/tauri";
import {
  applyTheme,
  parseThemeMode,
  type ThemeMode,
} from "../utils/theme";

/**
 * AI 供应商元数据。API Key 只保存在系统凭据库，前端只接收布尔状态。
 * 多个供应商并存于列表，任一时刻只有一个「当前」供应商被 AI 调用使用。
 */
export interface AiProvider {
  id: string;
  name: string;
  base_url: string;
  model: string;
  note: string;
  supports_json_schema: boolean;
  has_api_key: boolean;
}

export interface AppSettings {
  // AI 全局隐私开关（关闭后所有 AI 功能不可用，流量不外发）
  ai_enabled: boolean;
  // 多供应商列表 + 当前生效供应商 id
  providers: AiProvider[];
  current_provider_id: string;
  // 代理
  proxy_port: number;
  // 首次启动授权声明
  consent_accepted: boolean;
  // 外观：浅色 / 深色 / 跟随系统
  theme: ThemeMode;
}

const DEFAULTS = {
  ai_enabled: true,
  proxy_port: 8080,
  consent_accepted: false,
  theme: "dark" as ThemeMode,
};

/** 生成一个本地唯一 id（时间戳 + 随机后缀，够用即可） */
function genId(): string {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

export const useSettingsStore = defineStore("settings", {
  state: (): AppSettings => ({
    ai_enabled: DEFAULTS.ai_enabled,
    providers: [],
    current_provider_id: "",
    proxy_port: DEFAULTS.proxy_port,
    consent_accepted: DEFAULTS.consent_accepted,
    theme: DEFAULTS.theme,
  }),
  getters: {
    /** 当前生效的供应商（无则取列表首个，仍无则 null） */
    activeProvider(state): AiProvider | null {
      return (
        state.providers.find((p) => p.id === state.current_provider_id) ||
        state.providers[0] ||
        null
      );
    },
  },
  actions: {
    async load() {
      const all = await getAllSettings();
      this.ai_enabled = all.ai_enabled !== "false";
      this.proxy_port = Number(all.proxy_port) || DEFAULTS.proxy_port;
      this.consent_accepted = all.consent_accepted === "true";
      this.theme = parseThemeMode(all.theme);
      applyTheme(this.theme);

      // 解析多供应商列表
      let providers: AiProvider[] = [];
      if (all.ai_providers) {
        try {
          const arr = JSON.parse(all.ai_providers);
          if (Array.isArray(arr)) {
            providers = arr.map((p: Partial<AiProvider>) => ({
              id: String(p.id ?? ""),
              name: String(p.name ?? ""),
              base_url: String(p.base_url ?? ""),
              model: String(p.model ?? ""),
              note: String(p.note ?? ""),
              supports_json_schema: p.supports_json_schema === true,
              has_api_key: p.has_api_key === true,
            }));
            if (providers.some((provider) => !provider.id || !provider.base_url)) {
              throw new Error("AI 供应商配置缺少必填元数据");
            }
          }
        } catch {
          /* 忽略损坏的 JSON，按空列表处理 */
        }
      }

      this.providers = providers;
      this.current_provider_id =
        all.ai_current && providers.some((p) => p.id === all.ai_current)
          ? all.ai_current
          : providers[0]?.id ?? "";
    },

    async save() {
      const providerMetadata = this.providers.map(
        ({ id, name, base_url, model, note, supports_json_schema }) => ({
          id,
          name,
          base_url,
          model,
          note,
          supports_json_schema,
        })
      );
      // 供应商列表先落库，专用 Key 命令才能校验 providerId；布尔状态也不落 SQLite。
      await setSetting("ai_providers", JSON.stringify(providerMetadata));
      await Promise.all([
        setSetting("ai_enabled", String(this.ai_enabled)),
        setSetting("ai_current", this.current_provider_id),
        setSetting("proxy_port", String(this.proxy_port)),
        setSetting("consent_accepted", String(this.consent_accepted)),
        setSetting("theme", this.theme),
      ]);
    },

    async setTheme(mode: ThemeMode) {
      this.theme = mode;
      applyTheme(mode);
      await setSetting("theme", mode);
    },

    /** 新增供应商，返回其 id；若此前无当前项则自动设为当前 */
    addProvider(p: Omit<AiProvider, "id" | "has_api_key">): string {
      const id = genId();
      this.providers.push({ ...p, id, has_api_key: false });
      if (!this.current_provider_id) this.current_provider_id = id;
      return id;
    },

    updateProvider(
      id: string,
      patch: Partial<Omit<AiProvider, "id" | "has_api_key">>
    ) {
      const idx = this.providers.findIndex((x) => x.id === id);
      if (idx >= 0) this.providers[idx] = { ...this.providers[idx], ...patch, id };
    },

    setProviderKeyStatus(id: string, hasApiKey: boolean) {
      const provider = this.providers.find((item) => item.id === id);
      if (provider) provider.has_api_key = hasApiKey;
    },

    removeProvider(id: string) {
      this.providers = this.providers.filter((p) => p.id !== id);
      if (this.current_provider_id === id) {
        this.current_provider_id = this.providers[0]?.id ?? "";
      }
    },

    setCurrent(id: string) {
      this.current_provider_id = id;
    },

    async acceptConsent() {
      this.consent_accepted = true;
      await setSetting("consent_accepted", "true");
    },
  },
});
