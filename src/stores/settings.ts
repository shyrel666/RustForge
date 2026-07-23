import { defineStore } from "pinia";
import { getAllSettings, setSetting } from "../api/tauri";
import {
  applyTheme,
  parseThemeMode,
  type ThemeMode,
} from "../utils/theme";

/**
 * AI 供应商（CC-switch 风格）：一套完整的 API 配置三件套 + 名称/备注。
 * 多个供应商并存于列表，任一时刻只有一个「当前」供应商被 AI 调用使用。
 */
export interface AiProvider {
  id: string;
  name: string;
  base_url: string;
  api_key: string;
  model: string;
  note: string;
}

export interface AppSettings {
  // AI 全局隐私开关（关闭后所有 AI 功能不可用，流量不外发）
  ai_enabled: boolean;
  // 多供应商列表 + 当前生效供应商 id
  providers: AiProvider[];
  current_provider_id: string;
  // 代理
  proxy_port: number;
  // 成本提示：每百万 token 单价（货币自定，0=不估算）
  price_per_mtok: number;
  // 首次启动授权声明
  consent_accepted: boolean;
  // 外观：浅色 / 深色 / 跟随系统
  theme: ThemeMode;
}

const DEFAULTS = {
  ai_enabled: true,
  proxy_port: 8080,
  price_per_mtok: 0,
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
    price_per_mtok: DEFAULTS.price_per_mtok,
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
      this.price_per_mtok = Number(all.price_per_mtok) || DEFAULTS.price_per_mtok;
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
              id: String(p.id ?? genId()),
              name: String(p.name ?? ""),
              base_url: String(p.base_url ?? ""),
              api_key: String(p.api_key ?? ""),
              model: String(p.model ?? ""),
              note: String(p.note ?? ""),
            }));
          }
        } catch {
          /* 忽略损坏的 JSON，按空列表处理 */
        }
      }

      // 迁移：老版本单供应商设置 → 自动生成一个供应商
      if (providers.length === 0 && (all.api_key || all.base_url || all.model)) {
        providers = [
          {
            id: genId(),
            name: "默认供应商",
            base_url: all.base_url || "https://api.deepseek.com",
            api_key: all.api_key || "",
            model: all.model || "deepseek-chat",
            note: "",
          },
        ];
      }

      this.providers = providers;
      this.current_provider_id =
        all.ai_current && providers.some((p) => p.id === all.ai_current)
          ? all.ai_current
          : providers[0]?.id ?? "";
    },

    async save() {
      await Promise.all([
        setSetting("ai_enabled", String(this.ai_enabled)),
        setSetting("ai_providers", JSON.stringify(this.providers)),
        setSetting("ai_current", this.current_provider_id),
        setSetting("proxy_port", String(this.proxy_port)),
        setSetting("price_per_mtok", String(this.price_per_mtok)),
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
    addProvider(p: Omit<AiProvider, "id">): string {
      const id = genId();
      this.providers.push({ ...p, id });
      if (!this.current_provider_id) this.current_provider_id = id;
      return id;
    },

    updateProvider(id: string, patch: Partial<Omit<AiProvider, "id">>) {
      const idx = this.providers.findIndex((x) => x.id === id);
      if (idx >= 0) this.providers[idx] = { ...this.providers[idx], ...patch, id };
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
