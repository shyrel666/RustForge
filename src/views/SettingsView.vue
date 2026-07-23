<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";
import { getVersion } from "@tauri-apps/api/app";
import {
  Link,
  Document,
  Refresh,
  Sunny,
  Moon,
  Monitor,
  CopyDocument,
  FolderOpened,
} from "@element-plus/icons-vue";
import { useSettingsStore, type AiProvider } from "../stores/settings";
import { useAppUpdater } from "../services/appUpdater";
import AppUpdateButton from "../components/AppUpdateButton.vue";
import PageHeader from "../components/shell/PageHeader.vue";
import BrandMark from "../components/brand/BrandMark.vue";
import {
  getPromptTemplate,
  setPromptTemplate,
  resetPromptTemplate,
  getTokenUsage,
  resetTokenUsage,
  fetchModels,
  openUrl,
  proxyStatus,
  getCaInfo,
  getRuntimeInfo,
  revealAppDataDir,
  type TokenUsage,
  type RuntimeInfo,
} from "../api/tauri";
import type { ThemeMode } from "../utils/theme";

const settings = useSettingsStore();
const updater = useAppUpdater();
const saving = ref(false);
const activeTab = ref<"general" | "prompt" | "about">("general");

const TABS = [
  { id: "general" as const, label: "通用" },
  { id: "prompt" as const, label: "提示词" },
  { id: "about" as const, label: "关于" },
];

const THEME_OPTIONS: { id: ThemeMode; label: string; icon: typeof Sunny }[] = [
  { id: "light", label: "浅色", icon: Sunny },
  { id: "dark", label: "深色", icon: Moon },
  { id: "system", label: "跟随系统", icon: Monitor },
];

async function setTheme(mode: ThemeMode) {
  try {
    await settings.setTheme(mode);
  } catch (e) {
    ElMessage.error(String(e));
  }
}

const APP_NAME = "RustForge";
const GITHUB_REPO = "shyrel666/RustForge";
const LINK_GITHUB = `https://github.com/${GITHUB_REPO}`;
const LINK_CHANGELOG = `https://github.com/${GITHUB_REPO}/releases`;

const appVersion = ref("0.1.0");

const runtimeInfo = ref<RuntimeInfo | null>(null);
const proxyRunning = ref(false);
const proxyPort = ref(0);
const caTrusted = ref<boolean | null>(null);
const diagLoading = ref(false);

function formatOsLabel(os: string, arch: string): string {
  const osMap: Record<string, string> = {
    windows: "Windows",
    macos: "macOS",
    linux: "Linux",
  };
  const archMap: Record<string, string> = {
    x86_64: "x64",
    aarch64: "ARM64",
    x86: "x86",
  };
  return `${osMap[os] ?? os} · ${archMap[arch] ?? arch}`;
}

const systemLabel = computed(() => {
  if (!runtimeInfo.value) return "—";
  return formatOsLabel(runtimeInfo.value.os, runtimeInfo.value.arch);
});

const proxyLabel = computed(() => {
  const port =
    proxyRunning.value && proxyPort.value > 0
      ? proxyPort.value
      : settings.proxy_port;
  if (proxyRunning.value) return `运行中 · 端口 ${port}`;
  return `未运行 · 配置端口 ${port}`;
});

const caLabel = computed(() => {
  if (caTrusted.value === null) return "—";
  return caTrusted.value ? "已信任" : "未安装 / 未信任";
});

async function loadDiagnostics() {
  diagLoading.value = true;
  try {
    const [ver, runtime, proxy, ca] = await Promise.all([
      getVersion().catch(() => appVersion.value),
      getRuntimeInfo(),
      proxyStatus(),
      getCaInfo(),
    ]);
    appVersion.value = ver;
    runtimeInfo.value = runtime;
    proxyRunning.value = proxy.running;
    proxyPort.value = proxy.port;
    caTrusted.value = ca.trusted;
  } catch (e) {
    ElMessage.error(`加载运行环境失败：${String(e)}`);
  } finally {
    diagLoading.value = false;
  }
}

async function copyDiagnostics() {
  const port =
    proxyRunning.value && proxyPort.value > 0
      ? proxyPort.value
      : settings.proxy_port;
  const lines = [
    `${APP_NAME} 诊断信息`,
    `应用: v${appVersion.value}`,
    `系统: ${systemLabel.value}`,
    `代理: ${proxyRunning.value ? "运行中" : "未运行"} · 端口 ${port}`,
    `CA 证书: ${caLabel.value}`,
  ];
  if (runtimeInfo.value?.app_data_dir) {
    lines.push(`数据目录: ${runtimeInfo.value.app_data_dir}`);
  }
  try {
    await navigator.clipboard.writeText(lines.join("\n"));
    ElMessage.success("诊断信息已复制");
  } catch (e) {
    ElMessage.error(`复制失败：${String(e)}`);
  }
}

async function openDataDir() {
  try {
    await revealAppDataDir();
  } catch (e) {
    ElMessage.error(String(e));
  }
}

watch(activeTab, (tab) => {
  if (tab === "about") void loadDiagnostics();
});

async function openExternal(url: string) {
  try {
    await openUrl(url);
  } catch (e) {
    ElMessage.error(String(e));
  }
}

async function recheckUpdate() {
  const result = await updater.checkForUpdates({ silent: false });
  if (result === "latest") {
    ElMessage.success("当前已是最新版本");
  } else if (result === "available") {
    ElMessage.success(`发现新版本 v${updater.targetVersion.value}`);
  } else if (result === "error") {
    ElMessage.error(`检查更新失败：${updater.errorMessage.value}`);
  }
}

// 常用供应商预设：选择后自动填充名称/端点/默认模型，只需再填 API Key
const PRESETS: { label: string; name: string; base_url: string; model: string }[] = [
  { label: "DeepSeek", name: "DeepSeek", base_url: "https://api.deepseek.com", model: "deepseek-chat" },
  { label: "Kimi (Moonshot)", name: "Kimi", base_url: "https://api.moonshot.cn/v1", model: "moonshot-v1-8k" },
  { label: "通义千问（百炼）", name: "通义千问", base_url: "https://dashscope.aliyuncs.com/compatible-mode/v1", model: "qwen-plus" },
  { label: "智谱 GLM", name: "智谱 GLM", base_url: "https://open.bigmodel.cn/api/paas/v4", model: "glm-4-flash" },
  { label: "OpenAI", name: "OpenAI", base_url: "https://api.openai.com/v1", model: "gpt-4o-mini" },
  { label: "OpenRouter", name: "OpenRouter", base_url: "https://openrouter.ai/api/v1", model: "openai/gpt-4o-mini" },
  { label: "硅基流动 SiliconFlow", name: "SiliconFlow", base_url: "https://api.siliconflow.cn/v1", model: "deepseek-ai/DeepSeek-V3" },
  { label: "MiniMax", name: "MiniMax", base_url: "https://api.minimax.io/v1", model: "MiniMax-M3" },
  { label: "自定义", name: "", base_url: "", model: "" },
];

// ---------- 供应商增改对话框 ----------
const dialogVisible = ref(false);
const editingId = ref<string | null>(null);
const presetKey = ref("");
const modelOptions = ref<string[]>([]);
const fetchingModels = ref(false);
const testing = ref(false);
const form = reactive<Omit<AiProvider, "id">>({
  name: "",
  base_url: "",
  api_key: "",
  model: "",
  note: "",
});

const dialogTitle = computed(() => (editingId.value ? "编辑供应商" : "添加供应商"));

// 模型下拉候选：已获取模型 ∪ 当前已填模型（避免自定义值被下拉覆盖）
const modelSelectOptions = computed(() => {
  const set = new Set(modelOptions.value);
  if (form.model) set.add(form.model);
  return [...set];
});

function resetForm() {
  form.name = "";
  form.base_url = "";
  form.api_key = "";
  form.model = "";
  form.note = "";
  presetKey.value = "";
  modelOptions.value = [];
}

function openAdd() {
  editingId.value = null;
  resetForm();
  dialogVisible.value = true;
}

function openEdit(p: AiProvider) {
  editingId.value = p.id;
  form.name = p.name;
  form.base_url = p.base_url;
  form.api_key = p.api_key;
  form.model = p.model;
  form.note = p.note;
  presetKey.value = "";
  modelOptions.value = p.model ? [p.model] : [];
  dialogVisible.value = true;
}

function applyPreset(label: string) {
  const preset = PRESETS.find((p) => p.label === label);
  if (!preset) return;
  if (preset.name) form.name = preset.name;
  form.base_url = preset.base_url;
  form.model = preset.model;
  modelOptions.value = preset.model ? [preset.model] : [];
}

async function doFetchModels() {
  if (!form.base_url.trim() || !form.api_key.trim()) {
    ElMessage.warning("请先填写 Base URL 和 API Key");
    return;
  }
  fetchingModels.value = true;
  try {
    const list = await fetchModels(form.base_url.trim(), form.api_key.trim());
    modelOptions.value = list;
    if (!form.model && list.length) form.model = list[0];
    ElMessage.success(`获取到 ${list.length} 个模型`);
  } catch (e) {
    ElMessage.error(String(e));
  } finally {
    fetchingModels.value = false;
  }
}

// 复用 /models 端点校验 Base URL + API Key 是否可用（免费、不烧 token）
async function testConnection() {
  if (!form.base_url.trim() || !form.api_key.trim()) {
    ElMessage.warning("请先填写 Base URL 和 API Key");
    return;
  }
  testing.value = true;
  try {
    const list = await fetchModels(form.base_url.trim(), form.api_key.trim());
    ElMessage.success(`连接成功：鉴权通过，可用模型 ${list.length} 个`);
  } catch (e) {
    ElMessage.error(`连接失败：${String(e)}`);
  } finally {
    testing.value = false;
  }
}

async function saveProvider() {
  if (!form.base_url.trim()) {
    ElMessage.warning("请填写 Base URL");
    return;
  }
  if (!form.api_key.trim()) {
    ElMessage.warning("请填写 API Key");
    return;
  }
  // 名称留空时用端点主机名兜底
  let name = form.name.trim();
  if (!name) {
    try {
      name = new URL(form.base_url.trim()).hostname;
    } catch {
      name = "未命名供应商";
    }
  }
  const payload = {
    name,
    base_url: form.base_url.trim(),
    api_key: form.api_key.trim(),
    model: form.model.trim(),
    note: form.note.trim(),
  };
  if (editingId.value) {
    settings.updateProvider(editingId.value, payload);
  } else {
    settings.addProvider(payload);
  }
  try {
    await settings.save();
    ElMessage.success("供应商已保存");
    dialogVisible.value = false;
  } catch (e) {
    ElMessage.error(String(e));
  }
}

async function switchCurrent(id: string) {
  settings.setCurrent(id);
  try {
    await settings.save();
    ElMessage.success("已切换当前供应商");
  } catch (e) {
    ElMessage.error(String(e));
  }
}

async function confirmDelete(p: AiProvider) {
  try {
    await ElMessageBox.confirm(`确定删除供应商「${p.name}」？`, "删除确认", {
      type: "warning",
    });
  } catch {
    return; // 用户取消
  }
  settings.removeProvider(p.id);
  try {
    await settings.save();
    ElMessage.success("已删除");
  } catch (e) {
    ElMessage.error(String(e));
  }
}

/** 打码显示 Key，避免明文暴露在列表 */
function maskKey(k: string): string {
  if (!k) return "（未填）";
  if (k.length <= 8) return "••••";
  return `${k.slice(0, 4)}••••${k.slice(-4)}`;
}

// ---------- 提示词模板 ----------
const template = ref("");
const templateSaving = ref(false);
const templateDirty = ref(false);

// ---------- 用量统计 ----------
const usage = ref<TokenUsage>({ calls: 0, prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 });
const estCost = computed(() =>
  settings.price_per_mtok > 0
    ? ((usage.value.total_tokens / 1_000_000) * settings.price_per_mtok).toFixed(4)
    : ""
);

async function refreshUsage() {
  try {
    usage.value = await getTokenUsage();
  } catch (e) {
    ElMessage.error(String(e));
  }
}

async function doResetUsage() {
  try {
    await resetTokenUsage();
    await refreshUsage();
    ElMessage.success("用量已清零");
  } catch (e) {
    ElMessage.error(String(e));
  }
}

onMounted(async () => {
  template.value = await getPromptTemplate();
  await refreshUsage();
  try {
    appVersion.value = await getVersion();
  } catch {
    /* keep fallback */
  }
  if (activeTab.value === "about") {
    await loadDiagnostics();
  }
});

async function saveTemplate() {
  templateSaving.value = true;
  try {
    await setPromptTemplate(template.value);
    templateDirty.value = false;
    ElMessage.success("模板已保存，下次分析生效");
  } catch (e) {
    ElMessage.error(String(e));
  } finally {
    templateSaving.value = false;
  }
}

async function resetTemplate() {
  try {
    await resetPromptTemplate();
    template.value = await getPromptTemplate();
    templateDirty.value = false;
    ElMessage.success("已恢复内置默认模板");
  } catch (e) {
    ElMessage.error(String(e));
  }
}

async function save() {
  saving.value = true;
  try {
    await settings.save();
    ElMessage.success("设置已保存");
  } catch (e) {
    ElMessage.error(String(e));
  } finally {
    saving.value = false;
  }
}
</script>

<template>
  <div class="settings-page">
    <PageHeader
      title="设置"
      description="配置外观、AI 供应商、代理与关于信息。"
    />

    <nav class="rf-pill-tabs settings-tabs" aria-label="设置分类">
      <button
        v-for="tab in TABS"
        :key="tab.id"
        type="button"
        class="rf-pill-tab"
        :class="{ active: activeTab === tab.id }"
        @click="activeTab = tab.id"
      >
        {{ tab.label }}
      </button>
    </nav>

    <div v-show="activeTab === 'general'" class="general-stack">
      <section class="setting-block">
        <div class="setting-head">
          <h2 class="rf-section-title">外观主题</h2>
          <p class="rf-section-desc">选择应用的外观主题，立即生效。</p>
        </div>
        <div class="theme-seg" role="radiogroup" aria-label="外观主题">
          <button
            v-for="opt in THEME_OPTIONS"
            :key="opt.id"
            type="button"
            class="theme-opt"
            role="radio"
            :aria-checked="settings.theme === opt.id"
            :class="{ active: settings.theme === opt.id }"
            @click="setTheme(opt.id)"
          >
            <el-icon :size="16"><component :is="opt.icon" /></el-icon>
            <span>{{ opt.label }}</span>
          </button>
        </div>
      </section>

      <section class="setting-block">
        <div class="setting-head">
          <h2 class="rf-section-title">AI 供应商</h2>
          <p class="rf-section-desc">
            OpenAI 兼容接口，用户自带 Key。可添加多个供应商并一键切换「当前」。
          </p>
        </div>
        <div class="rf-card control-card">
          <div class="row-item">
            <div class="row-label">
              <div class="row-title">启用 AI</div>
              <div class="row-desc">关闭后所有 AI 功能不可用，流量不会外发到大模型服务</div>
            </div>
            <el-switch v-model="settings.ai_enabled" @change="save" />
          </div>
          <div v-if="!settings.providers.length" class="empty-providers">
            <p>尚未添加供应商</p>
            <el-button type="primary" @click="openAdd">添加供应商</el-button>
          </div>
          <template v-else>
            <div
              v-for="row in settings.providers"
              :key="row.id"
              class="provider-row"
              :class="{ active: row.id === settings.current_provider_id }"
            >
              <div class="provider-main">
                <div class="provider-title-row">
                  <span class="provider-name">{{ row.name }}</span>
                  <el-tag
                    v-if="row.id === settings.current_provider_id"
                    size="small"
                    effect="dark"
                    type="success"
                  >当前</el-tag>
                </div>
                <div class="provider-meta mono">{{ row.model || "未指定模型" }}</div>
                <div class="provider-url">{{ row.base_url }}</div>
                <div class="provider-key mono">{{ maskKey(row.api_key) }}</div>
              </div>
              <div class="provider-actions">
                <el-button
                  v-if="row.id !== settings.current_provider_id"
                  size="small"
                  type="primary"
                  @click="switchCurrent(row.id)"
                >启用</el-button>
                <el-button size="small" @click="openEdit(row)">编辑</el-button>
                <el-button size="small" type="danger" plain @click="confirmDelete(row)">删除</el-button>
              </div>
            </div>
            <div class="add-row">
              <el-button type="primary" plain @click="openAdd">添加供应商</el-button>
            </div>
          </template>
        </div>
      </section>

      <section class="setting-block">
        <div class="setting-head">
          <h2 class="rf-section-title">代理</h2>
          <p class="rf-section-desc">配置本机 MITM 代理监听端口。修改后需在流量页重启代理后生效。</p>
        </div>
        <div class="rf-card control-card">
          <div class="row-item">
            <div class="row-label">
              <div class="row-title">监听端口</div>
              <div class="row-desc">浏览器/系统代理指向 127.0.0.1:{{ settings.proxy_port }}</div>
            </div>
            <el-input-number v-model="settings.proxy_port" :min="1024" :max="65535" />
          </div>
        </div>
      </section>

      <section class="setting-block">
        <div class="setting-head with-action">
          <div>
            <h2 class="rf-section-title">AI 用量</h2>
            <p class="rf-section-desc">本机累计的调用次数与 Token 统计，仅供参考。</p>
          </div>
          <el-button link type="primary" @click="refreshUsage">刷新</el-button>
        </div>
        <div class="rf-card control-card">
          <div class="row-item">
            <div class="row-label"><div class="row-title">调用次数</div></div>
            <div class="row-value">{{ usage.calls }}</div>
          </div>
          <div class="row-item">
            <div class="row-label">
              <div class="row-title">Token 用量</div>
              <div class="row-desc">输入 {{ usage.prompt_tokens }} · 输出 {{ usage.completion_tokens }}</div>
            </div>
            <div class="row-value">{{ usage.total_tokens }}</div>
          </div>
          <div class="row-item">
            <div class="row-label">
              <div class="row-title">每百万单价</div>
              <div class="row-desc">按所用模型价格填写，0 表示不估算</div>
            </div>
            <el-input-number v-model="settings.price_per_mtok" :min="0" :precision="2" :step="0.5" />
          </div>
          <div v-if="estCost" class="row-item">
            <div class="row-label">
              <div class="row-title">预估成本</div>
              <div class="row-desc">仅本地估算，以服务商账单为准</div>
            </div>
            <div class="row-value">{{ estCost }}</div>
          </div>
        </div>
      </section>

      <div class="general-footer">
        <el-button type="danger" plain @click="doResetUsage">清零用量</el-button>
        <el-button type="primary" :loading="saving" @click="save">保存设置</el-button>
      </div>
    </div>

    <section v-show="activeTab === 'prompt'" class="block">
      <div class="setting-head">
        <h2 class="rf-section-title">提示词模板</h2>
        <p class="rf-section-desc">
          可用占位符：{METHOD} {URL} {HOST} {STATUS} {REQUEST} {RESPONSE} {RULE_TAGS}。
          REQUEST/RESPONSE 已自动脱敏并截断。
        </p>
      </div>
      <div class="rf-card control-card tpl-card">
        <el-input
          v-model="template"
          type="textarea"
          :rows="16"
          class="tpl-editor"
          @input="templateDirty = true"
        />
      </div>
      <div class="save-row">
        <el-button type="primary" :loading="templateSaving" :disabled="!templateDirty" @click="saveTemplate">
          保存模板
        </el-button>
        <el-button @click="resetTemplate">恢复默认</el-button>
      </div>
    </section>

    <section v-show="activeTab === 'about'" class="block">
      <div class="setting-head">
        <h2 class="rf-section-title">关于</h2>
        <p class="rf-section-desc">查看版本、更新状态与运行环境。</p>
      </div>

      <div class="about-card rf-card">
        <div class="about-top">
          <div class="about-identity">
            <span class="about-mark" aria-hidden="true">
              <BrandMark variant="app" :size="44" />
            </span>
            <div>
              <div class="about-name">{{ APP_NAME }}</div>
              <span class="about-version">版本 v{{ appVersion }}</span>
            </div>
            <AppUpdateButton />
          </div>

          <div class="about-actions">
            <el-button :icon="Link" @click="openExternal(LINK_GITHUB)">GitHub</el-button>
            <el-button :icon="Document" @click="openExternal(LINK_CHANGELOG)">更新日志</el-button>
            <el-button
              :icon="Refresh"
              :loading="updater.status.value === 'checking'"
              :disabled="
                updater.status.value === 'downloading' ||
                updater.status.value === 'installing'
              "
              @click="recheckUpdate"
            >
              重新检查
            </el-button>
          </div>
        </div>

        <div
          v-if="updater.status.value === 'checking'"
          class="about-banner checking"
        >
          正在检查更新…
        </div>
        <div
          v-else-if="updater.status.value === 'available'"
          class="about-banner available"
        >
          检测到新版本 v{{ updater.targetVersion.value }}，返回首页后可点击
          RustForge 右侧的上箭头更新
        </div>
        <div
          v-else-if="updater.status.value === 'downloading'"
          class="about-banner available"
        >
          正在下载更新{{
            updater.progressPercent.value === null
              ? "…"
              : ` · ${updater.progressPercent.value}%`
          }}
        </div>
        <div
          v-else-if="updater.status.value === 'installing'"
          class="about-banner available"
        >
          正在安装更新，完成后将自动重启
        </div>
        <div
          v-else-if="updater.status.value === 'latest'"
          class="about-banner latest"
        >
          当前已是最新版本
        </div>
        <div
          v-else-if="updater.status.value === 'error'"
          class="about-banner error"
        >
          更新操作失败：{{ updater.errorMessage.value || "请稍后重试" }}
        </div>
      </div>

      <div class="about-card rf-card env-card" v-loading="diagLoading">
        <div class="env-head">
          <div>
            <h3 class="env-title">运行环境</h3>
            <p class="env-desc">本地摘要，便于自查与提交 Issue。</p>
          </div>
          <div class="env-actions">
            <el-button :icon="CopyDocument" @click="copyDiagnostics">复制诊断信息</el-button>
            <el-button :icon="FolderOpened" @click="openDataDir">打开数据目录</el-button>
          </div>
        </div>
        <div class="env-rows">
          <div class="env-row">
            <span class="env-key">应用</span>
            <span class="env-val">{{ APP_NAME }} v{{ appVersion }}</span>
          </div>
          <div class="env-row">
            <span class="env-key">系统</span>
            <span class="env-val">{{ systemLabel }}</span>
          </div>
          <div class="env-row">
            <span class="env-key">代理</span>
            <span class="env-val">{{ proxyLabel }}</span>
          </div>
          <div class="env-row">
            <span class="env-key">CA 证书</span>
            <span class="env-val" :class="{ warn: caTrusted === false }">{{ caLabel }}</span>
          </div>
        </div>
      </div>

      <p class="foot-note">
        {{ APP_NAME }} 仅供授权渗透测试与安全学习使用 · MIT License
      </p>
    </section>

    <el-dialog v-model="dialogVisible" :title="dialogTitle" width="520px">
      <el-form label-width="90px">
        <el-form-item label="预设">
          <el-select v-model="presetKey" placeholder="选择预设自动填充（可选）" clearable style="width: 100%" @change="applyPreset">
            <el-option v-for="p in PRESETS" :key="p.label" :label="p.label" :value="p.label" />
          </el-select>
        </el-form-item>
        <el-form-item label="名称">
          <el-input v-model="form.name" placeholder="如 DeepSeek 生产 / 个人 Key（留空自动用域名）" />
        </el-form-item>
        <el-form-item label="Base URL">
          <el-input v-model="form.base_url" placeholder="https://api.deepseek.com" />
        </el-form-item>
        <el-form-item label="API Key">
          <el-input v-model="form.api_key" type="password" show-password placeholder="sk-..." />
        </el-form-item>
        <el-form-item label="模型">
          <div class="model-row">
            <el-select v-model="form.model" filterable allow-create default-first-option placeholder="deepseek-chat / gpt-4o-mini ..." style="flex: 1">
              <el-option v-for="m in modelSelectOptions" :key="m" :label="m" :value="m" />
            </el-select>
            <el-button :loading="fetchingModels" @click="doFetchModels">获取模型</el-button>
          </div>
        </el-form-item>
        <el-form-item label="备注">
          <el-input v-model="form.note" placeholder="可选：用途 / 套餐 / 到期时间" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button :loading="testing" @click="testConnection">测试连接</el-button>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" @click="saveProvider">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.settings-page {
  width: 100%;
  max-width: 880px;
  min-height: 100%;
  margin: 0 auto;
  display: flex;
  flex-direction: column;
  justify-content: flex-start;
  align-items: stretch;
  gap: var(--rf-space-5);
  box-sizing: border-box;
}

.block {
  display: flex;
  flex-direction: column;
  gap: var(--rf-space-4);
}

.settings-tabs {
  width: 100%;
  max-width: 100%;
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 4px;
  padding: 4px;
  box-sizing: border-box;
}

.settings-tabs .rf-pill-tab {
  width: 100%;
  justify-content: center;
  min-height: 40px;
  padding: 8px 12px;
}

.general-stack {
  display: flex;
  flex-direction: column;
  gap: var(--rf-space-5);
  width: 100%;
}

.setting-block {
  display: flex;
  flex-direction: column;
  gap: var(--rf-space-3);
}

.setting-head .rf-section-title {
  margin-bottom: 4px;
}

.setting-head .rf-section-desc {
  margin-bottom: 0;
}

.setting-head.with-action {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: var(--rf-space-3);
}

.general-footer {
  display: flex;
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: 8px;
  padding-top: var(--rf-space-2);
  padding-bottom: var(--rf-space-5);
}

.settings-page :deep(.rf-section-desc) {
  margin-bottom: var(--rf-space-4);
}

.theme-seg {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 4px;
  padding: 4px;
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-shell);
  background: var(--rf-bg-pill);
}

.theme-opt {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  min-height: 40px;
  border: none;
  border-radius: calc(var(--rf-radius-shell) - 2px);
  background: transparent;
  color: var(--rf-text-secondary);
  font: inherit;
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  transition:
    background var(--rf-duration) var(--rf-ease),
    color var(--rf-duration) var(--rf-ease);
}

.theme-opt:hover {
  color: var(--rf-text);
  background: var(--rf-bg-shell);
}

.theme-opt.active {
  background: var(--rf-accent);
  color: var(--rf-accent-on);
  font-weight: 650;
}

.block-head {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: var(--rf-space-4);
}
.control-card {
  display: flex;
  flex-direction: column;
  padding: 0;
  overflow: hidden;
}
.tpl-card { padding: var(--rf-space-4); }
.empty-providers {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: var(--rf-space-3);
  min-height: 140px;
  padding: var(--rf-space-5);
  color: var(--rf-text-secondary);
  border-top: 1px solid var(--rf-border);
  text-align: center;
}

.empty-providers p {
  margin: 0;
}
.provider-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--rf-space-4);
  padding: var(--rf-space-4) var(--rf-space-5);
  border-bottom: 1px solid var(--rf-border);
}
.provider-row.active {
  background: var(--rf-accent-muted);
  box-shadow: inset 3px 0 0 var(--rf-accent);
}
.provider-main { min-width: 0; flex: 1; }
.provider-title-row {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 4px;
}
.provider-name {
  font-size: 15px;
  font-weight: 650;
  color: var(--rf-text);
}
.provider-meta {
  font-size: 12px;
  color: var(--rf-text-secondary);
  margin-bottom: 2px;
}
.provider-url {
  font-size: 12.5px;
  color: var(--rf-info);
  word-break: break-all;
}
.provider-key {
  margin-top: 4px;
  font-size: 12px;
  color: var(--rf-text-muted);
}
.provider-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  flex-shrink: 0;
}
.add-row {
  padding: var(--rf-space-3) var(--rf-space-5) var(--rf-space-4);
  border-top: 1px solid var(--rf-border);
}
.foot-note {
  margin: var(--rf-space-3) 0 0;
  font-size: 12.5px;
  color: var(--rf-text-muted);
  text-align: center;
}
.row-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--rf-space-4);
  padding: var(--rf-space-4) var(--rf-space-5);
  border-bottom: 1px solid var(--rf-border);
}
.row-item:last-child { border-bottom: none; }
.row-title {
  font-size: 14px;
  font-weight: 600;
  color: var(--rf-text);
}
.row-desc {
  margin-top: 4px;
  font-size: 12.5px;
  color: var(--rf-text-secondary);
}
.row-value {
  font-size: 14px;
  font-weight: 650;
  color: var(--rf-text);
  flex-shrink: 0;
}
.save-row {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
  margin-top: var(--rf-space-4);
}
.model-row {
  display: flex;
  gap: 8px;
  width: 100%;
}
.mono { font-family: var(--rf-font-mono); }
.tpl-editor :deep(textarea) {
  font-family: var(--rf-font-mono);
  font-size: 12.5px;
  line-height: 1.6;
  box-shadow: none !important;
  background: transparent !important;
}

.about-card {
  padding: var(--rf-space-5);
  display: flex;
  flex-direction: column;
  gap: var(--rf-space-4);
}
.about-top {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: var(--rf-space-4);
  flex-wrap: wrap;
}
.about-identity {
  display: flex;
  align-items: center;
  gap: var(--rf-space-3);
}
.about-mark {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 44px;
  height: 44px;
  border-radius: 12px;
  overflow: hidden;
  flex-shrink: 0;
  line-height: 0;
}
.about-name {
  font-size: 18px;
  font-weight: 700;
  color: var(--rf-text);
  margin-bottom: 6px;
}
.about-version {
  display: inline-block;
  padding: 2px 10px;
  border-radius: var(--rf-radius-tag);
  background: var(--rf-bg-raised);
  border: 1px solid var(--rf-border);
  font-size: 12px;
  color: var(--rf-text-secondary);
}
.about-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  justify-content: flex-end;
}
.about-banner {
  padding: 12px 14px;
  border-radius: var(--rf-radius-control);
  font-size: 13px;
  font-weight: 500;
}
.about-banner.checking {
  background: var(--rf-bg-raised);
  color: var(--rf-text-secondary);
  border: 1px solid var(--rf-border);
}
.about-banner.available {
  background: var(--rf-accent-muted);
  color: var(--rf-accent);
  border: 1px solid rgba(45, 212, 191, 0.35);
}
.about-banner.latest {
  background: rgba(52, 211, 153, 0.1);
  color: var(--rf-success);
  border: 1px solid rgba(52, 211, 153, 0.3);
}
.about-banner.error {
  background: rgba(248, 113, 113, 0.1);
  color: var(--rf-danger);
  border: 1px solid rgba(248, 113, 113, 0.3);
}

.env-card {
  gap: var(--rf-space-4);
}
.env-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: var(--rf-space-4);
  flex-wrap: wrap;
}
.env-title {
  margin: 0 0 4px;
  font-size: 15px;
  font-weight: 650;
  color: var(--rf-text);
}
.env-desc {
  margin: 0;
  font-size: 12.5px;
  color: var(--rf-text-secondary);
}
.env-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}
.env-rows {
  display: flex;
  flex-direction: column;
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-control);
  overflow: hidden;
}
.env-row {
  display: grid;
  grid-template-columns: 96px 1fr;
  gap: var(--rf-space-3);
  padding: 10px 14px;
  border-bottom: 1px solid var(--rf-border);
  font-size: 13px;
}
.env-row:last-child {
  border-bottom: none;
}
.env-key {
  color: var(--rf-text-secondary);
}
.env-val {
  color: var(--rf-text);
  font-variant-numeric: tabular-nums;
}
.env-val.warn {
  color: var(--rf-warning, #e6a23c);
}
</style>
