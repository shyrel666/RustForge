<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";
import { getVersion } from "@tauri-apps/api/app";
import VChart from "vue-echarts";
import { use } from "echarts/core";
import { CanvasRenderer } from "echarts/renderers";
import { LineChart } from "echarts/charts";
import {
  TitleComponent,
  TooltipComponent,
  LegendComponent,
  GridComponent,
} from "echarts/components";
import {
  Link,
  Document,
  Refresh,
  Sunny,
  Moon,
  Monitor,
  CopyDocument,
  FolderOpened,
  Loading,
} from "@element-plus/icons-vue";
import { useSettingsStore, type AiProvider } from "../stores/settings";
import { useAppUpdater } from "../services/appUpdater";
import AppUpdateButton from "../components/AppUpdateButton.vue";
import PageHeader from "../components/shell/PageHeader.vue";
import BrandMark from "../components/brand/BrandMark.vue";
import packageMetadata from "../../package.json";
import {
  getPromptTemplate,
  listPromptVersions,
  setPromptTemplate,
  copyPromptTemplate,
  rollbackPromptTemplate,
  resetPromptTemplate,
  getAiDataPolicy,
  setAiDataPolicy,
  getTokenUsage,
  resetTokenUsage,
  fetchModels,
  setProviderApiKey,
  deleteProviderApiKey,
  openUrl,
  proxyStatus,
  getCaInfo,
  getRuntimeInfo,
  revealAppDataDir,
  getUsageTrend,
  type TokenUsage,
  type UsageTrendPoint,
  type RuntimeInfo,
  type AiDataPolicy,
  type PromptTemplateVersion,
} from "../api/tauri";
import type { ThemeMode } from "../utils/theme";
import { runDiagnosticJobs } from "../utils/runtimeDiagnostics";

use([
  CanvasRenderer,
  LineChart,
  TitleComponent,
  TooltipComponent,
  LegendComponent,
  GridComponent,
]);

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

const appVersion = ref(packageMetadata.version);

const runtimeInfo = ref<RuntimeInfo | null>(null);
const proxyRunning = ref(false);
const proxyPort = ref(0);
const proxyLoaded = ref(false);
const caTrusted = ref<boolean | null>(null);
const diagLoading = ref(false);
const diagnosticsLoaded = ref(false);
const diagnosticsError = ref("");
let diagnosticsGeneration = 0;

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
  if (!runtimeInfo.value) return diagLoading.value ? "正在读取…" : "—";
  return formatOsLabel(runtimeInfo.value.os, runtimeInfo.value.arch);
});

const proxyLabel = computed(() => {
  if (!proxyLoaded.value) return diagLoading.value ? "正在读取…" : "—";
  const port =
    proxyRunning.value && proxyPort.value > 0
      ? proxyPort.value
      : settings.proxy_port;
  if (proxyRunning.value) return `运行中 · 端口 ${port}`;
  return `未运行 · 配置端口 ${port}`;
});

const caLabel = computed(() => {
  if (caTrusted.value === null) {
    return diagLoading.value ? "正在读取…" : "—";
  }
  return caTrusted.value ? "已信任" : "未安装 / 未信任";
});

async function loadDiagnostics(force = false) {
  if (diagLoading.value || (diagnosticsLoaded.value && !force)) return;
  const generation = ++diagnosticsGeneration;
  const canCommit = () =>
    generation === diagnosticsGeneration && diagLoading.value;
  diagLoading.value = true;
  diagnosticsError.value = "";
  try {
    const result = await runDiagnosticJobs([
      {
        label: "应用版本",
        run: async () => {
          const version = await getVersion();
          if (canCommit()) appVersion.value = version;
        },
      },
      {
        label: "系统信息",
        run: async () => {
          const runtime = await getRuntimeInfo();
          if (canCommit()) runtimeInfo.value = runtime;
        },
      },
      {
        label: "代理状态",
        run: async () => {
          const proxy = await proxyStatus();
          if (canCommit()) {
            proxyRunning.value = proxy.running;
            proxyPort.value = proxy.port;
            proxyLoaded.value = true;
          }
        },
      },
      {
        label: "CA 证书",
        run: async () => {
          const ca = await getCaInfo();
          if (canCommit()) caTrusted.value = ca.trusted;
        },
      },
    ]);
    if (generation === diagnosticsGeneration) {
      diagnosticsLoaded.value = true;
      diagnosticsError.value = result.failures.join("；");
    }
  } finally {
    if (generation === diagnosticsGeneration) diagLoading.value = false;
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
const PRESETS: {
  label: string;
  name: string;
  base_url: string;
  model: string;
  supports_json_schema: boolean;
}[] = [
  { label: "深度求索 DeepSeek", name: "DeepSeek", base_url: "https://api.deepseek.com", model: "deepseek-v4-flash", supports_json_schema: false },
  { label: "月之暗面 Kimi", name: "Kimi", base_url: "https://api.moonshot.cn/v1", model: "kimi-k3", supports_json_schema: false },
  { label: "通义千问 Qwen", name: "通义千问", base_url: "https://dashscope.aliyuncs.com/compatible-mode/v1", model: "qwen-max", supports_json_schema: false },
  { label: "智谱 GLM", name: "智谱 GLM", base_url: "https://open.bigmodel.cn/api/paas/v4", model: "glm-5.2", supports_json_schema: false },
  { label: "MiniMax", name: "MiniMax", base_url: "https://api.minimax.io/v1", model: "MiniMax-M3", supports_json_schema: false },
  { label: "Xiaomi MiMo", name: "Xiaomi MiMo", base_url: "https://api.xiaomimimo.com/v1", model: "mimo-v2.5-pro", supports_json_schema: false },
  { label: "OpenAI", name: "OpenAI", base_url: "https://api.openai.com/v1", model: "gpt-5.6", supports_json_schema: true },
  { label: "OpenRouter", name: "OpenRouter", base_url: "https://openrouter.ai/api/v1", model: "openai/gpt-5.6", supports_json_schema: false },
  { label: "硅基流动 SiliconFlow", name: "SiliconFlow", base_url: "https://api.siliconflow.cn/v1", model: "deepseek-ai/DeepSeek-V4-Pro", supports_json_schema: false },
  { label: "自定义", name: "", base_url: "", model: "", supports_json_schema: false },
];

// ---------- 供应商增改对话框 ----------
const dialogVisible = ref(false);
const editingId = ref<string | null>(null);
const presetKey = ref("");
const modelOptions = ref<string[]>([]);
const fetchingModels = ref(false);
const testing = ref(false);
interface ProviderForm {
  name: string;
  base_url: string;
  api_key: string;
  model: string;
  note: string;
  supports_json_schema: boolean;
}

const form = reactive<ProviderForm>({
  name: "",
  base_url: "",
  api_key: "",
  model: "",
  note: "",
  supports_json_schema: false,
});

const dialogTitle = computed(() => (editingId.value ? "编辑供应商" : "添加供应商"));
const editingProvider = computed(() =>
  editingId.value
    ? settings.providers.find((provider) => provider.id === editingId.value) ?? null
    : null
);
const providerHasStoredKey = computed(
  () => editingProvider.value?.has_api_key === true
);

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
  form.supports_json_schema = false;
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
  // 系统凭据库里的 Key 永不回填到前端。
  form.api_key = "";
  form.model = p.model;
  form.note = p.note;
  form.supports_json_schema = p.supports_json_schema;
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
  form.supports_json_schema = preset.supports_json_schema;
  modelOptions.value = preset.model ? [preset.model] : [];
}

async function doFetchModels() {
  if (!form.base_url.trim()) {
    ElMessage.warning("请先填写 Base URL");
    return;
  }
  const providerId = editingId.value;
  if (!providerId) {
    ElMessage.warning("新增供应商请先保存，再编辑并获取模型");
    return;
  }
  const stored = settings.providers.find((provider) => provider.id === providerId);
  if (!stored || stored.base_url.replace(/\/+$/, "") !== form.base_url.trim().replace(/\/+$/, "")) {
    ElMessage.warning("Base URL 已修改，请先保存供应商后再获取模型");
    return;
  }
  fetchingModels.value = true;
  try {
    await persistDraftKey(providerId);
    const list = await fetchModels(providerId);
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
  if (!form.base_url.trim()) {
    ElMessage.warning("请先填写 Base URL");
    return;
  }
  const providerId = editingId.value;
  if (!providerId) {
    ElMessage.warning("新增供应商请先保存，再编辑并测试连接");
    return;
  }
  const stored = settings.providers.find((provider) => provider.id === providerId);
  if (!stored || stored.base_url.replace(/\/+$/, "") !== form.base_url.trim().replace(/\/+$/, "")) {
    ElMessage.warning("Base URL 已修改，请先保存供应商后再测试连接");
    return;
  }
  testing.value = true;
  try {
    await persistDraftKey(providerId);
    const list = await fetchModels(providerId);
    ElMessage.success(`连接成功：鉴权通过，可用模型 ${list.length} 个`);
  } catch (e) {
    ElMessage.error(`连接失败：${String(e)}`);
  } finally {
    testing.value = false;
  }
}

async function persistDraftKey(providerId: string) {
  const draftKey = form.api_key.trim();
  if (draftKey) {
    // Key 只在这次专用 IPC 写入期间短暂存在，立即清空响应式表单。
    form.api_key = "";
    const status = await setProviderApiKey(providerId, draftKey);
    settings.setProviderKeyStatus(providerId, status.has_api_key);
    return;
  }
  if (!settings.providers.find((provider) => provider.id === providerId)?.has_api_key) {
    throw new Error("当前供应商未配置 API Key");
  }
}

async function clearCurrentApiKey() {
  const providerId = editingId.value;
  if (!providerId) return;
  try {
    await ElMessageBox.confirm(
      "确定从系统凭据库删除这个供应商的 API Key？",
      "删除 API Key",
      { type: "warning" }
    );
  } catch {
    return;
  }
  try {
    const status = await deleteProviderApiKey(providerId);
    settings.setProviderKeyStatus(providerId, status.has_api_key);
    form.api_key = "";
    ElMessage.success("API Key 已从系统凭据库删除");
  } catch (e) {
    ElMessage.error(String(e));
  }
}

async function saveProvider() {
  if (!form.base_url.trim()) {
    ElMessage.warning("请填写 Base URL");
    return;
  }
  if (!editingId.value && !form.api_key.trim()) {
    ElMessage.warning("新增供应商时请填写 API Key");
    return;
  }
  if (
    editingId.value &&
    !providerHasStoredKey.value &&
    !form.api_key.trim()
  ) {
    ElMessage.warning("当前供应商尚未配置 API Key");
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
    model: form.model.trim(),
    note: form.note.trim(),
    supports_json_schema: form.supports_json_schema,
  };
  const existingId = editingId.value;
  let providerId: string;
  if (existingId) {
    settings.updateProvider(existingId, payload);
    providerId = existingId;
  } else {
    providerId = settings.addProvider(payload);
  }
  try {
    await settings.save();
    if (!existingId) {
      // 元数据已存在后立即切换为编辑态；即使凭据库写入失败，重试也不会重复新增。
      editingId.value = providerId;
    }
    await persistDraftKey(providerId);
    ElMessage.success("供应商已保存");
    dialogVisible.value = false;
  } catch (e) {
    // 重新读取后端真值：若仅 Key 写入失败，保留已落库的无 Key 供应商供重试；
    // 若元数据写入失败，则恢复修改前状态。
    await settings.load().catch(() => undefined);
    if (
      !existingId &&
      settings.providers.some((provider) => provider.id === providerId)
    ) {
      editingId.value = providerId;
    }
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
  const previousProviders = [...settings.providers];
  const previousCurrent = settings.current_provider_id;
  settings.removeProvider(p.id);
  try {
    await settings.save();
    ElMessage.success("已删除");
  } catch (e) {
    settings.providers = previousProviders;
    settings.current_provider_id = previousCurrent;
    await settings.load().catch(() => undefined);
    ElMessage.error(String(e));
  }
}

// ---------- 提示词模板 ----------
const template = ref("");
const templateSaving = ref(false);
const templateDirty = ref(false);
const promptState = ref<PromptTemplateVersion | null>(null);
const promptVersions = ref<PromptTemplateVersion[]>([]);

const aiPolicy = reactive<AiDataPolicy>({
  redact_query_values: true,
  redact_sensitive_headers: true,
  redact_body_secrets: true,
  include_truncated_bodies: false,
  include_binary_bodies: false,
  include_decode_failed_bodies: false,
  request_body_max_bytes: 8 * 1024,
  response_body_max_bytes: 12 * 1024,
  total_context_max_bytes: 32 * 1024,
});
const policyRelaxed = computed(
  () =>
    !aiPolicy.redact_query_values ||
    !aiPolicy.redact_sensitive_headers ||
    !aiPolicy.redact_body_secrets ||
    aiPolicy.include_truncated_bodies ||
    aiPolicy.include_binary_bodies ||
    aiPolicy.include_decode_failed_bodies ||
    aiPolicy.request_body_max_bytes > 8 * 1024 ||
    aiPolicy.response_body_max_bytes > 12 * 1024 ||
    aiPolicy.total_context_max_bytes > 32 * 1024
);

function applyPromptState(state: PromptTemplateVersion) {
  promptState.value = state;
  template.value = state.content;
  templateDirty.value = false;
}

async function refreshPromptVersions() {
  promptVersions.value = await listPromptVersions();
}

// ---------- 用量统计 ----------
const usage = ref<TokenUsage>({ calls: 0, prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 });

async function refreshUsage() {
  try {
    usage.value = await getTokenUsage();
  } catch (e) {
    ElMessage.error(String(e));
  }
}

// ---------- 使用趋势 ----------
const trendGranularity = ref<'day' | 'month'>('day');
const trendData = ref<UsageTrendPoint[]>([]);
const trendLoading = ref(false);

async function refreshTrend() {
  trendLoading.value = true;
  try {
    trendData.value = await getUsageTrend(trendGranularity.value);
  } catch (e) {
    ElMessage.error(String(e));
  } finally {
    trendLoading.value = false;
  }
}

watch(trendGranularity, refreshTrend);

const chartOption = computed(() => ({
  tooltip: { trigger: 'axis' as const },
  legend: { data: ['总 Token', '输入 Token', '输出 Token'], bottom: 0 },
  grid: { left: 60, right: 20, top: 20, bottom: 40 },
  xAxis: {
    type: 'category' as const,
    data: trendData.value.map((d) => d.period),
    axisLabel: { fontSize: 11 },
  },
  yAxis: {
    type: 'value' as const,
    name: 'Tokens',
    axisLabel: {
      formatter: (v: number) => (v >= 1000 ? `${(v / 1000).toFixed(0)}k` : String(v)),
    },
  },
  series: [
    {
      name: '总 Token',
      type: 'line',
      data: trendData.value.map((d) => d.total_tokens),
      smooth: true,
      showSymbol: false,
      lineStyle: { width: 2 },
      areaStyle: { opacity: 0.08 },
    },
    {
      name: '输入 Token',
      type: 'line',
      data: trendData.value.map((d) => d.prompt_tokens),
      smooth: true,
      showSymbol: false,
      lineStyle: { width: 1.5, type: 'dashed' as const },
    },
    {
      name: '输出 Token',
      type: 'line',
      data: trendData.value.map((d) => d.completion_tokens),
      smooth: true,
      showSymbol: false,
      lineStyle: { width: 1.5, type: 'dotted' as const },
    },
  ],
}));

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
  applyPromptState(await getPromptTemplate());
  await refreshPromptVersions();
  Object.assign(aiPolicy, await getAiDataPolicy());
  await refreshUsage();
  await refreshTrend();
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
    applyPromptState(await setPromptTemplate(template.value));
    await refreshPromptVersions();
    ElMessage.success("已保存为新的提示词版本，下次预览生效");
  } catch (e) {
    ElMessage.error(String(e));
  } finally {
    templateSaving.value = false;
  }
}

async function resetTemplate() {
  try {
    applyPromptState(await resetPromptTemplate());
    await refreshPromptVersions();
    ElMessage.success("已恢复内置默认模板");
  } catch (e) {
    ElMessage.error(String(e));
  }
}

async function copyTemplateVersion(source: PromptTemplateVersion) {
  try {
    applyPromptState(await copyPromptTemplate(source.id));
    await refreshPromptVersions();
    ElMessage.success("已复制为新的活动版本");
  } catch (e) {
    ElMessage.error(String(e));
  }
}

async function rollbackTemplateVersion(source: PromptTemplateVersion) {
  try {
    await ElMessageBox.confirm(
      `将 v${source.version} 的内容复制为一个新的活动版本？历史版本不会被覆盖。`,
      "回滚提示词",
      { type: "warning" }
    );
  } catch {
    return;
  }
  try {
    applyPromptState(await rollbackPromptTemplate(source.id));
    await refreshPromptVersions();
    ElMessage.success("回滚完成，已创建新的活动版本");
  } catch (e) {
    ElMessage.error(String(e));
  }
}

async function save() {
  saving.value = true;
  try {
    await Promise.all([settings.save(), setAiDataPolicy({ ...aiPolicy })]);
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
            OpenAI 兼容接口，用户自带 Key。Key 只保存在系统凭据库，不写入本地数据库。
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
                  <el-tag
                    v-if="row.supports_json_schema"
                    size="small"
                    effect="plain"
                    type="success"
                  >JSON Schema</el-tag>
                </div>
                <div class="provider-meta mono">{{ row.model || "未指定模型" }}</div>
                <div class="provider-url">{{ row.base_url }}</div>
                <div
                  class="provider-key"
                  :class="{ configured: row.has_api_key }"
                >
                  系统凭据库：{{ row.has_api_key ? "已配置" : "未配置" }}
                </div>
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
        <div class="setting-head">
          <h2 class="rf-section-title">AI 默认数据策略</h2>
          <p class="rf-section-desc">
            每次分析仍会显示最终发送预览；这里控制预览初始值。正文和总上下文上限由后端强制校验。
          </p>
        </div>
        <el-alert
          v-if="policyRelaxed"
          type="warning"
          :closable="false"
          title="当前默认策略放宽了至少一项最小披露保护；每次发送仍需在预览页再次确认。"
          class="policy-warning"
        />
        <div class="rf-card control-card">
          <div class="row-item">
            <div class="row-label">
              <div class="row-title">遮盖 URL 查询值</div>
              <div class="row-desc">保留 scheme、host、path 与参数名</div>
            </div>
            <el-switch v-model="aiPolicy.redact_query_values" />
          </div>
          <div class="row-item">
            <div class="row-label">
              <div class="row-title">遮盖敏感 Header</div>
              <div class="row-desc">Authorization、Cookie、Set-Cookie 与常见 Token Header</div>
            </div>
            <el-switch v-model="aiPolicy.redact_sensitive_headers" />
          </div>
          <div class="row-item">
            <div class="row-label">
              <div class="row-title">结构化正文秘密脱敏</div>
              <div class="row-desc">JSON、表单、multipart、秘密格式和高熵值</div>
            </div>
            <el-switch v-model="aiPolicy.redact_body_secrets" />
          </div>
          <div class="row-item">
            <div class="row-label">
              <div class="row-title">异常正文显式放宽</div>
              <div class="row-desc">默认不发送截断、二进制或解码/流异常正文</div>
            </div>
            <div class="inline-switches">
              <el-checkbox v-model="aiPolicy.include_truncated_bodies">截断</el-checkbox>
              <el-checkbox v-model="aiPolicy.include_binary_bodies">二进制</el-checkbox>
              <el-checkbox v-model="aiPolicy.include_decode_failed_bodies">解码异常</el-checkbox>
            </div>
          </div>
          <div class="row-item">
            <div class="row-label">
              <div class="row-title">请求 / 响应正文上限</div>
              <div class="row-desc">每方向最高 24 KiB</div>
            </div>
            <div class="inline-limits">
              <el-input-number v-model="aiPolicy.request_body_max_bytes" :min="0" :max="24576" :step="1024" />
              <span>/</span>
              <el-input-number v-model="aiPolicy.response_body_max_bytes" :min="0" :max="24576" :step="1024" />
            </div>
          </div>
          <div class="row-item">
            <div class="row-label">
              <div class="row-title">总上下文硬上限</div>
              <div class="row-desc">包含 system 与 user 消息，范围 16–64 KiB</div>
            </div>
            <el-input-number v-model="aiPolicy.total_context_max_bytes" :min="16384" :max="65536" :step="1024" />
          </div>
        </div>
      </section>

      <section class="setting-block">
        <div class="setting-head with-action">
          <div>
            <h2 class="rf-section-title">Token 统计</h2>
            <p class="rf-section-desc">本机累计的 AI 调用次数与 Token 消耗统计。</p>
          </div>
          <el-button link type="primary" @click="refreshUsage(); refreshTrend()">刷新</el-button>
        </div>

        <!-- 统计卡片 -->
        <div class="stats-cards">
          <div class="stat-card">
            <div class="stat-label">调用次数</div>
            <div class="stat-value">{{ usage.calls }}</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">输入 Token</div>
            <div class="stat-value">{{ usage.prompt_tokens.toLocaleString() }}</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">输出 Token</div>
            <div class="stat-value">{{ usage.completion_tokens.toLocaleString() }}</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">总 Token</div>
            <div class="stat-value">{{ usage.total_tokens.toLocaleString() }}</div>
          </div>
        </div>

        <!-- 使用趋势 -->
        <div class="trend-section">
          <div class="trend-head">
            <h3 class="trend-title">使用趋势</h3>
            <el-radio-group v-model="trendGranularity" size="small">
              <el-radio-button label="day">日</el-radio-button>
              <el-radio-button label="month">月</el-radio-button>
            </el-radio-group>
          </div>
          <div v-loading="trendLoading" class="trend-chart-wrapper">
            <div v-if="trendLoading" class="trend-empty">加载中...</div>
            <div v-else-if="trendData.length === 0" class="trend-empty">暂无使用数据</div>
            <v-chart v-else :option="chartOption" autoresize style="height: 280px; width: 100%" />
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
          REQUEST/RESPONSE 的实际内容由每次预览的 policy 与 manifest 决定；两者必须且只能各出现一次。
        </p>
      </div>
      <div v-if="promptState" class="prompt-current">
        <el-tag :type="promptState.source === 'builtin' ? 'info' : 'success'" effect="plain">
          当前：{{ promptState.source }} · v{{ promptState.version }}
        </el-tag>
        <span>{{ promptState.prompt_id }}</span>
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
          保存为新版本
        </el-button>
        <el-button v-if="promptState" @click="copyTemplateVersion(promptState)">复制当前版本</el-button>
        <el-button @click="resetTemplate">恢复默认</el-button>
      </div>

      <div class="setting-head version-head">
        <h3 class="rf-section-title">版本历史</h3>
        <p class="rf-section-desc">版本不可覆盖；回滚会复制所选内容并生成新的活动版本。</p>
      </div>
      <el-table :data="promptVersions" size="small" border row-key="version">
        <el-table-column label="版本" width="100">
          <template #default="scope">v{{ scope.row.version }}</template>
        </el-table-column>
        <el-table-column prop="source" label="来源" width="100" />
        <el-table-column prop="operation" label="操作" width="100" />
        <el-table-column prop="created_at" label="创建时间" min-width="170">
          <template #default="scope">{{ scope.row.created_at || "内置" }}</template>
        </el-table-column>
        <el-table-column label="状态 / 操作" min-width="230" align="right">
          <template #default="scope">
            <el-tag v-if="scope.row.active" type="success" size="small" effect="plain">活动</el-tag>
            <el-button link type="primary" @click="copyTemplateVersion(scope.row)">复制</el-button>
            <el-button
              v-if="!scope.row.active"
              link
              type="warning"
              @click="rollbackTemplateVersion(scope.row)"
            >回滚</el-button>
          </template>
        </el-table-column>
      </el-table>
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

      <div
        class="about-card rf-card env-card"
        :aria-busy="diagLoading"
      >
        <div class="env-head">
          <div>
            <h3 class="env-title">运行环境</h3>
            <p class="env-desc">本地摘要，便于自查与提交 Issue。</p>
          </div>
          <div class="env-actions">
            <el-button
              :icon="Refresh"
              :loading="diagLoading"
              @click="loadDiagnostics(true)"
            >
              刷新
            </el-button>
            <el-button
              :icon="CopyDocument"
              :disabled="!diagnosticsLoaded"
              @click="copyDiagnostics"
            >
              复制诊断信息
            </el-button>
            <el-button :icon="FolderOpened" @click="openDataDir">打开数据目录</el-button>
          </div>
        </div>
        <div
          v-if="diagLoading"
          class="env-load-status"
          role="status"
          aria-live="polite"
        >
          <el-icon class="is-loading"><Loading /></el-icon>
          <span>正在后台读取本机环境，页面仍可正常操作。</span>
        </div>
        <div
          v-else-if="diagnosticsError"
          class="env-load-status is-error"
          role="alert"
        >
          <strong>部分信息读取失败，不影响其他功能。</strong>
          <span>{{ diagnosticsError }}</span>
        </div>
        <div class="env-rows">
          <div class="env-row">
            <span class="env-key">应用</span>
            <span class="env-val">{{ APP_NAME }} v{{ appVersion }}</span>
          </div>
          <div class="env-row">
            <span class="env-key">系统</span>
            <span
              class="env-val"
              :class="{ pending: !runtimeInfo && diagLoading }"
            >
              {{ systemLabel }}
            </span>
          </div>
          <div class="env-row">
            <span class="env-key">代理</span>
            <span
              class="env-val"
              :class="{ pending: !proxyLoaded && diagLoading }"
            >
              {{ proxyLabel }}
            </span>
          </div>
          <div class="env-row">
            <span class="env-key">CA 证书</span>
            <span
              class="env-val"
              :class="{
                warn: caTrusted === false,
                pending: caTrusted === null && diagLoading,
              }"
            >
              {{ caLabel }}
            </span>
          </div>
        </div>
      </div>

      <p class="foot-note">
        {{ APP_NAME }} 仅供授权渗透测试与安全学习使用 · MIT License
      </p>
    </section>

    <el-dialog
      v-model="dialogVisible"
      :title="dialogTitle"
      width="520px"
      @closed="form.api_key = ''"
    >
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
          <div class="key-field">
            <div class="key-row">
              <el-input
                v-model="form.api_key"
                type="password"
                show-password
                :placeholder="
                  providerHasStoredKey
                    ? '留空则保留系统凭据库中的现有 Key'
                    : '输入后将写入系统凭据库'
                "
              />
              <el-button
                v-if="editingId && providerHasStoredKey"
                type="danger"
                plain
                @click="clearCurrentApiKey"
              >
                清除
              </el-button>
            </div>
            <div class="key-hint">
              {{
                providerHasStoredKey
                  ? "已配置；完整 Key 不会回填到界面"
                  : "尚未配置"
              }}
            </div>
          </div>
        </el-form-item>
        <el-form-item label="模型">
          <div class="model-row">
            <el-select v-model="form.model" filterable allow-create default-first-option placeholder="deepseek-chat / gpt-4o-mini ..." style="flex: 1">
              <el-option v-for="m in modelSelectOptions" :key="m" :label="m" :value="m" />
            </el-select>
            <el-button
              :loading="fetchingModels"
              :disabled="!editingId"
              @click="doFetchModels"
            >
              获取模型
            </el-button>
          </div>
        </el-form-item>
        <el-form-item label="结构化输出">
          <div class="schema-option">
            <el-switch v-model="form.supports_json_schema" />
            <span>仅在供应商明确支持 OpenAI JSON Schema `response_format` 时开启</span>
          </div>
        </el-form-item>
        <el-form-item label="备注">
          <el-input v-model="form.note" placeholder="可选：用途 / 套餐 / 到期时间" />
        </el-form-item>
      </el-form>
      <p v-if="!editingId" class="dialog-hint">
        新增供应商先保存元数据和 Key；之后可重新编辑并获取模型或测试连接。
      </p>
      <template #footer>
        <el-button :loading="testing" :disabled="!editingId" @click="testConnection">
          测试连接
        </el-button>
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
.provider-key.configured {
  color: var(--rf-success);
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
.schema-option {
  display: flex;
  align-items: center;
  gap: 10px;
  color: var(--el-text-color-secondary);
  font-size: 12px;
  line-height: 1.5;
}
.policy-warning {
  margin-bottom: 10px;
}
.inline-switches,
.inline-limits {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  flex-wrap: wrap;
  gap: 8px;
}
.prompt-current {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 10px;
  color: var(--el-text-color-secondary);
  font-size: 12px;
}
.version-head {
  margin-top: 28px;
}
.key-field {
  width: 100%;
}
.key-row {
  display: flex;
  gap: 8px;
  width: 100%;
}
.key-row .el-input {
  flex: 1;
}
.key-hint,
.dialog-hint {
  margin-top: 6px;
  font-size: 12px;
  line-height: 1.5;
  color: var(--rf-text-muted);
}
.dialog-hint {
  margin: 0 0 4px 90px;
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
.env-load-status {
  display: flex;
  align-items: center;
  gap: 9px;
  padding: 10px 12px;
  border: 1px solid
    color-mix(in srgb, var(--rf-accent) 28%, var(--rf-border));
  border-radius: var(--rf-radius-control);
  background: var(--rf-accent-muted);
  color: var(--rf-text-secondary);
  font-size: 12.5px;
  line-height: 1.5;
}
.env-load-status .el-icon {
  flex: 0 0 auto;
  color: var(--rf-accent);
}
.env-load-status.is-error {
  align-items: flex-start;
  flex-direction: column;
  gap: 3px;
  border-color: color-mix(
    in srgb,
    var(--rf-warning, #e6a23c) 34%,
    var(--rf-border)
  );
  background: color-mix(
    in srgb,
    var(--rf-warning, #e6a23c) 8%,
    transparent
  );
}
.env-load-status.is-error strong {
  color: var(--rf-warning, #e6a23c);
  font-size: 12.5px;
}
.env-load-status.is-error span {
  color: var(--rf-text-secondary);
  overflow-wrap: anywhere;
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
.env-val.pending {
  color: var(--rf-text-muted);
}
.env-val.warn {
  color: var(--rf-warning, #e6a23c);
}

.stats-cards {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 12px;
  margin-bottom: 20px;
}

.stat-card {
  background: var(--rf-bg-panel);
  border: 1px solid var(--rf-border);
  border-radius: 8px;
  padding: 16px;
  text-align: center;
}

.stat-label {
  font-size: 12px;
  color: var(--rf-text-secondary);
  margin-bottom: 8px;
}

.stat-value {
  font-size: 22px;
  font-weight: 600;
  color: var(--rf-text);
}

.trend-section {
  margin-top: 8px;
}

.trend-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 12px;
}

.trend-title {
  font-size: 15px;
  font-weight: 600;
  margin: 0;
  color: var(--rf-text);
}

.trend-chart-wrapper {
  background: var(--rf-bg-panel);
  border: 1px solid var(--rf-border);
  border-radius: 8px;
  padding: 16px;
  min-height: 320px;
}

.trend-empty {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 280px;
  color: var(--rf-text-secondary);
  font-size: 14px;
}
</style>
