<script setup lang="ts">
import { computed, onMounted, reactive, ref } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";
import { useSettingsStore, type AiProvider } from "../stores/settings";
import {
  getPromptTemplate,
  setPromptTemplate,
  resetPromptTemplate,
  getTokenUsage,
  resetTokenUsage,
  fetchModels,
  type TokenUsage,
} from "../api/tauri";

const settings = useSettingsStore();
const saving = ref(false);

// 常用供应商预设：选择后自动填充名称/端点/默认模型，只需再填 API Key
const PRESETS: { label: string; name: string; base_url: string; model: string }[] = [
  { label: "DeepSeek", name: "DeepSeek", base_url: "https://api.deepseek.com", model: "deepseek-chat" },
  { label: "Kimi (Moonshot)", name: "Kimi", base_url: "https://api.moonshot.cn/v1", model: "moonshot-v1-8k" },
  { label: "通义千问（百炼）", name: "通义千问", base_url: "https://dashscope.aliyuncs.com/compatible-mode/v1", model: "qwen-plus" },
  { label: "智谱 GLM", name: "智谱 GLM", base_url: "https://open.bigmodel.cn/api/paas/v4", model: "glm-4-flash" },
  { label: "OpenAI", name: "OpenAI", base_url: "https://api.openai.com/v1", model: "gpt-4o-mini" },
  { label: "OpenRouter", name: "OpenRouter", base_url: "https://openrouter.ai/api/v1", model: "openai/gpt-4o-mini" },
  { label: "硅基流动 SiliconFlow", name: "SiliconFlow", base_url: "https://api.siliconflow.cn/v1", model: "deepseek-ai/DeepSeek-V3" },
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
    <h2>设置</h2>

    <el-card shadow="never" class="card">
      <template #header>
        <div class="card-header">
          <span>🤖 AI 供应商（OpenAI 兼容接口，用户自带 Key）</span>
          <el-switch v-model="settings.ai_enabled" active-text="启用" @change="save" />
        </div>
      </template>

      <el-table :data="settings.providers" size="small" empty-text="尚未添加供应商，点击下方按钮新增">
        <el-table-column label="当前" width="82">
          <template #default="{ row }">
            <el-tag v-if="row.id === settings.current_provider_id" type="success" size="small" effect="dark">
              当前
            </el-tag>
            <el-button v-else link size="small" @click="switchCurrent(row.id)">设为当前</el-button>
          </template>
        </el-table-column>
        <el-table-column prop="name" label="名称" min-width="120" show-overflow-tooltip />
        <el-table-column prop="model" label="模型" min-width="140" show-overflow-tooltip />
        <el-table-column prop="base_url" label="Base URL" min-width="200" show-overflow-tooltip />
        <el-table-column label="API Key" min-width="120">
          <template #default="{ row }">
            <span class="mono">{{ maskKey(row.api_key) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="130">
          <template #default="{ row }">
            <el-button link size="small" @click="openEdit(row)">编辑</el-button>
            <el-button link size="small" type="danger" @click="confirmDelete(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>

      <div class="provider-actions">
        <el-button type="primary" plain size="small" @click="openAdd">＋ 添加供应商</el-button>
      </div>

      <el-alert type="info" :closable="false" class="provider-hint">
        每个供应商是一套完整配置：名称 + Base URL + API Key + 模型。可添加多个并一键切换「当前」供应商，
        所有 AI 功能使用当前供应商。禁用 AI 时所有功能不可用、流量不外发。
      </el-alert>
    </el-card>

    <el-card shadow="never" class="card">
      <template #header><span>🌐 代理</span></template>
      <el-form label-width="110px">
        <el-form-item label="监听端口">
          <el-input-number v-model="settings.proxy_port" :min="1024" :max="65535" />
          <span class="hint">浏览器/系统代理指向 127.0.0.1:{{ settings.proxy_port }}（修改端口后需重启代理生效）</span>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card shadow="never" class="card">
      <template #header>
        <div class="card-header">
          <span>📊 AI 用量统计（本机累计）</span>
          <el-button link @click="refreshUsage">刷新</el-button>
        </div>
      </template>
      <el-form label-width="110px">
        <el-form-item label="调用次数">{{ usage.calls }}</el-form-item>
        <el-form-item label="Token 用量">
          输入 {{ usage.prompt_tokens }} · 输出 {{ usage.completion_tokens }} ·
          合计 <b>{{ usage.total_tokens }}</b>
        </el-form-item>
        <el-form-item label="每百万单价">
          <el-input-number v-model="settings.price_per_mtok" :min="0" :precision="2" :step="0.5" />
          <span class="hint">按你所用模型价格填写（货币自定），0 表示不估算</span>
        </el-form-item>
        <el-form-item v-if="estCost" label="预估成本">
          <b>{{ estCost }}</b>
          <span class="hint">= 合计 token ÷ 100万 × 单价（仅本地估算，以服务商账单为准）</span>
        </el-form-item>
      </el-form>
      <el-button type="danger" plain size="small" @click="doResetUsage">清零统计</el-button>
    </el-card>

    <el-card shadow="never" class="card">
      <template #header><span>📝 AI 分析提示词模板</span></template>
      <el-alert type="info" :closable="false" class="tpl-hint">
        可用占位符：<code>{METHOD}</code> <code>{URL}</code> <code>{HOST}</code>
        <code>{STATUS}</code> <code>{REQUEST}</code> <code>{RESPONSE}</code>
        <code>{RULE_TAGS}</code>。
        其中 <code>{REQUEST}</code>/<code>{RESPONSE}</code> 已自动脱敏（凭据类头打码）并截断。
      </el-alert>
      <el-input
        v-model="template"
        type="textarea"
        :rows="14"
        class="tpl-editor"
        @input="templateDirty = true"
      />
      <div class="tpl-actions">
        <el-button type="primary" :loading="templateSaving" :disabled="!templateDirty" @click="saveTemplate">
          保存模板
        </el-button>
        <el-button @click="resetTemplate">恢复默认</el-button>
      </div>
    </el-card>

    <el-button type="primary" :loading="saving" @click="save">保存设置</el-button>

    <el-dialog v-model="dialogVisible" :title="dialogTitle" width="520px">
      <el-form label-width="90px">
        <el-form-item label="预设">
          <el-select
            v-model="presetKey"
            placeholder="选择预设自动填充（可选）"
            clearable
            style="width: 100%"
            @change="applyPreset"
          >
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
            <el-select
              v-model="form.model"
              filterable
              allow-create
              default-first-option
              placeholder="deepseek-chat / gpt-4o-mini ..."
              style="flex: 1"
            >
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
  max-width: 720px;
}
.card {
  margin-bottom: 16px;
}
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.hint {
  margin-left: 12px;
  color: var(--el-text-color-secondary);
  font-size: 12px;
}
.provider-actions {
  margin: 12px 0 10px;
}
.provider-hint {
  margin-top: 4px;
}
.model-row {
  display: flex;
  gap: 8px;
  width: 100%;
}
.mono {
  font-family: Consolas, monospace;
  font-size: 12px;
}
.tpl-hint {
  margin-bottom: 10px;
}
.tpl-editor :deep(textarea) {
  font-family: Consolas, monospace;
  font-size: 12px;
  line-height: 1.6;
}
.tpl-actions {
  margin-top: 10px;
  display: flex;
  gap: 8px;
}
</style>
