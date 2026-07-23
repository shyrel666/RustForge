<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { ElMessage } from "element-plus";
import { useSettingsStore } from "../stores/settings";
import {
  getPromptTemplate,
  setPromptTemplate,
  resetPromptTemplate,
  getTokenUsage,
  resetTokenUsage,
  type TokenUsage,
} from "../api/tauri";

const settings = useSettingsStore();
const saving = ref(false);

// 提示词模板
const template = ref("");
const templateSaving = ref(false);
const templateDirty = ref(false);

// 用量统计
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
          <span>🤖 AI 接入（OpenAI 兼容接口，用户自带 Key）</span>
          <el-switch v-model="settings.ai_enabled" active-text="启用" />
        </div>
      </template>
      <el-form label-width="110px" :disabled="!settings.ai_enabled">
        <el-form-item label="Base URL">
          <el-input
            v-model="settings.base_url"
            placeholder="https://api.deepseek.com / https://api.openai.com 等"
          />
        </el-form-item>
        <el-form-item label="API Key">
          <el-input
            v-model="settings.api_key"
            type="password"
            show-password
            placeholder="sk-..."
          />
        </el-form-item>
        <el-form-item label="模型">
          <el-input v-model="settings.model" placeholder="deepseek-chat / gpt-4o-mini ..." />
        </el-form-item>
      </el-form>
      <el-alert type="info" :closable="false">
        常用兼容服务：DeepSeek（api.deepseek.com）、Kimi（api.moonshot.cn）、
        通义（dashscope.aliyuncs.com/compatible-mode）、OpenRouter 等。
        禁用时所有 AI 功能不可用，流量不会外发。
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
