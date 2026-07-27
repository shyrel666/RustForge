<script setup lang="ts">
import { computed, nextTick, ref, watch } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";
import {
  previewAiContext,
  type AiContextPreview,
  type AiDataPolicy,
} from "../api/tauri";

const props = withDefaults(
  defineProps<{
    modelValue: boolean;
    trafficId?: number;
    loadPreview?: (policy: AiDataPolicy | null) => Promise<AiContextPreview>;
    allowPolicyEditing?: boolean;
    confirmText?: string;
    description?: string;
  }>(),
  {
    allowPolicyEditing: true,
    confirmText: "确认并开始分析",
    description:
      "下方列出首次调用及校验失败时可能使用的固定重试消息；确认时后端会再次核对供应商目标、提示词、策略与消息哈希。",
  }
);

const emit = defineEmits<{
  "update:modelValue": [value: boolean];
  confirm: [payload: { policy: AiDataPolicy; inputHash: string }];
}>();

const defaultPolicy: AiDataPolicy = {
  redact_query_values: true,
  redact_sensitive_headers: true,
  redact_body_secrets: true,
  include_truncated_bodies: false,
  include_binary_bodies: false,
  include_decode_failed_bodies: false,
  request_body_max_bytes: 8 * 1024,
  response_body_max_bytes: 12 * 1024,
  total_context_max_bytes: 32 * 1024,
};

const policy = ref<AiDataPolicy>({ ...defaultPolicy });
const preview = ref<AiContextPreview | null>(null);
const loading = ref(false);
const dirty = ref(false);
const activeTab = ref("content");
let syncingPolicy = false;

const redactionCount = computed(
  () =>
    preview.value?.manifest.redactions.reduce(
      (total, record) => total + record.count,
      0
    ) ?? 0
);
const responseSchemaText = computed(() =>
  preview.value?.response_schema
    ? JSON.stringify(preview.value.response_schema, null, 2)
    : ""
);

watch(
  policy,
  () => {
    if (!syncingPolicy && preview.value) dirty.value = true;
  },
  { deep: true }
);

watch(
  () => props.modelValue,
  (open) => {
    if (open) void refreshPreview(true);
  }
);

watch(
  () => props.trafficId,
  () => {
    if (props.modelValue) void refreshPreview(true);
  }
);

function close() {
  emit("update:modelValue", false);
}

async function refreshPreview(useSavedPolicy = false) {
  loading.value = true;
  dirty.value = true;
  if (useSavedPolicy) preview.value = null;
  try {
    let next: AiContextPreview;
    if (props.loadPreview) {
      next = await props.loadPreview(
        props.allowPolicyEditing && !useSavedPolicy ? policy.value : null
      );
    } else {
      if (props.trafficId === undefined) {
        throw new Error("缺少 AI 预览的数据来源");
      }
      next = await previewAiContext(
        props.trafficId,
        useSavedPolicy ? null : policy.value
      );
    }
    syncingPolicy = true;
    preview.value = next;
    policy.value = { ...next.policy };
    dirty.value = false;
    await nextTick();
    syncingPolicy = false;
  } catch (error) {
    syncingPolicy = false;
    ElMessage.error(String(error));
  } finally {
    loading.value = false;
  }
}

async function confirmSend() {
  if (!preview.value || dirty.value) return;
  if (props.allowPolicyEditing && preview.value.is_relaxed) {
    try {
      await ElMessageBox.confirm(
        "当前策略放宽了至少一项默认隐私保护。请确认发送内容页中没有不应离开本机的数据。",
        "确认放宽策略",
        { type: "warning", confirmButtonText: "确认并分析" }
      );
    } catch {
      return;
    }
  }
  emit("confirm", {
    policy: { ...preview.value.policy },
    inputHash: preview.value.input_hash,
  });
  close();
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  return `${(bytes / 1024).toFixed(1)} KiB`;
}
</script>

<template>
  <el-dialog
    :model-value="modelValue"
    title="AI 发送预览"
    width="min(920px, 94vw)"
    destroy-on-close
    @close="close"
  >
    <div v-loading="loading" class="preview-dialog">
      <el-alert
        type="info"
        :closable="false"
        :title="description"
      />

      <div class="meta" v-if="preview">
        <el-tag effect="plain">{{ preview.provider_id }}</el-tag>
        <el-tag effect="plain">{{ preview.model }}</el-tag>
        <el-tag
          :type="preview.response_schema ? 'success' : 'info'"
          effect="plain"
        >
          {{ preview.response_schema ? "Provider JSON Schema" : "后端统一校验" }}
        </el-tag>
        <el-tag effect="plain">
          {{ preview.prompt_source }} · v{{ preview.prompt_version }}
        </el-tag>
        <el-tag :type="preview.is_relaxed ? 'warning' : 'success'" effect="plain">
          {{ preview.is_relaxed ? "已放宽默认策略" : "默认最小披露策略" }}
        </el-tag>
      </div>
      <div v-if="preview" class="target-url">
        发送目标：{{ preview.provider_base_url }}/chat/completions
      </div>

      <el-collapse v-if="allowPolicyEditing" class="policy-panel">
        <el-collapse-item title="本次数据策略（修改后必须刷新预览）" name="policy">
          <div class="policy-grid">
            <label class="policy-row">
              <span>遮盖 URL 查询值</span>
              <el-switch v-model="policy.redact_query_values" />
            </label>
            <label class="policy-row">
              <span>遮盖敏感 Header</span>
              <el-switch v-model="policy.redact_sensitive_headers" />
            </label>
            <label class="policy-row">
              <span>结构化正文秘密脱敏</span>
              <el-switch v-model="policy.redact_body_secrets" />
            </label>
            <label class="policy-row warning-option">
              <span>发送已截断正文</span>
              <el-switch v-model="policy.include_truncated_bodies" />
            </label>
            <label class="policy-row warning-option">
              <span>发送有界二进制 base64</span>
              <el-switch v-model="policy.include_binary_bodies" />
            </label>
            <label class="policy-row warning-option">
              <span>发送解码/流异常正文</span>
              <el-switch v-model="policy.include_decode_failed_bodies" />
            </label>
            <label class="policy-row">
              <span>请求正文上限</span>
              <el-input-number
                v-model="policy.request_body_max_bytes"
                :min="0"
                :max="24576"
                :step="1024"
              />
            </label>
            <label class="policy-row">
              <span>响应正文上限</span>
              <el-input-number
                v-model="policy.response_body_max_bytes"
                :min="0"
                :max="24576"
                :step="1024"
              />
            </label>
            <label class="policy-row">
              <span>总上下文硬上限</span>
              <el-input-number
                v-model="policy.total_context_max_bytes"
                :min="16384"
                :max="65536"
                :step="1024"
              />
            </label>
          </div>
          <div class="refresh-row">
            <span v-if="dirty" class="stale">策略已变化，当前内容不是最终发送版本。</span>
            <el-button :loading="loading" @click="refreshPreview(false)">刷新最终内容</el-button>
          </div>
        </el-collapse-item>
      </el-collapse>

      <el-tabs v-if="preview" v-model="activeTab" class="preview-tabs">
        <el-tab-pane label="最终发送内容" name="content">
          <div class="message-label">System message</div>
          <el-input
            :model-value="preview.system_prompt"
            type="textarea"
            :rows="5"
            readonly
            resize="vertical"
          />
          <div class="message-label user-label">User message</div>
          <el-input
            :model-value="preview.user_prompt"
            type="textarea"
            :rows="16"
            readonly
            resize="vertical"
          />
          <div class="message-label user-label">校验失败时的固定重试 user message</div>
          <el-input
            :model-value="preview.retry_user_prompt"
            type="textarea"
            :rows="16"
            readonly
            resize="vertical"
          />
        </el-tab-pane>

        <el-tab-pane label="脱敏清单" name="manifest">
          <div class="manifest-summary">
            单次最大消息 {{ formatBytes(preview.manifest.total_input_bytes) }} ·
            遮盖 {{ redactionCount }} 处 ·
            省略 {{ preview.manifest.omissions.length }} 项 ·
            显式披露 {{ preview.manifest.disclosures.length }} 项
          </div>

          <el-table
            v-if="preview.manifest.redactions.length"
            :data="preview.manifest.redactions"
            size="small"
            border
          >
            <el-table-column prop="location" label="位置" min-width="220" />
            <el-table-column prop="kind" label="类型" min-width="160" />
            <el-table-column prop="count" label="数量" width="80" />
          </el-table>
          <el-empty v-else description="本次没有发生值遮盖" :image-size="44" />

          <div class="manifest-list" v-if="preview.manifest.body_decisions.length">
            <div
              v-for="decision in preview.manifest.body_decisions"
              :key="decision.location"
              class="manifest-item"
            >
              <b>{{ decision.location }}</b>：{{ decision.included ? "发送" : "不发送" }} ·
              {{ decision.capture_status }} · {{ formatBytes(decision.sent_bytes) }} / {{
                formatBytes(decision.source_bytes)
              }} · {{ decision.reason }}
              <span v-if="decision.truncated_by_policy"> · 已按策略截断</span>
            </div>
          </div>

          <el-alert
            v-for="item in preview.manifest.disclosures"
            :key="item"
            type="warning"
            :closable="false"
            :title="item"
            class="manifest-alert"
          />
          <div
            v-for="item in preview.manifest.omissions"
            :key="`${item.location}:${item.reason}`"
            class="manifest-item"
          >
            <b>{{ item.location }}</b>：{{ item.reason }}
          </div>
          <div v-for="item in preview.manifest.notes" :key="item" class="manifest-item note">
            {{ item }}
          </div>
        </el-tab-pane>

        <el-tab-pane
          v-if="preview.response_schema"
          label="响应 JSON Schema"
          name="schema"
        >
          <el-input
            :model-value="responseSchemaText"
            type="textarea"
            :rows="20"
            readonly
            resize="vertical"
          />
        </el-tab-pane>
      </el-tabs>
    </div>

    <template #footer>
      <el-button @click="close">取消</el-button>
      <el-button
        type="primary"
        :disabled="!preview || dirty || loading"
        @click="confirmSend"
      >
        {{ confirmText }}
      </el-button>
    </template>
  </el-dialog>
</template>

<style scoped>
.preview-dialog {
  min-height: 360px;
}
.meta {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin: 14px 0 10px;
}
.target-url {
  margin: -2px 0 12px;
  overflow-wrap: anywhere;
  color: var(--el-text-color-secondary);
  font-family: var(--rf-font-mono);
  font-size: 12px;
}
.policy-panel {
  margin-bottom: 10px;
}
.policy-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px 18px;
}
.policy-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  font-size: 13px;
}
.warning-option {
  color: var(--el-color-warning-dark-2);
}
.refresh-row {
  display: flex;
  justify-content: flex-end;
  align-items: center;
  gap: 12px;
  margin-top: 14px;
}
.stale {
  color: var(--el-color-warning);
  font-size: 12px;
}
.message-label {
  margin: 2px 0 6px;
  color: var(--el-text-color-secondary);
  font-size: 12px;
  font-weight: 600;
}
.user-label {
  margin-top: 14px;
}
.manifest-summary {
  margin-bottom: 10px;
  color: var(--el-text-color-secondary);
  font-size: 13px;
}
.manifest-list {
  margin-top: 12px;
}
.manifest-item {
  padding: 7px 0;
  border-bottom: 1px solid var(--el-border-color-lighter);
  font-size: 12px;
  line-height: 1.5;
}
.manifest-item.note {
  color: var(--el-text-color-secondary);
}
.manifest-alert {
  margin-top: 8px;
}
@media (max-width: 760px) {
  .policy-grid {
    grid-template-columns: 1fr;
  }
}
</style>
