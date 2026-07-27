<script setup lang="ts">
import { onMounted, ref, watch } from "vue";
import { ElMessage } from "element-plus";
import MarkdownIt from "markdown-it";
import {
  type AiDataPolicy,
  type AnalysisRun,
  AnalysisResult,
  analyzeTraffic,
  formatStandardReference,
  getAnalysis,
  getAnalysisRun,
} from "../api/tauri";
import { useSettingsStore } from "../stores/settings";
import AiContextPreviewDialog from "./AiContextPreviewDialog.vue";

const props = defineProps<{ trafficId: number }>();
const settings = useSettingsStore();
const md = new MarkdownIt({ breaks: true, linkify: true });

const result = ref<AnalysisResult | null>(null);
const analyzing = ref(false);
const loadingCache = ref(false);
const previewVisible = ref(false);
const runInfo = ref<AnalysisRun | null>(null);

onMounted(loadCache);
watch(() => props.trafficId, loadCache);

/** 先读缓存，避免重复调用烧 token */
async function loadCache() {
  result.value = null;
  runInfo.value = null;
  loadingCache.value = true;
  try {
    result.value = await getAnalysis(props.trafficId);
    if (result.value?.analysis_run_id) {
      runInfo.value = await getAnalysisRun(result.value.analysis_run_id);
    }
  } finally {
    loadingCache.value = false;
  }
}

async function run(payload: { policy: AiDataPolicy; inputHash: string }) {
  analyzing.value = true;
  try {
    result.value = await analyzeTraffic(
      props.trafficId,
      payload.policy,
      payload.inputHash
    );
    runInfo.value = result.value.analysis_run_id
      ? await getAnalysisRun(result.value.analysis_run_id)
      : null;
    ElMessage.success(
      `分析完成，生成 ${result.value.hypotheses.length} 条待验证假设（见"发现"页）`
    );
  } catch (e) {
    ElMessage.error(String(e));
  } finally {
    analyzing.value = false;
  }
}

function severityTag(s: string): string {
  const map: Record<string, string> = {
    critical: "danger",
    high: "danger",
    medium: "warning",
    low: "info",
    info: "info",
  };
  return map[s] ?? "info";
}

function confidenceType(c: number): string {
  if (c >= 70) return "success";
  if (c >= 40) return "warning";
  return "exception";
}
</script>

<template>
  <div v-loading="loadingCache" class="ai-panel">
    <div class="head">
      <el-button
        type="primary"
        :loading="analyzing"
        :disabled="!settings.ai_enabled"
        @click="previewVisible = true"
      >
        {{ result ? "重新分析" : "开始 AI 分析" }}
      </el-button>
      <el-tooltip
        v-if="!settings.ai_enabled"
        content="AI 功能已在设置中全局禁用"
        placement="top"
      >
        <el-tag type="info">AI 已禁用</el-tag>
      </el-tooltip>
      <span v-if="analyzing" class="waiting">AI 分析中，通常需要 10~60 秒…</span>
      <span v-else-if="result" class="cached">已加载缓存结果（重新分析会消耗 token）</span>
    </div>

    <template v-if="result">
      <el-alert type="info" :closable="false" class="disclaimer">
        AI 结论仅供学习参考，<b>每一条都需要你按验证步骤人工复核</b>；确认/误报请在"发现"页标记。
      </el-alert>

      <div v-if="runInfo" class="run-meta">
        <el-tag size="small" effect="plain">Run #{{ runInfo.id }}</el-tag>
        <el-tooltip
          :content="`${runInfo.provider_base_url}/chat/completions`"
          placement="top"
        >
          <el-tag size="small" effect="plain">{{ runInfo.provider_id }} / {{ runInfo.model }}</el-tag>
        </el-tooltip>
        <el-tag size="small" effect="plain">Prompt v{{ runInfo.prompt_version }}</el-tag>
        <el-tag size="small" :type="runInfo.schema_applied ? 'success' : 'info'" effect="plain">
          {{ runInfo.schema_applied ? "Provider JSON Schema" : "后端统一校验" }}
        </el-tag>
        <span class="run-hash">输入 {{ runInfo.input_hash.slice(0, 12) }}…</span>
      </div>

      <el-descriptions :column="1" border size="small" class="block">
        <el-descriptions-item label="接口用途">{{ result.purpose }}</el-descriptions-item>
        <el-descriptions-item label="值得关注参数">
          <el-tag
            v-for="p in result.suspicious_params"
            :key="p"
            size="small"
            type="warning"
            effect="plain"
            class="param-tag"
          >{{ p }}</el-tag>
          <span v-if="!result.suspicious_params.length">无</span>
        </el-descriptions-item>
        <el-descriptions-item label="总结">{{ result.summary }}</el-descriptions-item>
      </el-descriptions>

      <el-empty
        v-if="!result.hypotheses.length"
        description="AI 未发现可疑点（这本身也是一种结论）"
        :image-size="48"
      />

      <div v-for="(h, i) in result.hypotheses" :key="i" class="hypo">
        <div class="hypo-head">
          <span class="hypo-title">#{{ i + 1 }} {{ h.vuln_type }}</span>
          <el-tag size="small" :type="severityTag(h.severity)" effect="dark">{{ h.severity }}</el-tag>
          <el-tag
            v-for="reference in h.standard_references"
            :key="`${reference.framework}@${reference.version}/${reference.id}`"
            size="small"
            type="info"
            effect="plain"
          >{{ formatStandardReference(reference) }}</el-tag>
          <el-tag v-if="h.param" size="small" type="warning" effect="plain">参数: {{ h.param }}</el-tag>
          <el-tag
            size="small"
            :type="h.grounding_status === 'grounded' ? 'success' : 'warning'"
            effect="plain"
          >{{ h.grounding_status }}</el-tag>
        </div>
        <div class="hypo-conf">
          <span>置信度</span>
          <el-progress
            :percentage="h.confidence"
            :status="confidenceType(h.confidence)"
            :stroke-width="8"
            class="conf-bar"
          />
        </div>
        <div class="hypo-block">
          <div class="block-label">🔍 推理过程</div>
          <div class="md" v-html="md.render(h.reasoning)" />
        </div>
        <div class="evidence-refs">
          证据引用：{{ h.evidence_refs.length ? h.evidence_refs.join("、") : "无" }}
        </div>
        <el-alert
          v-if="h.validation_notes.length"
          type="warning"
          :closable="false"
          :title="h.validation_notes.join('；')"
          class="grounding-alert"
        />
        <div class="hypo-block">
          <div class="block-label">🧪 手动验证步骤</div>
          <div class="md" v-html="md.render(h.verify_steps)" />
        </div>
      </div>
    </template>

    <el-empty
      v-else-if="!loadingCache"
      description="尚未分析。点击上方按钮，AI 将解释这个接口并给出漏洞假设。"
      :image-size="48"
    />

    <AiContextPreviewDialog
      v-model="previewVisible"
      :traffic-id="trafficId"
      @confirm="run"
    />
  </div>
</template>

<style scoped>
.ai-panel {
  min-height: 120px;
}
.head {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 12px;
}
.waiting {
  color: var(--el-text-color-secondary);
  font-size: 12px;
}
.cached {
  color: var(--el-text-color-secondary);
  font-size: 12px;
}
.disclaimer {
  margin-bottom: 12px;
}
.run-meta {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 7px;
  margin-bottom: 12px;
}
.run-hash,
.evidence-refs {
  color: var(--el-text-color-secondary);
  font-size: 12px;
}
.grounding-alert {
  margin-top: 8px;
}
.block {
  margin-bottom: 16px;
}
.param-tag {
  margin-right: 6px;
}
.hypo {
  border: 1px solid var(--el-border-color);
  border-radius: 6px;
  padding: 12px;
  margin-bottom: 12px;
}
.hypo-head {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  margin-bottom: 8px;
}
.hypo-title {
  font-weight: 600;
}
.hypo-conf {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
  color: var(--el-text-color-secondary);
  margin-bottom: 10px;
}
.conf-bar {
  flex: 1;
}
.hypo-block {
  margin-bottom: 8px;
}
.block-label {
  font-size: 12px;
  color: var(--el-text-color-secondary);
  margin-bottom: 4px;
}
.md {
  font-size: 13px;
  line-height: 1.7;
  background: var(--el-fill-color-dark);
  border-radius: 4px;
  padding: 8px 12px;
}
.md :deep(p) {
  margin: 4px 0;
}
.md :deep(ol),
.md :deep(ul) {
  margin: 4px 0;
  padding-left: 20px;
}
.md :deep(code) {
  background: var(--el-fill-color);
  padding: 1px 4px;
  border-radius: 3px;
}
</style>
