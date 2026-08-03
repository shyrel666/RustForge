<script setup lang="ts">
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { ElMessage } from "element-plus";
import MarkdownIt from "markdown-it";
import {
  type AiDataPolicy,
  type AnalysisProgress,
  type AnalysisProgressStage,
  type AnalysisResult,
  type AnalysisRun,
  analyzeTraffic,
  formatStandardReference,
  getAnalysis,
  getAnalysisRun,
} from "../api/tauri";
import { useSettingsStore } from "../stores/settings";
import AiContextPreviewDialog from "./AiContextPreviewDialog.vue";

const props = defineProps<{ trafficId: number }>();
const settings = useSettingsStore();
const md = new MarkdownIt({ breaks: true, linkify: false });

const result = ref<AnalysisResult | null>(null);
const analyzing = ref(false);
const loadingCache = ref(false);
const previewVisible = ref(false);
const runInfo = ref<AnalysisRun | null>(null);
const analysisError = ref("");
const analysisProgress = ref<AnalysisProgress | null>(null);
const analysisElapsed = ref(0);

let analysisClock: number | null = null;
let analysisGeneration = 0;
let cacheGeneration = 0;
let activeUnlisten: UnlistenFn | null = null;

const ANALYSIS_STEPS = [
  { key: "preparing", label: "整理上下文" },
  { key: "generating", label: "AI 分析" },
  { key: "validating", label: "本地校验" },
  { key: "saving", label: "创建 Finding" },
] as const;

const analysisPercentage = computed(() => {
  const reported = analysisProgress.value?.percentage ?? 5;
  if (!analyzing.value || reported >= 82) return reported;
  // Chat Completions 没有可靠的 token 级进度；模型等待阶段使用有上限的
  // 时间估算，后端返回后立即切换为真实的校验和落库阶段。
  const estimated = Math.min(
    78,
    Math.round(8 + 70 * (1 - Math.exp(-analysisElapsed.value / 45)))
  );
  return Math.max(reported, estimated);
});

const analysisMessage = computed(
  () => analysisProgress.value?.message || "正在准备 AI 分析"
);

const analysisStepIndex = computed(() => {
  const stage: AnalysisProgressStage =
    analysisProgress.value?.stage ?? "preparing";
  if (stage === "completed") return ANALYSIS_STEPS.length;
  if (stage === "failed") {
    return Math.max(
      0,
      ANALYSIS_STEPS.findIndex(
        (step) => step.key === analysisProgress.value?.stage
      )
    );
  }
  const index = ANALYSIS_STEPS.findIndex((step) => step.key === stage);
  return index < 0 ? 0 : index;
});

function analysisStepClass(index: number) {
  if (index < analysisStepIndex.value) return "is-done";
  if (index === analysisStepIndex.value) return "is-active";
  return "";
}

function createAnalysisRequestId() {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  return `analysis-${Date.now().toString(36)}-${Math.random()
    .toString(36)
    .slice(2, 12)}`;
}

function stopAnalysisClock() {
  if (analysisClock !== null) {
    window.clearInterval(analysisClock);
    analysisClock = null;
  }
}

function stopAnalysisTracking() {
  stopAnalysisClock();
  activeUnlisten?.();
  activeUnlisten = null;
}

function cleanAnalysisError(error: unknown) {
  const message = String(error).replace(/^Error:\s*/i, "").trim();
  return message.length > 600 ? `${message.slice(0, 600)}…` : message;
}

onMounted(() => {
  void loadCache();
});
watch(
  () => props.trafficId,
  () => {
    void loadCache();
  }
);
onBeforeUnmount(() => {
  analysisGeneration += 1;
  cacheGeneration += 1;
  stopAnalysisTracking();
});

/** 先读缓存，避免重复调用烧 token */
async function loadCache() {
  const trafficId = props.trafficId;
  const generation = ++cacheGeneration;
  analysisGeneration += 1;
  stopAnalysisTracking();
  analyzing.value = false;
  analysisProgress.value = null;
  analysisError.value = "";
  result.value = null;
  runInfo.value = null;
  loadingCache.value = true;
  try {
    const cached = await getAnalysis(trafficId);
    if (generation !== cacheGeneration || trafficId !== props.trafficId) return;
    result.value = cached;
    if (cached?.analysis_run_id) {
      const cachedRun = await getAnalysisRun(cached.analysis_run_id);
      if (generation !== cacheGeneration || trafficId !== props.trafficId)
        return;
      runInfo.value = cachedRun;
    }
  } catch (error) {
    if (generation === cacheGeneration && trafficId === props.trafficId) {
      analysisError.value = `读取分析缓存失败：${cleanAnalysisError(error)}`;
    }
  } finally {
    if (generation === cacheGeneration) loadingCache.value = false;
  }
}

async function run(payload: { policy: AiDataPolicy; inputHash: string }) {
  const trafficId = props.trafficId;
  const requestId = createAnalysisRequestId();
  const generation = ++analysisGeneration;
  cacheGeneration += 1;
  loadingCache.value = false;
  stopAnalysisTracking();
  analyzing.value = true;
  analysisError.value = "";
  analysisElapsed.value = 0;
  analysisProgress.value = {
    request_id: requestId,
    traffic_id: trafficId,
    stage: "preparing",
    percentage: 5,
    message: "正在启动 AI 分析",
  };
  analysisClock = window.setInterval(() => {
    analysisElapsed.value += 1;
  }, 1000);
  let unlisten: UnlistenFn | null = null;
  try {
    try {
      unlisten = await listen<AnalysisProgress>(
        "traffic-analysis:progress",
        (event) => {
          const progress = event.payload;
          if (
            generation !== analysisGeneration ||
            progress.request_id !== requestId ||
            progress.traffic_id !== trafficId
          ) {
            return;
          }
          analysisProgress.value = {
            ...progress,
            percentage: Math.max(0, Math.min(100, progress.percentage)),
          };
        }
      );
      if (generation !== analysisGeneration || trafficId !== props.trafficId) {
        unlisten();
        unlisten = null;
        return;
      }
      activeUnlisten = unlisten;
    } catch {
      // 事件通道不可用时仍继续；界面保留计时和有上限的估算进度。
    }

    const nextResult = await analyzeTraffic(
      trafficId,
      payload.policy,
      payload.inputHash,
      requestId
    );
    if (generation !== analysisGeneration || trafficId !== props.trafficId)
      return;
    result.value = nextResult;
    let nextRunInfo: AnalysisRun | null = null;
    if (nextResult.analysis_run_id) {
      try {
        nextRunInfo = await getAnalysisRun(nextResult.analysis_run_id);
      } catch {
        if (
          generation === analysisGeneration &&
          trafficId === props.trafficId
        ) {
          ElMessage.warning("分析已完成，但审计详情暂时无法加载");
        }
      }
    }
    if (generation !== analysisGeneration || trafficId !== props.trafficId)
      return;
    runInfo.value = nextRunInfo;
    ElMessage.success(
      `分析完成，生成 ${nextResult.hypotheses.length} 条待验证假设（见"发现"页）`
    );
  } catch (error) {
    if (generation === analysisGeneration && trafficId === props.trafficId) {
      analysisError.value = cleanAnalysisError(error);
      analysisProgress.value = {
        request_id: requestId,
        traffic_id: trafficId,
        stage: "failed",
        percentage: analysisPercentage.value,
        message: "AI 分析未完成",
      };
    }
  } finally {
    unlisten?.();
    if (activeUnlisten === unlisten) activeUnlisten = null;
    if (generation === analysisGeneration) {
      stopAnalysisClock();
      analyzing.value = false;
    }
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
        :disabled="!settings.ai_enabled || analyzing"
        @click="previewVisible = true"
      >
        {{ analyzing ? "正在分析" : result ? "重新分析" : "开始 AI 分析" }}
      </el-button>
      <el-tooltip
        v-if="!settings.ai_enabled"
        content="AI 功能已在设置中全局禁用"
        placement="top"
      >
        <el-tag type="info">AI 已禁用</el-tag>
      </el-tooltip>
      <span v-if="result && !analyzing" class="cached">
        已加载缓存结果（重新分析会消耗 token）
      </span>
    </div>

    <div
      v-if="analyzing"
      class="analysis-progress-card"
      role="status"
      aria-live="polite"
    >
      <div class="analysis-progress-head">
        <span class="analysis-spinner" aria-hidden="true" />
        <div>
          <h3>正在进行 AI 分析</h3>
          <p>{{ analysisMessage }}</p>
        </div>
      </div>
      <el-progress
        :percentage="analysisPercentage"
        :stroke-width="10"
        :show-text="false"
        class="analysis-progress"
      />
      <div class="analysis-progress-meta">
        <span>预计 {{ analysisPercentage }}%</span>
        <span>已用时 {{ analysisElapsed }} 秒</span>
      </div>
      <div class="analysis-steps">
        <div
          v-for="(step, index) in ANALYSIS_STEPS"
          :key="step.key"
          class="analysis-step"
          :class="analysisStepClass(index)"
        >
          <span class="analysis-step-dot">
            {{ index < analysisStepIndex ? "✓" : index + 1 }}
          </span>
          <span>{{ step.label }}</span>
        </div>
      </div>
      <p class="analysis-progress-note">
        模型响应时间取决于本次请求与响应的长度；分析结果只会创建待验证 Finding，不会自动执行测试。
      </p>
    </div>

    <el-alert
      v-else-if="analysisError"
      type="error"
      title="AI 分析未完成"
      :description="analysisError"
      :closable="false"
      show-icon
      class="analysis-error"
    />

    <template v-if="result && !analyzing">
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
      v-else-if="!loadingCache && !analyzing && !analysisError"
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
.cached {
  color: var(--el-text-color-secondary);
  font-size: 12px;
}
.analysis-progress-card {
  width: min(640px, 100%);
  box-sizing: border-box;
  margin: 44px auto;
  padding: 24px 26px 22px;
  border: 1px solid var(--rf-border-strong);
  border-radius: var(--rf-radius-shell);
  background: var(--rf-bg-panel);
  box-shadow: var(--rf-shadow);
}
.analysis-progress-head {
  display: flex;
  align-items: center;
  gap: var(--rf-space-3);
}
.analysis-progress-head h3 {
  margin: 0 0 5px;
  font-size: 18px;
  font-weight: 650;
}
.analysis-progress-head p {
  margin: 0;
  color: var(--rf-text-secondary);
  font-size: 13px;
}
.analysis-spinner {
  width: 28px;
  height: 28px;
  flex: 0 0 28px;
  box-sizing: border-box;
  border: 3px solid var(--rf-accent-muted);
  border-top-color: var(--rf-accent);
  border-radius: 50%;
  animation: analysis-spin 0.9s linear infinite;
}
.analysis-progress {
  --el-color-primary: var(--rf-accent);
  margin-top: var(--rf-space-5);
}
.analysis-progress-meta {
  display: flex;
  justify-content: space-between;
  margin-top: 7px;
  color: var(--rf-text-secondary);
  font-size: 12px;
  font-variant-numeric: tabular-nums;
}
.analysis-steps {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: var(--rf-space-2);
  margin-top: 22px;
}
.analysis-step {
  display: flex;
  align-items: center;
  gap: 7px;
  min-width: 0;
  color: var(--rf-text-muted);
  font-size: 12px;
}
.analysis-step-dot {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 22px;
  height: 22px;
  flex: 0 0 22px;
  border: 1px solid var(--rf-border-strong);
  border-radius: 50%;
  background: var(--rf-bg-raised);
  font-size: 11px;
  font-weight: 700;
}
.analysis-step.is-active {
  color: var(--rf-text);
}
.analysis-step.is-active .analysis-step-dot {
  border-color: var(--rf-accent);
  color: var(--rf-accent);
  box-shadow: 0 0 0 3px var(--rf-accent-muted);
}
.analysis-step.is-done {
  color: var(--rf-success);
}
.analysis-step.is-done .analysis-step-dot {
  border-color: var(--rf-success);
  background: color-mix(in srgb, var(--rf-success) 14%, var(--rf-bg-raised));
}
.analysis-progress-note {
  margin: 20px 0 0;
  padding-top: var(--rf-space-3);
  border-top: 1px solid var(--rf-border);
  color: var(--rf-text-muted);
  font-size: 12px;
  line-height: 1.6;
}
.analysis-error {
  margin-bottom: 12px;
}
.analysis-error :deep(.el-alert__description) {
  line-height: 1.55;
  overflow-wrap: anywhere;
}
@keyframes analysis-spin {
  to {
    transform: rotate(360deg);
  }
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

@media (max-width: 720px) {
  .analysis-progress-card {
    margin: 24px auto;
    padding: 20px;
  }
  .analysis-steps {
    grid-template-columns: repeat(2, minmax(0, 1fr));
    row-gap: var(--rf-space-3);
  }
}
</style>
