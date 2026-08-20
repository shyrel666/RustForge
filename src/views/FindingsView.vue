<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";
import { Document, FolderOpened, Refresh } from "@element-plus/icons-vue";
import MarkdownIt from "markdown-it";
import { useFindingsStore } from "../stores/findings";
import { useProjectStore } from "../stores/project";
import {
  buildReport,
  exportReport,
  formatStandardReference,
  getRuleDiagnostics,
  listFindingRuleHits,
  listFindingTraffic,
  type Finding,
  type FindingRuleHit,
  type FindingTrafficRef,
  type RuleDiagnostics,
} from "../api/tauri";
import KnowledgeCard from "../components/KnowledgeCard.vue";
import EvidencePanel from "../components/EvidencePanel.vue";
import EmptyState from "../components/shell/EmptyState.vue";
import PageHeader from "../components/shell/PageHeader.vue";

const findings = useFindingsStore();
const project = useProjectStore();
const md = new MarkdownIt({ breaks: true, linkify: true });

const projectId = computed(() => project.current?.id ?? null);

const reportVisible = ref(false);
const reportMd = ref("");
const reportLoading = ref(false);
const reportExporting = ref(false);
const ruleDiagnostics = ref<RuleDiagnostics | null>(null);
const ruleDiagnosticsLoading = ref(false);
const findingTraffic = ref<Record<number, FindingTrafficRef[]>>({});
const findingRuleHits = ref<Record<number, FindingRuleHit[]>>({});
const findingTrafficLoading = ref<Record<number, boolean>>({});
const expandedFindingIds = ref<Set<number>>(new Set());
const detailLoadGeneration = new Map<number, number>();
let reportGeneration = 0;
let exportGeneration = 0;
let diagnosticsGeneration = 0;
let diagnosticsTimer: number | undefined;

async function openReport() {
  const requestedProjectId = projectId.value;
  if (requestedProjectId === null) return;
  const generation = ++reportGeneration;
  reportVisible.value = true;
  reportLoading.value = true;
  reportMd.value = "";
  try {
    const result = await buildReport(requestedProjectId);
    if (
      generation === reportGeneration &&
      projectId.value === requestedProjectId
    ) {
      reportMd.value = result;
    }
  } catch (e) {
    if (
      generation === reportGeneration &&
      projectId.value === requestedProjectId
    ) {
      ElMessage.error(String(e));
      reportVisible.value = false;
    }
  } finally {
    if (generation === reportGeneration) reportLoading.value = false;
  }
}

async function doExportReport(includeSensitiveEvidence = false) {
  if (projectId.value === null) return;
  const requestedProjectId = projectId.value;
  const generation = ++exportGeneration;
  reportExporting.value = true;
  try {
    const result = await exportReport(requestedProjectId, includeSensitiveEvidence);
    if (
      generation !== exportGeneration ||
      projectId.value !== requestedProjectId
    )
      return;
    ElMessage.success(
      `${result.contains_sensitive_evidence ? "敏感" : "脱敏"}报告已导出：${result.markdown_path}；JSON 备份：${result.json_path}`
    );
  } catch (e) {
    const message = String(e);
    if (
      generation === exportGeneration &&
      projectId.value === requestedProjectId &&
      !message.includes("已取消敏感")
    ) {
      ElMessage.error(message);
    }
  } finally {
    if (generation === exportGeneration) reportExporting.value = false;
  }
}

async function loadRuleDiagnostics(showError = false) {
  const requestedProjectId = projectId.value;
  if (requestedProjectId === null) {
    diagnosticsGeneration += 1;
    ruleDiagnostics.value = null;
    return;
  }
  const generation = ++diagnosticsGeneration;
  ruleDiagnosticsLoading.value = true;
  try {
    const result = await getRuleDiagnostics(requestedProjectId);
    if (
      generation === diagnosticsGeneration &&
      projectId.value === requestedProjectId
    )
      ruleDiagnostics.value = result;
  } catch (e) {
    if (
      showError &&
      generation === diagnosticsGeneration &&
      projectId.value === requestedProjectId
    )
      ElMessage.error(String(e));
  } finally {
    if (generation === diagnosticsGeneration)
      ruleDiagnosticsLoading.value = false;
  }
}

async function loadFindingDetails(row: Finding, showError = true) {
  const generation = (detailLoadGeneration.get(row.id) ?? 0) + 1;
  detailLoadGeneration.set(row.id, generation);
  findingTrafficLoading.value[row.id] = true;
  try {
    const [traffic, ruleHits] = await Promise.all([
      listFindingTraffic(row.id),
      row.producer === "passive_rule"
        ? listFindingRuleHits(row.id)
        : Promise.resolve<FindingRuleHit[]>([]),
    ]);
    if (
      detailLoadGeneration.get(row.id) !== generation ||
      projectId.value !== row.project_id
    ) {
      return;
    }
    findingTraffic.value[row.id] = traffic;
    findingRuleHits.value[row.id] = ruleHits;
  } catch (e) {
    if (showError && detailLoadGeneration.get(row.id) === generation) {
      ElMessage.error(String(e));
    }
  } finally {
    if (detailLoadGeneration.get(row.id) === generation) {
      findingTrafficLoading.value[row.id] = false;
    }
  }
}

async function handleExpand(row: Finding, expandedRows: Finding[]) {
  expandedFindingIds.value = new Set(
    expandedRows.map((expanded) => expanded.id)
  );
  if (!expandedFindingIds.value.has(row.id)) return;
  await loadFindingDetails(row);
}

onMounted(async () => {
  if (projectId.value !== null) await findings.refresh(projectId.value);
  await findings.bindEvents(() => projectId.value);
  await loadRuleDiagnostics();
  diagnosticsTimer = window.setInterval(() => void loadRuleDiagnostics(), 5_000);
});

onUnmounted(() => {
  findings.unbindEvents();
  if (diagnosticsTimer !== undefined) window.clearInterval(diagnosticsTimer);
});

watch(projectId, async (id) => {
  findings.activateProject(id);
  reportGeneration += 1;
  exportGeneration += 1;
  diagnosticsGeneration += 1;
  reportVisible.value = false;
  reportMd.value = "";
  reportLoading.value = false;
  reportExporting.value = false;
  ruleDiagnosticsLoading.value = false;
  findingTraffic.value = {};
  findingRuleHits.value = {};
  findingTrafficLoading.value = {};
  expandedFindingIds.value = new Set();
  detailLoadGeneration.clear();
  if (id !== null) {
    await Promise.all([findings.refresh(id), loadRuleDiagnostics()]);
  } else {
    ruleDiagnostics.value = null;
  }
});

watch(
  () => findings.items.map((item) => item),
  (items, previousItems) => {
    const previousById = new Map(
      previousItems.map((item) => [item.id, item] as const)
    );
    for (const item of items) {
      if (
        expandedFindingIds.value.has(item.id) &&
        previousById.has(item.id) &&
        previousById.get(item.id) !== item
      ) {
        void loadFindingDetails(item, false);
      }
    }
  }
);

async function setStatus(id: number, status: string) {
  try {
    const required = status === "rejected";
    const { value } = await ElMessageBox.prompt(
      required ? "请填写判定为误报的原因" : "可填写本次状态变更说明",
      status === "confirmed"
        ? "确认该 Finding"
        : status === "rejected"
          ? "标记为误报 (False Positive)"
          : "重置为待验证",
      {
        confirmButtonText: "提交变更",
        cancelButtonText: "取消",
        inputType: "textarea",
        inputPlaceholder: required ? "必填说明" : "可选说明",
        inputValidator: (input) =>
          !required || Boolean(input.trim()) || "标记误报必须填写原因",
      }
    );
    await findings.setStatus(id, status, value);
  } catch (e) {
    if (e === "cancel" || e === "close") return;
    ElMessage.error(String(e));
  }
}

const severityCounts = computed(() => {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const item of findings.items) {
    if (item.severity in counts) {
      counts[item.severity as keyof typeof counts]++;
    }
  }
  return counts;
});

function severityTag(s: string): "danger" | "warning" | "info" {
  const map: Record<string, "danger" | "warning" | "info"> = {
    critical: "danger",
    high: "danger",
    medium: "warning",
    low: "info",
    info: "info",
  };
  return map[s] ?? "info";
}

function statusTag(s: string): { text: string; type: "warning" | "success" | "info" } {
  const map: Record<string, { text: string; type: "warning" | "success" | "info" }> = {
    pending: { text: "待验证", type: "warning" },
    confirmed: { text: "已确认", type: "success" },
    rejected: { text: "误报", type: "info" },
  };
  return map[s] ?? { text: s, type: "info" };
}

function producerLabel(producer: Finding["producer"]): string {
  const labels: Record<Finding["producer"], string> = {
    ai: "AI 诊断",
    passive_rule: "被动规则",
    safe_verifier: "安全验证器",
  };
  return labels[producer];
}

function producerTagType(
  producer: Finding["producer"]
): "primary" | "info" | "success" {
  if (producer === "ai") return "primary";
  if (producer === "safe_verifier") return "success";
  return "info";
}

function standardReferencesLabel(references: Finding["standard_references"]): string {
  return references.map(formatStandardReference).join(" · ") || "—";
}

const ruleIssueSummary = computed(() => {
  const diagnostics = ruleDiagnostics.value;
  if (!diagnostics) return "";
  const issues: string[] = [];
  for (const pack of diagnostics.packs.filter((item) => !item.loaded)) {
    issues.push(
      `${pack.pack_id} 已禁用：${pack.disabled_reason || "规则包校验失败"}`
    );
  }
  if (diagnostics.dropped_evaluations) {
    issues.push(`队列已丢弃 ${diagnostics.dropped_evaluations} 次求值`);
  }
  if (diagnostics.timed_out_evaluations) {
    issues.push(`本轮有 ${diagnostics.timed_out_evaluations} 次求值超时`);
  }
  if (diagnostics.failed_evaluations) {
    issues.push(`本轮有 ${diagnostics.failed_evaluations} 次后台写入失败`);
  }
  if (diagnostics.last_error) issues.push(diagnostics.last_error);
  return issues.join("；");
});
</script>

<template>
  <div class="findings-page rf-page rf-page--inset">
    <PageHeader
      title="安全发现与证据审查 (Findings)"
      description="复核 AI 评估、被动规则与确定性验证器结论；证据闭环生成标准安全报告。"
    />

    <!-- 控制与过滤条 -->
    <div class="rf-toolbar">
      <!-- 严重度统计徽章矩阵 -->
      <div class="severity-matrix">
        <span class="severity-chip severity-critical" title="严重">
          <span class="mono">{{ severityCounts.critical }}</span> CRIT
        </span>
        <span class="severity-chip severity-high" title="高危">
          <span class="mono">{{ severityCounts.high }}</span> HIGH
        </span>
        <span class="severity-chip severity-medium" title="中危">
          <span class="mono">{{ severityCounts.medium }}</span> MED
        </span>
        <span class="severity-chip severity-low" title="低危">
          <span class="mono">{{ severityCounts.low }}</span> LOW
        </span>
        <span class="severity-chip severity-info" title="提示">
          <span class="mono">{{ severityCounts.info }}</span> INFO
        </span>
      </div>

      <div class="rf-filters">
        <div class="rf-toolbar-group">
          <el-select
            v-model="findings.filterStatus"
            placeholder="状态"
            clearable
            size="small"
            class="f"
            @change="projectId !== null && findings.refresh(projectId)"
          >
            <el-option label="待验证" value="pending" />
            <el-option label="已确认" value="confirmed" />
            <el-option label="误报" value="rejected" />
          </el-select>
          <el-select
            v-model="findings.filterSeverity"
            placeholder="严重度"
            clearable
            size="small"
            class="f"
            @change="projectId !== null && findings.refresh(projectId)"
          >
            <el-option
              v-for="s in ['critical', 'high', 'medium', 'low', 'info']"
              :key="s"
              :label="s.toUpperCase()"
              :value="s"
            />
          </el-select>
          <el-select
            v-model="findings.filterSource"
            placeholder="来源"
            clearable
            size="small"
            class="f"
            @change="projectId !== null && findings.refresh(projectId)"
          >
            <el-option label="AI 分析" value="ai" />
            <el-option label="被动规则" value="rule" />
          </el-select>
        </div>

        <el-button
          type="primary"
          size="small"
          :icon="Document"
          :disabled="projectId === null"
          @click="openReport"
        >
          导出证据报告
        </el-button>
      </div>
    </div>

    <!-- 空状态 -->
    <EmptyState
      v-if="!project.current"
      centered
      title="尚未选择测试项目"
      description="请在顶部切换或新建项目。发现列表与规则引擎按项目严格隔离。"
    >
      <template #icon><el-icon :size="20"><FolderOpened /></el-icon></template>
    </EmptyState>

    <template v-else>
      <!-- 规则引擎诊断条 -->
      <div v-loading="ruleDiagnosticsLoading" class="rule-health">
        <div class="rule-health__summary">
          <strong class="health-title">被动规则引擎</strong>
          <span class="rf-pulse-dot" :class="ruleDiagnostics?.worker_running ? 'rf-pulse-dot--active' : 'rf-pulse-dot--stopped'" />
          <span class="health-status">{{ ruleDiagnostics?.worker_running ? "后台监听中" : "代理未启动" }}</span>

          <template v-if="ruleDiagnostics">
            <span class="health-meta mono">
              队列 {{ ruleDiagnostics.queue_depth }}/{{ ruleDiagnostics.queue_capacity }}
            </span>
            <span class="health-meta mono">已求值 {{ ruleDiagnostics.completed_evaluations }}</span>
            <el-tag
              v-if="ruleDiagnostics.dropped_evaluations"
              size="small"
              type="danger"
            >
              丢弃 {{ ruleDiagnostics.dropped_evaluations }}
            </el-tag>
          </template>

          <el-button
            link
            size="small"
            :icon="Refresh"
            :loading="ruleDiagnosticsLoading"
            class="refresh-btn"
            @click="loadRuleDiagnostics(true)"
          >
            刷新状态
          </el-button>
        </div>

        <div v-if="ruleDiagnostics" class="rule-pack-list">
          <el-tooltip
            v-for="pack in ruleDiagnostics.packs"
            :key="`${pack.pack_id}@${pack.version}`"
            :content="pack.loaded ? `${pack.rule_count} 条已加载声明式规则` : pack.disabled_reason || '规则包未加载'"
          >
            <span class="rule-pack-chip" :class="{ 'is-disabled': !pack.loaded }">
              <span class="mono">{{ pack.pack_id }}@{{ pack.version || "未知版本" }}</span>
              <small>{{ pack.loaded ? `${pack.rule_count} rules` : "禁用" }}</small>
            </span>
          </el-tooltip>
        </div>

        <el-alert
          v-if="ruleIssueSummary"
          type="warning"
          :closable="false"
          show-icon
          title="规则后台状态提示"
          :description="ruleIssueSummary"
          class="rule-alert"
        />
      </div>

      <!-- 发现列表表格 -->
      <el-table
        v-loading="findings.loading"
        :data="findings.items"
        class="findings-table rf-table-shell"
        size="small"
        row-key="id"
        @expand-change="handleExpand"
      >
        <el-table-column type="expand">
          <template #default="{ row }">
            <div class="expand-content">
              <div v-if="row.producer === 'passive_rule'" class="expand-section">
                <div class="section-label">规则命中证据快照</div>
                <el-table
                  v-loading="findingTrafficLoading[row.id]"
                  :data="findingRuleHits[row.id] ?? []"
                  size="small"
                  border
                >
                  <el-table-column label="规则" min-width="220">
                    <template #default="{ row: hit }">
                      <div class="rule-identity">
                        <span class="mono">{{ hit.pack_id }}@{{ hit.pack_version }}</span>
                        <span class="mono text-muted">{{ hit.rule_id }}@{{ hit.rule_version }}</span>
                      </div>
                    </template>
                  </el-table-column>
                  <el-table-column prop="field_path" label="命中位置" min-width="160">
                    <template #default="{ row: hit }"><span class="mono">{{ hit.field_path }}</span></template>
                  </el-table-column>
                  <el-table-column prop="evidence" label="脱敏证据" min-width="240">
                    <template #default="{ row: hit }">
                      <pre class="rf-mono-pre snippet">{{ hit.evidence }}</pre>
                    </template>
                  </el-table-column>
                  <el-table-column label="置信度" width="90" align="center">
                    <template #default="{ row: hit }">{{ hit.confidence }}</template>
                  </el-table-column>
                  <el-table-column label="完整性" width="90" align="center">
                    <template #default="{ row: hit }">
                      <el-tag size="small" :type="hit.incomplete_evidence ? 'warning' : 'success'">
                        {{ hit.incomplete_evidence ? "不完整" : "完整" }}
                      </el-tag>
                    </template>
                  </el-table-column>
                </el-table>
              </div>

              <!-- 知识库映射标准 -->
              <KnowledgeCard
                v-if="row.standard_references.length"
                :references="row.standard_references"
                class="knowledge-block"
              />

              <!-- Evidence 闭环审计面板 -->
              <EvidencePanel
                :finding="row"
                :traffic="findingTraffic[row.id] ?? []"
                class="evidence-block"
                @finding-updated="findings.refresh(projectId!)"
              />
            </div>
          </template>
        </el-table-column>

        <el-table-column prop="id" label="#" width="65" sortable />

        <el-table-column label="严重度" width="90">
          <template #default="{ row }">
            <el-tag size="small" :type="severityTag(row.severity)">
              {{ row.severity.toUpperCase() }}
            </el-tag>
          </template>
        </el-table-column>

        <el-table-column prop="title" label="漏洞标题" min-width="220" show-overflow-tooltip>
          <template #default="{ row }">
            <span class="finding-title">{{ row.title }}</span>
          </template>
        </el-table-column>

        <el-table-column label="标准映射" min-width="170" show-overflow-tooltip>
          <template #default="{ row }">
            <span class="mono standard-ref">
              {{ standardReferencesLabel(row.standard_references) }}
            </span>
          </template>
        </el-table-column>

        <el-table-column label="来源" width="100">
          <template #default="{ row }">
            <el-tag size="small" :type="producerTagType(row.producer)">
              {{ producerLabel(row.producer) }}
            </el-tag>
          </template>
        </el-table-column>

        <el-table-column label="验证状态" width="95">
          <template #default="{ row }">
            <el-tag size="small" :type="statusTag(row.status).type">
              {{ statusTag(row.status).text }}
            </el-tag>
          </template>
        </el-table-column>

        <el-table-column label="状态决策" width="180" fixed="right">
          <template #default="{ row }">
            <div class="status-actions">
              <el-button
                v-if="row.status !== 'confirmed'"
                size="small"
                type="success"
                link
                @click="setStatus(row.id, 'confirmed')"
              >
                确认
              </el-button>
              <el-button
                v-if="row.status !== 'rejected'"
                size="small"
                type="danger"
                link
                @click="setStatus(row.id, 'rejected')"
              >
                误报
              </el-button>
              <el-button
                v-if="row.status !== 'pending'"
                size="small"
                type="info"
                link
                @click="setStatus(row.id, 'pending')"
              >
                重置
              </el-button>
            </div>
          </template>
        </el-table-column>

        <template #empty>
          <el-empty description="暂未发现安全问题。可在 AI 评估中执行测试或开启代理采集流量。" />
        </template>
      </el-table>
    </template>

    <!-- 报告预览对话框 -->
    <el-dialog v-model="reportVisible" title="安全评估与证据化报告" width="min(860px, 94vw)">
      <div v-loading="reportLoading" class="report-container">
        <div v-if="reportMd" class="report-rendered" v-html="md.render(reportMd)" />
      </div>
      <template #footer>
        <el-button @click="reportVisible = false">关闭</el-button>
        <el-button
          type="primary"
          :loading="reportExporting"
          @click="doExportReport(false)"
        >
          导出脱敏报告 (Markdown + JSON)
        </el-button>
        <el-button
          type="warning"
          :loading="reportExporting"
          @click="doExportReport(true)"
        >
          导出完整敏感证据报告
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.findings-page {
  gap: var(--rf-space-2);
}

.severity-matrix {
  display: inline-flex;
  align-items: center;
  gap: 4px;
}

.severity-chip {
  padding: 3px 7px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 700;
  display: inline-flex;
  align-items: center;
  gap: 4px;
}

.severity-critical {
  background: rgba(239, 68, 68, 0.12);
  color: var(--rf-danger);
}

.severity-high {
  background: rgba(249, 115, 22, 0.12);
  color: var(--rf-accent);
}

.severity-medium {
  background: rgba(245, 158, 11, 0.12);
  color: var(--rf-warning);
}

.severity-low {
  background: rgba(59, 130, 246, 0.12);
  color: var(--rf-info);
}

.severity-info {
  background: var(--rf-bg-raised);
  color: var(--rf-text-secondary);
}

.f {
  width: 100px;
}

.rule-health {
  padding: var(--rf-space-2) var(--rf-space-3);
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-card);
  background: var(--rf-bg-panel);
  display: grid;
  gap: 6px;
}

.rule-health__summary {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
}

.health-title {
  color: var(--rf-text);
  font-size: 12px;
}

.health-status {
  color: var(--rf-text-secondary);
  font-size: 11.5px;
}

.health-meta {
  color: var(--rf-text-muted);
  font-size: 11px;
}

.refresh-btn {
  margin-left: auto;
}

.rule-pack-list {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.rule-pack-chip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 2px 7px;
  border: 1px solid var(--rf-border);
  border-radius: 4px;
  background: var(--rf-bg-raised);
  font-size: 11px;
  color: var(--rf-text-secondary);
}

.rule-pack-chip.is-disabled {
  opacity: 0.5;
  border-color: var(--rf-danger);
}

.rule-alert {
  margin-top: 4px;
}

.findings-table {
  flex: 1;
}

.finding-title {
  font-weight: 600;
  color: var(--rf-text);
}

.standard-ref {
  color: var(--rf-text-secondary);
  font-size: 11.5px;
}

.status-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}

.expand-content {
  padding: var(--rf-space-3);
  background: var(--rf-bg-raised);
  display: grid;
  gap: var(--rf-space-3);
  border-radius: var(--rf-radius-control);
}

.expand-section {
  display: grid;
  gap: 6px;
}

.section-label {
  font-size: 11.5px;
  font-weight: 700;
  color: var(--rf-text-secondary);
  text-transform: uppercase;
}

.rule-identity {
  display: grid;
  gap: 2px;
}

.snippet {
  margin: 0;
  max-height: 80px;
}

.report-container {
  min-height: 300px;
  max-height: 65vh;
  overflow-y: auto;
  padding: var(--rf-space-4);
  background: var(--rf-bg-raised);
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-control);
}

.report-rendered {
  color: var(--rf-text);
  font-size: 13px;
  line-height: 1.6;
}

.report-rendered :deep(pre) {
  padding: 10px;
  background: var(--rf-bg-panel);
  border: 1px solid var(--rf-border);
  border-radius: 6px;
  font-family: var(--rf-font-mono);
  font-size: 12px;
}
</style>
