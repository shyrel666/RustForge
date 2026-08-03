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
      required ? "请填写判断为误报的原因" : "可填写本次状态变更说明",
      status === "confirmed"
        ? "确认 Finding"
        : status === "rejected"
          ? "标记误报"
          : "重置待验证",
      {
        confirmButtonText: "提交",
        cancelButtonText: "取消",
        inputType: "textarea",
        inputPlaceholder: required ? "必填" : "可选",
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

const pendingCount = computed(
  () => findings.items.filter((f) => f.status === "pending").length
);

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

function statusTag(s: string): { text: string; type: string } {
  const map: Record<string, { text: string; type: string }> = {
    pending: { text: "待验证", type: "warning" },
    confirmed: { text: "已确认", type: "success" },
    rejected: { text: "误报", type: "info" },
  };
  return map[s] ?? { text: s, type: "info" };
}

function evaluationStatusTag(s: string): { text: string; type: string } {
  const map: Record<string, { text: string; type: string }> = {
    completed: { text: "完成", type: "success" },
    timed_out: { text: "超时", type: "warning" },
    pack_disabled: { text: "包已禁用", type: "danger" },
  };
  return map[s] ?? { text: s, type: "info" };
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
      title="发现"
      description="复核 AI、被动规则与安全验证器结果，并导出可追溯的证据化报告。"
    />
    <div class="rf-toolbar">
      <div v-if="pendingCount" class="rf-toolbar-group">
        <el-tag type="warning" effect="plain" size="small">
          {{ pendingCount }} 条待验证
        </el-tag>
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
              :label="s"
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
          生成报告
        </el-button>
      </div>
    </div>

    <EmptyState
      v-if="!project.current"
      centered
      title="尚未选择项目"
      description="请先在顶部创建或选择项目。发现列表按项目隔离。"
    >
      <template #icon><el-icon :size="20"><FolderOpened /></el-icon></template>
    </EmptyState>

    <template v-else>
      <el-alert type="info" :closable="false" class="hint" show-icon>
        AI 与被动规则结果默认待验证；只有版本化安全验证器满足完整证据阈值时才会自动确认，人工结论始终可覆盖。
      </el-alert>

      <div v-loading="ruleDiagnosticsLoading" class="rule-health">
        <div class="rule-health__summary">
          <strong>被动规则后台</strong>
          <el-tag
            size="small"
            :type="ruleDiagnostics?.worker_running ? 'success' : 'info'"
            effect="plain"
          >
            {{ ruleDiagnostics?.worker_running ? "运行中" : "代理未运行" }}
          </el-tag>
          <template v-if="ruleDiagnostics">
            <span>
              队列 {{ ruleDiagnostics.queue_depth }}/{{ ruleDiagnostics.queue_capacity }}
            </span>
            <span>完成 {{ ruleDiagnostics.completed_evaluations }}</span>
            <el-tag
              v-if="ruleDiagnostics.dropped_evaluations"
              size="small"
              type="danger"
              effect="plain"
            >
              丢弃 {{ ruleDiagnostics.dropped_evaluations }}
            </el-tag>
            <el-tag
              v-if="ruleDiagnostics.timed_out_evaluations"
              size="small"
              type="warning"
              effect="plain"
            >
              超时 {{ ruleDiagnostics.timed_out_evaluations }}
            </el-tag>
            <el-tag
              v-if="ruleDiagnostics.failed_evaluations"
              size="small"
              type="danger"
              effect="plain"
            >
              失败 {{ ruleDiagnostics.failed_evaluations }}
            </el-tag>
          </template>
          <el-button
            link
            size="small"
            :icon="Refresh"
            :loading="ruleDiagnosticsLoading"
            @click="loadRuleDiagnostics(true)"
          >
            刷新
          </el-button>
        </div>

        <div v-if="ruleDiagnostics" class="rule-pack-list">
          <el-tooltip
            v-for="pack in ruleDiagnostics.packs"
            :key="`${pack.pack_id}@${pack.version}`"
            :content="
              pack.loaded
                ? `${pack.rule_count} 条规则`
                : pack.disabled_reason || '规则包校验失败'
            "
          >
            <el-tag
              size="small"
              :type="pack.loaded ? 'success' : 'danger'"
              effect="plain"
            >
              {{ pack.pack_id }}@{{ pack.version || "未知版本" }}
              · {{ pack.loaded ? `${pack.rule_count} 条` : "已禁用" }}
            </el-tag>
          </el-tooltip>
        </div>

        <el-alert
          v-if="ruleIssueSummary"
          type="warning"
          :closable="false"
          show-icon
          title="规则后台存在降级"
          :description="ruleIssueSummary"
        />

        <el-collapse
          v-if="ruleDiagnostics?.recent_evaluations.length"
          class="rule-evaluations"
        >
          <el-collapse-item
            :title="`最近 ${ruleDiagnostics.recent_evaluations.length} 次求值审计`"
            name="evaluations"
          >
            <el-table
              :data="ruleDiagnostics.recent_evaluations"
              size="small"
              max-height="240"
            >
              <el-table-column prop="traffic_id" label="流量" width="90">
                <template #default="{ row }">#{{ row.traffic_id }}</template>
              </el-table-column>
              <el-table-column label="规则包" min-width="150">
                <template #default="{ row }">
                  {{ row.pack_id }}@{{ row.pack_version || "未知版本" }}
                </template>
              </el-table-column>
              <el-table-column label="状态" width="90">
                <template #default="{ row }">
                  <el-tag
                    size="small"
                    :type="evaluationStatusTag(row.status).type"
                    effect="plain"
                  >
                    {{ evaluationStatusTag(row.status).text }}
                  </el-tag>
                </template>
              </el-table-column>
              <el-table-column prop="hit_count" label="命中" width="70" />
              <el-table-column prop="finding_count" label="Finding" width="85" />
              <el-table-column prop="duration_ms" label="耗时(ms)" width="90" />
              <el-table-column label="诊断" min-width="220">
                <template #default="{ row }">
                  <span v-if="row.diagnostics.length">
                    {{ row.diagnostics.join("；") }}
                  </span>
                  <span v-else class="cell-sub">—</span>
                </template>
              </el-table-column>
            </el-table>
          </el-collapse-item>
        </el-collapse>
      </div>

      <EmptyState
        v-if="!findings.loading && findings.items.length === 0"
        centered
        title="暂无发现"
        description="可从 AI 评估直接扫描已授权 URL，也可抓包后由被动规则打标或在流量页做 AI 分析。"
      >
        <template #icon><el-icon :size="20"><Document /></el-icon></template>
      </EmptyState>

      <el-table
        v-else
        v-loading="findings.loading"
        :data="findings.items"
        row-key="id"
        size="small"
        class="rf-table-shell"
        @expand-change="handleExpand"
      >
      <el-table-column type="expand">
        <template #default="{ row }">
          <div class="expand">
            <div class="block">
              <div class="label">推理过程 / 命中说明</div>
              <div class="md" v-html="md.render(row.reasoning || '（无）')" />
            </div>
            <div class="block">
              <div class="label">手动验证步骤</div>
              <div class="md" v-html="md.render(row.verify_steps || '（无）')" />
            </div>
            <div v-if="row.standard_references.length" class="block">
              <div class="label">知识卡片</div>
              <KnowledgeCard :references="row.standard_references" />
            </div>
            <div v-if="row.fingerprint" class="block">
              <div class="label">稳定指纹</div>
              <code class="fingerprint">{{ row.fingerprint }}</code>
            </div>
            <div v-if="row.producer === 'passive_rule'" class="block">
              <div class="label">关联流量（累计 {{ row.occurrences }}）</div>
              <div v-if="findingTrafficLoading[row.id]" class="cell-sub">
                正在读取关联流量…
              </div>
              <el-table
                v-else-if="findingTraffic[row.id]?.length"
                :data="findingTraffic[row.id]"
                size="small"
                max-height="220"
              >
                <el-table-column prop="traffic_id" label="#" width="70" />
                <el-table-column prop="method" label="方法" width="80" />
                <el-table-column prop="url" label="URL" min-width="320" show-overflow-tooltip />
                <el-table-column prop="status" label="状态码" width="80" />
                <el-table-column prop="first_seen_at" label="首次关联" width="165" />
              </el-table>
              <span v-else class="cell-sub">暂无可读取的关联流量。</span>
            </div>
            <div v-if="row.producer === 'passive_rule'" class="block">
              <div class="label">
                规则命中审计（最近 {{ findingRuleHits[row.id]?.length ?? 0 }} 条）
              </div>
              <div v-if="findingTrafficLoading[row.id]" class="cell-sub">
                正在读取规则命中记录…
              </div>
              <el-table
                v-else-if="findingRuleHits[row.id]?.length"
                :data="findingRuleHits[row.id]"
                size="small"
                max-height="260"
              >
                <el-table-column prop="created_at" label="命中时间" width="175" />
                <el-table-column prop="traffic_id" label="流量" width="70">
                  <template #default="{ row: hit }">#{{ hit.traffic_id }}</template>
                </el-table-column>
                <el-table-column label="规则包 / 规则版本" min-width="230">
                  <template #default="{ row: hit }">
                    <div>{{ hit.pack_id }}@{{ hit.pack_version }}</div>
                    <div class="cell-sub">{{ hit.rule_id }}@{{ hit.rule_version }}</div>
                  </template>
                </el-table-column>
                <el-table-column prop="field_path" label="命中位置" min-width="190" show-overflow-tooltip />
                <el-table-column prop="evidence" label="脱敏证据" min-width="280" show-overflow-tooltip />
                <el-table-column prop="confidence" label="置信度" width="80" />
                <el-table-column label="完整性" width="90">
                  <template #default="{ row: hit }">
                    <el-tag
                      size="small"
                      :type="hit.incomplete_evidence ? 'warning' : 'success'"
                      effect="plain"
                    >
                      {{ hit.incomplete_evidence ? "不完整" : "完整" }}
                    </el-tag>
                  </template>
                </el-table-column>
              </el-table>
              <span v-else class="cell-sub">暂无规则命中记录。</span>
            </div>
            <EvidencePanel
              :finding="row"
              :traffic="findingTraffic[row.id] ?? []"
              @finding-updated="findings.applyFinding"
            />
          </div>
        </template>
      </el-table-column>
      <el-table-column prop="id" label="#" width="60" />
      <el-table-column label="标题" min-width="200">
        <template #default="{ row }">
          <div class="cell-title">{{ row.title }}</div>
          <div class="cell-sub">
            <el-tag
              size="small"
              :type="row.producer === 'safe_verifier' ? 'success' : row.producer === 'ai' ? 'primary' : 'info'"
              effect="plain"
            >
              {{
                row.producer === "safe_verifier"
                  ? "安全验证器"
                  : row.producer === "ai"
                    ? "AI"
                    : "被动规则"
              }}
            </el-tag>
            <el-tag
              v-if="row.producer === 'safe_verifier' && row.status === 'confirmed'"
              size="small"
              type="success"
              effect="dark"
            >自动确认</el-tag>
            <span v-if="row.traffic_id" class="tid">流量 #{{ row.traffic_id }}</span>
            <span v-if="row.producer === 'passive_rule'" class="tid">
              累计 {{ row.occurrences }} 条关联流量
            </span>
          </div>
        </template>
      </el-table-column>
      <el-table-column label="严重度" width="90">
        <template #default="{ row }">
          <el-tag size="small" :type="severityTag(row.severity)" effect="dark">{{ row.severity }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="置信度" width="120">
        <template #default="{ row }">
          <el-progress
            :percentage="row.confidence"
            :stroke-width="6"
            :status="row.confidence >= 70 ? 'success' : row.confidence >= 40 ? 'warning' : 'exception'"
          />
        </template>
      </el-table-column>
      <el-table-column label="标准引用" min-width="220">
        <template #default="{ row }">
          <div v-if="row.standard_references.length" class="reference-list">
            <el-tag
              v-for="reference in row.standard_references"
              :key="`${reference.framework}@${reference.version}/${reference.id}`"
              size="small"
              effect="plain"
            >
              {{ formatStandardReference(reference) }}
            </el-tag>
          </div>
          <span v-else class="cell-sub">—</span>
        </template>
      </el-table-column>
      <el-table-column label="状态" width="90">
        <template #default="{ row }">
          <el-tag size="small" :type="statusTag(row.status).type">{{ statusTag(row.status).text }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="操作" width="210">
        <template #default="{ row }">
          <el-button
            v-if="row.status !== 'confirmed'"
            size="small"
            type="success"
            link
            @click="setStatus(row.id, 'confirmed')"
          >确认</el-button>
          <el-button
            v-if="row.status !== 'rejected'"
            size="small"
            type="info"
            link
            @click="setStatus(row.id, 'rejected')"
          >误报</el-button>
          <el-button
            v-if="row.status !== 'pending'"
            size="small"
            type="warning"
            link
            @click="setStatus(row.id, 'pending')"
          >重置</el-button>
        </template>
      </el-table-column>
    </el-table>
    </template>

    <el-dialog v-model="reportVisible" title="证据化报告 v2（默认脱敏预览）" width="76%" top="5vh">
      <el-alert type="info" :closable="false" show-icon class="report-alert">
        主报告只列 confirmed Finding；pending 位于独立附录，rejected 默认省略。预览始终使用不可变脱敏 Evidence 快照。
      </el-alert>
      <div v-loading="reportLoading" class="report-preview md" v-html="md.render(reportMd)" />
      <template #footer>
        <el-button @click="reportVisible = false">关闭</el-button>
        <el-button
          type="danger"
          plain
          :loading="reportExporting"
          @click="doExportReport(true)"
        >
          单次导出原始敏感内容
        </el-button>
        <el-button
          type="primary"
          :loading="reportExporting"
          @click="doExportReport(false)"
        >
          导出脱敏 .md + .json
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.f {
  width: 110px;
}
.hint {
  flex-shrink: 0;
}
.report-alert {
  margin-bottom: 12px;
}
.rule-health {
  flex-shrink: 0;
  padding: 10px 12px;
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-control);
  background: var(--rf-bg-raised);
}
.rule-health__summary,
.rule-pack-list {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
  font-size: 12px;
  color: var(--rf-text-secondary);
}
.rule-pack-list {
  margin-top: 8px;
}
.rule-evaluations {
  margin-top: 8px;
}
.cell-title {
  font-weight: 600;
}
.cell-sub {
  font-size: 12px;
  color: var(--rf-text-secondary);
  display: flex;
  gap: 6px;
  align-items: center;
}
.reference-list {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
}
.tid {
  font-family: var(--rf-font-mono);
}
.fingerprint {
  display: block;
  overflow-wrap: anywhere;
  color: var(--rf-text-secondary);
  font-family: var(--rf-font-mono);
  font-size: 11px;
}
.expand {
  padding: var(--rf-space-3) var(--rf-space-4);
}
.report-preview {
  max-height: 62vh;
  overflow: auto;
}
.block {
  margin-bottom: var(--rf-space-4);
}
.label {
  font-size: 12px;
  font-weight: 600;
  color: var(--rf-text-muted);
  margin-bottom: var(--rf-space-2);
}
.md {
  font-size: 13px;
  line-height: 1.7;
  background: var(--rf-bg-raised);
  border-radius: var(--rf-radius-control);
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
  background: var(--rf-bg-hover);
  padding: 1px 4px;
  border-radius: 3px;
}
</style>
