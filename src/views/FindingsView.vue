<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { ElMessage } from "element-plus";
import MarkdownIt from "markdown-it";
import { useFindingsStore } from "../stores/findings";
import { useProjectStore } from "../stores/project";
import { buildReport, exportReport } from "../api/tauri";
import KnowledgeCard from "../components/KnowledgeCard.vue";

const findings = useFindingsStore();
const project = useProjectStore();
const md = new MarkdownIt({ breaks: true, linkify: true });

const projectId = computed(() => project.current?.id ?? null);

// ---------- 学习报告 ----------
const reportVisible = ref(false);
const reportMd = ref("");
const reportLoading = ref(false);

async function openReport() {
  if (projectId.value === null) return;
  reportVisible.value = true;
  reportLoading.value = true;
  reportMd.value = "";
  try {
    reportMd.value = await buildReport(projectId.value);
  } catch (e) {
    ElMessage.error(String(e));
    reportVisible.value = false;
  } finally {
    reportLoading.value = false;
  }
}

async function doExportReport() {
  if (projectId.value === null) return;
  try {
    const path = await exportReport(projectId.value);
    ElMessage.success(`报告已导出：${path}`);
  } catch (e) {
    ElMessage.error(String(e));
  }
}

onMounted(async () => {
  if (projectId.value !== null) await findings.refresh(projectId.value);
  await findings.bindEvents(() => projectId.value);
});

onUnmounted(() => findings.unbindEvents());

watch(projectId, async (id) => {
  if (id !== null) await findings.refresh(id);
  else findings.items = [];
});

async function setStatus(id: number, status: string) {
  try {
    await findings.setStatus(id, status);
  } catch (e) {
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
</script>

<template>
  <div class="findings-page">
    <div class="toolbar">
      <h3 class="title">
        发现
        <el-tag v-if="pendingCount" type="warning" effect="dark" size="small" class="pending-tag">
          {{ pendingCount }} 条待验证
        </el-tag>
      </h3>
      <div class="filters">
        <el-select v-model="findings.filterStatus" placeholder="状态" clearable class="f"
          @change="projectId !== null && findings.refresh(projectId)">
          <el-option label="待验证" value="pending" />
          <el-option label="已确认" value="confirmed" />
          <el-option label="误报" value="rejected" />
        </el-select>
        <el-select v-model="findings.filterSeverity" placeholder="严重度" clearable class="f"
          @change="projectId !== null && findings.refresh(projectId)">
          <el-option v-for="s in ['critical', 'high', 'medium', 'low', 'info']" :key="s" :label="s" :value="s" />
        </el-select>
        <el-select v-model="findings.filterSource" placeholder="来源" clearable class="f"
          @change="projectId !== null && findings.refresh(projectId)">
          <el-option label="AI 分析" value="ai" />
          <el-option label="被动规则" value="rule" />
        </el-select>
        <el-button type="primary" plain :disabled="projectId === null" @click="openReport">
          📄 生成报告
        </el-button>
      </div>
    </div>

    <el-alert type="info" :closable="false" class="hint">
      所有 Finding 默认「待验证」——这是设计红线：AI 和规则都会误报，
      请按验证步骤人工复核后标记「已确认」或「误报」。
    </el-alert>

    <el-table v-loading="findings.loading" :data="findings.items" size="small" class="table">
      <el-table-column type="expand">
        <template #default="{ row }">
          <div class="expand">
            <div class="block">
              <div class="label">🔍 推理过程 / 命中说明</div>
              <div class="md" v-html="md.render(row.reasoning || '（无）')" />
            </div>
            <div class="block">
              <div class="label">🧪 手动验证步骤</div>
              <div class="md" v-html="md.render(row.verify_steps || '（无）')" />
            </div>
            <div class="block" v-if="row.owasp || row.cwe">
              <div class="label">📚 知识卡片</div>
              <KnowledgeCard :owasp="row.owasp" :cwe="row.cwe" />
            </div>
          </div>
        </template>
      </el-table-column>
      <el-table-column prop="id" label="#" width="60" />
      <el-table-column label="标题" min-width="200">
        <template #default="{ row }">
          <div class="cell-title">{{ row.title }}</div>
          <div class="cell-sub">
            <el-tag size="small" :type="row.source === 'ai' ? 'primary' : 'success'" effect="plain">
              {{ row.source === "ai" ? "AI" : "规则" }}
            </el-tag>
            <span v-if="row.traffic_id" class="tid">流量 #{{ row.traffic_id }}</span>
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
          <el-progress :percentage="row.confidence" :stroke-width="6"
            :status="row.confidence >= 70 ? 'success' : row.confidence >= 40 ? 'warning' : 'exception'" />
        </template>
      </el-table-column>
      <el-table-column label="OWASP / CWE" min-width="180" show-overflow-tooltip>
        <template #default="{ row }">
          <div class="cell-sub">{{ row.owasp || "—" }}</div>
          <div class="cell-sub">{{ row.cwe || "—" }}</div>
        </template>
      </el-table-column>
      <el-table-column label="状态" width="90">
        <template #default="{ row }">
          <el-tag size="small" :type="statusTag(row.status).type">{{ statusTag(row.status).text }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="操作" width="210">
        <template #default="{ row }">
          <el-button v-if="row.status !== 'confirmed'" size="small" type="success" link
            @click="setStatus(row.id, 'confirmed')">✓ 确认</el-button>
          <el-button v-if="row.status !== 'rejected'" size="small" type="info" link
            @click="setStatus(row.id, 'rejected')">✗ 误报</el-button>
          <el-button v-if="row.status !== 'pending'" size="small" type="warning" link
            @click="setStatus(row.id, 'pending')">↺ 重置</el-button>
        </template>
      </el-table-column>
      <template #empty>
        <el-empty description="暂无发现。抓包后规则会自动打标，选中流量做 AI 分析也会生成发现。" />
      </template>
    </el-table>

    <el-dialog v-model="reportVisible" title="学习报告（Markdown 预览）" width="70%" top="6vh">
      <div v-loading="reportLoading" class="report-preview md" v-html="md.render(reportMd)" />
      <template #footer>
        <el-button @click="reportVisible = false">关闭</el-button>
        <el-button type="primary" @click="doExportReport">导出 .md 到下载目录</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.findings-page {
  height: 100%;
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.title {
  margin: 0;
  display: flex;
  align-items: center;
  gap: 10px;
}
.pending-tag {
  font-weight: 400;
}
.filters {
  display: flex;
  gap: 8px;
}
.f {
  width: 120px;
}
.hint {
  flex-shrink: 0;
}
.table {
  flex: 1;
}
.cell-title {
  font-weight: 600;
}
.cell-sub {
  font-size: 12px;
  color: var(--el-text-color-secondary);
  display: flex;
  gap: 6px;
  align-items: center;
}
.tid {
  font-family: Consolas, monospace;
}
.expand {
  padding: 8px 16px;
}
.report-preview {
  max-height: 62vh;
  overflow: auto;
}
.block {
  margin-bottom: 10px;
}
.label {
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
