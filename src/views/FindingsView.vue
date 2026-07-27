<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { ElMessage } from "element-plus";
import { Document, FolderOpened } from "@element-plus/icons-vue";
import MarkdownIt from "markdown-it";
import { useFindingsStore } from "../stores/findings";
import { useProjectStore } from "../stores/project";
import {
  buildReport,
  exportReport,
  formatStandardReference,
} from "../api/tauri";
import KnowledgeCard from "../components/KnowledgeCard.vue";
import EmptyState from "../components/shell/EmptyState.vue";
import PageHeader from "../components/shell/PageHeader.vue";

const findings = useFindingsStore();
const project = useProjectStore();
const md = new MarkdownIt({ breaks: true, linkify: true });

const projectId = computed(() => project.current?.id ?? null);

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
  <div class="findings-page rf-page rf-page--inset">
    <PageHeader
      title="发现"
      description="复核 AI / 规则命中，标记确认或误报，并导出学习报告。"
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
        所有 Finding 默认「待验证」。请按验证步骤人工复核后标记「已确认」或「误报」。
      </el-alert>

      <EmptyState
        v-if="!findings.loading && findings.items.length === 0"
        centered
        title="暂无发现"
        description="抓包后被动规则会自动打标；在流量页选中请求做 AI 分析，也会生成待验证发现。"
      >
        <template #icon><el-icon :size="20"><Document /></el-icon></template>
      </EmptyState>

      <el-table
        v-else
        v-loading="findings.loading"
        :data="findings.items"
        size="small"
        class="rf-table-shell"
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
.f {
  width: 110px;
}
.hint {
  flex-shrink: 0;
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
