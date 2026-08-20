<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { Connection, DocumentCopy, Link } from "@element-plus/icons-vue";
import type { ReplayRunSummary } from "../api/tauri";

const props = defineProps<{
  projectId: number | null;
  runs: ReplayRunSummary[];
  selectedRunId: number | null;
  loading: boolean;
  hasMore: boolean;
  loadingMore: boolean;
}>();

const emit = defineEmits<{
  select: [run: ReplayRunSummary];
  restore: [run: ReplayRunSummary];
  link: [run: ReplayRunSummary];
  compare: [leftRunId: number, rightRunId: number];
  "load-more": [];
}>();

const comparisonIds = ref<number[]>([]);
const canCompare = computed(() => comparisonIds.value.length === 2);

watch(
  () => props.projectId,
  () => {
    comparisonIds.value = [];
  }
);

function toggleComparison(runId: number, checked: boolean) {
  if (checked) {
    if (!comparisonIds.value.includes(runId)) {
      comparisonIds.value = [...comparisonIds.value, runId].slice(-2);
    }
  } else {
    comparisonIds.value = comparisonIds.value.filter((id) => id !== runId);
  }
}

function compareSelected() {
  if (comparisonIds.value.length !== 2) return;
  emit("compare", comparisonIds.value[0], comparisonIds.value[1]);
}

function runRowClassName({ row }: { row: ReplayRunSummary }): string {
  return row.id === props.selectedRunId ? "selected-run" : "";
}

function selectRun(run: ReplayRunSummary) {
  emit("select", run);
}

function outcomeLabel(run: ReplayRunSummary): string {
  switch (run.outcome) {
    case "completed":
      return run.status === null ? "完成" : String(run.status);
    case "response_incomplete":
      return `${run.status ?? "响应"} (截断)`;
    case "scope_rejected":
      return "Scope 拒绝";
    default:
      return "请求失败";
  }
}

function outcomeType(
  run: ReplayRunSummary
): "success" | "warning" | "danger" | "info" {
  if (run.outcome === "scope_rejected" || run.outcome === "request_failed") {
    return "danger";
  }
  if (run.outcome === "response_incomplete") return "warning";
  if (run.status !== null && run.status >= 400) return "warning";
  return "success";
}

function methodClass(m: string): string {
  const map: Record<string, string> = {
    GET: "rf-method-get",
    POST: "rf-method-post",
    PUT: "rf-method-put",
    PATCH: "rf-method-patch",
    DELETE: "rf-method-delete",
  };
  return map[m] ?? "rf-method";
}
</script>

<template>
  <section class="history">
    <div class="history-head">
      <div class="history-title-block">
        <div class="history-title">不可变运行历史 (Runs)</div>
        <div class="history-hint">每次发送均生成不可变快照；勾选两项可执行逐字节 Diff 差分。</div>
      </div>
      <div class="comparison-actions">
        <el-button
          v-if="comparisonIds.length"
          size="small"
          link
          @click="comparisonIds = []"
        >
          取消选择
        </el-button>
        <el-button
          size="small"
          :icon="Connection"
          :disabled="!canCompare"
          @click="compareSelected"
        >
          差分比对 ({{ comparisonIds.length }}/2)
        </el-button>
      </div>
    </div>

    <el-table
      v-loading="loading"
      :data="runs"
      size="small"
      row-key="id"
      max-height="240"
      :row-class-name="runRowClassName"
      @row-click="selectRun"
    >
      <el-table-column label="比对" width="48" align="center">
        <template #default="{ row }">
          <el-checkbox
            :model-value="comparisonIds.includes(row.id)"
            @click.stop
            @change="(checked: boolean) => toggleComparison(row.id, checked)"
          />
        </template>
      </el-table-column>

      <el-table-column prop="id" label="Run" width="65">
        <template #default="{ row }"><span class="mono">#{{ row.id }}</span></template>
      </el-table-column>

      <el-table-column prop="method" label="Method" width="80">
        <template #default="{ row }">
          <span class="rf-method" :class="methodClass(row.method)">{{ row.method }}</span>
        </template>
      </el-table-column>

      <el-table-column prop="url" label="URL" min-width="220" show-overflow-tooltip>
        <template #default="{ row }"><span class="mono">{{ row.url }}</span></template>
      </el-table-column>

      <el-table-column label="结果" width="110">
        <template #default="{ row }">
          <el-tag size="small" :type="outcomeType(row)">
            {{ outcomeLabel(row) }}
          </el-tag>
        </template>
      </el-table-column>

      <el-table-column prop="duration_ms" label="耗时" width="80">
        <template #default="{ row }"><span class="mono">{{ row.duration_ms }} ms</span></template>
      </el-table-column>

      <el-table-column prop="created_at" label="时间" width="140">
        <template #default="{ row }"><span class="mono text-muted">{{ row.created_at }}</span></template>
      </el-table-column>

      <el-table-column label="操作" width="160" fixed="right">
        <template #default="{ row }">
          <el-button
            link
            size="small"
            :icon="DocumentCopy"
            @click.stop="emit('restore', row)"
          >
            载入编辑器
          </el-button>
          <el-button
            link
            size="small"
            :icon="Link"
            @click.stop="emit('link', row)"
          >
            关联证据
          </el-button>
        </template>
      </el-table-column>

      <template #empty>
        <div class="empty">尚无运行记录；首次点击发送后将沉淀在此。</div>
      </template>
    </el-table>

    <div v-if="hasMore" class="history-more">
      <el-button
        size="small"
        :loading="loadingMore"
        :disabled="loading"
        @click="emit('load-more')"
      >
        加载更早的运行
      </el-button>
    </div>
  </section>
</template>

<style scoped>
.history {
  flex: 0 0 auto;
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-card);
  background: var(--rf-bg-panel);
  overflow: hidden;
}

.history-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 16px;
  padding: 8px 12px;
  border-bottom: 1px solid var(--rf-border);
  background: var(--rf-bg-raised);
}

.history-title-block {
  display: grid;
  gap: 2px;
}

.history-title {
  font-size: 12px;
  font-weight: 650;
  color: var(--rf-text);
  letter-spacing: 0.01em;
}

.comparison-actions {
  display: flex;
  align-items: center;
  gap: 6px;
}

.history-hint,
.empty {
  color: var(--rf-text-muted);
  font-size: 11px;
}

.empty {
  padding: 16px;
  text-align: center;
}

.text-muted {
  color: var(--rf-text-muted);
}

.history-more {
  display: flex;
  justify-content: center;
  padding: 6px 12px;
  border-top: 1px solid var(--rf-border);
}

:deep(.selected-run td) {
  background: var(--rf-accent-muted) !important;
}
</style>
