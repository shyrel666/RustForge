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

function outcomeLabel(run: ReplayRunSummary): string {
  switch (run.outcome) {
    case "completed":
      return run.status === null ? "完成" : String(run.status);
    case "response_incomplete":
      return `${run.status ?? "响应"} / 不完整`;
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
</script>

<template>
  <section class="history">
    <div class="history-head">
      <div>
        <div class="history-title">运行历史</div>
        <div class="history-hint">每次发送都会追加不可变快照；勾选两项比较。</div>
      </div>
      <div class="comparison-actions">
        <el-button
          v-if="comparisonIds.length"
          size="small"
          link
          @click="comparisonIds = []"
        >
          清空
        </el-button>
        <el-button
          size="small"
          :icon="Connection"
          :disabled="!canCompare"
          @click="compareSelected"
        >
          比较 {{ comparisonIds.length }}/2
        </el-button>
      </div>
    </div>

    <el-table
      v-loading="loading"
      :data="runs"
      size="small"
      row-key="id"
      max-height="260"
      :row-class-name="
        ({ row }: { row: ReplayRunSummary }) =>
          row.id === selectedRunId ? 'selected-run' : ''
      "
      @row-click="(run: ReplayRunSummary) => emit('select', run)"
    >
      <el-table-column label="比" width="46" align="center">
        <template #default="{ row }">
          <el-checkbox
            :model-value="comparisonIds.includes(row.id)"
            @click.stop
            @change="(checked: boolean) => toggleComparison(row.id, checked)"
          />
        </template>
      </el-table-column>
      <el-table-column prop="id" label="Run" width="70">
        <template #default="{ row }">#{{ row.id }}</template>
      </el-table-column>
      <el-table-column prop="method" label="方法" width="76" />
      <el-table-column prop="url" label="URL" min-width="230" show-overflow-tooltip />
      <el-table-column label="结果" width="118">
        <template #default="{ row }">
          <el-tag size="small" :type="outcomeType(row)">
            {{ outcomeLabel(row) }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="duration_ms" label="耗时" width="82">
        <template #default="{ row }">{{ row.duration_ms }} ms</template>
      </el-table-column>
      <el-table-column prop="created_at" label="时间" width="168" />
      <el-table-column label="操作" width="176" fixed="right">
        <template #default="{ row }">
          <el-button
            link
            size="small"
            :icon="DocumentCopy"
            @click.stop="emit('restore', row)"
          >
            载入
          </el-button>
          <el-button
            link
            size="small"
            :icon="Link"
            @click.stop="emit('link', row)"
          >
            作为证据
          </el-button>
        </template>
      </el-table-column>
      <template #empty>
        <div class="empty">尚无运行；第一次发送后会出现在这里。</div>
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
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-shell);
  background: var(--rf-bg-panel);
  overflow: hidden;
}
.history-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 16px;
  padding: 10px 12px;
  border-bottom: 1px solid var(--rf-border);
}
.history-title {
  font-size: 13px;
  font-weight: 650;
}
.comparison-actions {
  display: flex;
  align-items: center;
  gap: 4px;
}
.history-hint,
.empty {
  color: var(--rf-text-muted);
  font-size: 12px;
}
.history-more {
  display: flex;
  justify-content: center;
  padding: 9px 12px;
  border-top: 1px solid var(--rf-border);
}
:deep(.selected-run td) {
  background: var(--el-color-primary-light-9) !important;
}
</style>
