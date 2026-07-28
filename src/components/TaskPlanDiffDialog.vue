<script setup lang="ts">
import { computed } from "vue";
import type {
  TaskPlanDiffItem,
  TaskPlanProposal,
} from "../api/tauri";

const props = defineProps<{
  modelValue: boolean;
  proposal: TaskPlanProposal | null;
  loading?: boolean;
}>();

const emit = defineEmits<{
  "update:modelValue": [value: boolean];
  confirm: [];
  reject: [];
}>();

const operationLabel = computed(() => {
  const labels = {
    generate: "生成 / 增量规划",
    expand: "展开节点",
    alternative: "换个思路",
  };
  return props.proposal ? labels[props.proposal.operation] : "";
});

const sections = computed(() => {
  const diff = props.proposal?.diff;
  return [
    {
      key: "additions",
      label: "新增",
      tone: "success",
      items: diff?.additions ?? [],
    },
    {
      key: "updates",
      label: "更新",
      tone: "warning",
      items: diff?.updates ?? [],
    },
    {
      key: "preserved",
      label: "保留",
      tone: "info",
      items: diff?.preserved ?? [],
    },
    {
      key: "archives",
      label: "归档",
      tone: "danger",
      items: diff?.archives ?? [],
    },
  ] as Array<{
    key: string;
    label: string;
    tone: "success" | "warning" | "info" | "danger";
    items: TaskPlanDiffItem[];
  }>;
});

const changedCount = computed(() => {
  const diff = props.proposal?.diff;
  return diff
    ? diff.additions.length + diff.updates.length + diff.archives.length
    : 0;
});
</script>

<template>
  <el-dialog
    :model-value="modelValue"
    title="确认测试计划变更"
    width="760px"
    :close-on-click-modal="!loading"
    :close-on-press-escape="!loading"
    @update:model-value="emit('update:modelValue', $event)"
  >
    <template v-if="proposal">
      <div class="proposal-meta">
        <el-tag effect="plain">{{ operationLabel }}</el-tag>
        <span>Proposal #{{ proposal.id }}</span>
        <span>基于 revision {{ proposal.base_revision }}</span>
        <span v-if="proposal.analysis_run_id !== null">
          审计运行 #{{ proposal.analysis_run_id }}
        </span>
      </div>

      <el-alert type="info" :closable="false" show-icon class="guard-note">
        AI 只提出变更。人工节点、人工进度、锁定字段及已关联 Evidence 的节点会保留；
        “归档”保留历史记录和关系，不会物理删除。
      </el-alert>

      <div class="summary-grid">
        <div
          v-for="section in sections"
          :key="section.key"
          class="summary-card"
        >
          <el-tag :type="section.tone" effect="dark" size="small">
            {{ section.label }}
          </el-tag>
          <strong>{{ section.items.length }}</strong>
        </div>
      </div>

      <el-scrollbar max-height="440px" class="diff-scroll">
        <section
          v-for="section in sections"
          :key="section.key"
          class="diff-section"
        >
          <h3>
            {{ section.label }}
            <span>{{ section.items.length }}</span>
          </h3>
          <div v-if="section.items.length" class="diff-list">
            <div
              v-for="item in section.items"
              :key="`${section.key}:${item.stable_key}`"
              class="diff-item"
            >
              <div class="diff-title">
                <span>{{ item.title }}</span>
                <code>{{ item.stable_key }}</code>
              </div>
              <div v-if="item.changed_fields.length" class="field-tags">
                <el-tag
                  v-for="field in item.changed_fields"
                  :key="field"
                  size="small"
                  effect="plain"
                >
                  {{ field }}
                </el-tag>
              </div>
              <p>{{ item.reason }}</p>
            </div>
          </div>
          <div v-else class="empty-row">无</div>
        </section>
      </el-scrollbar>
    </template>

    <template #footer>
      <el-button :disabled="loading" @click="emit('update:modelValue', false)">
        稍后处理
      </el-button>
      <el-button type="danger" plain :disabled="loading" @click="emit('reject')">
        拒绝提案
      </el-button>
      <el-button type="primary" :loading="loading" @click="emit('confirm')">
        确认并合并 {{ changedCount }} 项变更
      </el-button>
    </template>
  </el-dialog>
</template>

<style scoped>
.proposal-meta {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px 14px;
  color: var(--rf-text-secondary);
  font-size: 12px;
}
.guard-note {
  margin-top: var(--rf-space-3);
}
.summary-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: var(--rf-space-2);
  margin: var(--rf-space-3) 0;
}
.summary-card {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 9px 10px;
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-control);
  background: var(--rf-bg-raised);
}
.summary-card strong {
  font-size: 18px;
}
.diff-scroll {
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-control);
}
.diff-section {
  padding: 12px;
  border-bottom: 1px solid var(--rf-border);
}
.diff-section:last-child {
  border-bottom: none;
}
.diff-section h3 {
  display: flex;
  gap: 8px;
  margin: 0 0 8px;
  font-size: 13px;
}
.diff-section h3 span {
  color: var(--rf-text-muted);
  font-weight: 400;
}
.diff-list {
  display: grid;
  gap: 7px;
}
.diff-item {
  padding: 8px 10px;
  background: var(--rf-bg-raised);
  border-radius: var(--rf-radius-control);
}
.diff-title {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 12px;
  font-size: 13px;
}
.diff-title code {
  color: var(--rf-text-muted);
  font-size: 10px;
  overflow: hidden;
  text-overflow: ellipsis;
}
.field-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  margin-top: 6px;
}
.diff-item p,
.empty-row {
  margin: 6px 0 0;
  color: var(--rf-text-secondary);
  font-size: 12px;
}
</style>
