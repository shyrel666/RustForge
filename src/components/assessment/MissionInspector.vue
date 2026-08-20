<script setup lang="ts">
import { computed } from "vue";
import {
  CircleCheck,
  Document,
  FolderOpened,
  Key,
  Plus,
  Upload,
  Warning,
} from "@element-plus/icons-vue";
import type {
  AssessmentAuthProfile,
  AssessmentMissionDetail,
  AssessmentToolPermissionDecision,
  MissionContextPreview,
  Project,
} from "../../api/tauri";

const props = defineProps<{
  project: Project;
  detail: AssessmentMissionDetail;
  context: MissionContextPreview | null;
  profiles: AssessmentAuthProfile[];
  disabled?: boolean;
}>();

const emit = defineEmits<{
  openContext: [];
  openResource: [];
  importOpenApi: [];
  openIdentity: [];
  updatePermission: [toolId: string, decision: AssessmentToolPermissionDecision];
}>();

const profileById = computed(
  () => new Map<number, AssessmentAuthProfile>(props.profiles.map((profile) => [profile.id, profile]))
);

const resourceMutable = computed(() =>
  ["draft", "awaiting_context_approval"].includes(props.detail.mission.status)
);

const identityLabel = (profileId: number | null, fallback: string) => {
  if (profileId === null) return "未选择";
  const profile = profileById.value.get(profileId);
  return profile?.label ?? `${fallback} · #${profileId}`;
};

function permissionOptions(executionKind: string) {
  const options: Array<{ label: string; value: AssessmentToolPermissionDecision }> = [
    { label: "禁用", value: "disabled" },
    { label: "询问", value: "ask" },
  ];
  if (executionKind !== "manual_recipe") {
    options.push({ label: "执行", value: "execute" });
  }
  return options;
}
</script>

<template>
  <aside class="inspector" aria-label="任务安全边界与覆盖信息">
    <section class="inspector-section">
      <header class="section-heading">
        <span class="heading-title">Scope 边界</span>
        <span class="badge-guard">后端强制</span>
      </header>
      <div class="origin-line">
        <el-icon class="origin-icon"><FolderOpened /></el-icon>
        <code>{{ detail.mission.exactOrigin }}</code>
      </div>
      <div class="scope-list">
        <span v-for="item in project.scope" :key="item" class="scope-chip">{{ item }}</span>
        <span v-if="project.scope.length === 0" class="muted">项目未配置额外 Scope</span>
      </div>
    </section>

    <section class="inspector-section">
      <header class="section-heading">
        <span class="heading-title">上下文与附件</span>
        <button type="button" class="text-action" @click="emit('openContext')">
          查看披露
        </button>
      </header>
      <el-alert
        v-if="context?.requiresApproval"
        type="warning"
        :closable="false"
        show-icon
        title="上下文已变化，需再次确认"
        class="alert-compact"
      />
      <div class="resource-list">
        <div v-for="resource in detail.resources" :key="resource.id" class="resource-row">
          <el-icon><Document /></el-icon>
          <span>{{ resource.displayName }}</span>
        </div>
        <span v-if="detail.resources.length === 0" class="muted">尚未附加项目资源</span>
      </div>
      <div class="inline-actions">
        <el-button
          size="small"
          :icon="Plus"
          :disabled="disabled || !resourceMutable"
          @click="emit('openResource')"
        >
          同项目资源
        </el-button>
        <el-button
          size="small"
          :icon="Upload"
          :disabled="disabled || !resourceMutable"
          @click="emit('importOpenApi')"
        >
          OpenAPI
        </el-button>
      </div>
      <p v-if="!resourceMutable" class="microcopy">资源在首次上下文确认后冻结。</p>
    </section>

    <section class="inspector-section">
      <header class="section-heading">
        <span class="heading-title">身份模式</span>
        <button type="button" class="text-action" @click="emit('openIdentity')">凭据库</button>
      </header>
      <div class="identity-row">
        <el-icon><Key /></el-icon>
        <div><small>身份 A</small><span>{{ identityLabel(detail.mission.identityAProfileId, "身份 A") }}</span></div>
      </div>
      <div class="identity-row">
        <el-icon><Key /></el-icon>
        <div><small>身份 B</small><span>{{ identityLabel(detail.mission.identityBProfileId, "身份 B") }}</span></div>
      </div>
      <div class="safety-note">
        <el-icon><CircleCheck /></el-icon>
        <span>凭据不进入上下文，只在 Rust 端注入</span>
      </div>
    </section>

    <section class="inspector-section">
      <header class="section-heading">
        <span class="heading-title">预算消耗</span>
        <span class="budget-badge">{{ detail.mission.budgetProfile }}</span>
      </header>
      <el-progress
        :percentage="Math.min(100, Math.round((detail.mission.requestCount / Math.max(1, detail.mission.requestBudget)) * 100))"
        :stroke-width="4"
        :show-text="false"
      />
      <div class="budget-meta">
        <span>{{ detail.mission.requestCount }} / {{ detail.mission.requestBudget }} 请求</span>
        <span>2 RPS · 单并发</span>
        <span>{{ detail.mission.completedCycles }} / {{ detail.mission.maxPlanningCycles }} 轮规划</span>
      </div>
    </section>

    <section class="inspector-section">
      <header class="section-heading">
        <span class="heading-title">覆盖度指标</span>
      </header>
      <div class="coverage-grid">
        <div class="coverage-cell"><strong>{{ detail.coverage.confirmed }}</strong><span>Confirmed</span></div>
        <div class="coverage-cell"><strong>{{ detail.coverage.suspected }}</strong><span>Suspected</span></div>
        <div class="coverage-cell"><strong>{{ detail.coverage.notObserved }}</strong><span>Not Observed</span></div>
        <div class="coverage-cell"><strong>{{ detail.coverage.coverageGap }}</strong><span>Gap</span></div>
      </div>
    </section>

    <section class="inspector-section tool-section">
      <header class="section-heading">
        <span class="heading-title">ToolSpec 权限</span>
        <el-tag size="small" type="info">{{ detail.mission.autonomyMode }}</el-tag>
      </header>
      <div v-if="context" class="tool-list">
        <div v-for="tool in context.tools" :key="tool.id" class="tool-row">
          <div class="tool-copy">
            <span class="tool-title">{{ tool.displayName }}</span>
            <small class="tool-sub">{{ tool.id }}@{{ tool.version }}</small>
          </div>
          <el-select
            :model-value="tool.effectivePermission"
            size="small"
            class="permission-select"
            :disabled="disabled"
            :aria-label="`${tool.displayName}权限`"
            @change="emit('updatePermission', tool.id, $event as AssessmentToolPermissionDecision)"
          >
            <el-option
              v-for="option in permissionOptions(tool.executionKind)"
              :key="option.value"
              :label="option.label"
              :value="option.value"
            />
          </el-select>
        </div>
      </div>
      <div v-else class="muted"><el-icon><Warning /></el-icon>旧运行不提供 v2 工具权限快照</div>
    </section>
  </aside>
</template>

<style scoped>
.inspector {
  display: flex;
  min-width: 0;
  flex-direction: column;
  gap: 1px;
  overflow: auto;
  background: var(--rf-border);
}

.inspector-section {
  padding: var(--rf-space-3) var(--rf-space-4);
  background: var(--rf-bg-panel);
}

.section-heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  margin-bottom: var(--rf-space-2);
}

.heading-title {
  font-size: 11.5px;
  font-weight: 700;
  color: var(--rf-text);
  letter-spacing: 0.01em;
  text-transform: uppercase;
}

.badge-guard {
  font-size: 10px;
  font-weight: 600;
  padding: 1px 6px;
  border-radius: var(--rf-radius-tag);
  background: var(--rf-success-muted);
  color: var(--rf-success);
}

.budget-badge {
  font-family: var(--rf-font-mono);
  font-size: 10.5px;
  font-weight: 600;
  color: var(--rf-accent);
  text-transform: uppercase;
}

.text-action {
  border: 0;
  background: transparent;
  color: var(--rf-accent);
  cursor: pointer;
  font: inherit;
  font-size: 11px;
  font-weight: 500;
  padding: 0;
  transition: opacity var(--rf-duration) var(--rf-ease);
}

.text-action:hover {
  opacity: 0.8;
}

.origin-line {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 4px 6px;
  background: var(--rf-bg-raised);
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-control);
}

.origin-icon {
  color: var(--rf-accent);
  font-size: 13px;
}

.origin-line code {
  min-width: 0;
  overflow: hidden;
  color: var(--rf-text);
  font-family: var(--rf-font-mono);
  font-size: 11px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.scope-list {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  margin-top: 6px;
}

.scope-chip {
  padding: 2px 6px;
  border-radius: 4px;
  background: var(--rf-bg-raised);
  border: 1px solid var(--rf-border);
  color: var(--rf-text-secondary);
  font-family: var(--rf-font-mono);
  font-size: 10.5px;
}

.resource-list {
  display: grid;
  gap: 6px;
  margin-bottom: 8px;
}

.resource-row {
  display: flex;
  align-items: center;
  gap: 6px;
  color: var(--rf-text-secondary);
  font-size: 11.5px;
}

.resource-row span {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.inline-actions {
  display: flex;
  gap: 6px;
}

.inline-actions :deep(.el-button + .el-button) { margin-left: 0; }

.microcopy,
.muted {
  margin: 6px 0 0;
  color: var(--rf-text-muted);
  font-size: 11px;
  line-height: 1.4;
}

.identity-row {
  display: flex;
  align-items: center;
  gap: 8px;
  color: var(--rf-text-secondary);
}

.identity-row + .identity-row { margin-top: 6px; }

.identity-row div { display: grid; min-width: 0; }
.identity-row small { color: var(--rf-text-muted); font-size: 9px; text-transform: uppercase; }
.identity-row span { overflow: hidden; font-size: 11.5px; text-overflow: ellipsis; white-space: nowrap; color: var(--rf-text); }

.safety-note {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-top: 8px;
  color: var(--rf-success);
  font-size: 10.5px;
}

.budget-meta {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 4px;
  margin-top: 6px;
  color: var(--rf-text-muted);
  font-size: 10.5px;
}

.budget-meta span:last-child { grid-column: 1 / -1; }

.coverage-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 6px;
}

.coverage-cell {
  display: grid;
  gap: 2px;
  padding: 6px 8px;
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-control);
  background: var(--rf-bg-raised);
}

.coverage-cell strong {
  color: var(--rf-text);
  font-size: 14px;
  font-family: var(--rf-font-mono);
}

.coverage-cell span {
  color: var(--rf-text-muted);
  font-size: 10px;
  text-transform: uppercase;
}

.tool-list { display: grid; gap: 6px; }
.tool-row { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.tool-copy { display: grid; min-width: 0; flex: 1; }
.tool-title { color: var(--rf-text); font-size: 11.5px; font-weight: 500; }
.tool-sub {
  overflow: hidden;
  color: var(--rf-text-muted);
  font-family: var(--rf-font-mono);
  font-size: 9.5px;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.permission-select { width: 72px; flex: 0 0 auto; }
</style>
