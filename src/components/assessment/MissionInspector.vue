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
        <span>Scope</span>
        <el-tag size="small" type="success">后端强制</el-tag>
      </header>
      <div class="origin-line">
        <el-icon><FolderOpened /></el-icon>
        <code>{{ detail.mission.exactOrigin }}</code>
      </div>
      <div class="scope-list">
        <span v-for="item in project.scope" :key="item">{{ item }}</span>
        <span v-if="project.scope.length === 0" class="muted">项目未配置额外 Scope</span>
      </div>
    </section>

    <section class="inspector-section">
      <header class="section-heading">
        <span>上下文与附件</span>
        <button type="button" class="text-action" @click="emit('openContext')">
          查看披露
        </button>
      </header>
      <el-alert
        v-if="context?.requiresApproval"
        type="warning"
        :closable="false"
        show-icon
        title="上下文已变化，需要再次确认"
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
          项目资源
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
        <span>身份与授权</span>
        <button type="button" class="text-action" @click="emit('openIdentity')">管理身份</button>
      </header>
      <div class="identity-row">
        <el-icon><Key /></el-icon>
        <div><small>身份 A</small><span>{{ identityLabel(detail.mission.identityAProfileId, "身份 A") }}</span></div>
      </div>
      <div class="identity-row">
        <el-icon><Key /></el-icon>
        <div><small>身份 B</small><span>{{ identityLabel(detail.mission.identityBProfileId, "身份 B") }}</span></div>
      </div>
      <div class="safety-note"><el-icon><CircleCheck /></el-icon>真实秘密只从系统凭据库注入执行器</div>
    </section>

    <section class="inspector-section">
      <header class="section-heading"><span>预算</span><b>{{ detail.mission.budgetProfile }}</b></header>
      <el-progress
        :percentage="Math.min(100, Math.round((detail.mission.requestCount / Math.max(1, detail.mission.requestBudget)) * 100))"
        :stroke-width="6"
        :show-text="false"
      />
      <div class="budget-meta">
        <span>{{ detail.mission.requestCount }} / {{ detail.mission.requestBudget }} 请求</span>
        <span>2 RPS · 单并发</span>
        <span>{{ detail.mission.completedCycles }} / {{ detail.mission.maxPlanningCycles }} 次规划</span>
      </div>
    </section>

    <section class="inspector-section coverage-section">
      <header class="section-heading"><span>覆盖矩阵</span></header>
      <div class="coverage-grid">
        <div><strong>{{ detail.coverage.confirmed }}</strong><span>confirmed</span></div>
        <div><strong>{{ detail.coverage.suspected }}</strong><span>suspected</span></div>
        <div><strong>{{ detail.coverage.notObserved }}</strong><span>not observed</span></div>
        <div><strong>{{ detail.coverage.coverageGap }}</strong><span>coverage gap</span></div>
      </div>
    </section>

    <section class="inspector-section tool-section">
      <header class="section-heading">
        <span>工具权限</span>
        <el-tag size="small">{{ detail.mission.autonomyMode }}</el-tag>
      </header>
      <div v-if="context" class="tool-list">
        <div v-for="tool in context.tools" :key="tool.id" class="tool-row">
          <div class="tool-copy">
            <span>{{ tool.displayName }}</span>
            <small>{{ tool.id }}@{{ tool.version }} · {{ tool.riskLevel }}</small>
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
  padding: 14px;
  background: var(--rf-bg-panel);
}

.section-heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  margin-bottom: 10px;
  color: var(--rf-text);
  font-size: 12px;
  font-weight: 700;
}

.section-heading b {
  color: var(--rf-text-secondary);
  font-size: 11px;
  text-transform: uppercase;
}

.text-action {
  border: 0;
  background: transparent;
  color: var(--rf-accent);
  cursor: pointer;
  font: inherit;
}

.text-action:focus-visible {
  outline: 2px solid var(--rf-accent);
  outline-offset: 2px;
}

.origin-line,
.identity-row,
.resource-row,
.safety-note {
  display: flex;
  align-items: center;
  gap: 8px;
}

.origin-line code {
  min-width: 0;
  overflow: hidden;
  color: var(--rf-text-secondary);
  font-family: var(--rf-font-mono);
  font-size: 11px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.scope-list {
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
  margin-top: 8px;
}

.scope-list > span:not(.muted) {
  padding: 3px 7px;
  border-radius: var(--rf-radius-tag);
  background: var(--rf-bg-raised);
  color: var(--rf-text-secondary);
  font-size: 10px;
}

.resource-list {
  display: grid;
  gap: 7px;
  margin-bottom: 10px;
}

.resource-row {
  min-width: 0;
  color: var(--rf-text-secondary);
  font-size: 11px;
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
  margin: 7px 0 0;
  color: var(--rf-text-muted);
  font-size: 10.5px;
  line-height: 1.45;
}

.identity-row + .identity-row { margin-top: 8px; }
.identity-row { color: var(--rf-text-secondary); }
.identity-row div { display: grid; min-width: 0; }
.identity-row small { color: var(--rf-text-muted); font-size: 9px; text-transform: uppercase; }
.identity-row span { overflow: hidden; font-size: 11px; text-overflow: ellipsis; white-space: nowrap; }

.safety-note {
  margin-top: 9px;
  color: var(--rf-success);
  font-size: 10px;
}

.budget-meta {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 5px;
  margin-top: 8px;
  color: var(--rf-text-muted);
  font-size: 10px;
}

.budget-meta span:last-child { grid-column: 1 / -1; }

.coverage-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 6px;
}

.coverage-grid > div {
  display: grid;
  gap: 2px;
  padding: 8px;
  border: 1px solid var(--rf-border);
  border-radius: 8px;
  background: var(--rf-bg-raised);
}

.coverage-grid strong { color: var(--rf-text); font-size: 16px; }
.coverage-grid span { color: var(--rf-text-muted); font-size: 9px; }

.tool-list { display: grid; gap: 9px; }
.tool-row { display: flex; align-items: center; gap: 8px; }
.tool-copy { display: grid; min-width: 0; flex: 1; }
.tool-copy > span { color: var(--rf-text-secondary); font-size: 11px; }
.tool-copy small {
  overflow: hidden;
  color: var(--rf-text-muted);
  font-family: var(--rf-font-mono);
  font-size: 9px;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.permission-select { width: 76px; flex: 0 0 auto; }
</style>
