<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { isNavigationFailure, useRouter } from "vue-router";
import { ElMessage } from "element-plus";
import { ArrowRight, Plus } from "@element-plus/icons-vue";
import { useProjectStore } from "../stores/project";
import {
  countTraffic,
  getTaskTree,
  listFindings,
  type Project,
} from "../api/tauri";
import {
  EMPTY_HOME_SUMMARY,
  loadHomeSummary,
  type HomeSummary,
} from "../utils/homeSummary";
import {
  formatRelativeVisit,
  getProjectMark,
  getResumePath,
  getWorkspaceLabel,
  readWorkspaceHistory,
  sortRecentProjects,
} from "../utils/workspaceHistory";

const router = useRouter();
const project = useProjectStore();
const history = readWorkspaceHistory();
const summary = ref<HomeSummary>({ ...EMPTY_HOME_SUMMARY });
const summaryLoading = ref(false);
const numberFormatter = new Intl.NumberFormat("zh-CN");
let summaryRequest = 0;

const currentVisit = computed(() => {
  const id = project.current?.id;
  return id === undefined ? undefined : history[String(id)];
});

const currentWorkspaceLabel = computed(() => {
  const current = project.current;
  return current
    ? getWorkspaceLabel(getResumePath(current.id, history))
    : "流量分析";
});

const currentVisitLabel = computed(() =>
  formatRelativeVisit(currentVisit.value?.openedAt),
);

const recentProjects = computed(() =>
  sortRecentProjects(
    project.projects,
    project.current?.id ?? null,
    history,
    5,
  ),
);

const trafficMetric = computed(() =>
  formatMetric(summary.value.trafficTotal),
);

const taskMetric = computed(() => {
  const { tasksDone, tasksTotal } = summary.value;
  if (tasksDone === null || tasksTotal === null) return "—";
  return `${numberFormatter.format(tasksDone)} / ${numberFormatter.format(tasksTotal)}`;
});

const findingsMetric = computed(() =>
  formatMetric(summary.value.pendingFindings),
);

watch(
  () => project.current?.id ?? null,
  (projectId) => {
    void refreshSummary(projectId);
  },
  { immediate: true },
);

function formatMetric(value: number | null): string {
  return value === null ? "—" : numberFormatter.format(value);
}

function projectTarget(item: Project): string {
  return item.target_host.trim() || "未设置目标";
}

function projectWorkspaceLabel(item: Project): string {
  return getWorkspaceLabel(getResumePath(item.id, history));
}

function projectVisitLabel(item: Project): string {
  return formatRelativeVisit(history[String(item.id)]?.openedAt);
}

async function refreshSummary(projectId: number | null) {
  const request = ++summaryRequest;
  summary.value = { ...EMPTY_HOME_SUMMARY };
  summaryLoading.value = projectId !== null;
  if (projectId === null) return;

  try {
    const next = await loadHomeSummary(projectId, {
      countTraffic: (id) => countTraffic(id, {}),
      getTaskTree,
      listPendingFindings: (id) =>
        listFindings(id, { status: "pending" }),
    });
    if (request === summaryRequest && project.current?.id === projectId) {
      summary.value = next;
    }
  } catch {
    if (request === summaryRequest) {
      summary.value = { ...EMPTY_HOME_SUMMARY };
    }
  } finally {
    if (request === summaryRequest) summaryLoading.value = false;
  }
}

async function resumeProject(item: Project) {
  const path = getResumePath(item.id, history);
  try {
    if (project.current?.id !== item.id) {
      await project.select(item.id);
    }
    const failure = await router.push(path);
    if (isNavigationFailure(failure)) {
      ElMessage.error("无法继续项目：导航被取消");
    }
  } catch (error) {
    ElMessage.error(`无法继续项目：${String(error)}`);
  }
}
</script>

<template>
  <div class="home-page">
    <section v-if="project.projects.length === 0" class="empty-home">
      <div class="empty-mark" aria-hidden="true">
        <el-icon :size="22"><Plus /></el-icon>
      </div>
      <h1>还没有授权项目</h1>
      <p>
        点击右上角的“+”新建项目，用于隔离目标、流量、任务与发现。
      </p>
    </section>

    <template v-else>
      <section v-if="project.current" class="current-section">
        <div class="section-kicker">当前项目</div>
        <article class="focus-card">
          <div class="focus-main">
            <div class="project-mark" aria-hidden="true">
              {{ getProjectMark(project.current.name) }}
            </div>
            <div class="focus-copy">
              <h1>{{ project.current.name }}</h1>
              <div class="focus-meta">
                <span>{{ projectTarget(project.current) }}</span>
                <span class="meta-divider" aria-hidden="true">·</span>
                <span>Scope {{ project.current.scope.length }} 项</span>
                <span class="meta-divider" aria-hidden="true">·</span>
                <span>上次工作区：{{ currentWorkspaceLabel }}</span>
                <span class="meta-divider" aria-hidden="true">·</span>
                <span>{{ currentVisitLabel }}</span>
              </div>
            </div>
            <button
              type="button"
              class="resume-primary"
              @click="resumeProject(project.current)"
            >
              <span>继续{{ currentWorkspaceLabel }}</span>
              <el-icon :size="14"><ArrowRight /></el-icon>
            </button>
          </div>

          <div
            class="focus-metrics"
            aria-label="当前项目统计"
            :aria-busy="summaryLoading"
            aria-live="polite"
          >
            <div class="metric-item">
              <span v-if="summaryLoading" class="metric-skeleton" />
              <strong v-else>{{ trafficMetric }}</strong>
              <span>流量</span>
            </div>
            <div class="metric-item">
              <span v-if="summaryLoading" class="metric-skeleton" />
              <strong v-else>{{ taskMetric }}</strong>
              <span>任务完成</span>
            </div>
            <div class="metric-item">
              <span v-if="summaryLoading" class="metric-skeleton" />
              <strong v-else>{{ findingsMetric }}</strong>
              <span>待确认发现</span>
            </div>
          </div>
        </article>
      </section>

      <section v-else class="no-current">
        <div class="no-current-mark" aria-hidden="true">RF</div>
        <div>
          <h1>选择一个项目继续</h1>
          <p>可从顶部选择项目，或直接打开下方最近项目。</p>
        </div>
      </section>

      <section v-if="recentProjects.length" class="recent-section">
        <div class="recent-head">
          <div class="section-kicker">最近项目</div>
          <span>按最近打开排序</span>
        </div>
        <div class="recent-list">
          <button
            v-for="item in recentProjects"
            :key="item.id"
            type="button"
            class="recent-row"
            :aria-label="`继续项目 ${item.name}`"
            @click="resumeProject(item)"
          >
            <span class="recent-mark" aria-hidden="true">
              {{ getProjectMark(item.name) }}
            </span>
            <span class="recent-copy">
              <strong>{{ item.name }}</strong>
              <span>
                {{ projectTarget(item) }}
                <span class="meta-divider" aria-hidden="true">·</span>
                上次工作区：{{ projectWorkspaceLabel(item) }}
                <span class="meta-divider" aria-hidden="true">·</span>
                {{ projectVisitLabel(item) }}
              </span>
            </span>
            <span class="recent-action">
              继续
              <el-icon :size="13"><ArrowRight /></el-icon>
            </span>
          </button>
        </div>
      </section>
    </template>

  </div>
</template>

<style scoped>
.home-page {
  width: 100%;
  max-width: 760px;
  margin: 0 auto;
  padding: clamp(28px, 6vh, 56px) 0 var(--rf-space-6);
  display: flex;
  flex-direction: column;
  gap: var(--rf-space-6);
}

.section-kicker {
  margin: 0 0 10px 2px;
  color: var(--rf-text-muted);
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.08em;
}

.focus-card {
  overflow: hidden;
  border: 1px solid
    color-mix(in srgb, var(--rf-accent) 42%, var(--rf-border));
  border-radius: var(--rf-radius-shell);
  background: var(--rf-bg-panel);
  box-shadow:
    inset 0 1px 0 var(--rf-accent-muted),
    var(--rf-shadow-light);
}

.focus-main {
  display: flex;
  align-items: center;
  gap: var(--rf-space-4);
  padding: 21px var(--rf-space-5) 18px;
}

.project-mark,
.recent-mark,
.no-current-mark,
.empty-mark {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  background: var(--rf-accent-muted);
  color: var(--rf-accent);
  font-weight: 750;
  user-select: none;
}

.project-mark {
  width: 46px;
  height: 46px;
  border-radius: 13px;
  font-size: 13px;
}

.focus-copy {
  flex: 1;
  min-width: 0;
}

.focus-copy h1 {
  margin: 0;
  overflow: hidden;
  color: var(--rf-text);
  font-size: 17px;
  font-weight: 720;
  letter-spacing: -0.015em;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.focus-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 0 7px;
  margin-top: 6px;
  color: var(--rf-text-secondary);
  font-size: 11.5px;
  line-height: 1.55;
}

.meta-divider {
  color: var(--rf-text-muted);
}

.resume-primary {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  border: none;
  border-radius: var(--rf-radius-control);
  background: var(--rf-accent);
  color: var(--rf-accent-on);
  font: inherit;
  font-size: 12px;
  font-weight: 700;
  cursor: pointer;
  transition:
    background var(--rf-duration) var(--rf-ease),
    transform var(--rf-duration) var(--rf-ease);
}

.resume-primary {
  flex-shrink: 0;
  padding: 9px 14px;
}

.resume-primary:hover {
  background: var(--rf-accent-hover);
  transform: translateY(-1px);
}

.resume-primary:focus-visible,
.recent-row:focus-visible {
  outline: 2px solid var(--rf-accent);
  outline-offset: 2px;
}

.focus-metrics {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  border-top: 1px solid var(--rf-border);
  background: var(--rf-bg-raised);
}

.metric-item {
  min-width: 0;
  padding: 13px var(--rf-space-5);
  border-right: 1px solid var(--rf-border);
}

.metric-item:last-child {
  border-right: none;
}

.metric-item strong,
.metric-skeleton {
  display: block;
  min-height: 20px;
  color: var(--rf-text);
  font-size: 15px;
  font-weight: 700;
  line-height: 20px;
}

.metric-item > span:last-child {
  display: block;
  margin-top: 2px;
  color: var(--rf-text-secondary);
  font-size: 10.5px;
}

.metric-skeleton {
  width: 46px;
  border-radius: 5px;
  background: var(--rf-bg-hover);
  animation: metric-pulse 1.2s ease-in-out infinite;
}

.recent-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--rf-space-3);
  margin: 0 2px 10px;
}

.recent-head .section-kicker {
  margin: 0;
}

.recent-head > span {
  color: var(--rf-text-secondary);
  font-size: 10.5px;
}

.recent-list {
  overflow: hidden;
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-shell);
  background: var(--rf-bg-panel);
}

.recent-row {
  width: 100%;
  min-height: 66px;
  display: flex;
  align-items: center;
  gap: var(--rf-space-3);
  padding: 12px var(--rf-space-4);
  border: none;
  border-bottom: 1px solid var(--rf-border);
  border-radius: 0;
  background: transparent;
  color: inherit;
  font: inherit;
  text-align: left;
  cursor: pointer;
  transition: background var(--rf-duration) var(--rf-ease);
}

.recent-row:last-child {
  border-bottom: none;
}

.recent-row:hover {
  background: var(--rf-bg-hover);
}

.recent-mark {
  width: 34px;
  height: 34px;
  border-radius: 10px;
  background: var(--rf-bg-raised);
  color: var(--rf-text-secondary);
  font-size: 10.5px;
}

.recent-row:hover .recent-mark {
  background: var(--rf-accent-muted);
  color: var(--rf-accent);
}

.recent-copy {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.recent-copy > strong {
  overflow: hidden;
  color: var(--rf-text);
  font-size: 12.5px;
  font-weight: 650;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.recent-copy > span {
  color: var(--rf-text-secondary);
  font-size: 10.5px;
  line-height: 1.5;
}

.recent-action {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  flex-shrink: 0;
  padding: 6px 9px;
  border-radius: 7px;
  color: var(--rf-accent);
  font-size: 11px;
  font-weight: 650;
}

.recent-row:hover .recent-action {
  background: var(--rf-accent-muted);
}

.no-current {
  display: flex;
  align-items: center;
  gap: var(--rf-space-4);
  padding: var(--rf-space-5);
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-shell);
  background: var(--rf-bg-panel);
}

.no-current-mark {
  width: 42px;
  height: 42px;
  border-radius: 12px;
  font-size: 11px;
}

.no-current h1,
.empty-home h1 {
  margin: 0;
  color: var(--rf-text);
  font-size: 18px;
  font-weight: 700;
  letter-spacing: -0.01em;
}

.no-current p,
.empty-home p {
  margin: 5px 0 0;
  color: var(--rf-text-secondary);
  font-size: 12px;
  line-height: 1.6;
}

.empty-home {
  min-height: 420px;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  text-align: center;
}

.empty-home p {
  max-width: 420px;
}

.empty-mark {
  width: 48px;
  height: 48px;
  margin-bottom: var(--rf-space-4);
  border-radius: 14px;
}

@keyframes metric-pulse {
  0%,
  100% {
    opacity: 0.45;
  }
  50% {
    opacity: 0.9;
  }
}

@media (max-width: 700px) {
  .home-page {
    padding-top: var(--rf-space-4);
  }

  .focus-main {
    align-items: flex-start;
    flex-wrap: wrap;
  }

  .focus-copy {
    min-width: calc(100% - 62px);
  }

  .resume-primary {
    width: 100%;
    margin-left: 62px;
  }
}

@media (max-width: 520px) {
  .resume-primary {
    margin-left: 0;
  }

  .focus-metrics {
    grid-template-columns: 1fr;
  }

  .metric-item {
    border-right: none;
    border-bottom: 1px solid var(--rf-border);
  }

  .metric-item:last-child {
    border-bottom: none;
  }

  .recent-row {
    align-items: flex-start;
  }

  .recent-action {
    padding-right: 0;
  }
}

@media (prefers-reduced-motion: reduce) {
  .metric-skeleton {
    animation: none;
  }
}
</style>
