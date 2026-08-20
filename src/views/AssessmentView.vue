<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref, watch } from "vue";
import { useRouter } from "vue-router";
import { ElMessage, ElMessageBox } from "element-plus";
import {
  Aim,
  ChatDotRound,
  Close,
  Document,
  FolderOpened,
  Key,
  Plus,
  Refresh,
  Setting,
  VideoPause,
  VideoPlay,
  View,
  Warning,
} from "@element-plus/icons-vue";
import {
  buildAssessmentMissionReport,
  createAssessmentAuthProfile,
  exportAssessmentMissionReport,
  listAssessmentRuns,
  listFindings,
  listTraffic,
  type AssessmentAction,
  type AssessmentAutonomyMode,
  type AssessmentBudgetProfile,
  type AssessmentManualHandoff,
  type AssessmentMissionStatus,
  type AssessmentRun,
  type Finding,
  type TrafficSummary,
} from "../api/tauri";
import MissionInspector from "../components/assessment/MissionInspector.vue";
import ProjectCreateDialog from "../components/ProjectCreateDialog.vue";
import EmptyState from "../components/shell/EmptyState.vue";
import PageHeader from "../components/shell/PageHeader.vue";
import { useAssessmentMissionStore } from "../stores/assessmentMission";
import { useProjectStore } from "../stores/project";

type TagType = "primary" | "success" | "warning" | "info" | "danger";

const router = useRouter();
const project = useProjectStore();
const missions = useAssessmentMissionStore();

const projectId = computed(() => project.current?.id ?? null);
const detail = computed(() => missions.detail);
const selectedMission = computed(() => missions.selectedMission);
const creating = ref(false);
const createProjectVisible = ref(false);
const emptyProjectChoice = ref<number | null>(null);
const inspectorDrawerVisible = ref(false);
const contextDialogVisible = ref(false);
const resourceDialogVisible = ref(false);
const resourceLoading = ref(false);
const identityDialogVisible = ref(false);
const identitySaving = ref(false);
const actionDrawerVisible = ref(false);
const selectedAction = ref<AssessmentAction | null>(null);
const handoffDialogVisible = ref(false);
const selectedHandoff = ref<AssessmentManualHandoff | null>(null);
const handoffReplayRunId = ref<number | null>(null);
const reportVisible = ref(false);
const reportLoading = ref(false);
const reportExporting = ref(false);
const reportMarkdown = ref("");
const reportProjectId = ref<number | null>(null);
const reportMissionId = ref<number | null>(null);
let reportGeneration = 0;
let reportExportGeneration = 0;
const followUp = ref("");
const followUpSending = ref(false);

const createForm = reactive({
  title: "",
  goal: "",
  startUrl: "",
  excludedPaths: "",
  identityAProfileId: null as number | null,
  identityBProfileId: null as number | null,
  budgetProfile: "standard" as AssessmentBudgetProfile,
  autonomyMode: "smart" as AssessmentAutonomyMode,
  tlsPolicy: "strict" as "strict" | "ignore_invalid",
  includeRecentTraffic: true,
  writtenAuthorizationConfirmed: false,
});

const identityForm = reactive({
  label: "",
  headerName: "Authorization" as "Authorization" | "Cookie" | "X-API-Key" | "X-Auth-Token",
  secret: "",
});

const resourceForm = reactive({
  type: "traffic" as "traffic" | "finding" | "assessment_run",
  sourceId: null as number | null,
});
const trafficResources = ref<TrafficSummary[]>([]);
const findingResources = ref<Finding[]>([]);
const runResources = ref<AssessmentRun[]>([]);

const STATUS_LABEL: Record<AssessmentMissionStatus, string> = {
  draft: "草稿",
  awaiting_context_approval: "等待上下文确认",
  queued: "已入队",
  discovering: "发现攻击面",
  planning: "诊断规划",
  awaiting_action_approval: "等待动作审批",
  executing: "执行探针",
  verifying: "确定性验证",
  awaiting_manual_handoff: "等待人工接力",
  completed: "已完成",
  stopped: "已停止",
  cancelled: "已取消",
  failed: "失败",
  interrupted: "中断",
};

const STATUS_TAG: Record<AssessmentMissionStatus, TagType> = {
  draft: "info",
  awaiting_context_approval: "warning",
  queued: "info",
  discovering: "primary",
  planning: "primary",
  awaiting_action_approval: "warning",
  executing: "warning",
  verifying: "warning",
  awaiting_manual_handoff: "warning",
  completed: "success",
  stopped: "info",
  cancelled: "info",
  failed: "danger",
  interrupted: "warning",
};

const ACTIVE_STATUSES = new Set<AssessmentMissionStatus>([
  "queued",
  "discovering",
  "planning",
  "executing",
  "verifying",
]);
const TERMINAL_STATUSES = new Set<AssessmentMissionStatus>([
  "completed",
  "stopped",
  "cancelled",
  "failed",
  "interrupted",
]);

const BUDGETS: Array<{
  key: AssessmentBudgetProfile;
  name: string;
  requests: number;
  cycles: number;
  description: string;
}> = [
  { key: "quick", name: "快速模式", requests: 40, cycles: 2, description: "验证主要入口与低风险基线" },
  { key: "standard", name: "标准模式", requests: 120, cycles: 4, description: "默认平衡覆盖与目标负载" },
  { key: "deep", name: "深入模式", requests: 300, cycles: 6, description: "扩大 Surface 覆盖，仍保持串行" },
];

const canStart = computed(
  () =>
    detail.value?.mission.status === "queued" &&
    missions.pendingActions.length === 0 &&
    missions.context?.approved === true
);
const isActive = computed(() =>
  selectedMission.value ? ACTIVE_STATUSES.has(selectedMission.value.status) : false
);
const canStop = computed(
  () => selectedMission.value && !selectedMission.value.legacy && !TERMINAL_STATUSES.has(selectedMission.value.status)
);
const contextJson = computed(() =>
  JSON.stringify(missions.context?.contextSummary ?? {}, null, 2)
);
const eventAnnouncement = computed(() => missions.lastEvent?.message ?? "");

watch(
  projectId,
  async (id) => {
    invalidateReport();
    missions.activateProject(id);
    creating.value = false;
    if (id === null) return;
    seedStartUrl();
    try {
      await missions.refresh(id);
      creating.value = missions.missions.length === 0;
      if (missions.context?.requiresApproval) contextDialogVisible.value = true;
    } catch (error) {
      ElMessage.error(String(error));
      creating.value = missions.missions.length === 0;
    }
  },
  { immediate: true }
);

watch(
  () => missions.selectedMissionId,
  (missionId) => {
    if (reportVisible.value && missionId !== reportMissionId.value) {
      invalidateReport();
    }
  }
);

onMounted(async () => {
  try {
    await missions.bindEvents();
  } catch (error) {
    ElMessage.warning(`任务事件通道不可用，可使用刷新恢复：${String(error)}`);
  }
});

onUnmounted(() => {
  invalidateReport();
  void missions.unbindEvents();
});

function seedStartUrl() {
  const target = project.current?.target_host.trim() ?? "";
  createForm.startUrl = !target
    ? ""
    : /^https?:\/\//i.test(target)
      ? target
      : `https://${target}/`;
}

function resetComposer() {
  createForm.title = "";
  createForm.goal = "";
  createForm.excludedPaths = "";
  createForm.identityAProfileId = null;
  createForm.identityBProfileId = null;
  createForm.budgetProfile = "standard";
  createForm.autonomyMode = "smart";
  createForm.tlsPolicy = "strict";
  createForm.includeRecentTraffic = true;
  createForm.writtenAuthorizationConfirmed = false;
  seedStartUrl();
}

async function selectEmptyProject() {
  if (emptyProjectChoice.value === null) return;
  await project.select(emptyProjectChoice.value);
}

async function refresh() {
  if (projectId.value === null) return;
  try {
    await missions.refresh(projectId.value);
  } catch (error) {
    ElMessage.error(String(error));
  }
}

async function createMission() {
  if (projectId.value === null) return;
  if (!createForm.goal.trim() || !createForm.startUrl.trim()) {
    ElMessage.warning("请填写评估目标和起始 URL");
    return;
  }
  if (!createForm.writtenAuthorizationConfirmed) {
    ElMessage.warning("请确认已获得书面授权声明");
    return;
  }

  const excluded = createForm.excludedPaths
    .split("\n")
    .map((item) => item.trim())
    .filter(Boolean);

  try {
    await missions.create({
      projectId: projectId.value,
      title: createForm.title.trim() || undefined,
      goal: createForm.goal.trim(),
      startUrl: createForm.startUrl.trim(),
      excludedPaths: excluded,
      identityAProfileId: createForm.identityAProfileId,
      identityBProfileId: createForm.identityBProfileId,
      budgetProfile: createForm.budgetProfile,
      autonomyMode: createForm.autonomyMode,
      tlsPolicy: createForm.tlsPolicy,
      includeRecentTraffic: createForm.includeRecentTraffic,
      writtenAuthorizationConfirmed: true,
    });
    creating.value = false;
    resetComposer();
    if (missions.context?.requiresApproval) contextDialogVisible.value = true;
    ElMessage.success("评估任务已创建；请先审查 AI 上下文披露");
  } catch (error) {
    ElMessage.error(String(error));
  }
}

async function confirmContext() {
  if (!missions.context) return;
  try {
    await missions.confirmContext();
    contextDialogVisible.value = false;
    ElMessage.success("上下文已确认；后端正在规划安全动作");
  } catch (error) {
    ElMessage.error(String(error));
  }
}

async function startMission() {
  try {
    await missions.start();
    ElMessage.success("评估引擎已启动");
  } catch (error) {
    ElMessage.error(String(error));
  }
}

async function stopMission() {
  try {
    await ElMessageBox.confirm("确定安全停止当前任务？当前正在进行的单个请求会安全结束，后续计划不会执行。", "停止评估任务", {
      confirmButtonText: "停止",
      cancelButtonText: "继续运行",
      type: "warning",
    });
    await missions.stop();
    ElMessage.info("评估已安全停止");
  } catch (error) {
    if (error !== "cancel") ElMessage.error(String(error));
  }
}

async function decide(action: AssessmentAction, approve: boolean, rememberForTool = false) {
  try {
    await missions.decide(action, approve, rememberForTool);
    ElMessage.success(approve ? "已批准执行该动作" : "已拒绝该动作");
  } catch (error) {
    ElMessage.error(String(error));
  }
}

async function sendFollowUp() {
  if (!followUp.value.trim()) return;
  followUpSending.value = true;
  try {
    await missions.sendMessage(followUp.value.trim());
    followUp.value = "";
    ElMessage.success("引导提示已进入执行队列");
  } catch (error) {
    ElMessage.error(String(error));
  } finally {
    followUpSending.value = false;
  }
}

async function openResourceDialog() {
  if (projectId.value === null) return;
  resourceDialogVisible.value = true;
  resourceLoading.value = true;
  resourceForm.sourceId = null;
  try {
    [trafficResources.value, findingResources.value, runResources.value] = await Promise.all([
      listTraffic(projectId.value, { limit: 100 }),
      listFindings(projectId.value),
      listAssessmentRuns(projectId.value),
    ]);
  } catch (error) {
    ElMessage.error(String(error));
  } finally {
    resourceLoading.value = false;
  }
}

async function attachResource() {
  if (resourceForm.sourceId === null) {
    ElMessage.warning("请选择一个同项目资源");
    return;
  }
  try {
    await missions.attachResource(resourceForm.type, resourceForm.sourceId);
    resourceDialogVisible.value = false;
    contextDialogVisible.value = true;
    ElMessage.success("资源摘要已冻结并加入上下文");
  } catch (error) {
    ElMessage.error(String(error));
  }
}

async function importOpenApi() {
  try {
    if (await missions.importOpenApi()) {
      contextDialogVisible.value = true;
      ElMessage.success("已导入有界 OpenAPI 结构摘要");
    }
  } catch (error) {
    ElMessage.error(String(error));
  }
}

async function createIdentity() {
  if (projectId.value === null || !identityForm.label.trim() || !identityForm.secret.trim()) {
    ElMessage.warning("请填写身份名称和凭据值");
    return;
  }
  identitySaving.value = true;
  try {
    await createAssessmentAuthProfile({
      projectId: projectId.value,
      label: identityForm.label.trim(),
      headerName: identityForm.headerName,
      secret: identityForm.secret,
      sourceTrafficId: null,
    });
    identityForm.label = "";
    identityForm.secret = "";
    await missions.refresh(projectId.value);
    identityDialogVisible.value = false;
    ElMessage.success("身份已保存到系统凭据库");
  } catch (error) {
    ElMessage.error(String(error));
  } finally {
    identityForm.secret = "";
    identitySaving.value = false;
  }
}

async function updatePermission(toolId: string, decision: "disabled" | "ask" | "execute") {
  try {
    await missions.setPermission(toolId, decision);
    if (missions.context?.requiresApproval) contextDialogVisible.value = true;
    ElMessage.success("项目级工具权限已更新");
  } catch (error) {
    ElMessage.error(String(error));
    await refresh();
  }
}

function openActionDetails(action: AssessmentAction) {
  selectedAction.value = action;
  actionDrawerVisible.value = true;
}

function handoffFor(actionId: number) {
  return detail.value?.handoffs.find((handoff) => handoff.actionId === actionId) ?? null;
}

async function createHandoff(action: AssessmentAction) {
  try {
    const handoff = await missions.createHandoff(action);
    ElMessage.success("人工 Repeater 会话已创建并选中；草稿尚未发送");
    selectedHandoff.value = handoff;
    await router.push("/repeater");
  } catch (error) {
    ElMessage.error(String(error));
  }
}

function openHandoffLink(handoff: AssessmentManualHandoff) {
  selectedHandoff.value = handoff;
  handoffReplayRunId.value = null;
  handoffDialogVisible.value = true;
}

async function linkHandoff() {
  if (!selectedHandoff.value || handoffReplayRunId.value === null) {
    ElMessage.warning("请输入在该人工会话中发送得到的 ReplayRun ID");
    return;
  }
  try {
    await missions.linkHandoff(selectedHandoff.value.id, handoffReplayRunId.value);
    handoffDialogVisible.value = false;
    ElMessage.success("结果已回传为默认未接受的 Evidence");
  } catch (error) {
    ElMessage.error(String(error));
  }
}

async function previewReport() {
  const current = detail.value;
  if (!current) return;
  const projectId = current.mission.projectId;
  const missionId = current.mission.id;
  const generation = ++reportGeneration;
  reportExportGeneration += 1;
  reportProjectId.value = projectId;
  reportMissionId.value = missionId;
  reportMarkdown.value = "";
  reportVisible.value = true;
  reportLoading.value = true;
  reportExporting.value = false;
  try {
    const markdown = await buildAssessmentMissionReport(projectId, missionId);
    if (
      generation === reportGeneration &&
      reportVisible.value &&
      detail.value?.mission.projectId === projectId &&
      detail.value?.mission.id === missionId
    ) {
      reportMarkdown.value = markdown;
    }
  } catch (error) {
    if (
      generation === reportGeneration &&
      reportVisible.value &&
      detail.value?.mission.projectId === projectId &&
      detail.value?.mission.id === missionId
    ) {
      reportMarkdown.value = `报告生成失败：${String(error)}`;
    }
  } finally {
    if (generation === reportGeneration) reportLoading.value = false;
  }
}

async function exportMissionReport() {
  const projectId = reportProjectId.value;
  const missionId = reportMissionId.value;
  if (
    projectId === null ||
    missionId === null ||
    detail.value?.mission.projectId !== projectId ||
    detail.value?.mission.id !== missionId
  ) {
    return;
  }
  const generation = ++reportExportGeneration;
  reportExporting.value = true;
  try {
    const result = await exportAssessmentMissionReport(projectId, missionId);
    if (
      generation === reportExportGeneration &&
      reportVisible.value &&
      reportProjectId.value === projectId &&
      reportMissionId.value === missionId
    ) {
      ElMessage.success(`Report v4 已导出：${result.markdown_path}`);
    }
  } catch (error) {
    if (generation === reportExportGeneration) ElMessage.error(String(error));
  } finally {
    if (generation === reportExportGeneration) reportExporting.value = false;
  }
}

function invalidateReport(close = true) {
  reportGeneration += 1;
  reportExportGeneration += 1;
  reportLoading.value = false;
  reportExporting.value = false;
  reportMarkdown.value = "";
  reportProjectId.value = null;
  reportMissionId.value = null;
  if (close) reportVisible.value = false;
}

function selectMission(missionId: number) {
  invalidateReport();
  creating.value = false;
  void missions.selectMission(missionId).catch((error) => ElMessage.error(String(error)));
}

function formatTime(value: string | null | undefined) {
  if (!value) return "—";
  const parsed = new Date(value.replace(" ", "T"));
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString("zh-CN", { hour12: false });
}

function shortHash(value: string | null | undefined) {
  return value ? `${value.slice(0, 10)}…${value.slice(-6)}` : "—";
}

function pretty(value: unknown) {
  return value === null || value === undefined ? "—" : JSON.stringify(value, null, 2);
}

function actionToolLabel(action: AssessmentAction) {
  return missions.context?.tools.find((tool) => tool.id === action.toolId)?.displayName ?? action.toolId;
}

function workstreamTitle(workstreamId: number | null) {
  return detail.value?.workstreams.find((item) => item.id === workstreamId)?.title ?? "未归类工作流";
}

function riskType(risk: string): TagType {
  if (risk === "manual") return "danger";
  if (risk === "guarded") return "warning";
  if (risk === "low") return "primary";
  return "info";
}

function resultLabel(action: AssessmentAction) {
  if (action.status === "awaiting_approval") return "等待批准";
  if (action.executionKind === "manual_recipe" && action.status === "queued") return "已批准 · 等待选择";
  if (action.status === "manual_ready") return "等待人工发送";
  if (action.status === "manual_result_pending") return "Evidence 待复核";
  if (action.status === "completed") return "已完成";
  if (action.status === "rejected") return "已拒绝 · 零请求";
  return action.status;
}
</script>

<template>
  <div class="assessment-page">
    <PageHeader
      title="AI 自动化安全评估引擎"
      description="目标驱动地发现、规划、审批、验证并沉淀证据；严格单并发、2 RPS 与 Rust 后端 Scope 约束。"
    >
      <template v-if="project.current">
        <el-button :icon="Refresh" circle aria-label="刷新任务" :loading="missions.loading" @click="refresh" />
        <el-button class="inspector-trigger" :icon="Setting" @click="inspectorDrawerVisible = true">边界与覆盖</el-button>
        <el-button type="primary" :icon="Plus" @click="resetComposer(); creating = true">新评估任务</el-button>
      </template>
    </PageHeader>

    <div class="sr-live" aria-live="polite">{{ eventAnnouncement }}</div>

    <section v-if="!project.current" class="project-empty-shell">
      <EmptyState
        centered
        title="选择已授权项目以启动评估"
        description="评估任务绑定后端 Scope、AI 供应商、身份凭据与书面授权。未选择项目时不会执行任何请求。"
      >
        <template #icon><FolderOpened :size="24" /></template>
        <template #action>
          <div class="project-actions">
            <el-select v-model="emptyProjectChoice" placeholder="选择已有项目" aria-label="选择已有项目">
              <el-option v-for="item in project.projects" :key="item.id" :label="item.name" :value="item.id" />
            </el-select>
            <el-button type="primary" :disabled="emptyProjectChoice === null" @click="selectEmptyProject">进入项目</el-button>
            <el-button :icon="Plus" @click="createProjectVisible = true">创建新项目</el-button>
          </div>
        </template>
      </EmptyState>
    </section>

    <div v-else class="mission-layout">
      <!-- 任务历史与工作流左侧栏 -->
      <aside class="mission-sidebar" aria-label="评估任务历史">
        <div class="sidebar-heading">
          <div class="sidebar-project-info">
            <small class="project-tag">{{ project.current.name }}</small>
            <strong class="sidebar-title">任务记录</strong>
          </div>
          <button type="button" class="icon-add-btn" title="创建新任务" @click="resetComposer(); creating = true">
            <el-icon :size="13"><Plus /></el-icon>
          </button>
        </div>

        <div class="mission-list">
          <button
            v-for="mission in missions.missions"
            :key="mission.id"
            type="button"
            class="mission-item"
            :class="{ active: mission.id === missions.selectedMissionId && !creating }"
            @click="selectMission(mission.id)"
          >
            <div class="mission-item-top">
              <strong class="item-title">{{ mission.title }}</strong>
              <el-tag size="small" :type="STATUS_TAG[mission.status]">{{ STATUS_LABEL[mission.status] }}</el-tag>
            </div>
            <span class="mission-goal">{{ mission.goal }}</span>
            <div class="mission-meta">
              <span>#{{ mission.id }}{{ mission.legacy ? " · legacy" : "" }}</span>
              <time>{{ formatTime(mission.updatedAt) }}</time>
            </div>
          </button>
          <div v-if="missions.missions.length === 0" class="sidebar-empty">暂无评估任务</div>
        </div>

        <div v-if="detail && !creating" class="workflow-list">
          <header class="workflow-header">执行逻辑工作流</header>
          <div v-for="stream in detail.workstreams" :key="stream.id" class="workflow-row">
            <span class="workflow-dot" :data-status="stream.status" />
            <div class="workflow-content">
              <strong>{{ stream.title }}</strong>
              <small>{{ stream.objective }}</small>
            </div>
          </div>
          <div v-if="detail.workstreams.length === 0" class="sidebar-empty">
            {{ detail.mission.legacy ? "旧运行不激活 task_nodes" : "确认上下文后生成工作流" }}
          </div>
        </div>
      </aside>

      <!-- 任务主控台 -->
      <main class="mission-main" :class="{ 'mission-main--creating': creating }">
        <!-- 创建任务视图 -->
        <section v-if="creating" class="composer-card">
          <header class="composer-heading">
            <div>
              <span class="eyebrow">NEW MISSION</span>
              <h2>设定安全测试目标</h2>
              <p>评估引擎会将目标自动分解为严格受控的工作流，模型仅能调用预注册 ToolSpec 与已知 Surface。</p>
            </div>
            <el-button v-if="missions.missions.length" text :icon="Close" @click="creating = false">取消</el-button>
          </header>

          <el-form label-position="top" class="mission-form">
            <div class="form-grid two">
              <el-form-item label="任务标题（可选）">
                <el-input v-model="createForm.title" maxlength="160" placeholder="例如：订单接口水平越权边界诊断" />
              </el-form-item>
              <el-form-item label="起始 URL" required>
                <el-input v-model="createForm.startUrl" placeholder="https://target.example/" />
              </el-form-item>
            </div>

            <el-form-item label="评估目标与问题假设" required>
              <el-input
                v-model="createForm.goal"
                type="textarea"
                :rows="4"
                maxlength="4000"
                show-word-limit
                placeholder="描述业务范围、希望验证的安全假设以及严格排除项。例：检查 /api/v1/orders 接口的只读授权边界、CORS 配置与参数枚举风险，对破坏性操作只生成 Repeater 配方。"
              />
            </el-form-item>

            <div class="form-grid two">
              <el-form-item label="身份 A（测试主体）">
                <el-select v-model="createForm.identityAProfileId" clearable placeholder="匿名或选择凭据 A">
                  <el-option v-for="profile in missions.profiles" :key="profile.id" :label="profile.label" :value="profile.id" />
                </el-select>
              </el-form-item>
              <el-form-item label="身份 B（对比主体）">
                <el-select v-model="createForm.identityBProfileId" clearable placeholder="可选，用于越权 A/B 比对">
                  <el-option v-for="profile in missions.profiles" :key="profile.id" :label="profile.label" :value="profile.id" />
                </el-select>
              </el-form-item>
            </div>

            <div class="identity-action-bar">
              <el-button text :icon="Key" class="identity-link" @click="identityDialogVisible = true">新建凭据身份</el-button>
            </div>

            <label class="field-label">评估预算档位</label>
            <div class="budget-options">
              <label
                v-for="budget in BUDGETS"
                :key="budget.key"
                :class="{ selected: createForm.budgetProfile === budget.key }"
              >
                <input v-model="createForm.budgetProfile" type="radio" :value="budget.key" />
                <div class="budget-header">
                  <strong>{{ budget.name }}</strong>
                  <span class="budget-quota">{{ budget.requests }} 请求 · {{ budget.cycles }} 轮</span>
                </div>
                <small>{{ budget.description }}</small>
              </label>
            </div>

            <div class="form-grid two compact-grid">
              <el-form-item label="自主控制模式">
                <el-radio-group v-model="createForm.autonomyMode">
                  <el-radio-button value="manual">手动审批</el-radio-button>
                  <el-radio-button value="smart">智能放行（推荐）</el-radio-button>
                  <el-radio-button value="automatic">完全自动</el-radio-button>
                </el-radio-group>
              </el-form-item>
              <el-form-item label="TLS 策略">
                <el-select v-model="createForm.tlsPolicy">
                  <el-option label="严格校验证书" value="strict" />
                  <el-option label="忽略无效证书（靶场环境）" value="ignore_invalid" />
                </el-select>
              </el-form-item>
            </div>

            <el-form-item label="排除路径（黑名单）">
              <el-input v-model="createForm.excludedPaths" type="textarea" :rows="2" placeholder="每行一个路径，例：/logout、/delete_account" />
            </el-form-item>

            <div class="composer-checks">
              <el-checkbox v-model="createForm.includeRecentTraffic">将同项目近期捕获的 Traffic 作为只读发现种子</el-checkbox>
              <el-checkbox v-model="createForm.writtenAuthorizationConfirmed">我确认已获得对目标系统进行安全评估的合法授权</el-checkbox>
            </div>

            <footer class="composer-footer">
              <span class="footer-note">硬上限约束：2 RPS、单并发、目标 Host 精确 Scope。</span>
              <el-button type="primary" :icon="Aim" :loading="missions.mutating" @click="createMission">
                创建任务并审查上下文
              </el-button>
            </footer>
          </el-form>
        </section>

        <!-- 空状态 -->
        <EmptyState v-else-if="!detail" centered title="选择或创建一个安全评估任务" description="任务历史、审批决策与证据链均持久化保存。">
          <template #icon><Aim :size="24" /></template>
          <template #action>
            <el-button type="primary" :icon="Plus" @click="resetComposer(); creating = true">创建评估任务</el-button>
          </template>
        </EmptyState>

        <!-- 任务工作台流水线 -->
        <template v-else>
          <!-- 任务 Hero 诊断条 -->
          <section class="mission-hero">
            <div class="mission-title-row">
              <div class="title-meta">
                <span class="eyebrow">MISSION #{{ detail.mission.id }}</span>
                <h2>{{ detail.mission.title }}</h2>
              </div>
              <el-tag :type="STATUS_TAG[detail.mission.status]" size="large">{{ STATUS_LABEL[detail.mission.status] }}</el-tag>
            </div>

            <p class="goal-copy">{{ detail.mission.goal }}</p>

            <div class="mission-command-row">
              <div class="mission-facts">
                <span class="fact-chip">Origin: {{ detail.mission.exactOrigin }}</span>
                <span class="fact-chip">模式: {{ detail.mission.autonomyMode }}</span>
                <span class="fact-chip">预算: {{ detail.mission.budgetProfile }}</span>
              </div>
              <div class="mission-buttons">
                <el-button :icon="Document" @click="previewReport">证据报告</el-button>
                <el-button v-if="canStop" :icon="VideoPause" :loading="missions.mutating" @click="stopMission">安全停止</el-button>
                <el-button v-if="!detail.mission.legacy" type="primary" :icon="VideoPlay" :disabled="!canStart" :loading="missions.mutating" @click="startMission">
                  启动 / 恢复执行
                </el-button>
              </div>
            </div>

            <el-progress
              v-if="isActive"
              :percentage="Math.min(100, Math.round((detail.mission.requestCount / Math.max(1, detail.mission.requestBudget)) * 100))"
              :stroke-width="3"
              :show-text="false"
              class="hero-progress"
            />
          </section>

          <!-- 审批横幅 -->
          <el-alert v-if="detail.mission.legacy" class="mission-alert" type="info" :closable="false" show-icon title="这是旧版 Phase 6 运行：仅支持只读查看与 legacy 报告，不会重新激活旧 task_nodes。" />

          <section v-else-if="missions.context?.requiresApproval" class="approval-banner">
            <div class="approval-info">
              <el-icon :size="18"><Warning /></el-icon>
              <div>
                <strong>需要确认 AI 上下文披露</strong>
                <small>目标附件或工具权限变更后，模型将在确认披露后才接收上下文。</small>
              </div>
            </div>
            <el-button type="warning" @click="contextDialogVisible = true">审查披露清单并确认</el-button>
          </section>

          <!-- 诊断流水线执行记录 (Trace Console) -->
          <section class="trace-console" aria-label="诊断执行轨迹">
            <header class="trace-header">
              <span class="eyebrow">EXECUTION TRACE</span>
              <span class="trace-meta">{{ detail.messages.length }} 条事件</span>
            </header>
            <div class="trace-feed">
              <div v-for="message in detail.messages" :key="message.id" class="trace-row" :data-role="message.role">
                <span class="trace-tag" :class="`trace-tag--${message.role}`">
                  {{ message.messageKind === "goal" ? "GOAL" : message.messageKind === "follow_up" ? "GUIDE" : message.role.toUpperCase() }}
                </span>
                <div class="trace-body">
                  <div class="trace-time">{{ formatTime(message.createdAt) }}</div>
                  <div class="trace-text">{{ message.content }}</div>
                  <div v-if="message.redactionManifest.length" class="trace-redacted">
                    脱敏项: {{ message.redactionManifest.join("、") }}
                  </div>
                </div>
              </div>
            </div>
          </section>

          <!-- 可信工具调用与动作列表 -->
          <section v-if="!detail.mission.legacy" class="action-timeline" aria-label="可信工具动作">
            <header class="timeline-heading">
              <div>
                <span class="eyebrow">TRUSTED TOOL ACTIONS</span>
                <h3>执行动作与验证链</h3>
              </div>
              <span class="action-count">{{ detail.actions.length }} 个动作 · {{ missions.pendingActions.length }} 个待审批</span>
            </header>

            <article
              v-for="action in detail.actions"
              :key="action.id"
              class="action-card"
              :class="{ pending: action.approvalStatus === 'pending', manual: action.executionKind === 'manual_recipe' }"
            >
              <header class="action-header">
                <div class="action-name">
                  <span class="action-index">#{{ action.id }}</span>
                  <div>
                    <strong class="action-title">{{ actionToolLabel(action) }}</strong>
                    <span class="action-sub">{{ workstreamTitle(action.workstreamId) }} · {{ action.toolId }}@{{ action.toolVersion }}</span>
                  </div>
                </div>
                <div class="action-tags">
                  <el-tag size="small" :type="riskType(action.riskLevel)">{{ action.riskLevel }}</el-tag>
                  <el-tag size="small" type="info">{{ resultLabel(action) }}</el-tag>
                </div>
              </header>

              <div class="action-explanation">
                <div class="rationale-box">
                  <small>执行理由</small>
                  <p>{{ action.rationale }}</p>
                </div>
                <div class="signal-box">
                  <small>预期观察信号</small>
                  <p>{{ action.expectedSignal || "等待确定性执行器记录预期信号" }}</p>
                </div>
              </div>

              <div class="action-meta">
                <span>后端工具: {{ action.toolId }}</span>
                <span>审批来源: {{ action.approvalSource || action.permissionSnapshot }}</span>
                <span>身份: {{ action.identityMode }}</span>
                <span>开销: {{ action.requestCost }} 请求</span>
              </div>

              <el-alert v-if="action.executionKind === 'manual_recipe'" type="warning" :closable="false" show-icon title="高风险探针：仅生成 Repeater 差异草稿，必须由测试员在重放模块中人工发送。" class="manual-alert" />

              <footer class="action-footer">
                <el-button text :icon="View" @click="openActionDetails(action)">技术诊断详情</el-button>
                <div v-if="action.approvalStatus === 'pending'" class="approval-buttons">
                  <el-button :loading="missions.mutating" @click="decide(action, false)">拒绝</el-button>
                  <el-button :loading="missions.mutating" @click="decide(action, true, true)">批准同工具</el-button>
                  <el-button type="primary" :loading="missions.mutating" @click="decide(action, true)">批准执行</el-button>
                </div>
                <div v-else-if="action.executionKind === 'manual_recipe' && ['manual_ready', 'manual_result_pending'].includes(action.status)" class="approval-buttons">
                  <el-button v-if="!handoffFor(action.id)" type="warning" @click="createHandoff(action)">创建 Repeater 草稿</el-button>
                  <template v-else>
                    <el-tag type="warning">会话 #{{ handoffFor(action.id)?.replaySessionId }} · 等待发送</el-tag>
                    <el-button v-if="handoffFor(action.id)?.status !== 'result_linked'" @click="openHandoffLink(handoffFor(action.id)!)">回传 ReplayRun</el-button>
                  </template>
                </div>
              </footer>
            </article>

            <div v-if="detail.actions.length === 0" class="timeline-empty">
              确认上下文后，工具动作将按规划顺序在此展示理由、预期信号与审批控制。
            </div>
          </section>

          <!-- 中途引导控制条 -->
          <section v-if="!detail.mission.legacy && !TERMINAL_STATUSES.has(detail.mission.status)" class="followup-box">
            <el-icon class="followup-icon" :size="16"><ChatDotRound /></el-icon>
            <el-input
              v-model="followUp"
              type="textarea"
              :autosize="{ minRows: 1, maxRows: 3 }"
              maxlength="2000"
              placeholder="中途调整目标或提出补充要求；当前单个请求将安全结束，下一个规划周期生效。（Ctrl + Enter 发送）"
              @keydown.ctrl.enter.prevent="sendFollowUp"
            />
            <el-button type="primary" :loading="followUpSending" :disabled="!followUp.trim()" @click="sendFollowUp">
              注入引导
            </el-button>
          </section>
        </template>
      </main>

      <!-- 侧边边界与覆盖检查器 -->
      <MissionInspector
        v-if="detail && !creating"
        class="mission-inspector desktop-inspector"
        :project="project.current"
        :detail="detail"
        :context="missions.context"
        :profiles="missions.profiles"
        :disabled="missions.mutating || detail.mission.legacy"
        @open-context="contextDialogVisible = true"
        @open-resource="openResourceDialog"
        @import-open-api="importOpenApi"
        @open-identity="identityDialogVisible = true"
        @update-permission="updatePermission"
      />
    </div>

    <!-- 移动/窄屏抽屉 -->
    <el-drawer v-model="inspectorDrawerVisible" title="边界、资源与覆盖" direction="rtl" size="360px">
      <MissionInspector
        v-if="detail && project.current"
        :project="project.current"
        :detail="detail"
        :context="missions.context"
        :profiles="missions.profiles"
        :disabled="missions.mutating || detail.mission.legacy"
        @open-context="contextDialogVisible = true"
        @open-resource="openResourceDialog"
        @import-open-api="importOpenApi"
        @open-identity="identityDialogVisible = true"
        @update-permission="updatePermission"
      />
    </el-drawer>

    <!-- 对话框群 -->
    <el-dialog v-model="contextDialogVisible" title="最终 AI 上下文与披露清单" width="min(820px, 92vw)" destroy-on-close>
      <template v-if="missions.context">
        <el-alert :type="missions.context.approved ? 'success' : 'warning'" :closable="false" show-icon :title="missions.context.approved ? '当前上下文已确认' : '确认披露前模型不会接收任何目标上下文'" />
        <div class="context-manifest">
          <strong>披露数据类别</strong>
          <div><el-tag v-for="item in missions.context.disclosureManifest" :key="item" size="small">{{ item }}</el-tag></div>
        </div>
        <details class="context-details" open>
          <summary>脱敏结构摘要</summary>
          <pre>{{ contextJson }}</pre>
        </details>
        <div class="hash-grid">
          <span>context <code>{{ shortHash(missions.context.contextHash) }}</code></span>
          <span>contract <code>{{ shortHash(missions.context.contractHash) }}</code></span>
          <span>registry <code>{{ shortHash(missions.context.toolRegistryHash) }}</code></span>
          <span>permission <code>{{ shortHash(missions.context.permissionHash) }}</code></span>
        </div>
      </template>
      <el-empty v-else description="旧运行无 v2 AI 上下文" />
      <template #footer>
        <el-button @click="contextDialogVisible = false">关闭</el-button>
        <el-button v-if="missions.context?.requiresApproval" type="primary" :loading="missions.mutating" @click="confirmContext">
          确认上下文并生成动作
        </el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="resourceDialogVisible" title="附加同项目资源" width="560px">
      <el-form label-position="top" v-loading="resourceLoading">
        <el-form-item label="资源类型">
          <el-radio-group v-model="resourceForm.type" @change="resourceForm.sourceId = null">
            <el-radio-button value="traffic">Traffic</el-radio-button>
            <el-radio-button value="finding">Finding</el-radio-button>
            <el-radio-button value="assessment_run">历史评估</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="选择资源" required>
          <el-select v-if="resourceForm.type === 'traffic'" v-model="resourceForm.sourceId" filterable placeholder="选择最近 Traffic">
            <el-option v-for="item in trafficResources" :key="item.id" :value="item.id" :label="`#${item.id} · ${item.method} ${item.path} · ${item.status ?? '—'}`" />
          </el-select>
          <el-select v-else-if="resourceForm.type === 'finding'" v-model="resourceForm.sourceId" filterable placeholder="选择 Finding">
            <el-option v-for="item in findingResources" :key="item.id" :value="item.id" :label="`#${item.id} · ${item.title} · ${item.status}`" />
          </el-select>
          <el-select v-else v-model="resourceForm.sourceId" filterable placeholder="选择历史运行">
            <el-option v-for="item in runResources" :key="item.id" :value="item.id" :label="`Run #${item.id} · ${item.status} · ${item.startUrl}`" />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="resourceDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="missions.mutating" @click="attachResource">附加并重新预览</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="identityDialogVisible" title="新建评估身份凭据" width="480px" destroy-on-close>
      <el-alert type="warning" :closable="false" title="凭据真实值只写入系统凭据库，不进入 SQLite、事件、报告或 AI 上下文。" />
      <el-form label-position="top" class="identity-form">
        <el-form-item label="身份名称" required>
          <el-input v-model="identityForm.label" maxlength="80" placeholder="例如：测试用户 A" />
        </el-form-item>
        <el-form-item label="Header 字段">
          <el-select v-model="identityForm.headerName">
            <el-option label="Authorization" value="Authorization" />
            <el-option label="Cookie" value="Cookie" />
            <el-option label="X-API-Key" value="X-API-Key" />
            <el-option label="X-Auth-Token" value="X-Auth-Token" />
          </el-select>
        </el-form-item>
        <el-form-item label="凭据真实值" required>
          <el-input v-model="identityForm.secret" type="password" show-password autocomplete="off" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="identityDialogVisible = false; identityForm.secret = ''">取消</el-button>
        <el-button type="primary" :loading="identitySaving" @click="createIdentity">保存到凭据库</el-button>
      </template>
    </el-dialog>

    <el-drawer v-model="actionDrawerVisible" title="动作技术详情" size="min(600px, 92vw)">
      <template v-if="selectedAction">
        <el-descriptions :column="1" border>
          <el-descriptions-item label="工具">{{ selectedAction.toolId }}@{{ selectedAction.toolVersion }}</el-descriptions-item>
          <el-descriptions-item label="Surface">{{ selectedAction.surfaceId ?? "后端发现后绑定" }}</el-descriptions-item>
          <el-descriptions-item label="风险 / 权限">{{ selectedAction.riskLevel }} / {{ selectedAction.permissionSnapshot }} / {{ selectedAction.approvalSource }}</el-descriptions-item>
          <el-descriptions-item label="策略结果">{{ selectedAction.policyReason || selectedAction.status }}</el-descriptions-item>
          <el-descriptions-item label="Request Hash">{{ selectedAction.requestHash ?? "—" }}</el-descriptions-item>
          <el-descriptions-item label="Response Hash">{{ selectedAction.responseHash ?? "—" }}</el-descriptions-item>
        </el-descriptions>
        <section class="technical-block"><h4>参数（仅已知参数名）</h4><pre>{{ pretty(selectedAction.parameters) }}</pre></section>
        <section class="technical-block"><h4>脱敏请求</h4><pre>{{ pretty(selectedAction.redactedRequest) }}</pre></section>
        <section class="technical-block"><h4>脱敏响应</h4><pre>{{ pretty(selectedAction.redactedResponse) }}</pre></section>
        <section class="technical-block"><h4>确定性验证结果</h4><pre>{{ pretty(selectedAction.result) }}</pre></section>
      </template>
    </el-drawer>

    <el-dialog v-model="handoffDialogVisible" title="回传人工 ReplayRun" width="480px">
      <el-alert type="warning" :closable="false" show-icon title="只接受同项目、同 handoff 人工会话的 ReplayRun；Evidence 默认未接受且不会自动确认 Finding。" />
      <el-form label-position="top">
        <el-form-item label="ReplayRun ID" required>
          <el-input-number v-model="handoffReplayRunId" :min="1" :step="1" controls-position="right" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="handoffDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="missions.mutating" @click="linkHandoff">回传为待复核 Evidence</el-button>
      </template>
    </el-dialog>

    <el-dialog
      v-model="reportVisible"
      title="证据化安全报告 · Schema v4"
      width="min(880px, 94vw)"
      @close="invalidateReport(false)"
    >
      <div v-loading="reportLoading" class="report-preview">
        <pre>{{ reportMarkdown }}</pre>
      </div>
      <template #footer>
        <el-button @click="reportVisible = false">关闭</el-button>
        <el-button
          type="primary"
          :loading="reportExporting"
          :disabled="reportLoading || reportMissionId === null"
          @click="exportMissionReport"
        >导出 Markdown + JSON</el-button>
      </template>
    </el-dialog>

    <ProjectCreateDialog v-model="createProjectVisible" />
  </div>
</template>

<style scoped>
.assessment-page {
  display: flex;
  height: 100%;
  min-height: 0;
  flex-direction: column;
  gap: var(--rf-space-3);
  overflow: hidden;
}

.sr-live {
  position: absolute;
  width: 1px;
  height: 1px;
  clip: rect(0, 0, 0, 0);
  overflow: hidden;
}

.project-empty-shell {
  display: flex;
  flex: 1;
  min-height: 0;
}

.project-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}

.project-actions :deep(.el-select) {
  width: 200px;
}

.mission-layout {
  display: grid;
  min-height: 0;
  flex: 1;
  grid-template-columns: 240px minmax(400px, 1fr) 290px;
  overflow: hidden;
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-card);
  background: var(--rf-bg-panel);
  box-shadow: var(--rf-shadow-light);
}

/* 侧边栏 */
.mission-sidebar {
  display: flex;
  min-height: 0;
  flex-direction: column;
  border-right: 1px solid var(--rf-border);
  background: var(--rf-bg-panel);
}

.sidebar-heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: var(--rf-space-3);
  border-bottom: 1px solid var(--rf-border);
}

.sidebar-project-info {
  display: grid;
  gap: 1px;
}

.project-tag {
  color: var(--rf-accent);
  font-size: 10px;
  font-family: var(--rf-font-mono);
  text-transform: uppercase;
}

.sidebar-title {
  color: var(--rf-text);
  font-size: 12.5px;
  font-weight: 600;
}

.icon-add-btn {
  width: 24px;
  height: 24px;
  border: 1px solid var(--rf-border);
  border-radius: 4px;
  background: var(--rf-bg-raised);
  color: var(--rf-text-secondary);
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  transition: all var(--rf-duration) var(--rf-ease);
}

.icon-add-btn:hover {
  background: var(--rf-accent-muted);
  border-color: var(--rf-accent);
  color: var(--rf-accent);
}

.mission-list {
  display: grid;
  gap: 4px;
  max-height: 50%;
  padding: 6px;
  overflow-y: auto;
}

.mission-item {
  display: grid;
  gap: 4px;
  width: 100%;
  padding: 8px 10px;
  border: 1px solid transparent;
  border-radius: var(--rf-radius-control);
  background: transparent;
  color: inherit;
  text-align: left;
  cursor: pointer;
  transition: all var(--rf-duration) var(--rf-ease);
}

.mission-item:hover {
  background: var(--rf-bg-hover);
}

.mission-item.active {
  border-color: var(--rf-accent);
  background: var(--rf-accent-muted);
}

.mission-item-top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 6px;
}

.item-title {
  color: var(--rf-text);
  font-size: 11.5px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.mission-goal {
  color: var(--rf-text-secondary);
  font-size: 11px;
  line-height: 1.4;
  overflow: hidden;
  display: -webkit-box;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
}

.mission-meta {
  display: flex;
  justify-content: space-between;
  color: var(--rf-text-muted);
  font-size: 9.5px;
  font-family: var(--rf-font-mono);
}

.sidebar-empty {
  padding: 14px;
  color: var(--rf-text-muted);
  font-size: 11px;
  text-align: center;
}

.workflow-list {
  min-height: 0;
  flex: 1;
  padding: var(--rf-space-3);
  overflow-y: auto;
  border-top: 1px solid var(--rf-border);
}

.workflow-header {
  margin-bottom: 8px;
  color: var(--rf-text-muted);
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

.workflow-row {
  position: relative;
  display: grid;
  grid-template-columns: 10px 1fr;
  gap: 8px;
  padding-bottom: 10px;
}

.workflow-row:not(:last-child)::before {
  position: absolute;
  top: 8px;
  bottom: 0;
  left: 4px;
  width: 1px;
  background: var(--rf-border);
  content: "";
}

.workflow-dot {
  z-index: 1;
  width: 8px;
  height: 8px;
  margin-top: 3px;
  border: 2px solid var(--rf-border-strong);
  border-radius: 50%;
  background: var(--rf-bg-panel);
}

.workflow-dot[data-status="completed"] {
  border-color: var(--rf-success);
  background: var(--rf-success);
}

.workflow-dot[data-status="active"] {
  border-color: var(--rf-accent);
  background: var(--rf-accent);
}

.workflow-content { display: grid; gap: 1px; }
.workflow-content strong { color: var(--rf-text); font-size: 11px; font-weight: 600; }
.workflow-content small { color: var(--rf-text-secondary); font-size: 10px; line-height: 1.35; }

/* 主工作区 */
.mission-main {
  min-width: 0;
  min-height: 0;
  padding: var(--rf-space-4);
  overflow-y: auto;
  background: var(--rf-bg-base);
  display: flex;
  flex-direction: column;
  gap: var(--rf-space-3);
}

.mission-main--creating {
  grid-column: 2 / -1;
}

.composer-card {
  padding: var(--rf-space-4);
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-card);
  background: var(--rf-bg-panel);
}

.composer-heading {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  margin-bottom: var(--rf-space-4);
}

.composer-heading h2 {
  margin: 2px 0 0;
  font-size: 16px;
  color: var(--rf-text);
  letter-spacing: -0.01em;
}

.composer-heading p {
  margin: 4px 0 0;
  color: var(--rf-text-secondary);
  font-size: 12px;
  line-height: 1.5;
}

.eyebrow {
  color: var(--rf-accent);
  font-size: 9.5px;
  font-weight: 700;
  letter-spacing: 0.08em;
  font-family: var(--rf-font-mono);
}

.form-grid { display: grid; gap: 10px; }
.form-grid.two { grid-template-columns: repeat(2, minmax(0, 1fr)); }

.identity-action-bar {
  margin-top: -6px;
  margin-bottom: 8px;
}

.identity-link {
  font-size: 11.5px;
  padding: 0;
}

.budget-options {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 8px;
  margin-bottom: 12px;
}

.budget-options label {
  position: relative;
  display: grid;
  gap: 2px;
  padding: 8px 10px;
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-control);
  background: var(--rf-bg-raised);
  cursor: pointer;
  transition: all var(--rf-duration) var(--rf-ease);
}

.budget-options label:hover {
  border-color: var(--rf-border-strong);
}

.budget-options label.selected {
  border-color: var(--rf-accent);
  box-shadow: 0 0 0 1px var(--rf-accent-muted);
  background: var(--rf-bg-panel);
}

.budget-options input { position: absolute; opacity: 0; }

.budget-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.budget-header strong { color: var(--rf-text); font-size: 11.5px; }
.budget-quota { color: var(--rf-accent); font-size: 10px; font-family: var(--rf-font-mono); }
.budget-options small { color: var(--rf-text-muted); font-size: 10px; line-height: 1.35; }

.composer-checks {
  display: grid;
  gap: 4px;
  margin: 6px 0 12px;
}

.composer-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-top: 14px;
  padding-top: 12px;
  border-top: 1px solid var(--rf-border);
}

.footer-note {
  color: var(--rf-text-muted);
  font-size: 11px;
}

/* Mission Hero */
.mission-hero {
  padding: var(--rf-space-3);
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-card);
  background: var(--rf-bg-panel);
}

.mission-title-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.title-meta h2 {
  margin: 2px 0 0;
  font-size: 16px;
  color: var(--rf-text);
}

.goal-copy {
  margin: 8px 0 10px;
  color: var(--rf-text-secondary);
  font-size: 12px;
  line-height: 1.6;
}

.mission-command-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
}

.mission-facts {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.fact-chip {
  padding: 2px 7px;
  border-radius: 4px;
  background: var(--rf-bg-raised);
  border: 1px solid var(--rf-border);
  color: var(--rf-text-secondary);
  font-family: var(--rf-font-mono);
  font-size: 10.5px;
}

.mission-buttons {
  display: flex;
  align-items: center;
  gap: 6px;
}

.hero-progress {
  margin-top: 10px;
}

.approval-banner {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: var(--rf-space-3);
  border: 1px solid rgba(245, 158, 11, 0.3);
  border-radius: var(--rf-radius-card);
  background: rgba(245, 158, 11, 0.08);
}

.approval-info {
  display: flex;
  align-items: center;
  gap: 8px;
  color: var(--rf-warning);
}

.approval-info strong {
  display: block;
  color: var(--rf-text);
  font-size: 12px;
}

.approval-info small {
  color: var(--rf-text-secondary);
  font-size: 11px;
}

/* Trace Console */
.trace-console {
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-card);
  background: var(--rf-bg-panel);
  overflow: hidden;
}

.trace-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 8px 12px;
  background: var(--rf-bg-raised);
  border-bottom: 1px solid var(--rf-border);
}

.trace-meta {
  color: var(--rf-text-muted);
  font-size: 10px;
  font-family: var(--rf-font-mono);
}

.trace-feed {
  display: grid;
  gap: 1px;
  background: var(--rf-border);
  max-height: 280px;
  overflow-y: auto;
}

.trace-row {
  display: grid;
  grid-template-columns: 60px 1fr;
  gap: 8px;
  padding: 8px 12px;
  background: var(--rf-bg-panel);
  font-size: 11.5px;
}

.trace-tag {
  height: 18px;
  padding: 0 4px;
  border-radius: 3px;
  font-family: var(--rf-font-mono);
  font-size: 9.5px;
  font-weight: 700;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--rf-bg-raised);
  color: var(--rf-text-secondary);
}

.trace-tag--user {
  background: var(--rf-accent-muted);
  color: var(--rf-accent);
}

.trace-tag--assistant {
  background: var(--rf-info-muted);
  color: var(--rf-info);
}

.trace-body {
  display: grid;
  gap: 2px;
}

.trace-time {
  color: var(--rf-text-muted);
  font-size: 9.5px;
  font-family: var(--rf-font-mono);
}

.trace-text {
  color: var(--rf-text);
  line-height: 1.5;
  white-space: pre-wrap;
}

.trace-redacted {
  color: var(--rf-warning);
  font-size: 10px;
}

/* Action Timeline */
.action-timeline {
  display: grid;
  gap: 8px;
}

.timeline-heading {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  margin: 4px 0 2px;
}

.timeline-heading h3 {
  margin: 0;
  font-size: 14px;
  color: var(--rf-text);
}

.action-count {
  color: var(--rf-text-muted);
  font-size: 11px;
}

.action-card {
  padding: var(--rf-space-3);
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-card);
  background: var(--rf-bg-panel);
  box-shadow: var(--rf-shadow-light);
}

.action-card.pending {
  border-color: var(--rf-warning);
}

.action-card.manual {
  border-left: 3px solid var(--rf-warning);
}

.action-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
}

.action-name {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
}

.action-index {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 24px;
  height: 24px;
  border-radius: 4px;
  background: var(--rf-bg-raised);
  color: var(--rf-text-muted);
  font-family: var(--rf-font-mono);
  font-size: 10px;
  font-weight: 600;
}

.action-title {
  color: var(--rf-text);
  font-size: 12px;
}

.action-sub {
  display: block;
  color: var(--rf-text-muted);
  font-family: var(--rf-font-mono);
  font-size: 10px;
}

.action-explanation {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 8px;
  margin: 8px 0;
}

.rationale-box,
.signal-box {
  padding: 6px 8px;
  border-radius: var(--rf-radius-control);
  background: var(--rf-bg-raised);
}

.rationale-box small,
.signal-box small {
  color: var(--rf-text-muted);
  font-size: 9.5px;
  text-transform: uppercase;
}

.rationale-box p,
.signal-box p {
  margin: 2px 0 0;
  color: var(--rf-text-secondary);
  font-size: 11px;
  line-height: 1.45;
}

.action-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 4px 12px;
  margin-bottom: 6px;
  color: var(--rf-text-muted);
  font-size: 10px;
}

.manual-alert {
  margin: 6px 0;
}

.action-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-top: 8px;
  padding-top: 6px;
  border-top: 1px solid var(--rf-border);
}

.approval-buttons {
  display: flex;
  align-items: center;
  gap: 6px;
}

.timeline-empty {
  padding: 18px;
  border: 1px dashed var(--rf-border-strong);
  border-radius: var(--rf-radius-card);
  color: var(--rf-text-muted);
  font-size: 11.5px;
  text-align: center;
}

/* Follow-up box */
.followup-box {
  display: grid;
  grid-template-columns: 20px 1fr auto;
  align-items: center;
  gap: 8px;
  padding: 8px;
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-card);
  background: var(--rf-bg-panel);
}

.followup-icon {
  color: var(--rf-accent);
}

.mission-inspector {
  border-left: 1px solid var(--rf-border);
}

.inspector-trigger {
  display: none;
}

.context-manifest {
  display: grid;
  gap: 6px;
  margin: 12px 0;
}

.context-details {
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-control);
  background: var(--rf-bg-raised);
}

.context-details summary {
  padding: 8px 10px;
  color: var(--rf-text-secondary);
  font-size: 11.5px;
  cursor: pointer;
}

.context-details pre,
.technical-block pre,
.report-preview pre {
  margin: 0;
  padding: 10px;
  overflow: auto;
  color: var(--rf-text-secondary);
  font-family: var(--rf-font-mono);
  font-size: 11px;
  line-height: 1.5;
  white-space: pre-wrap;
}

.hash-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 4px;
  margin-top: 8px;
}

.hash-grid span {
  color: var(--rf-text-muted);
  font-size: 10px;
}

.hash-grid code {
  color: var(--rf-text-secondary);
  font-family: var(--rf-font-mono);
}

.technical-block {
  margin-top: 10px;
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-control);
  background: var(--rf-bg-raised);
}

.technical-block h4 {
  margin: 0;
  padding: 8px 10px;
  border-bottom: 1px solid var(--rf-border);
  color: var(--rf-text);
  font-size: 11.5px;
}

.report-preview {
  min-height: 260px;
  max-height: 60vh;
  overflow: auto;
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-control);
  background: var(--rf-bg-raised);
}

@media (max-width: 1200px) {
  .mission-layout { grid-template-columns: 220px minmax(0, 1fr); }
  .desktop-inspector { display: none; }
  .inspector-trigger { display: inline-flex; }
}

@media (max-width: 768px) {
  .mission-layout { display: flex; flex-direction: column; }
  .mission-sidebar { max-height: 240px; border-right: none; border-bottom: 1px solid var(--rf-border); }
  .form-grid.two, .action-explanation, .budget-options { grid-template-columns: 1fr; }
}
</style>
