<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref, watch } from "vue";
import { useRouter } from "vue-router";
import { ElMessage, ElMessageBox } from "element-plus";
import {
  Aim,
  ChatDotRound,
  CircleCheck,
  Close,
  Connection,
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
  queued: "已进入队列",
  discovering: "发现攻击面",
  planning: "AI 规划",
  awaiting_action_approval: "等待动作审批",
  executing: "执行工具",
  verifying: "确定性验证",
  awaiting_manual_handoff: "等待人工接力",
  completed: "已完成",
  stopped: "已停止",
  cancelled: "已取消",
  failed: "失败",
  interrupted: "应用中断",
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
  { key: "quick", name: "快速", requests: 40, cycles: 2, description: "验证主要入口与低风险基线" },
  { key: "standard", name: "标准", requests: 120, cycles: 4, description: "默认，平衡覆盖与目标负载" },
  { key: "deep", name: "深入", requests: 300, cycles: 6, description: "扩大 surface 覆盖，仍保持串行" },
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

onMounted(async () => {
  try {
    await missions.bindEvents();
  } catch (error) {
    ElMessage.warning(`任务事件通道不可用，可使用刷新恢复：${String(error)}`);
  }
});

onUnmounted(() => void missions.unbindEvents());

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
    ElMessage.warning("请确认已获得目标系统的书面授权");
    return;
  }
  if (
    createForm.identityAProfileId !== null &&
    createForm.identityAProfileId === createForm.identityBProfileId
  ) {
    ElMessage.warning("身份 A 与身份 B 不能使用同一凭据");
    return;
  }
  try {
    await missions.create({
      projectId: projectId.value,
      title: createForm.title.trim() || null,
      goal: createForm.goal.trim(),
      startUrl: createForm.startUrl.trim(),
      excludedPaths: createForm.excludedPaths
        .split(/[\n,;]+/)
        .map((item) => item.trim())
        .filter(Boolean),
      tlsPolicy: createForm.tlsPolicy,
      identityAProfileId: createForm.identityAProfileId,
      identityBProfileId: createForm.identityBProfileId,
      includeRecentTraffic: createForm.includeRecentTraffic,
      autonomyMode: createForm.autonomyMode,
      budgetProfile: createForm.budgetProfile,
      writtenAuthorizationConfirmed: true,
    });
    creating.value = false;
    contextDialogVisible.value = true;
    ElMessage.success("任务已创建，请检查最终 AI 上下文");
  } catch (error) {
    ElMessage.error(String(error));
  }
}

async function confirmContext() {
  try {
    await missions.confirmContext();
    contextDialogVisible.value = false;
    ElMessage.success(
      missions.pendingActions.length > 0 ? "上下文已确认，请审批待处理动作" : "上下文与动作策略已确认"
    );
  } catch (error) {
    ElMessage.error(String(error));
  }
}

async function decide(action: AssessmentAction, approve: boolean, sameTool = false) {
  try {
    await missions.decide(action, approve, sameTool);
    ElMessage.success(approve ? "动作已批准" : "动作已拒绝；不会创建目标请求");
  } catch (error) {
    ElMessage.error(String(error));
  }
}

async function startMission() {
  if (missions.context?.requiresApproval) {
    contextDialogVisible.value = true;
    ElMessage.warning("上下文或权限已变化，请再次确认");
    return;
  }
  try {
    await missions.start();
    ElMessage.success("任务已进入串行执行器");
  } catch (error) {
    ElMessage.error(String(error));
  }
}

async function stopMission() {
  try {
    await ElMessageBox.confirm(
      "将立即取消等待；正在执行的单个请求安全结束后保存部分结果。",
      "停止当前任务",
      { type: "warning", confirmButtonText: "停止并保存", cancelButtonText: "继续任务" }
    );
    await missions.stop();
    ElMessage.success("停止请求已记录");
  } catch (error) {
    if (String(error).includes("cancel")) return;
    ElMessage.error(String(error));
  }
}

async function sendFollowUp() {
  const content = followUp.value.trim();
  if (!content) return;
  followUpSending.value = true;
  try {
    await missions.sendMessage(content);
    followUp.value = "";
    ElMessage.success("追问已加入，下一个规划点会重新规划");
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
  if (!detail.value) return;
  reportVisible.value = true;
  reportLoading.value = true;
  try {
    reportMarkdown.value = await buildAssessmentMissionReport(
      detail.value.mission.projectId,
      detail.value.mission.id
    );
  } catch (error) {
    reportMarkdown.value = `报告生成失败：${String(error)}`;
  } finally {
    reportLoading.value = false;
  }
}

async function exportMissionReport() {
  if (!detail.value) return;
  reportExporting.value = true;
  try {
    const result = await exportAssessmentMissionReport(
      detail.value.mission.projectId,
      detail.value.mission.id
    );
    ElMessage.success(`Report v4 已导出：${result.markdown_path}`);
  } catch (error) {
    ElMessage.error(String(error));
  } finally {
    reportExporting.value = false;
  }
}

function selectMission(missionId: number) {
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
  if (action.executionKind === "manual_recipe" && action.status === "queued") return "已批准 · 等待 AI 选择";
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
      title="AI 安全评估"
      description="目标驱动地发现、规划、审批、验证并沉淀证据；AI 不能生成或发送任意请求。"
    >
      <template v-if="project.current">
        <el-button :icon="Refresh" circle aria-label="刷新任务" :loading="missions.loading" @click="refresh" />
        <el-button class="inspector-trigger" :icon="Setting" @click="inspectorDrawerVisible = true">边界与覆盖</el-button>
        <el-button type="primary" :icon="Plus" @click="resetComposer(); creating = true">新任务</el-button>
      </template>
    </PageHeader>

    <div class="sr-live" aria-live="polite">{{ eventAnnouncement }}</div>

    <section v-if="!project.current" class="project-empty-shell">
      <EmptyState
        centered
        title="先选择一个已授权项目"
        description="任务必须绑定后端 Scope、AI Provider、身份凭据与书面授权。未选择项目时不会构造任何目标请求。"
      >
        <template #icon><FolderOpened :size="26" /></template>
        <template #action>
          <div class="project-actions">
            <el-select v-model="emptyProjectChoice" placeholder="选择已有项目" aria-label="选择已有项目">
              <el-option v-for="item in project.projects" :key="item.id" :label="item.name" :value="item.id" />
            </el-select>
            <el-button type="primary" :disabled="emptyProjectChoice === null" @click="selectEmptyProject">进入项目</el-button>
            <el-button :icon="Plus" @click="createProjectVisible = true">创建项目</el-button>
          </div>
        </template>
      </EmptyState>
      <div class="readiness-grid" aria-label="开始评估前准备清单">
        <div><CircleCheck /><strong>Scope</strong><span>由项目白名单和精确 origin 双重约束</span></div>
        <div><Connection /><strong>AI Provider</strong><span>创建任务时由后端重新解析并绑定</span></div>
        <div><Key /><strong>身份</strong><span>真实值只保存在系统凭据库，不进入上下文</span></div>
        <div><Document /><strong>授权</strong><span>每个新任务都需要显式确认书面授权</span></div>
      </div>
    </section>

    <div v-else class="mission-layout">
      <aside class="mission-sidebar" aria-label="评估任务历史">
        <div class="sidebar-heading">
          <div><small>{{ project.current.name }}</small><strong>任务历史</strong></div>
          <el-button text :icon="Plus" aria-label="创建新任务" @click="resetComposer(); creating = true" />
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
            <span class="mission-item-top">
              <strong>{{ mission.title }}</strong>
              <el-tag size="small" :type="STATUS_TAG[mission.status]">{{ STATUS_LABEL[mission.status] }}</el-tag>
            </span>
            <span class="mission-goal">{{ mission.goal }}</span>
            <span class="mission-meta">
              <span>#{{ mission.id }}{{ mission.legacy ? " · legacy" : "" }}</span>
              <time>{{ formatTime(mission.updatedAt) }}</time>
            </span>
          </button>
          <div v-if="missions.missions.length === 0" class="sidebar-empty">还没有任务</div>
        </div>

        <div v-if="detail && !creating" class="workflow-list">
          <header>逻辑工作流</header>
          <div v-for="stream in detail.workstreams" :key="stream.id" class="workflow-row">
            <span class="workflow-dot" :data-status="stream.status" />
            <div><strong>{{ stream.title }}</strong><small>{{ stream.objective }}</small></div>
          </div>
          <div v-if="detail.workstreams.length === 0" class="sidebar-empty">
            {{ detail.mission.legacy ? "旧运行不激活 task_nodes" : "确认上下文后生成工作流" }}
          </div>
        </div>
      </aside>

      <main class="mission-main">
        <section v-if="creating" class="composer-card">
          <header class="composer-heading">
            <div><span class="eyebrow">NEW MISSION</span><h2>描述你想达成的安全目标</h2><p>后端会把目标分解为有界工作流，模型只能选择已注册工具与不透明 surface。</p></div>
            <el-button v-if="missions.missions.length" text :icon="Close" @click="creating = false">取消</el-button>
          </header>
          <el-form label-position="top" class="mission-form">
            <div class="form-grid two">
              <el-form-item label="任务标题（可选）"><el-input v-model="createForm.title" maxlength="160" placeholder="例如：登录后订单接口授权边界" /></el-form-item>
              <el-form-item label="起始 URL" required><el-input v-model="createForm.startUrl" placeholder="https://target.example/" /></el-form-item>
            </div>
            <el-form-item label="评估目标" required>
              <el-input v-model="createForm.goal" type="textarea" :rows="4" maxlength="4000" show-word-limit placeholder="说明业务区域、希望回答的问题和不希望触碰的边界。例：检查登录前后订单 API 的可见性、CORS 与只读授权边界，并为高风险输入点生成人工 Repeater 配方。" />
            </el-form-item>
            <div class="form-grid two">
              <el-form-item label="身份 A">
                <el-select v-model="createForm.identityAProfileId" clearable placeholder="匿名或选择身份 A">
                  <el-option v-for="profile in missions.profiles" :key="profile.id" :label="profile.label" :value="profile.id" />
                </el-select>
              </el-form-item>
              <el-form-item label="身份 B">
                <el-select v-model="createForm.identityBProfileId" clearable placeholder="可选，用于 A/B 只读比较">
                  <el-option v-for="profile in missions.profiles" :key="profile.id" :label="profile.label" :value="profile.id" />
                </el-select>
              </el-form-item>
            </div>
            <el-button text :icon="Key" class="identity-link" @click="identityDialogVisible = true">新建系统凭据身份</el-button>

            <label class="field-label">评估档位</label>
            <div class="budget-options">
              <label v-for="budget in BUDGETS" :key="budget.key" :class="{ selected: createForm.budgetProfile === budget.key }">
                <input v-model="createForm.budgetProfile" type="radio" :value="budget.key" />
                <strong>{{ budget.name }}</strong><span>{{ budget.requests }} 请求 · {{ budget.cycles }} 次规划</span><small>{{ budget.description }}</small>
              </label>
            </div>

            <div class="form-grid two compact-grid">
              <el-form-item label="权限模式">
                <el-radio-group v-model="createForm.autonomyMode">
                  <el-radio-button value="manual">手动</el-radio-button>
                  <el-radio-button value="smart">智能（默认）</el-radio-button>
                  <el-radio-button value="automatic">自动</el-radio-button>
                </el-radio-group>
              </el-form-item>
              <el-form-item label="TLS 策略">
                <el-select v-model="createForm.tlsPolicy"><el-option label="严格校验证书" value="strict" /><el-option label="忽略无效证书（靶场）" value="ignore_invalid" /></el-select>
              </el-form-item>
            </div>
            <el-form-item label="额外排除路径">
              <el-input v-model="createForm.excludedPaths" type="textarea" :rows="2" placeholder="每行一个路径；内置危险路径仍始终拒绝" />
            </el-form-item>
            <div class="composer-checks">
              <el-checkbox v-model="createForm.includeRecentTraffic">把同项目近期 Traffic 作为只读发现种子</el-checkbox>
              <el-checkbox v-model="createForm.writtenAuthorizationConfirmed">我确认已获得对该目标执行安全评估的书面授权</el-checkbox>
            </div>
            <el-alert type="info" :closable="false" show-icon title="人工配方永远不会自动发送；SQLi、SSRF、XSS 和业务逻辑差异必须由你在 Repeater 中亲自点击。" />
            <footer class="composer-footer">
              <span>硬上限始终为 2 RPS、单并发、精确 origin。</span>
              <el-button type="primary" :icon="Aim" :loading="missions.mutating" @click="createMission">创建并预览上下文</el-button>
            </footer>
          </el-form>
        </section>

        <EmptyState v-else-if="!detail" centered title="选择或创建一个任务" description="任务历史、审批等待和旧版运行都会保存在当前项目中。">
          <template #icon><Aim :size="26" /></template>
          <template #action><el-button type="primary" :icon="Plus" @click="resetComposer(); creating = true">创建任务</el-button></template>
        </EmptyState>

        <template v-else>
          <section class="mission-hero">
            <div class="mission-title-row">
              <div><span class="eyebrow">MISSION #{{ detail.mission.id }}</span><h2>{{ detail.mission.title }}</h2></div>
              <el-tag :type="STATUS_TAG[detail.mission.status]">{{ STATUS_LABEL[detail.mission.status] }}</el-tag>
            </div>
            <p class="goal-copy">{{ detail.mission.goal }}</p>
            <div class="mission-command-row">
              <div class="mission-facts"><span>{{ detail.mission.exactOrigin }}</span><span>{{ detail.mission.autonomyMode }}</span><span>{{ detail.mission.budgetProfile }}</span></div>
              <div class="mission-buttons">
                <el-button :icon="Document" @click="previewReport">报告</el-button>
                <el-button v-if="canStop" :icon="VideoPause" :loading="missions.mutating" @click="stopMission">停止</el-button>
                <el-button v-if="!detail.mission.legacy" type="primary" :icon="VideoPlay" :disabled="!canStart" :loading="missions.mutating" @click="startMission">开始 / 恢复</el-button>
              </div>
            </div>
            <el-progress v-if="isActive" :percentage="Math.min(100, Math.round((detail.mission.requestCount / Math.max(1, detail.mission.requestBudget)) * 100))" :stroke-width="5" :show-text="false" />
          </section>

          <el-alert v-if="detail.mission.legacy" class="mission-alert" type="info" :closable="false" show-icon title="这是旧版 Phase 6 运行：仅支持只读查看与 legacy 报告，不会重新激活旧 task_nodes。" />
          <section v-else-if="missions.context?.requiresApproval" class="approval-banner">
            <div><Warning /><span><strong>需要确认 AI 上下文</strong><small>首次调用、附件或工具权限变化后，模型不会在确认前收到上下文。</small></span></div>
            <el-button type="warning" @click="contextDialogVisible = true">查看披露清单并确认</el-button>
          </section>

          <section class="conversation" aria-label="任务对话与事件">
            <article v-for="message in detail.messages" :key="message.id" class="message" :data-role="message.role">
              <div class="message-avatar">{{ message.role === "user" ? "你" : message.role === "assistant" ? "AI" : "RF" }}</div>
              <div class="message-body"><header><strong>{{ message.messageKind === "goal" ? "任务目标" : message.messageKind === "follow_up" ? "中途引导" : "系统记录" }}</strong><time>{{ formatTime(message.createdAt) }}</time></header><p>{{ message.content }}</p><small v-if="message.redactionManifest.length">已脱敏：{{ message.redactionManifest.join("、") }}</small></div>
            </article>
          </section>

          <section v-if="!detail.mission.legacy" class="action-timeline" aria-label="可信工具动作">
            <header class="timeline-heading"><div><span class="eyebrow">TRUSTED ACTIONS</span><h3>计划与动作</h3></div><span>{{ detail.actions.length }} 个动作 · {{ missions.pendingActions.length }} 个待审批</span></header>
            <article v-for="action in detail.actions" :key="action.id" class="action-card" :class="{ pending: action.approvalStatus === 'pending', manual: action.executionKind === 'manual_recipe' }">
              <header class="action-header">
                <div class="action-name"><span class="action-index">{{ action.id }}</span><div><strong>{{ actionToolLabel(action) }}</strong><small>{{ workstreamTitle(action.workstreamId) }} · {{ action.toolId }}@{{ action.toolVersion }}</small></div></div>
                <div class="action-tags"><el-tag size="small" :type="riskType(action.riskLevel)">{{ action.riskLevel }}</el-tag><el-tag size="small" type="info">{{ resultLabel(action) }}</el-tag></div>
              </header>
              <div class="action-explanation">
                <div><small>为什么执行</small><p>{{ action.rationale }}</p></div>
                <div><small>预期观察</small><p>{{ action.expectedSignal || "等待确定性执行器记录预期信号" }}</p></div>
              </div>
              <div class="action-meta"><span>后端工具：{{ action.toolId }}</span><span>批准方式：{{ action.approvalSource || action.permissionSnapshot }}</span><span>身份：{{ action.identityMode }}</span><span>成本：{{ action.requestCost }} 请求</span></div>
              <el-alert v-if="action.executionKind === 'manual_recipe'" type="warning" :closable="false" show-icon title="仅生成 Repeater 差异草稿；评估引擎不能自动发送。" />
              <footer class="action-footer">
                <el-button text :icon="View" @click="openActionDetails(action)">技术详情</el-button>
                <div v-if="action.approvalStatus === 'pending'" class="approval-buttons">
                  <el-button :loading="missions.mutating" @click="decide(action, false)">拒绝</el-button>
                  <el-button :loading="missions.mutating" @click="decide(action, true, true)">批准同工具</el-button>
                  <el-button type="primary" :loading="missions.mutating" @click="decide(action, true)">批准本动作</el-button>
                </div>
                <div v-else-if="action.executionKind === 'manual_recipe' && ['manual_ready', 'manual_result_pending'].includes(action.status)" class="approval-buttons">
                  <el-button v-if="!handoffFor(action.id)" type="warning" @click="createHandoff(action)">创建 Repeater 草稿</el-button>
                  <template v-else><el-tag type="warning">会话 #{{ handoffFor(action.id)?.replaySessionId }} · 尚需用户点击发送</el-tag><el-button v-if="handoffFor(action.id)?.status !== 'result_linked'" @click="openHandoffLink(handoffFor(action.id)!)">回传 ReplayRun</el-button></template>
                </div>
              </footer>
            </article>
            <div v-if="detail.actions.length === 0" class="timeline-empty">确认上下文后，工具动作会在这里显示理由、预期信号、风险与审批方式。</div>
          </section>

          <section v-if="!detail.mission.legacy && !TERMINAL_STATUSES.has(detail.mission.status)" class="followup-box">
            <ChatDotRound />
            <el-input v-model="followUp" type="textarea" :autosize="{ minRows: 1, maxRows: 4 }" maxlength="2000" placeholder="中途调整目标或追问；当前单个请求先安全结束，下一规划点重新规划。" @keydown.ctrl.enter.prevent="sendFollowUp" />
            <el-button type="primary" :loading="followUpSending" :disabled="!followUp.trim()" @click="sendFollowUp">发送</el-button>
          </section>
        </template>
      </main>

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

    <el-drawer v-model="inspectorDrawerVisible" title="边界、资源与覆盖" direction="rtl" size="380px">
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

    <el-dialog v-model="contextDialogVisible" title="最终 AI 上下文与披露清单" width="min(820px, 92vw)" destroy-on-close>
      <template v-if="missions.context">
        <el-alert :type="missions.context.approved ? 'success' : 'warning'" :closable="false" show-icon :title="missions.context.approved ? '当前上下文已确认' : '确认前不会调用模型'" />
        <div class="context-manifest"><strong>披露数据类别</strong><div><el-tag v-for="item in missions.context.disclosureManifest" :key="item" size="small">{{ item }}</el-tag></div></div>
        <details class="context-details" open><summary>脱敏结构摘要</summary><pre>{{ contextJson }}</pre></details>
        <div class="hash-grid"><span>context <code>{{ shortHash(missions.context.contextHash) }}</code></span><span>contract <code>{{ shortHash(missions.context.contractHash) }}</code></span><span>registry <code>{{ shortHash(missions.context.toolRegistryHash) }}</code></span><span>permission <code>{{ shortHash(missions.context.permissionHash) }}</code></span></div>
      </template>
      <el-empty v-else description="旧运行没有 v2 AI 上下文" />
      <template #footer><el-button @click="contextDialogVisible = false">关闭</el-button><el-button v-if="missions.context?.requiresApproval" type="primary" :loading="missions.mutating" @click="confirmContext">确认上下文并生成动作</el-button></template>
    </el-dialog>

    <el-dialog v-model="resourceDialogVisible" title="附加同项目资源" width="620px">
      <el-form label-position="top" v-loading="resourceLoading">
        <el-form-item label="资源类型"><el-radio-group v-model="resourceForm.type" @change="resourceForm.sourceId = null"><el-radio-button value="traffic">Traffic</el-radio-button><el-radio-button value="finding">Finding</el-radio-button><el-radio-button value="assessment_run">历史评估</el-radio-button></el-radio-group></el-form-item>
        <el-form-item label="资源" required>
          <el-select v-if="resourceForm.type === 'traffic'" v-model="resourceForm.sourceId" filterable placeholder="选择最近 Traffic"><el-option v-for="item in trafficResources" :key="item.id" :value="item.id" :label="`#${item.id} · ${item.method} ${item.path} · ${item.status ?? '—'}`" /></el-select>
          <el-select v-else-if="resourceForm.type === 'finding'" v-model="resourceForm.sourceId" filterable placeholder="选择 Finding"><el-option v-for="item in findingResources" :key="item.id" :value="item.id" :label="`#${item.id} · ${item.title} · ${item.status}`" /></el-select>
          <el-select v-else v-model="resourceForm.sourceId" filterable placeholder="选择历史运行"><el-option v-for="item in runResources" :key="item.id" :value="item.id" :label="`Run #${item.id} · ${item.status} · ${item.startUrl}`" /></el-select>
        </el-form-item>
        <el-alert type="info" :closable="false" title="只保存不可变脱敏摘要与 hash；资源必须属于当前项目。" />
      </el-form>
      <template #footer><el-button @click="resourceDialogVisible = false">取消</el-button><el-button type="primary" :loading="missions.mutating" @click="attachResource">附加并重新预览</el-button></template>
    </el-dialog>

    <el-dialog v-model="identityDialogVisible" title="新建评估身份" width="520px" destroy-on-close>
      <el-alert type="warning" :closable="false" title="凭据真实值只写入系统凭据库，不进入 SQLite、事件、报告或 AI 上下文。" />
      <el-form label-position="top" class="identity-form"><el-form-item label="名称" required><el-input v-model="identityForm.label" maxlength="80" placeholder="例如：普通用户 A" /></el-form-item><el-form-item label="Header"><el-select v-model="identityForm.headerName"><el-option label="Authorization" value="Authorization" /><el-option label="Cookie" value="Cookie" /><el-option label="X-API-Key" value="X-API-Key" /><el-option label="X-Auth-Token" value="X-Auth-Token" /></el-select></el-form-item><el-form-item label="凭据值" required><el-input v-model="identityForm.secret" type="password" show-password autocomplete="off" /></el-form-item></el-form>
      <template #footer><el-button @click="identityDialogVisible = false; identityForm.secret = ''">取消</el-button><el-button type="primary" :loading="identitySaving" @click="createIdentity">保存到系统凭据库</el-button></template>
    </el-dialog>

    <el-drawer v-model="actionDrawerVisible" title="动作技术详情" size="min(620px, 92vw)">
      <template v-if="selectedAction">
        <el-descriptions :column="1" border><el-descriptions-item label="工具">{{ selectedAction.toolId }}@{{ selectedAction.toolVersion }}</el-descriptions-item><el-descriptions-item label="surface">{{ selectedAction.surfaceId ?? "由后端在发现后绑定" }}</el-descriptions-item><el-descriptions-item label="风险 / 权限">{{ selectedAction.riskLevel }} / {{ selectedAction.permissionSnapshot }} / {{ selectedAction.approvalSource }}</el-descriptions-item><el-descriptions-item label="策略结果">{{ selectedAction.policyReason || selectedAction.status }}</el-descriptions-item><el-descriptions-item label="request hash">{{ selectedAction.requestHash ?? "—" }}</el-descriptions-item><el-descriptions-item label="response hash">{{ selectedAction.responseHash ?? "—" }}</el-descriptions-item><el-descriptions-item label="result hash">{{ selectedAction.resultHash ?? "—" }}</el-descriptions-item></el-descriptions>
        <section class="technical-block"><h4>参数（仅已有参数名与身份模式）</h4><pre>{{ pretty(selectedAction.parameters) }}</pre></section>
        <section class="technical-block"><h4>脱敏请求</h4><pre>{{ pretty(selectedAction.redactedRequest) }}</pre></section>
        <section class="technical-block"><h4>脱敏响应 / Replay 关联结果</h4><pre>{{ pretty(selectedAction.redactedResponse) }}</pre></section>
        <section class="technical-block"><h4>确定性结果</h4><pre>{{ pretty(selectedAction.result) }}</pre></section>
      </template>
    </el-drawer>

    <el-dialog v-model="handoffDialogVisible" title="回传人工 ReplayRun" width="520px"><el-alert type="warning" :closable="false" show-icon title="只接受同项目、同 handoff 人工会话的 ReplayRun；Evidence 默认未接受且不会自动确认 Finding。" /><el-form label-position="top"><el-form-item label="ReplayRun ID" required><el-input-number v-model="handoffReplayRunId" :min="1" :step="1" controls-position="right" /></el-form-item></el-form><template #footer><el-button @click="handoffDialogVisible = false">取消</el-button><el-button type="primary" :loading="missions.mutating" @click="linkHandoff">回传为待复核 Evidence</el-button></template></el-dialog>

    <el-dialog v-model="reportVisible" title="证据化报告 · Schema v4" width="min(900px, 94vw)"><div v-loading="reportLoading" class="report-preview"><pre>{{ reportMarkdown }}</pre></div><template #footer><el-button @click="reportVisible = false">关闭</el-button><el-button type="primary" :loading="reportExporting" @click="exportMissionReport">导出 Markdown + JSON</el-button></template></el-dialog>
    <ProjectCreateDialog v-model="createProjectVisible" />
  </div>
</template>

<style scoped>
.assessment-page {
  display: flex;
  height: 100%;
  min-height: 0;
  flex-direction: column;
  gap: 14px;
  padding: 16px 20px 18px;
  overflow: hidden;
  background: var(--rf-bg-base);
}

.sr-live {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}

.project-empty-shell {
  display: grid;
  min-height: 0;
  flex: 1;
  grid-template-rows: minmax(300px, 1fr) auto;
  gap: 14px;
}

.project-actions { display: flex; flex-wrap: wrap; justify-content: center; gap: 8px; }
.project-actions :deep(.el-select) { width: 230px; }
.project-actions :deep(.el-button + .el-button) { margin-left: 0; }

.readiness-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; }
.readiness-grid > div {
  display: grid;
  grid-template-columns: 24px 1fr;
  gap: 2px 8px;
  padding: 13px;
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-control);
  background: var(--rf-bg-panel);
}
.readiness-grid svg { grid-row: 1 / 3; width: 20px; color: var(--rf-accent); }
.readiness-grid strong { color: var(--rf-text); font-size: 12px; }
.readiness-grid span { color: var(--rf-text-muted); font-size: 10.5px; line-height: 1.4; }

.mission-layout {
  display: grid;
  min-height: 0;
  flex: 1;
  grid-template-columns: 250px minmax(430px, 1fr) 310px;
  overflow: hidden;
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-shell);
  background: var(--rf-bg-panel);
  box-shadow: var(--rf-shadow-light);
}

.mission-sidebar { display: flex; min-height: 0; flex-direction: column; border-right: 1px solid var(--rf-border); background: color-mix(in srgb, var(--rf-bg-panel) 80%, var(--rf-bg-base)); }
.sidebar-heading { display: flex; align-items: center; justify-content: space-between; padding: 13px; border-bottom: 1px solid var(--rf-border); }
.sidebar-heading div { display: grid; gap: 1px; }
.sidebar-heading small { color: var(--rf-text-muted); font-size: 9px; text-transform: uppercase; }
.sidebar-heading strong { color: var(--rf-text); font-size: 13px; }
.mission-list { display: grid; gap: 5px; max-height: 48%; padding: 8px; overflow: auto; }
.mission-item { display: grid; gap: 6px; width: 100%; padding: 10px; border: 1px solid transparent; border-radius: 9px; background: transparent; color: inherit; text-align: left; cursor: pointer; }
.mission-item:hover { background: var(--rf-bg-hover); }
.mission-item.active { border-color: color-mix(in srgb, var(--rf-accent) 45%, var(--rf-border)); background: var(--rf-accent-muted); }
.mission-item:focus-visible { outline: 2px solid var(--rf-accent); outline-offset: -2px; }
.mission-item-top { display: flex; align-items: flex-start; justify-content: space-between; gap: 6px; }
.mission-item-top strong { min-width: 0; overflow: hidden; color: var(--rf-text); font-size: 11.5px; text-overflow: ellipsis; white-space: nowrap; }
.mission-goal { display: -webkit-box; overflow: hidden; color: var(--rf-text-secondary); font-size: 10.5px; line-height: 1.45; -webkit-box-orient: vertical; -webkit-line-clamp: 2; }
.mission-meta { display: flex; justify-content: space-between; gap: 5px; color: var(--rf-text-muted); font-size: 9px; }
.sidebar-empty { padding: 14px; color: var(--rf-text-muted); font-size: 10.5px; text-align: center; }
.workflow-list { min-height: 0; flex: 1; padding: 12px; overflow: auto; border-top: 1px solid var(--rf-border); }
.workflow-list > header { margin-bottom: 10px; color: var(--rf-text-muted); font-size: 9px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }
.workflow-row { position: relative; display: grid; grid-template-columns: 12px 1fr; gap: 7px; padding-bottom: 13px; }
.workflow-row:not(:last-child)::before { position: absolute; top: 10px; bottom: 0; left: 4px; width: 1px; background: var(--rf-border-strong); content: ""; }
.workflow-dot { z-index: 1; width: 9px; height: 9px; margin-top: 3px; border: 2px solid var(--rf-border-strong); border-radius: 50%; background: var(--rf-bg-panel); }
.workflow-dot[data-status="completed"] { border-color: var(--rf-success); background: var(--rf-success); }
.workflow-dot[data-status="active"] { border-color: var(--rf-accent); background: var(--rf-accent); }
.workflow-row div { display: grid; gap: 2px; }
.workflow-row strong { color: var(--rf-text-secondary); font-size: 10.5px; }
.workflow-row small { color: var(--rf-text-muted); font-size: 9.5px; line-height: 1.4; }

.mission-main { min-width: 0; min-height: 0; padding: 16px 18px 24px; overflow: auto; background: var(--rf-bg-base); }
.composer-card, .mission-hero, .conversation, .action-timeline, .followup-box { max-width: 880px; margin-right: auto; margin-left: auto; }
.composer-card { padding: 20px; border: 1px solid var(--rf-border); border-radius: var(--rf-radius-shell); background: var(--rf-bg-panel); }
.composer-heading { display: flex; align-items: flex-start; justify-content: space-between; gap: 20px; margin-bottom: 18px; }
.composer-heading h2, .mission-title-row h2, .timeline-heading h3 { margin: 2px 0 0; color: var(--rf-text); }
.composer-heading h2 { font-size: 19px; }
.composer-heading p { max-width: 660px; margin: 5px 0 0; color: var(--rf-text-secondary); font-size: 11.5px; line-height: 1.5; }
.eyebrow { color: var(--rf-accent); font-size: 9px; font-weight: 750; letter-spacing: .11em; }
.form-grid { display: grid; gap: 12px; }
.form-grid.two { grid-template-columns: repeat(2, minmax(0, 1fr)); }
.mission-form :deep(.el-form-item) { margin-bottom: 13px; }
.mission-form :deep(.el-form-item__label) { color: var(--rf-text-secondary); font-size: 11px; }
.identity-link { margin: -9px 0 12px; }
.field-label { display: block; margin: 1px 0 8px; color: var(--rf-text-secondary); font-size: 11px; }
.budget-options { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; margin-bottom: 14px; }
.budget-options label { position: relative; display: grid; gap: 3px; padding: 11px; border: 1px solid var(--rf-border); border-radius: 9px; background: var(--rf-bg-raised); cursor: pointer; }
.budget-options label.selected { border-color: var(--rf-accent); box-shadow: 0 0 0 1px var(--rf-accent-muted); }
.budget-options input { position: absolute; opacity: 0; }
.budget-options strong { color: var(--rf-text); font-size: 12px; }
.budget-options span { color: var(--rf-accent); font-size: 10px; }
.budget-options small { color: var(--rf-text-muted); font-size: 9.5px; line-height: 1.4; }
.composer-checks { display: grid; gap: 5px; margin: 4px 0 13px; }
.composer-footer { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-top: 16px; }
.composer-footer > span { color: var(--rf-text-muted); font-size: 10.5px; }

.mission-hero { padding: 3px 2px 15px; }
.mission-title-row { display: flex; align-items: flex-start; justify-content: space-between; gap: 14px; }
.mission-title-row h2 { font-size: 20px; }
.goal-copy { margin: 9px 0 12px; color: var(--rf-text-secondary); font-size: 12.5px; line-height: 1.65; }
.mission-command-row { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.mission-facts, .mission-buttons { display: flex; flex-wrap: wrap; align-items: center; gap: 7px; }
.mission-facts span { padding: 4px 8px; border-radius: var(--rf-radius-tag); background: var(--rf-bg-raised); color: var(--rf-text-muted); font-family: var(--rf-font-mono); font-size: 9.5px; }
.mission-buttons :deep(.el-button + .el-button) { margin-left: 0; }
.mission-hero :deep(.el-progress) { margin-top: 12px; }
.mission-alert { max-width: 880px; margin: 0 auto 12px; }
.approval-banner { display: flex; max-width: 880px; align-items: center; justify-content: space-between; gap: 12px; margin: 0 auto 12px; padding: 12px; border: 1px solid color-mix(in srgb, var(--rf-warning) 50%, var(--rf-border)); border-radius: 10px; background: color-mix(in srgb, var(--rf-warning) 9%, var(--rf-bg-panel)); }
.approval-banner > div { display: flex; align-items: center; gap: 9px; color: var(--rf-warning); }
.approval-banner span { display: grid; gap: 2px; }
.approval-banner strong { color: var(--rf-text); font-size: 11.5px; }
.approval-banner small { color: var(--rf-text-secondary); font-size: 10px; }

.conversation { display: grid; gap: 9px; margin-bottom: 16px; }
.message { display: grid; grid-template-columns: 30px minmax(0, 1fr); gap: 9px; }
.message-avatar { display: grid; width: 28px; height: 28px; place-items: center; border-radius: 9px; background: var(--rf-bg-raised); color: var(--rf-text-muted); font-size: 9px; font-weight: 700; }
.message[data-role="user"] .message-avatar { background: var(--rf-accent); color: var(--rf-accent-on); }
.message-body { padding: 10px 12px; border: 1px solid var(--rf-border); border-radius: 2px 10px 10px; background: var(--rf-bg-panel); }
.message-body header { display: flex; justify-content: space-between; gap: 8px; }
.message-body strong { color: var(--rf-text); font-size: 10.5px; }
.message-body time, .message-body small { color: var(--rf-text-muted); font-size: 9px; }
.message-body p { margin: 5px 0 0; color: var(--rf-text-secondary); font-size: 11.5px; line-height: 1.55; white-space: pre-wrap; }

.action-timeline { display: grid; gap: 10px; }
.timeline-heading { display: flex; align-items: flex-end; justify-content: space-between; gap: 12px; margin: 5px 0 2px; }
.timeline-heading h3 { font-size: 15px; }
.timeline-heading > span { color: var(--rf-text-muted); font-size: 10px; }
.action-card { padding: 13px; border: 1px solid var(--rf-border); border-radius: 11px; background: var(--rf-bg-panel); box-shadow: var(--rf-shadow-light); }
.action-card.pending { border-color: color-mix(in srgb, var(--rf-warning) 55%, var(--rf-border)); }
.action-card.manual { border-left: 3px solid var(--rf-warning); }
.action-header, .action-name, .action-tags, .action-footer, .approval-buttons { display: flex; align-items: center; }
.action-header, .action-footer { justify-content: space-between; gap: 10px; }
.action-name { min-width: 0; gap: 9px; }
.action-index { display: grid; width: 25px; height: 25px; flex: 0 0 auto; place-items: center; border-radius: 8px; background: var(--rf-bg-raised); color: var(--rf-text-muted); font-family: var(--rf-font-mono); font-size: 9px; }
.action-name > div { display: grid; min-width: 0; gap: 2px; }
.action-name strong { color: var(--rf-text); font-size: 12px; }
.action-name small { overflow: hidden; color: var(--rf-text-muted); font-family: var(--rf-font-mono); font-size: 9px; text-overflow: ellipsis; white-space: nowrap; }
.action-tags, .approval-buttons { flex-wrap: wrap; justify-content: flex-end; gap: 6px; }
.approval-buttons :deep(.el-button + .el-button) { margin-left: 0; }
.action-explanation { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; margin: 11px 0; }
.action-explanation > div { padding: 9px; border-radius: 8px; background: var(--rf-bg-raised); }
.action-explanation small { color: var(--rf-text-muted); font-size: 9px; }
.action-explanation p { margin: 3px 0 0; color: var(--rf-text-secondary); font-size: 10.5px; line-height: 1.5; }
.action-meta { display: flex; flex-wrap: wrap; gap: 5px 12px; margin-bottom: 9px; color: var(--rf-text-muted); font-size: 9.5px; }
.action-footer { margin-top: 10px; padding-top: 9px; border-top: 1px solid var(--rf-border); }
.timeline-empty { padding: 22px; border: 1px dashed var(--rf-border-strong); border-radius: 10px; color: var(--rf-text-muted); font-size: 11px; text-align: center; }
.followup-box { display: grid; grid-template-columns: 22px minmax(0, 1fr) auto; align-items: center; gap: 9px; margin-top: 13px; padding: 10px; border: 1px solid var(--rf-border); border-radius: 11px; background: var(--rf-bg-panel); }
.followup-box > svg { color: var(--rf-accent); }

.mission-inspector { border-left: 1px solid var(--rf-border); }
.inspector-trigger { display: none; }
.context-manifest { display: grid; gap: 8px; margin: 14px 0; }
.context-manifest strong { color: var(--rf-text); font-size: 12px; }
.context-manifest > div { display: flex; flex-wrap: wrap; gap: 5px; }
.context-details { border: 1px solid var(--rf-border); border-radius: 9px; background: var(--rf-bg-raised); }
.context-details summary { padding: 10px; color: var(--rf-text-secondary); font-size: 11px; cursor: pointer; }
.context-details pre, .technical-block pre, .report-preview pre { margin: 0; padding: 12px; overflow: auto; color: var(--rf-text-secondary); font-family: var(--rf-font-mono); font-size: 10px; line-height: 1.55; white-space: pre-wrap; overflow-wrap: anywhere; }
.context-details pre { max-height: 360px; border-top: 1px solid var(--rf-border); }
.hash-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 6px; margin-top: 10px; }
.hash-grid span { color: var(--rf-text-muted); font-size: 9px; }
.hash-grid code { color: var(--rf-text-secondary); font-family: var(--rf-font-mono); }
.identity-form { margin-top: 14px; }
.technical-block { margin-top: 12px; border: 1px solid var(--rf-border); border-radius: 9px; background: var(--rf-bg-raised); }
.technical-block h4 { margin: 0; padding: 10px 12px; border-bottom: 1px solid var(--rf-border); color: var(--rf-text); font-size: 11px; }
.report-preview { min-height: 280px; max-height: 65vh; overflow: auto; border: 1px solid var(--rf-border); border-radius: 9px; background: var(--rf-bg-raised); }

@media (max-width: 1260px) {
  .mission-layout { grid-template-columns: 240px minmax(0, 1fr); }
  .desktop-inspector { display: none; }
  .inspector-trigger { display: inline-flex; }
}

@media (max-width: 780px) {
  .assessment-page { padding: 12px; overflow: auto; }
  .mission-layout { display: flex; min-height: 720px; flex-direction: column; overflow: visible; }
  .mission-sidebar { max-height: 290px; flex: 0 0 auto; border-right: 0; border-bottom: 1px solid var(--rf-border); }
  .mission-list { display: flex; max-height: 150px; overflow-x: auto; }
  .mission-item { min-width: 220px; }
  .workflow-list { display: none; }
  .mission-main { overflow: visible; }
  .form-grid.two, .action-explanation, .budget-options, .readiness-grid { grid-template-columns: 1fr; }
  .mission-command-row, .composer-footer, .approval-banner { align-items: stretch; flex-direction: column; }
  .followup-box { grid-template-columns: 1fr; }
  .followup-box > svg { display: none; }
  .hash-grid { grid-template-columns: 1fr; }
}

@media (max-width: 640px) {
  .mission-sidebar { max-height: 360px; }
  .mission-list { display: grid; max-height: 230px; overflow-x: hidden; overflow-y: auto; }
  .mission-item { min-width: 0; }
  .mission-title-row { align-items: flex-start; flex-direction: column; }
  .mission-buttons { width: 100%; }
}
</style>
