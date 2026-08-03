<script setup lang="ts">
import {
  computed,
  onMounted,
  onUnmounted,
  reactive,
  ref,
  watch,
} from "vue";
import { useRouter } from "vue-router";
import { ElMessage, ElMessageBox } from "element-plus";
import {
  Aim,
  CircleCheck,
  Close,
  Document,
  FolderOpened,
  Key,
  Plus,
  Refresh,
  Warning,
} from "@element-plus/icons-vue";
import MarkdownIt from "markdown-it";
import { useProjectStore } from "../stores/project";
import { useAssessmentStore } from "../stores/assessment";
import {
  buildReport,
  exportReport,
  previewAssessmentContract,
  type AssessmentAuthProfile,
  type AssessmentCheck,
  type AssessmentContractInput,
  type AssessmentContractPreview,
  type AssessmentRun,
  type AssessmentStatus,
  type AssessmentVerification,
} from "../api/tauri";
import EmptyState from "../components/shell/EmptyState.vue";
import PageHeader from "../components/shell/PageHeader.vue";

const project = useProjectStore();
const assessment = useAssessmentStore();
const router = useRouter();
const md = new MarkdownIt({ breaks: true, linkify: false });

const projectId = computed(() => project.current?.id ?? null);
const composerVisible = ref(false);
const composerStep = ref<"setup" | "confirm">("setup");
const preview = ref<AssessmentContractPreview | null>(null);
const previewing = ref(false);
const authorizationConfirmed = ref(false);
const advancedOpen = ref<string[]>([]);
const reportVisible = ref(false);
const reportMarkdown = ref("");
const reportLoading = ref(false);
const reportExporting = ref(false);

const form = reactive({
  startUrl: "",
  identityAProfileId: null as number | null,
  identityBProfileId: null as number | null,
  ownershipPaths: "",
  excludedPaths: "",
  tlsPolicy: "strict" as "strict" | "ignore_invalid",
  requestBudget: 120,
  requestsPerSecond: 1,
  maxRounds: 3,
  includeRecentTraffic: false,
});

const profileDialogVisible = ref(false);
const profileSaving = ref(false);
const profileForm = reactive({
  mode: "paste" as "paste" | "traffic",
  label: "",
  headerName: "Authorization" as AssessmentAuthProfile["headerName"],
  secret: "",
  trafficId: null as number | null,
});
// 候选列表与手动输入 ID 二选一；切换时清空 trafficId，避免跨模式残留。
const profileTrafficManual = ref(false);

function toggleTrafficManual() {
  profileTrafficManual.value = !profileTrafficManual.value;
  profileForm.trafficId = null;
}

// 切换到 Traffic 提取或更换 Header 时，自动刷新候选请求列表。
// 更换 Header 时必须清空已选中的 trafficId：旧选择属于上一个 Header，
// 保留会导致用旧请求 + 新 Header 导入而失败。
watch(
  () => [profileForm.mode, profileForm.headerName] as const,
  ([mode, headerName], [prevMode, prevHeader]) => {
    if (mode !== "traffic" || !profileDialogVisible.value) return;
    if (prevHeader !== headerName) {
      profileForm.trafficId = null;
      profileTrafficManual.value = false;
    }
    void assessment.loadAuthCandidates(headerName);
  }
);

const STATUS_LABEL: Record<AssessmentStatus, string> = {
  queued: "排队中",
  discovering: "发现端点",
  planning: "AI 规划",
  executing: "执行只读检查",
  verifying: "确定性验证",
  completed: "已完成",
  stopped: "安全停止",
  cancelled: "已取消",
  failed: "失败",
  interrupted: "应用中断",
};

type TagType = "primary" | "success" | "warning" | "info" | "danger";
const STATUS_TAG: Record<AssessmentStatus, TagType> = {
  queued: "info",
  discovering: "primary",
  planning: "primary",
  executing: "warning",
  verifying: "warning",
  completed: "success",
  stopped: "warning",
  cancelled: "info",
  failed: "danger",
  interrupted: "warning",
};

const TEMPLATE_LABEL: Record<string, string> = {
  security_headers_cookie: "安全 Header / Cookie",
  credentialed_cors: "凭据型 CORS",
  jwt_integrity: "JWT 完整性",
  open_redirect: "开放重定向",
  lazy_reflection: "只读反射迹象",
  readonly_idor: "双身份只读越权",
};

const PHASES: Array<{ key: AssessmentStatus; label: string }> = [
  { key: "discovering", label: "发现" },
  { key: "planning", label: "规划" },
  { key: "executing", label: "执行" },
  { key: "verifying", label: "验证" },
  { key: "completed", label: "完成" },
];

const ACTIVE_STATUSES = new Set<AssessmentStatus>([
  "queued",
  "discovering",
  "planning",
  "executing",
  "verifying",
]);

const selectedRun = computed(() => assessment.selectedRun);
const selectedIsActive = computed(() =>
  selectedRun.value ? ACTIVE_STATUSES.has(selectedRun.value.status) : false
);
const detail = computed(() => assessment.detail);
const verificationByCheck = computed(() => {
  const result = new Map<number, AssessmentVerification>();
  for (const item of detail.value?.verifications ?? []) {
    result.set(item.checkId, item);
  }
  return result;
});
const checksById = computed(() =>
  new Map((detail.value?.checks ?? []).map((item) => [item.id, item]))
);

const confirmed = computed(() =>
  (detail.value?.verifications ?? []).filter(
    (item) => item.verdict === "confirmed"
  )
);
const suspected = computed(() =>
  (detail.value?.verifications ?? []).filter(
    (item) => item.verdict === "suspected"
  )
);
const notObserved = computed(() =>
  (detail.value?.verifications ?? []).filter(
    (item) => item.verdict === "not_observed"
  )
);
const inconclusive = computed(() =>
  (detail.value?.verifications ?? []).filter((item) =>
    ["inconclusive", "skipped"].includes(item.verdict)
  )
);

const requestPercentage = computed(() => {
  const run = selectedRun.value;
  if (!run || run.requestBudget <= 0) return 0;
  return Math.min(100, Math.round((run.requestCount / run.requestBudget) * 100));
});

const currentPhaseIndex = computed(() => {
  const status = selectedRun.value?.status;
  if (!status) return 0;
  if (["stopped", "cancelled", "failed", "interrupted"].includes(status)) {
    // 只取 status_changed 事件中最后一个仍处于活动阶段的 newValue，
    // 避免 coverage_gap / check 事件的 newValue 干扰阶段条。
    const lastActive = detail.value?.events
      .filter((event) => event.eventType === "status_changed")
      .map((event) => event.newValue)
      .filter((value): value is string => Boolean(value))
      .filter((value) => ACTIVE_STATUSES.has(value as AssessmentStatus))
      .at(-1);
    const index = lastActive ? PHASES.findIndex((item) => item.key === lastActive) : -1;
    return Math.max(0, index);
  }
  const index = PHASES.findIndex((item) => item.key === status);
  return Math.max(0, index);
});

watch(
  projectId,
  async (id) => {
    assessment.activateProject(id);
    preview.value = null;
    authorizationConfirmed.value = false;
    composerStep.value = "setup";
    reportVisible.value = false;
    if (id === null) {
      composerVisible.value = false;
      return;
    }
    seedStartUrl();
    try {
      await assessment.refresh(id);
      composerVisible.value = assessment.runs.length === 0;
    } catch (error) {
      ElMessage.error(String(error));
      // 已有运行历史时保持详情视图；只有没有任何历史才退回空表单，
      // 避免一次暂时性 IPC 失败把用户从运行详情踢回 composer。
      composerVisible.value = assessment.runs.length === 0;
    }
  },
  { immediate: true }
);

onMounted(async () => {
  try {
    await assessment.bindEvents(() => projectId.value);
  } catch (error) {
    ElMessage.warning(`实时进度通道不可用，将通过刷新恢复：${String(error)}`);
  }
});

onUnmounted(() => assessment.unbindEvents());

function seedStartUrl() {
  const target = project.current?.target_host.trim() ?? "";
  if (!target) {
    form.startUrl = "";
  } else if (/^https?:\/\//i.test(target)) {
    form.startUrl = target;
  } else {
    form.startUrl = `https://${target}/`;
  }
}

function resetComposer() {
  seedStartUrl();
  form.identityAProfileId = null;
  form.identityBProfileId = null;
  form.ownershipPaths = "";
  form.excludedPaths = "";
  form.tlsPolicy = "strict";
  form.requestBudget = 120;
  form.requestsPerSecond = 1;
  form.maxRounds = 3;
  form.includeRecentTraffic = false;
  preview.value = null;
  authorizationConfirmed.value = false;
  composerStep.value = "setup";
  composerVisible.value = true;
}

function lines(value: string): string[] {
  return [...new Set(value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean))];
}

function buildContract(writtenAuthorizationConfirmed: boolean): AssessmentContractInput {
  const id = projectId.value;
  if (id === null) throw new Error("请先选择项目");
  const ownershipPaths = lines(form.ownershipPaths);
  if (ownershipPaths.length && form.identityAProfileId === null) {
    throw new Error("声明资源归属前，请先选择身份 A");
  }
  return {
    projectId: id,
    startUrl: form.startUrl.trim(),
    excludedPaths: lines(form.excludedPaths),
    tlsPolicy: form.tlsPolicy,
    requestBudget: form.requestBudget,
    requestsPerSecond: form.requestsPerSecond,
    identityAProfileId: form.identityAProfileId,
    identityBProfileId: form.identityBProfileId,
    resourceOwnership: ownershipPaths.map((path) => ({
      path,
      ownerProfileId: form.identityAProfileId!,
    })),
    includeRecentTraffic: form.includeRecentTraffic,
    providerId: "",
    model: "",
    maxRounds: form.maxRounds,
    writtenAuthorizationConfirmed,
  };
}

async function previewContract() {
  if (!form.startUrl.trim()) {
    ElMessage.warning("请填写已授权目标的起始 URL");
    return;
  }
  if (
    form.identityAProfileId !== null &&
    form.identityAProfileId === form.identityBProfileId
  ) {
    ElMessage.warning("身份 A 与 B 必须选择不同的凭据档案");
    return;
  }
  previewing.value = true;
  try {
    preview.value = await previewAssessmentContract(buildContract(false));
    authorizationConfirmed.value = false;
    composerStep.value = "confirm";
  } catch (error) {
    ElMessage.error(String(error));
  } finally {
    previewing.value = false;
  }
}

async function startRun() {
  if (!authorizationConfirmed.value) return;
  previewing.value = true;
  try {
    const contract = buildContract(true);
    const finalPreview = await previewAssessmentContract(contract);
    preview.value = finalPreview;
    await assessment.start(contract, finalPreview.contractHash);
    composerVisible.value = false;
    ElMessage.success("评估已在后台启动；离开页面不会中断运行");
  } catch (error) {
    ElMessage.error(String(error));
  } finally {
    previewing.value = false;
  }
}

async function refresh() {
  const id = projectId.value;
  if (id === null) return;
  try {
    await assessment.refresh(id);
  } catch (error) {
    ElMessage.error(String(error));
  }
}

async function selectRun(run: AssessmentRun) {
  composerVisible.value = false;
  try {
    await assessment.selectRun(run.id);
  } catch (error) {
    ElMessage.error(String(error));
  }
}

async function cancelRun() {
  try {
    await ElMessageBox.confirm(
      "将终止当前 AI 或 HTTP 等待，并保存已经产生的脱敏证据与部分结果。不会自动恢复网络动作。",
      "停止本次评估",
      { type: "warning", confirmButtonText: "停止并保存", cancelButtonText: "继续运行" }
    );
    await assessment.cancel();
  } catch (error) {
    if (error === "cancel" || error === "close") return;
    ElMessage.error(String(error));
  }
}

function openProfileDialog() {
  profileForm.mode = "paste";
  profileForm.label = "";
  profileForm.headerName = "Authorization";
  profileForm.secret = "";
  profileForm.trafficId = null;
  profileTrafficManual.value = false;
  assessment.resetAuthCandidates();
  profileDialogVisible.value = true;
}

function refreshAuthCandidates() {
  profileForm.trafficId = null;
  void assessment.loadAuthCandidates(profileForm.headerName);
}

async function saveProfile() {
  if (!profileForm.label.trim()) {
    ElMessage.warning("请填写身份标签");
    return;
  }
  profileSaving.value = true;
  try {
    if (profileForm.mode === "paste") {
      if (!profileForm.secret) throw new Error("请填写 Header 值");
      await assessment.createProfile({
        label: profileForm.label.trim(),
        headerName: profileForm.headerName,
        secret: profileForm.secret,
      });
    } else {
      if (!profileForm.trafficId) throw new Error("请选择候选请求");
      await assessment.importProfile(
        profileForm.trafficId,
        profileForm.label.trim(),
        profileForm.headerName
      );
    }
    profileForm.secret = "";
    profileDialogVisible.value = false;
    ElMessage.success("身份已保存到系统凭据库；SQLite 不保存秘密值");
  } catch (error) {
    ElMessage.error(String(error));
  } finally {
    profileSaving.value = false;
  }
}

async function removeProfile(profile: AssessmentAuthProfile) {
  try {
    await ElMessageBox.confirm(
      `删除身份“${profile.label}”及其系统凭据？`,
      "删除身份",
      { type: "warning", confirmButtonText: "删除", cancelButtonText: "取消" }
    );
    await assessment.removeProfile(profile.id);
    if (form.identityAProfileId === profile.id) form.identityAProfileId = null;
    if (form.identityBProfileId === profile.id) form.identityBProfileId = null;
  } catch (error) {
    if (error === "cancel" || error === "close") return;
    ElMessage.error(String(error));
  }
}

async function openRunReport() {
  const id = projectId.value;
  const runId = selectedRun.value?.id;
  if (id === null || runId === undefined) return;
  reportVisible.value = true;
  reportLoading.value = true;
  reportMarkdown.value = "";
  try {
    reportMarkdown.value = await buildReport(id, runId);
  } catch (error) {
    reportVisible.value = false;
    ElMessage.error(String(error));
  } finally {
    reportLoading.value = false;
  }
}

async function exportRunReport() {
  const id = projectId.value;
  const runId = selectedRun.value?.id;
  if (id === null || runId === undefined) return;
  reportExporting.value = true;
  try {
    const result = await exportReport(id, false, runId);
    ElMessage.success(`报告已导出：${result.markdown_path}`);
  } catch (error) {
    ElMessage.error(String(error));
  } finally {
    reportExporting.value = false;
  }
}

function checkFor(verification: AssessmentVerification): AssessmentCheck | null {
  return checksById.value.get(verification.checkId) ?? null;
}

function checkLabel(verification: AssessmentVerification): string {
  const check = checkFor(verification);
  return check
    ? TEMPLATE_LABEL[check.templateId] ?? check.templateId
    : verification.verifierId;
}

function endpointLabel(verification: AssessmentVerification): string {
  const check = checkFor(verification);
  if (!check) return "未知端点";
  const endpoint = detail.value?.endpoints.find(
    (candidate) => candidate.id === check.endpointId
  );
  return endpoint?.path ?? check.requestedEndpointId;
}

function observationText(verification: AssessmentVerification): string {
  try {
    return JSON.stringify(verification.observations, null, 2);
  } catch {
    return String(verification.observations);
  }
}

function formatDate(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : new Intl.DateTimeFormat("zh-CN", {
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      }).format(date);
}

function shortHash(value: string): string {
  return value.length > 18 ? `${value.slice(0, 12)}…${value.slice(-6)}` : value;
}

function goFindings() {
  void router.push("/findings");
}
</script>

<template>
  <div class="assessment-page rf-page rf-page--inset">
    <PageHeader
      title="AI 安全评估"
      description="在后端只读安全边界内自动发现、规划、执行和验证；AI 不能生成请求或漏洞结论。"
    >
      <el-button v-if="project.current" :icon="Refresh" :loading="assessment.loading" @click="refresh">
        刷新
      </el-button>
      <el-button
        v-if="project.current && !assessment.isRunning && !composerVisible"
        type="primary"
        :icon="Plus"
        @click="resetComposer"
      >
        新评估
      </el-button>
    </PageHeader>

    <EmptyState
      v-if="!project.current"
      title="尚未选择项目"
      description="请先创建或选择一个包含书面授权 Scope 的项目。"
      centered
    >
      <template #icon><el-icon :size="22"><FolderOpened /></el-icon></template>
    </EmptyState>

    <template v-else>
      <el-alert
        class="safety-banner"
        type="info"
        :closable="false"
        show-icon
        title="强制安全边界：仅 GET / HEAD / OPTIONS、无正文、精确同源、单并发、不跟随重定向。"
      />

      <div class="workspace">
        <aside class="history-panel">
          <div class="panel-heading">
            <div>
              <strong>运行历史</strong>
              <span>中断与停止也保留部分结果</span>
            </div>
          </div>
          <div v-if="assessment.runs.length" class="run-list">
            <button
              v-for="run in assessment.runs"
              :key="run.id"
              type="button"
              class="run-row"
              :class="{ active: !composerVisible && assessment.selectedRunId === run.id }"
              @click="selectRun(run)"
            >
              <span class="run-row-top">
                <strong>#{{ run.id }}</strong>
                <el-tag size="small" :type="STATUS_TAG[run.status]" effect="plain">
                  {{ STATUS_LABEL[run.status] }}
                </el-tag>
              </span>
              <span class="run-origin">{{ run.exactOrigin }}</span>
              <span class="run-meta">
                {{ run.requestCount }}/{{ run.requestBudget }} 请求 · {{ formatDate(run.createdAt) }}
              </span>
            </button>
          </div>
          <div v-else class="history-empty">尚无评估记录</div>

          <div v-if="assessment.profiles.length" class="identity-list">
            <div class="identity-title">身份档案</div>
            <div v-for="profile in assessment.profiles" :key="profile.id" class="identity-row">
              <span>
                <strong>{{ profile.label }}</strong>
                <small>{{ profile.headerName }} · r{{ profile.secretRevision }}</small>
              </span>
              <button
                type="button"
                class="icon-action"
                :aria-label="`删除身份 ${profile.label}`"
                :disabled="assessment.isRunning"
                @click="removeProfile(profile)"
              >
                <el-icon><Close /></el-icon>
              </button>
            </div>
          </div>
          <el-button
            class="profile-button"
            :icon="Key"
            :disabled="assessment.isRunning"
            @click="openProfileDialog"
          >
            添加身份
          </el-button>
        </aside>

        <main class="main-panel" v-loading="assessment.loading">
          <section v-if="composerVisible" class="composer-card">
            <template v-if="composerStep === 'setup'">
              <div class="card-head">
                <span class="step-number">1</span>
                <div>
                  <h2>填写已授权目标</h2>
                  <p>无需预先抓包。RustForge 从这个 URL 开始，只跟随页面中实际出现的同源链接。</p>
                </div>
              </div>

              <el-form label-position="top" class="contract-form" @submit.prevent="previewContract">
                <el-form-item label="起始 URL" required>
                  <el-input
                    v-model="form.startUrl"
                    size="large"
                    placeholder="https://example.com/app"
                    spellcheck="false"
                    clearable
                  />
                  <div class="field-help">必须同时属于当前项目 Scope；最终只访问它的精确 scheme、host 和端口。</div>
                </el-form-item>

                <el-collapse v-model="advancedOpen" class="advanced-collapse">
                  <el-collapse-item name="advanced" title="高级选项（身份、排除路径与预算）">
                    <div class="advanced-grid">
                      <el-form-item label="身份 A（可选）">
                        <el-select v-model="form.identityAProfileId" clearable placeholder="匿名评估">
                          <el-option
                            v-for="item in assessment.profiles"
                            :key="item.id"
                            :label="`${item.label} · ${item.headerName}`"
                            :value="item.id"
                          />
                        </el-select>
                      </el-form-item>
                      <el-form-item label="身份 B（可选）">
                        <el-select v-model="form.identityBProfileId" clearable placeholder="不做双身份比较">
                          <el-option
                            v-for="item in assessment.profiles"
                            :key="item.id"
                            :label="`${item.label} · ${item.headerName}`"
                            :value="item.id"
                            :disabled="item.id === form.identityAProfileId"
                          />
                        </el-select>
                      </el-form-item>
                    </div>

                    <el-form-item label="仅属于身份 A 的资源路径（可选，每行一条）">
                      <el-input
                        v-model="form.ownershipPaths"
                        type="textarea"
                        :rows="2"
                        placeholder="/account/orders/123"
                      />
                      <div class="field-help">没有明确归属声明时，双身份结果最多标为疑似，不会自动确认越权。</div>
                    </el-form-item>

                    <el-form-item label="额外排除路径（可选，每行一条）">
                      <el-input
                        v-model="form.excludedPaths"
                        type="textarea"
                        :rows="2"
                        placeholder="/billing/&#10;/internal/archive/"
                      />
                      <div class="field-help">只能增加排除项；logout、delete、reset 等内置危险路径始终禁止。</div>
                    </el-form-item>

                    <div class="advanced-grid three">
                      <el-form-item label="最大请求数">
                        <el-input-number v-model="form.requestBudget" :min="1" :max="300" controls-position="right" />
                      </el-form-item>
                      <el-form-item label="每秒请求数">
                        <el-input-number
                          v-model="form.requestsPerSecond"
                          :min="0.1"
                          :max="2"
                          :step="0.1"
                          :precision="1"
                          controls-position="right"
                        />
                      </el-form-item>
                      <el-form-item label="TLS">
                        <el-select v-model="form.tlsPolicy">
                          <el-option label="严格校验证书（推荐）" value="strict" />
                          <el-option label="忽略无效证书" value="ignore_invalid" />
                        </el-select>
                      </el-form-item>
                    </div>
                    <el-checkbox v-model="form.includeRecentTraffic">
                      合并同 origin 最近的唯一 GET / HEAD Traffic 作为端点种子
                    </el-checkbox>
                  </el-collapse-item>
                </el-collapse>

                <div class="composer-actions">
                  <span>下一步只生成契约预览，不会建立网络连接。</span>
                  <el-button type="primary" size="large" :loading="previewing" @click="previewContract">
                    预览运行契约
                  </el-button>
                </div>
              </el-form>
            </template>

            <template v-else-if="preview">
              <div class="card-head">
                <span class="step-number">2</span>
                <div>
                  <h2>确认一次运行契约</h2>
                  <p>开始时后端会重建并比对 hash；Scope、身份、AI 或模板版本变化都会拒绝运行。</p>
                </div>
              </div>

              <div class="contract-summary">
                <div class="summary-primary">
                  <span>精确 origin</span>
                  <strong>{{ preview.exactOrigin }}</strong>
                </div>
                <dl>
                  <div><dt>允许动作</dt><dd>GET / HEAD / OPTIONS，无正文，不跟随重定向</dd></div>
                  <div><dt>预算</dt><dd>最多 {{ preview.requestBudget }} 请求，{{ preview.requestsPerSecond }}/秒，并发 1</dd></div>
                  <div><dt>发现预算</dt><dd>{{ preview.discoveryBudget }} 请求；其余保留给验证</dd></div>
                  <div><dt>身份</dt><dd>A：{{ preview.identityALabel ?? "无" }}；B：{{ preview.identityBLabel ?? "无" }}</dd></div>
                  <div><dt>AI</dt><dd>{{ preview.providerId }} / {{ preview.model }}，最多 {{ preview.maxRounds }} 轮</dd></div>
                  <div><dt>AI 可见数据</dt><dd>{{ preview.dataDisclosure.join("、") }}</dd></div>
                  <div><dt>模板注册表</dt><dd>{{ preview.templateRegistryVersion }} · {{ shortHash(preview.templateRegistryHash) }}</dd></div>
                  <div><dt>契约 hash</dt><dd class="mono">{{ shortHash(preview.contractHash) }}</dd></div>
                </dl>
              </div>

              <el-alert
                type="warning"
                :closable="false"
                show-icon
                :title="preview.residualRiskNotice"
              />
              <label class="authorization-check">
                <el-checkbox v-model="authorizationConfirmed" />
                <span>我确认已获得对该目标和 Scope 进行本次安全评估的书面授权，并理解上述残余风险。</span>
              </label>
              <div class="composer-actions">
                <el-button @click="composerStep = 'setup'">返回修改</el-button>
                <el-button
                  type="primary"
                  size="large"
                  :disabled="!authorizationConfirmed"
                  :loading="previewing || assessment.starting"
                  @click="startRun"
                >
                  确认并开始评估
                </el-button>
              </div>
            </template>
          </section>

          <template v-else-if="selectedRun">
            <section class="run-header-card">
              <div class="run-title-row">
                <div>
                  <span class="eyebrow">评估 #{{ selectedRun.id }}</span>
                  <h2>{{ selectedRun.exactOrigin }}</h2>
                  <p>{{ selectedRun.startUrl }}</p>
                </div>
                <div class="run-actions">
                  <el-tag :type="STATUS_TAG[selectedRun.status]" effect="dark">
                    {{ STATUS_LABEL[selectedRun.status] }}
                  </el-tag>
                  <el-button
                    v-if="selectedIsActive"
                    type="danger"
                    plain
                    :loading="assessment.cancelling"
                    @click="cancelRun"
                  >停止</el-button>
                  <template v-else>
                    <el-button :icon="Document" @click="openRunReport">报告</el-button>
                    <el-button type="primary" :icon="Plus" :disabled="assessment.isRunning" @click="resetComposer">
                      新评估
                    </el-button>
                  </template>
                </div>
              </div>

              <div class="phase-strip" role="list" aria-label="评估阶段">
                <div
                  v-for="(phase, index) in PHASES"
                  :key="phase.key"
                  class="phase-item"
                  :class="{
                    done: index < currentPhaseIndex || selectedRun.status === 'completed',
                    active: index === currentPhaseIndex && selectedRun.status !== 'completed',
                  }"
                  role="listitem"
                >
                  <span>{{ index + 1 }}</span>
                  <strong>{{ phase.label }}</strong>
                </div>
              </div>

              <div class="runtime-metrics">
                <div>
                  <span>目标请求</span>
                  <strong>{{ selectedRun.requestCount }} / {{ selectedRun.requestBudget }}</strong>
                  <el-progress :percentage="requestPercentage" :stroke-width="5" :show-text="false" />
                </div>
                <div><span>响应读取</span><strong>{{ (selectedRun.responseBytesRead / 1024 / 1024).toFixed(2) }} / {{ (selectedRun.responseByteBudget / 1024 / 1024).toFixed(2) }} MiB</strong></div>
                <div><span>AI 轮次</span><strong>{{ selectedRun.completedRounds }} / {{ selectedRun.maxRounds }}</strong></div>
                <div><span>端点</span><strong>{{ detail?.endpoints.length ?? 0 }}</strong></div>
              </div>

              <div v-if="selectedIsActive" class="live-progress" aria-live="polite">
                <span class="live-dot" />
                <div>
                  <strong>{{ assessment.progress?.message ?? "后台运行中" }}</strong>
                  <span>已验证 {{ assessment.progress?.completedChecks ?? detail?.verifications.length ?? 0 }} / {{ assessment.progress?.totalChecks ?? detail?.checks.length ?? 0 }} 项</span>
                </div>
              </div>
              <el-alert
                v-else-if="selectedRun.stopReason"
                :type="selectedRun.status === 'failed' ? 'error' : 'warning'"
                :closable="false"
                show-icon
                :title="selectedRun.stopReason"
              />
            </section>

            <section v-if="!selectedIsActive || (detail?.verifications.length ?? 0) > 0" class="results-grid">
              <article class="result-column confirmed-column">
                <header>
                  <span class="result-icon"><el-icon><CircleCheck /></el-icon></span>
                  <div><h3>已确认漏洞</h3><p>安全验证器已满足版本化证据阈值</p></div>
                  <strong>{{ confirmed.length }}</strong>
                </header>
                <div v-if="confirmed.length" class="result-list">
                  <button v-for="item in confirmed" :key="item.id" type="button" class="result-card" @click="goFindings">
                    <span class="result-card-title">{{ checkLabel(item) }}</span>
                    <span class="result-target">{{ endpointLabel(item) }}</span>
                    <small>Finding #{{ item.findingId }} · {{ item.verifierId }}@{{ item.verifierVersion }}</small>
                    <pre>{{ observationText(item) }}</pre>
                  </button>
                </div>
                <p v-else class="result-empty">本轮没有满足自动确认阈值的漏洞。</p>
              </article>

              <article class="result-column suspected-column">
                <header>
                  <span class="result-icon"><el-icon><Warning /></el-icon></span>
                  <div><h3>疑似漏洞</h3><p>存在迹象，但非破坏式证据不足</p></div>
                  <strong>{{ suspected.length }}</strong>
                </header>
                <div v-if="suspected.length" class="result-list">
                  <button v-for="item in suspected" :key="item.id" type="button" class="result-card" @click="goFindings">
                    <span class="result-card-title">{{ checkLabel(item) }}</span>
                    <span class="result-target">{{ endpointLabel(item) }}</span>
                    <small>{{ item.verifierId }}@{{ item.verifierVersion }}</small>
                    <pre>{{ observationText(item) }}</pre>
                  </button>
                </div>
                <p v-else class="result-empty">没有仅停留在疑似层级的验证结果。</p>
              </article>

              <article class="result-column neutral-column">
                <header>
                  <span class="result-icon"><el-icon><Aim /></el-icon></span>
                  <div><h3>未观察到</h3><p>本轮已执行，但验证器未命中</p></div>
                  <strong>{{ notObserved.length }}</strong>
                </header>
                <div v-if="notObserved.length" class="result-list">
                  <div v-for="item in notObserved" :key="item.id" class="result-card">
                    <span class="result-card-title">{{ checkLabel(item) }}</span>
                    <span class="result-target">{{ endpointLabel(item) }}</span>
                    <small>{{ item.verifierId }}@{{ item.verifierVersion }}</small>
                  </div>
                </div>
                <p v-else class="result-empty">尚无完整执行且未命中的检查。</p>
              </article>

              <article class="result-column gap-column">
                <header>
                  <span class="result-icon"><el-icon><Close /></el-icon></span>
                  <div><h3>覆盖缺口</h3><p>安全边界、预算或上下文限制</p></div>
                  <strong>{{ (detail?.coverageGaps.length ?? 0) + inconclusive.length }}</strong>
                </header>
                <div v-if="(detail?.coverageGaps.length ?? 0) || inconclusive.length" class="result-list">
                  <div v-for="gap in detail?.coverageGaps ?? []" :key="`gap-${gap.id}`" class="result-card">
                    <span class="result-card-title">{{ gap.category }}</span>
                    <span class="result-target">{{ gap.reasonCode }}</span>
                    <small>{{ gap.detail }}</small>
                  </div>
                  <div v-for="item in inconclusive" :key="`verification-${item.id}`" class="result-card">
                    <span class="result-card-title">{{ checkLabel(item) }}</span>
                    <span class="result-target">{{ item.verdict }}</span>
                    <small>{{ endpointLabel(item) }}</small>
                  </div>
                </div>
                <p v-else class="result-empty">没有额外覆盖缺口。</p>
              </article>
            </section>

            <section class="audit-card">
              <div class="panel-heading">
                <div><strong>运行审计</strong><span>事件、契约与验证结果均来自持久化数据</span></div>
              </div>
              <div class="audit-layout">
                <dl class="audit-facts">
                  <div><dt>契约</dt><dd class="mono">{{ shortHash(selectedRun.contractHash) }}</dd></div>
                  <div><dt>模板注册表</dt><dd class="mono">{{ shortHash(selectedRun.templateRegistryHash) }}</dd></div>
                  <div><dt>AI</dt><dd>{{ selectedRun.providerId }} / {{ selectedRun.model }}</dd></div>
                  <div><dt>TLS</dt><dd>{{ selectedRun.tlsPolicy }}</dd></div>
                  <div><dt>开始</dt><dd>{{ formatDate(selectedRun.startedAt ?? selectedRun.createdAt) }}</dd></div>
                  <div><dt>结束</dt><dd>{{ formatDate(selectedRun.endedAt) }}</dd></div>
                </dl>
                <div class="event-list">
                  <div v-for="event in (detail?.events ?? []).slice().reverse().slice(0, 12)" :key="event.id" class="event-row">
                    <span />
                    <div><strong>{{ event.eventType }}</strong><small>{{ event.oldValue ?? "—" }} → {{ event.newValue ?? "—" }} · {{ formatDate(event.createdAt) }}</small></div>
                  </div>
                  <p v-if="!detail?.events.length" class="result-empty">暂无审计事件。</p>
                </div>
              </div>
            </section>
          </template>

          <EmptyState
            v-else
            title="开始第一次 AI 安全评估"
            description="填写一个已授权起始 URL；不需要先抓取流量，也不需要手写测试计划。"
            action-label="配置评估"
            centered
            @action="resetComposer"
          >
            <template #icon><el-icon :size="22"><Aim /></el-icon></template>
          </EmptyState>
        </main>
      </div>
    </template>

    <el-dialog v-model="profileDialogVisible" title="添加评估身份" width="540px" destroy-on-close>
      <el-alert
        type="info"
        :closable="false"
        show-icon
        title="秘密值只写入系统凭据库；界面、SQLite、AI 上下文、事件和报告只使用身份占位符。"
      />
      <el-form label-position="top" class="profile-form">
        <el-form-item label="来源">
          <el-segmented v-model="profileForm.mode" :options="[{ label: '粘贴 Header', value: 'paste' }, { label: '从 Traffic 提取', value: 'traffic' }]" />
        </el-form-item>
        <div class="advanced-grid">
          <el-form-item label="身份标签" required>
            <el-input v-model="profileForm.label" placeholder="例如：普通用户 A" maxlength="80" />
          </el-form-item>
          <el-form-item label="鉴权 Header" required>
            <el-select v-model="profileForm.headerName">
              <el-option label="Authorization" value="Authorization" />
              <el-option label="Cookie" value="Cookie" />
              <el-option label="X-API-Key" value="X-API-Key" />
              <el-option label="X-Auth-Token" value="X-Auth-Token" />
            </el-select>
          </el-form-item>
        </div>
        <el-form-item v-if="profileForm.mode === 'paste'" label="Header 值" required>
          <el-input
            v-model="profileForm.secret"
            type="password"
            show-password
            autocomplete="new-password"
            placeholder="只粘贴值，不包含 Header 名称"
          />
        </el-form-item>
        <el-form-item v-else label="候选请求" required>
          <template #label>
            <span class="candidate-label">
              候选请求
              <el-tooltip content="重新扫描近期流量" placement="top">
                <el-button
                  class="candidate-refresh"
                  text
                  :icon="Refresh"
                  :loading="assessment.authCandidatesLoading"
                  :aria-label="`重新扫描 ${profileForm.headerName} 候选`"
                  @click.stop="refreshAuthCandidates"
                />
              </el-tooltip>
            </span>
          </template>
          <template v-if="!profileTrafficManual">
            <div v-if="assessment.authCandidatesLoading" class="candidate-hint">
              正在扫描近期流量…
            </div>
            <el-alert
              v-else-if="assessment.authCandidatesError"
              type="error"
              :closable="false"
              show-icon
              class="candidate-error"
              :title="`候选扫描失败：${assessment.authCandidatesError}`"
            />
            <el-radio-group
              v-else-if="assessment.authCandidates.length"
              v-model="profileForm.trafficId"
              class="candidate-list"
            >
              <el-radio
                v-for="candidate in assessment.authCandidates"
                :key="candidate.trafficId"
                :value="candidate.trafficId"
                class="candidate-row"
                border
              >
                <span class="candidate-method">{{ candidate.method }}</span>
                <span class="candidate-url">{{ candidate.url }}</span>
                <span class="candidate-meta">
                  {{ candidate.status ?? "—" }} · {{ formatDate(candidate.createdAt) }}
                </span>
              </el-radio>
            </el-radio-group>
            <el-empty
              v-else
              description="近期流量中没有包含该 Header 的请求"
              :image-size="56"
            />
          </template>
          <el-input-number
            v-else
            v-model="profileForm.trafficId"
            :min="1"
            :precision="0"
            controls-position="right"
            class="candidate-manual"
          />
          <div class="field-help">
            只读取所选请求的这一项 Header，不会复用其他 Header 或正文；若列表为空，可先在抓包页产生该 Header 的流量后刷新。
          </div>
          <el-button
            v-if="profileForm.mode === 'traffic'"
            text
            type="primary"
            class="candidate-toggle"
            @click="toggleTrafficManual"
          >
            {{ profileTrafficManual ? "返回候选列表" : "手动输入 Traffic ID" }}
          </el-button>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="profileDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="profileSaving" @click="saveProfile">保存到系统凭据库</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="reportVisible" title="本次评估报告" width="min(940px, 92vw)" top="5vh">
      <div v-loading="reportLoading" class="report-preview" v-html="md.render(reportMarkdown)" />
      <template #footer>
        <el-button @click="reportVisible = false">关闭</el-button>
        <el-button type="primary" :icon="Document" :loading="reportExporting" @click="exportRunReport">
          导出 Markdown + JSON
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.assessment-page {
  min-height: 0;
}

.safety-banner {
  flex-shrink: 0;
}

.workspace {
  flex: 1;
  min-height: 0;
  display: grid;
  grid-template-columns: 240px minmax(0, 1fr);
  gap: var(--rf-space-3);
}

.history-panel,
.main-panel,
.composer-card,
.run-header-card,
.result-column,
.audit-card {
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-shell);
  background: var(--rf-bg-panel);
}

.history-panel {
  min-height: 0;
  padding: var(--rf-space-3);
  display: flex;
  flex-direction: column;
  gap: var(--rf-space-3);
  overflow: auto;
}

.main-panel {
  min-width: 0;
  min-height: 0;
  padding: var(--rf-space-3);
  display: flex;
  flex-direction: column;
  gap: var(--rf-space-3);
  overflow: auto;
  background: color-mix(in srgb, var(--rf-bg-panel) 72%, var(--rf-bg-base));
}

.panel-heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.panel-heading > div {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.panel-heading strong,
.identity-title {
  font-size: 12.5px;
  color: var(--rf-text);
}

.panel-heading span {
  font-size: 11px;
  color: var(--rf-text-muted);
}

.run-list {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.run-row {
  width: 100%;
  padding: 9px 10px;
  border: 1px solid transparent;
  border-radius: 10px;
  background: transparent;
  color: inherit;
  text-align: left;
  cursor: pointer;
  display: flex;
  flex-direction: column;
  gap: 5px;
}

.run-row:hover {
  background: var(--rf-bg-hover);
}

.run-row.active {
  border-color: var(--rf-accent);
  background: var(--rf-accent-muted);
}

.run-row-top {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.run-row-top strong {
  font-size: 12px;
}

.run-origin {
  font-size: 11.5px;
  color: var(--rf-text-secondary);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.run-meta,
.history-empty {
  font-size: 10.5px;
  color: var(--rf-text-muted);
}

.history-empty {
  padding: 24px 8px;
  text-align: center;
  border: 1px dashed var(--rf-border);
  border-radius: 10px;
}

.identity-list {
  padding-top: var(--rf-space-2);
  border-top: 1px solid var(--rf-border);
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.identity-title {
  margin-bottom: 2px;
}

.identity-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding: 7px 8px;
  border-radius: 8px;
  background: var(--rf-bg-raised);
}

.identity-row > span {
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.identity-row strong {
  font-size: 11.5px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.identity-row small {
  font-size: 10px;
  color: var(--rf-text-muted);
}

.icon-action {
  border: 0;
  background: transparent;
  color: var(--rf-text-muted);
  cursor: pointer;
  padding: 3px;
}

.icon-action:hover:not(:disabled) {
  color: var(--rf-danger);
}

.profile-button {
  width: 100%;
  margin-top: auto;
}

.candidate-label {
  display: inline-flex;
  align-items: center;
  gap: 4px;
}

.candidate-refresh {
  padding: 0;
  margin: 0;
}

.candidate-hint {
  padding: 10px 0;
  font-size: 12px;
  color: var(--rf-text-muted);
}

.candidate-list {
  display: flex;
  flex-direction: column;
  gap: 6px;
  width: 100%;
  max-height: 220px;
  overflow-y: auto;
}

.candidate-row {
  display: flex;
  align-items: center;
  gap: 10px;
  width: 100%;
  height: auto;
  margin-right: 0;
  padding: 7px 10px;
}

/* Element Plus 的 el-radio 内部 label 默认是 inline 布局；这里把插槽内容
   变成 flex 容器，长 URL 才能用 ellipsis 收进一行而不是溢出对话框。 */
.candidate-row :deep(.el-radio__label) {
  flex: 1;
  min-width: 0;
  display: flex;
  align-items: center;
  gap: 10px;
  white-space: nowrap;
}

.candidate-method {
  flex-shrink: 0;
  font-size: 11px;
  font-weight: 600;
  font-family: var(--rf-mono, ui-monospace, monospace);
  color: var(--rf-accent, var(--el-color-primary));
}

.candidate-url {
  flex: 1;
  min-width: 0;
  font-size: 12px;
  overflow: hidden;
  text-overflow: ellipsis;
}

.candidate-meta {
  flex-shrink: 0;
  font-size: 10.5px;
  color: var(--rf-text-muted);
}

.candidate-error {
  margin-bottom: 6px;
}

.candidate-manual {
  width: 100%;
}

.candidate-toggle {
  padding: 0;
  margin-top: 2px;
  font-size: 12px;
}

.composer-card {
  width: min(780px, 100%);
  margin: auto;
  padding: clamp(22px, 4vw, 36px);
}

.card-head {
  display: flex;
  gap: 14px;
  align-items: flex-start;
  margin-bottom: 24px;
}

.step-number {
  width: 30px;
  height: 30px;
  flex-shrink: 0;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border-radius: 50%;
  background: var(--rf-accent);
  color: var(--rf-accent-on);
  font-weight: 750;
}

.card-head h2,
.run-title-row h2 {
  margin: 0;
  font-size: 19px;
  color: var(--rf-text);
}

.card-head p,
.run-title-row p {
  margin: 4px 0 0;
  font-size: 12.5px;
  line-height: 1.55;
  color: var(--rf-text-secondary);
}

.contract-form,
.profile-form {
  display: flex;
  flex-direction: column;
}

.field-help {
  margin-top: 5px;
  font-size: 11px;
  line-height: 1.5;
  color: var(--rf-text-muted);
}

.advanced-collapse {
  margin: 2px 0 18px;
  border-color: var(--rf-border);
}

.advanced-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0 var(--rf-space-3);
}

.advanced-grid.three {
  grid-template-columns: repeat(3, minmax(0, 1fr));
}

.advanced-grid :deep(.el-select),
.advanced-grid :deep(.el-input-number) {
  width: 100%;
}

.composer-actions {
  display: flex;
  justify-content: flex-end;
  align-items: center;
  gap: var(--rf-space-2);
  margin-top: 18px;
}

.composer-actions > span {
  margin-right: auto;
  font-size: 11px;
  color: var(--rf-text-muted);
}

.contract-summary {
  border: 1px solid var(--rf-border);
  border-radius: 12px;
  overflow: hidden;
  margin-bottom: var(--rf-space-3);
}

.summary-primary {
  padding: 15px 17px;
  display: flex;
  flex-direction: column;
  gap: 4px;
  background: var(--rf-accent-muted);
}

.summary-primary span,
.contract-summary dt {
  font-size: 10.5px;
  color: var(--rf-text-muted);
}

.summary-primary strong {
  font-size: 16px;
  word-break: break-all;
}

.contract-summary dl,
.audit-facts {
  margin: 0;
}

.contract-summary dl > div,
.audit-facts > div {
  display: grid;
  grid-template-columns: 130px 1fr;
  gap: 12px;
  padding: 9px 16px;
  border-top: 1px solid var(--rf-border);
}

.contract-summary dd,
.audit-facts dd {
  margin: 0;
  font-size: 11.5px;
  color: var(--rf-text-secondary);
  overflow-wrap: anywhere;
}

.authorization-check {
  margin-top: var(--rf-space-3);
  display: flex;
  gap: 8px;
  align-items: flex-start;
  padding: 13px;
  border: 1px solid var(--rf-border-strong);
  border-radius: 10px;
  cursor: pointer;
}

.authorization-check span {
  font-size: 12px;
  line-height: 1.55;
}

.run-header-card,
.audit-card {
  padding: var(--rf-space-4);
}

.run-title-row {
  display: flex;
  justify-content: space-between;
  gap: var(--rf-space-3);
}

.run-title-row h2 {
  overflow-wrap: anywhere;
}

.run-title-row p {
  word-break: break-all;
}

.eyebrow {
  display: block;
  margin-bottom: 4px;
  color: var(--rf-accent);
  font-size: 10.5px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.08em;
}

.run-actions {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  flex-shrink: 0;
}

.phase-strip {
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  gap: 4px;
  margin: 22px 0 18px;
}

.phase-item {
  position: relative;
  display: flex;
  align-items: center;
  gap: 7px;
  padding: 8px 9px;
  border-radius: 9px;
  background: var(--rf-bg-raised);
  color: var(--rf-text-muted);
}

.phase-item span {
  width: 20px;
  height: 20px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border-radius: 50%;
  border: 1px solid var(--rf-border-strong);
  font-size: 10px;
}

.phase-item strong {
  font-size: 11px;
}

.phase-item.done {
  color: var(--rf-success);
  background: color-mix(in srgb, var(--rf-success) 10%, var(--rf-bg-panel));
}

.phase-item.active {
  color: var(--rf-accent);
  background: var(--rf-accent-muted);
}

.phase-item.active span,
.phase-item.done span {
  border-color: currentColor;
}

.runtime-metrics {
  display: grid;
  grid-template-columns: 1.4fr repeat(3, 1fr);
  border: 1px solid var(--rf-border);
  border-radius: 10px;
  overflow: hidden;
}

.runtime-metrics > div {
  min-width: 0;
  padding: 10px 12px;
  display: flex;
  flex-direction: column;
  gap: 4px;
  border-left: 1px solid var(--rf-border);
}

.runtime-metrics > div:first-child {
  border-left: 0;
}

.runtime-metrics span {
  font-size: 10px;
  color: var(--rf-text-muted);
}

.runtime-metrics strong {
  font-size: 13px;
}

.live-progress {
  margin-top: var(--rf-space-3);
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 12px;
  border-radius: 10px;
  background: var(--rf-accent-muted);
}

.live-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--rf-accent);
  box-shadow: 0 0 0 5px color-mix(in srgb, var(--rf-accent) 17%, transparent);
  animation: pulse 1.6s ease-in-out infinite;
}

.live-progress > div {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.live-progress strong {
  font-size: 11.5px;
}

.live-progress span {
  font-size: 10.5px;
  color: var(--rf-text-secondary);
}

.results-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: var(--rf-space-3);
}

.result-column {
  min-width: 0;
  overflow: hidden;
}

.result-column > header {
  padding: 13px 14px;
  display: grid;
  grid-template-columns: auto 1fr auto;
  gap: 10px;
  align-items: center;
  border-bottom: 1px solid var(--rf-border);
}

.result-icon {
  width: 28px;
  height: 28px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border-radius: 8px;
  background: var(--rf-bg-raised);
}

.result-column h3 {
  margin: 0;
  font-size: 13px;
}

.result-column header p {
  margin: 2px 0 0;
  font-size: 10.5px;
  color: var(--rf-text-muted);
}

.result-column header > strong {
  font-size: 20px;
}

.confirmed-column .result-icon,
.confirmed-column header > strong { color: var(--rf-success); }
.suspected-column .result-icon,
.suspected-column header > strong { color: var(--rf-warning); }
.neutral-column .result-icon,
.neutral-column header > strong { color: var(--rf-accent); }
.gap-column .result-icon,
.gap-column header > strong { color: var(--rf-text-secondary); }

.result-list {
  max-height: 360px;
  overflow: auto;
  padding: 8px;
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.result-card {
  width: 100%;
  min-width: 0;
  padding: 9px 10px;
  border: 1px solid var(--rf-border);
  border-radius: 8px;
  background: var(--rf-bg-raised);
  color: inherit;
  text-align: left;
  display: flex;
  flex-direction: column;
  gap: 3px;
}

button.result-card {
  cursor: pointer;
}

button.result-card:hover {
  border-color: var(--rf-accent);
}

.result-card-title {
  font-size: 11.5px;
  font-weight: 650;
}

.result-target {
  font-size: 10.5px;
  color: var(--rf-accent);
  overflow-wrap: anywhere;
}

.result-card small {
  font-size: 10px;
  line-height: 1.45;
  color: var(--rf-text-muted);
  overflow-wrap: anywhere;
}

.result-card pre {
  margin: 5px 0 0;
  max-height: 110px;
  overflow: auto;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  font: 10px/1.45 ui-monospace, SFMono-Regular, Consolas, monospace;
  color: var(--rf-text-secondary);
}

.result-empty {
  margin: 0;
  padding: 24px 14px;
  font-size: 11px;
  text-align: center;
  color: var(--rf-text-muted);
}

.audit-layout {
  display: grid;
  grid-template-columns: minmax(260px, 0.8fr) minmax(300px, 1.2fr);
  gap: var(--rf-space-4);
  margin-top: var(--rf-space-3);
}

.audit-facts {
  border: 1px solid var(--rf-border);
  border-radius: 9px;
  overflow: hidden;
}

.audit-facts > div:first-child {
  border-top: 0;
}

.event-list {
  max-height: 250px;
  overflow: auto;
  display: flex;
  flex-direction: column;
  gap: 9px;
}

.event-row {
  display: grid;
  grid-template-columns: 8px 1fr;
  gap: 9px;
  align-items: start;
}

.event-row > span {
  width: 7px;
  height: 7px;
  margin-top: 4px;
  border-radius: 50%;
  background: var(--rf-border-strong);
}

.event-row > div {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.event-row strong { font-size: 11px; }
.event-row small { font-size: 10px; color: var(--rf-text-muted); }

.mono {
  font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
}

.profile-form {
  margin-top: var(--rf-space-3);
}

.report-preview {
  min-height: 220px;
  max-height: 72vh;
  overflow: auto;
  padding: 4px 12px;
  line-height: 1.65;
}

.report-preview :deep(pre) {
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}

@keyframes pulse {
  0%, 100% { opacity: 0.55; }
  50% { opacity: 1; }
}

@media (max-width: 900px) {
  .workspace { grid-template-columns: 190px minmax(0, 1fr); }
  .results-grid { grid-template-columns: 1fr; }
  .runtime-metrics { grid-template-columns: repeat(2, 1fr); }
  .runtime-metrics > div:nth-child(3) { border-left: 0; border-top: 1px solid var(--rf-border); }
  .runtime-metrics > div:nth-child(4) { border-top: 1px solid var(--rf-border); }
  .audit-layout { grid-template-columns: 1fr; }
}

@media (max-width: 680px) {
  .workspace { grid-template-columns: 1fr; }
  .history-panel { max-height: 250px; }
  .advanced-grid,
  .advanced-grid.three { grid-template-columns: 1fr; }
  .phase-item strong { display: none; }
  .run-title-row { flex-direction: column; }
  .run-actions { align-self: flex-start; }
}
</style>
