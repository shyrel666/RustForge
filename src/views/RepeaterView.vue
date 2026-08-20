<script setup lang="ts">
import {
  Connection,
  DocumentCopy,
  Link,
  Promotion,
} from "@element-plus/icons-vue";
import { computed, onBeforeUnmount, ref, watch } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";
import {
  compareReplayRuns,
  createFindingEvidence,
  createTaskEvidence,
  getTaskTree,
  listFindings,
  type Finding,
  type ReplayRunDiff,
  type ReplayRunSummary,
  type TaskNode,
  type TlsPolicy,
} from "../api/tauri";
import { useProjectStore } from "../stores/project";
import { useRepeaterStore } from "../stores/repeater";
import type { ReplayWarningConfirmation } from "../utils/repeaterDraft";
import EmptyState from "../components/shell/EmptyState.vue";
import PageHeader from "../components/shell/PageHeader.vue";
import ReplayDiff from "../components/ReplayDiff.vue";
import ReplayHistory from "../components/ReplayHistory.vue";

const rep = useRepeaterStore();
const project = useProjectStore();
const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
let authorizationTimer: ReturnType<typeof setTimeout> | null = null;

const sessionTitle = ref("");
const sessionTlsPolicy = ref<TlsPolicy>("ignore_invalid");
const diffVisible = ref(false);
const diffLoading = ref(false);
const diffData = ref<ReplayRunDiff | null>(null);
const linkVisible = ref(false);
const linkLoading = ref(false);
const linkRun = ref<ReplayRunSummary | null>(null);
const linkTargetType = ref<"finding" | "task">("finding");
const linkTargetId = ref<number | null>(null);
const linkObservation = ref("");
const linkFindings = ref<Finding[]>([]);
const linkTasks = ref<TaskNode[]>([]);
let diffLoadId = 0;
let linkLoadId = 0;

const currentProjectId = computed(() => project.current?.id ?? null);
const canSend = computed(
  () =>
    rep.activeSessionId !== null &&
    !rep.sending &&
    !rep.loadingWorkspace &&
    !rep.loadingRuns &&
    !rep.checkingAuthorization &&
    rep.authorization !== null &&
    rep.authorizationProjectId === currentProjectId.value &&
    rep.authorizationUrl === rep.draft.url.trim()
);
const linkRunQualifies = computed(() => {
  const run = linkRun.value;
  return (
    run !== null &&
    run.status !== null &&
    (run.outcome === "completed" || run.outcome === "response_incomplete")
  );
});
const linkTargets = computed(() =>
  linkTargetType.value === "finding"
    ? linkFindings.value.map((finding) => ({
        id: finding.id,
        label: `#${finding.id} · ${finding.title}`,
      }))
    : linkTasks.value.map((task) => ({
        id: task.id,
        label: `#${task.id} · ${task.title}`,
      }))
);

function scheduleAuthorizationCheck() {
  rep.clearAuthorization();
  if (authorizationTimer) clearTimeout(authorizationTimer);
  authorizationTimer = setTimeout(() => {
    authorizationTimer = null;
    void rep.checkAuthorization(currentProjectId.value);
  }, 200);
}

async function sendRequest() {
  if (!canSend.value) return;
  if (authorizationTimer) {
    clearTimeout(authorizationTimer);
    authorizationTimer = null;
  }
  let warningConfirmation: ReplayWarningConfirmation | null = null;
  if (rep.sourceReplayWarning) {
    const projectId = currentProjectId.value;
    const sessionId = rep.activeSessionId;
    const warning = rep.sourceReplayWarning;
    if (projectId === null || sessionId === null) return;
    try {
      await ElMessageBox.confirm(
        `${warning} 发送后可能产生与原请求不同的副作用，run 会记录实际输入和截断状态。仍要发送吗？`,
        "确认发送不能精确还原的正文",
        {
          type: "warning",
          confirmButtonText: "确认按当前内容发送",
          cancelButtonText: "取消",
        }
      );
      if (
        currentProjectId.value !== projectId ||
        rep.activeSessionId !== sessionId ||
        rep.sourceReplayWarning !== warning
      ) {
        return;
      }
      warningConfirmation = { projectId, sessionId, warning };
    } catch {
      return;
    }
  }
  if (!canSend.value) return;
  await rep.send(warningConfirmation);
}

async function handleTabsEdit(
  targetName: string | number | undefined,
  action: "remove" | "add"
) {
  const projectId = currentProjectId.value;
  if (projectId === null) return;
  if (action === "add") {
    try {
      await rep.addSession(projectId);
    } catch (error) {
      ElMessage.error(String(error));
    }
    return;
  }
  const sessionId = Number(targetName);
  const session = rep.sessions.find((item) => item.id === sessionId);
  if (!session) return;
  try {
    await ElMessageBox.confirm(
      `删除会话“${session.title}”会同时删除其 ${session.run_count} 条运行历史，且不能恢复。`,
      "删除 Repeater 会话",
      {
        type: "warning",
        confirmButtonText: "删除会话与历史",
        cancelButtonText: "取消",
      }
    );
  } catch {
    return;
  }
  try {
    await rep.removeSession(sessionId);
  } catch (error) {
    ElMessage.error(String(error));
  }
}

async function saveSessionSettings() {
  const active = rep.activeSession;
  const projectId = currentProjectId.value;
  const title = sessionTitle.value.trim();
  if (!active || !title || active.project_id !== projectId) return;
  try {
    await rep.saveActiveSession(title, sessionTlsPolicy.value);
  } catch (error) {
    ElMessage.error(String(error));
    if (
      rep.activeSessionId === active.id &&
      currentProjectId.value === projectId
    ) {
      sessionTitle.value = active.title;
      sessionTlsPolicy.value = active.tls_policy;
    }
  }
}

async function changeTlsPolicy(value: TlsPolicy) {
  const active = rep.activeSession;
  const projectId = currentProjectId.value;
  if (!active || active.project_id !== projectId) return;
  if (value === "ignore_invalid") {
    try {
      await ElMessageBox.confirm(
        "忽略证书错误会降低 TLS 身份校验强度，但便于人工检查测试环境。该策略会写入之后的每次 run。",
        "启用忽略证书错误",
        {
          type: "warning",
          confirmButtonText: "启用并记录",
          cancelButtonText: "保持严格校验",
        }
      );
    } catch {
      if (
        rep.activeSessionId === active.id &&
        currentProjectId.value === projectId
      ) {
        sessionTlsPolicy.value = active.tls_policy;
      }
      return;
    }
  }
  if (
    rep.activeSessionId !== active.id ||
    currentProjectId.value !== projectId
  ) {
    return;
  }
  await saveSessionSettings();
}

async function showDiff(leftRunId: number, rightRunId: number) {
  const projectId = currentProjectId.value;
  if (projectId === null) return;
  const loadId = ++diffLoadId;
  diffVisible.value = true;
  diffLoading.value = true;
  diffData.value = null;
  try {
    const result = await compareReplayRuns(projectId, leftRunId, rightRunId);
    if (loadId !== diffLoadId || currentProjectId.value !== projectId) return;
    diffData.value = result;
  } catch (error) {
    if (loadId !== diffLoadId) return;
    diffVisible.value = false;
    ElMessage.error(String(error));
  } finally {
    if (loadId === diffLoadId) diffLoading.value = false;
  }
}

async function openEvidenceLink(run: ReplayRunSummary) {
  const projectId = currentProjectId.value;
  if (projectId === null || run.project_id !== projectId) return;
  const loadId = ++linkLoadId;
  linkRun.value = run;
  linkVisible.value = true;
  linkLoading.value = true;
  linkTargetId.value = null;
  linkObservation.value =
    run.status === null
      ? `人工重放 run #${run.id}：${run.error_message || run.outcome}`
      : `人工重放 run #${run.id} 返回 HTTP ${run.status}，耗时 ${run.duration_ms} ms`;
  try {
    const [findings, tasks] = await Promise.all([
      listFindings(projectId),
      getTaskTree(projectId),
    ]);
    if (
      loadId !== linkLoadId ||
      currentProjectId.value !== projectId ||
      linkRun.value?.id !== run.id
    ) {
      return;
    }
    linkFindings.value = findings;
    linkTasks.value = tasks;
    linkTargetType.value = linkFindings.value.length > 0 ? "finding" : "task";
    linkTargetId.value = linkTargets.value[0]?.id ?? null;
  } catch (error) {
    if (loadId !== linkLoadId) return;
    ElMessage.error(String(error));
  } finally {
    if (loadId === linkLoadId) linkLoading.value = false;
  }
}

async function submitEvidenceLink() {
  const run = linkRun.value;
  const targetId = linkTargetId.value;
  const projectId = currentProjectId.value;
  const targetType = linkTargetType.value;
  const observation = linkObservation.value.trim();
  if (
    !run ||
    targetId === null ||
    !observation ||
    projectId === null ||
    run.project_id !== projectId
  ) {
    return;
  }
  const loadId = ++linkLoadId;
  const qualifiesForConfirmation = linkRunQualifies.value;
  linkLoading.value = true;
  try {
    if (targetType === "finding") {
      await createFindingEvidence(
        targetId,
        "replay_run",
        run.id,
        observation
      );
    } else {
      await createTaskEvidence(
        targetId,
        "replay_run",
        run.id,
        observation
      );
    }
    if (
      loadId !== linkLoadId ||
      currentProjectId.value !== projectId ||
      linkRun.value?.id !== run.id
    ) {
      return;
    }
    ElMessage.success(
      targetType === "task"
        ? "已关联为任务 Evidence"
        : qualifiesForConfirmation
          ? "已关联为 Finding Evidence；仍需人工接受后才能用于确认"
          : "已关联为审计 Evidence；该运行没有可用响应，不能单独用于确认 Finding"
    );
    linkVisible.value = false;
  } catch (error) {
    if (
      loadId !== linkLoadId ||
      currentProjectId.value !== projectId ||
      linkRun.value?.id !== run.id
    ) {
      return;
    }
    ElMessage.error(String(error));
  } finally {
    if (loadId === linkLoadId) linkLoading.value = false;
  }
}

function statusType(
  status: number | null
): "success" | "info" | "warning" | "danger" {
  if (status === null) return "danger";
  const group = Math.floor(status / 100);
  return group === 2
    ? "success"
    : group === 3
      ? "info"
      : group === 4
        ? "warning"
        : "danger";
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

watch(
  currentProjectId,
  async (projectId) => {
    diffLoadId += 1;
    linkLoadId += 1;
    diffVisible.value = false;
    diffLoading.value = false;
    linkVisible.value = false;
    linkLoading.value = false;
    linkRun.value = null;
    if (projectId === null) rep.resetWorkspace();
    else await rep.loadWorkspace(projectId);
  },
  { immediate: true }
);

watch(
  () => rep.activeSession,
  (session) => {
    if (!session) return;
    sessionTitle.value = session.title;
    sessionTlsPolicy.value = session.tls_policy;
  },
  { immediate: true }
);

watch(
  [
    () => project.current?.id ?? null,
    () => project.current?.scope.join("\u0000") ?? "",
    () => rep.draft.url,
  ],
  scheduleAuthorizationCheck,
  { immediate: true }
);

watch(linkTargetType, () => {
  linkTargetId.value = linkTargets.value[0]?.id ?? null;
});

onBeforeUnmount(() => {
  rep.stashDraft();
  if (authorizationTimer) clearTimeout(authorizationTimer);
});
</script>

<template>
  <div class="rep-page rf-page rf-page--inset">
    <PageHeader
      title="HTTP 重放测试工作台 (Repeater)"
      description="多会话改包测试与差分比对；发送结果不可变归档并支持一键关联为漏洞证据。"
    />

    <EmptyState
      v-if="!project.current"
      title="请先选择测试项目"
      description="Repeater 会话、Scope 白名单与 Evidence 链严格归属于项目目标。"
    >
      <template #icon><el-icon :size="20"><Connection /></el-icon></template>
    </EmptyState>

    <template v-else>
      <!-- 会话标签页 -->
      <el-tabs
        :model-value="rep.activeSessionId === null ? '' : String(rep.activeSessionId)"
        type="card"
        editable
        class="session-tabs"
        @tab-change="(name: string | number) => rep.activateSession(Number(name))"
        @edit="handleTabsEdit"
      >
        <el-tab-pane
          v-for="session in rep.sessions"
          :key="session.id"
          :name="String(session.id)"
        >
          <template #label>
            <span class="tab-label" :title="session.title">
              <span class="tab-title">{{ session.title }}</span>
              <span v-if="session.run_count" class="tab-count mono">{{ session.run_count }}</span>
            </span>
          </template>
        </el-tab-pane>
      </el-tabs>

      <!-- 会话属性与策略条 -->
      <div v-if="rep.activeSession" class="session-policy">
        <el-input
          v-model="sessionTitle"
          size="small"
          maxlength="120"
          class="session-title-input"
          placeholder="会话名称"
          @change="saveSessionSettings"
        />
        <span class="policy-label">TLS 校验:</span>
        <el-select
          v-model="sessionTlsPolicy"
          size="small"
          class="tls-select"
          @change="changeTlsPolicy"
        >
          <el-option label="严格校验证书" value="strict" />
          <el-option label="忽略证书错误（已审计）" value="ignore_invalid" />
        </el-select>
        <el-tag
          v-if="sessionTlsPolicy === 'ignore_invalid'"
          size="small"
          type="warning"
        >
          TLS 校验已放宽
        </el-tag>
        <span v-if="rep.activeSession.source_traffic_id" class="source-label mono">
          源自 Traffic #{{ rep.activeSession.source_traffic_id }}
        </span>
      </div>

      <!-- 人工接力横幅 -->
      <section
        v-if="rep.activeAssessmentHandoff"
        class="assessment-handoff-banner"
        aria-live="polite"
      >
        <div class="handoff-header">
          <el-tag size="small" type="warning">AI 评估接力草稿</el-tag>
          <strong>
            Mission #{{ rep.activeAssessmentHandoff.missionId }} ·
            {{ rep.activeAssessmentHandoff.recipeId }}@{{ rep.activeAssessmentHandoff.recipeVersion }}
          </strong>
        </div>
        <p class="handoff-instruction">
          {{ rep.activeAssessmentHandoff.draft.proposedDifference?.instructions }}
          已自动填入草稿参数；请人工审查后点击发送。
        </p>
        <code class="handoff-hash">draft hash: {{ rep.activeAssessmentHandoff.draftHash }}</code>
      </section>

      <!-- 请求发送控制条 -->
      <div class="rf-toolbar request-toolbar">
        <div class="rf-toolbar-group request-bar">
          <el-select v-model="rep.draft.method" class="method" size="default">
            <el-option
              v-for="method in METHODS"
              :key="method"
              :label="method"
              :value="method"
            />
          </el-select>
          <el-input
            v-model="rep.draft.url"
            placeholder="https://target.example.com/path?a=1"
            class="url mono"
            @keyup.ctrl.enter="sendRequest"
          />
        </div>
        <el-button
          type="primary"
          :icon="Promotion"
          :loading="rep.sending"
          :disabled="!canSend"
          @click="sendRequest"
        >
          发送请求 <span class="rf-kbd" style="margin-left: 6px;">Ctrl + ↵</span>
        </el-button>
      </div>

      <!-- Scope 授权校验条 -->
      <div class="scope-bar">
        <div class="scope-notice">向目标发送真实网络请求；不自动跟随重定向。后端在发送前严格复核 Scope。</div>
        <div class="scope-state">
          <span v-if="rep.checkingAuthorization" class="mono text-muted">校验 Scope 白名单中…</span>
          <span v-else-if="rep.authorization" class="scope-ok mono">
            ✓ 已授权：{{ rep.authorization.normalized_host }} ({{ rep.authorization.matched_scope }})
          </span>
          <span v-else class="scope-denied mono">
            ✗ {{ rep.authorizationError || "等待填写合法 URL" }}
          </span>
        </div>
      </div>

      <!-- 请求/响应双栏工作区 -->
      <div class="rf-split-shell content">
        <!-- 请求栏 -->
        <div class="pane">
          <div class="pane-title">
            <span>Request 草稿</span>
          </div>

          <el-alert
            v-if="rep.sourceReplayWarning"
            type="warning"
            :closable="false"
            class="body-warning"
            :title="rep.sourceReplayWarning"
          />

          <div class="field">
            <div class="rf-field-label">Headers（每行 Header: Value）</div>
            <el-input
              v-model="rep.draft.headersRaw"
              type="textarea"
              :rows="8"
              class="mono"
              placeholder="User-Agent: RustForge&#10;Authorization: ..."
            />
          </div>

          <div class="field grow">
            <div class="body-label-row">
              <div class="rf-field-label">Body 正文</div>
              <el-radio-group v-model="rep.draft.bodyEncoding" size="small">
                <el-radio-button value="text">UTF-8 文本</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
            </div>

            <el-input
              v-model="rep.draft.body"
              type="textarea"
              :rows="10"
              class="mono body-input"
              :placeholder="rep.draft.bodyEncoding === 'base64' ? 'AAEC/w==' : 'JSON / 表单 / Raw 报文'"
            />
          </div>
        </div>

        <div class="pane-divider" aria-hidden="true" />

        <!-- 响应栏 -->
        <div class="pane response-pane">
          <div class="pane-title">
            <span>Response 结果</span>
            <span v-if="rep.resp" class="run-id mono">Run #{{ rep.resp.id }}</span>
          </div>

          <el-alert
            v-if="rep.error"
            type="error"
            :closable="false"
            class="resp-err"
          >
            {{ rep.error }}
          </el-alert>

          <template v-if="rep.resp?.status !== null && rep.resp?.status !== undefined">
            <div class="resp-status">
              <el-tag :type="statusType(rep.resp.status)" size="default">
                {{ rep.resp.status }} {{ rep.resp.status_text }}
              </el-tag>
              <span class="resp-meta mono">
                {{ rep.resp.duration_ms }} ms · {{ formatSize(rep.resp.resp_captured_size) }} / {{ formatSize(rep.resp.resp_wire_size) }}
              </span>
              <el-tag v-if="rep.resp.resp_truncated" size="small" type="warning">已截断</el-tag>
            </div>

            <div class="field response-headers-field">
              <div class="rf-field-label">Response Headers</div>
              <pre class="rf-mono-pre response-headers">{{
                rep.resp.response_headers
                  .map((header) => `${header.name}: ${header.value}`)
                  .join("\n") || "(无)"
              }}</pre>
            </div>

            <div class="field grow response-body-field">
              <div class="rf-field-label">Response Body</div>
              <pre
                v-if="rep.resp.response_body_text !== null"
                class="rf-mono-pre body-view"
              >{{ rep.resp.response_body_text || "(空正文)" }}</pre>
              <el-alert
                v-else-if="rep.resp.response_body_base64"
                type="info"
                :closable="false"
              >
                二进制捕获（Base64 预览）：
                <pre class="rf-mono-pre body-view">{{
                  rep.resp.response_body_base64.slice(0, 4000)
                }}{{ rep.resp.response_body_base64.length > 4000 ? "…" : "" }}</pre>
              </el-alert>
              <div v-else class="empty-body">无响应体</div>
            </div>
          </template>

          <div v-else-if="rep.resp" class="failed-run">
            <el-icon :size="20"><DocumentCopy /></el-icon>
            <strong>该次重放已记录，但未收到成功响应</strong>
            <span>{{ rep.resp.error_code || rep.resp.outcome }} · {{ rep.resp.error_message || "网络请求未完成" }}</span>
            <code class="mono">request sha256: {{ rep.resp.request_hash }}</code>
          </div>

          <EmptyState
            v-else-if="!rep.error"
            title="等待发送"
            description="点击“发送请求”或按下 Ctrl + Enter，响应与不可变 Run 历史将展示在此。"
          >
            <template #icon>
              <el-icon :size="20"><DocumentCopy /></el-icon>
            </template>
          </EmptyState>
        </div>
      </div>

      <!-- 历史运行列表 -->
      <ReplayHistory
        :project-id="currentProjectId"
        :runs="rep.runs"
        :selected-run-id="rep.selectedRunId"
        :loading="rep.loadingRuns"
        :has-more="rep.hasMoreRuns"
        :loading-more="rep.loadingMoreRuns"
        @select="rep.selectRun"
        @restore="rep.restoreRun"
        @compare="showDiff"
        @link="openEvidenceLink"
        @load-more="rep.loadMoreRuns"
      />
    </template>

    <!-- 比对 Diff 对话框 -->
    <el-dialog v-model="diffVisible" title="Repeater Run 差分比对 (Diff)" width="85%">
      <div v-loading="diffLoading" class="diff-shell">
        <ReplayDiff v-if="diffData" :diff="diffData" />
      </div>
    </el-dialog>

    <!-- 关联 Evidence 对话框 -->
    <el-dialog v-model="linkVisible" title="将 Run 关联为漏洞 Evidence" width="500px">
      <div v-loading="linkLoading" class="link-form">
        <el-alert
          :type="linkRunQualifies ? 'info' : 'warning'"
          :closable="false"
          :title="
            linkRunQualifies
              ? '新 Finding Evidence 默认未接受，不能直接将 Finding 转为已确认。'
              : '该 Run 没有可用 HTTP 响应，作为审计记录；即使人工接受也不能单独确认 Finding。'
          "
        />
        <div class="rf-field-label">关联目标</div>
        <el-radio-group v-model="linkTargetType">
          <el-radio-button value="finding">Finding ({{ linkFindings.length }})</el-radio-button>
          <el-radio-button value="task">任务 ({{ linkTasks.length }})</el-radio-button>
        </el-radio-group>
        <el-select
          v-model="linkTargetId"
          class="target-select"
          filterable
          placeholder="选择关联目标"
        >
          <el-option
            v-for="target in linkTargets"
            :key="target.id"
            :label="target.label"
            :value="target.id"
          />
        </el-select>
        <div class="rf-field-label">人工观察结论</div>
        <el-input
          v-model="linkObservation"
          type="textarea"
          :rows="3"
          maxlength="4000"
          show-word-limit
          placeholder="记录观察到的漏洞特征、关键差异或业务影响..."
        />
      </div>
      <template #footer>
        <el-button @click="linkVisible = false">取消</el-button>
        <el-button
          type="primary"
          :icon="Link"
          :loading="linkLoading"
          :disabled="linkTargetId === null || !linkObservation.trim()"
          @click="submitEvidenceLink"
        >
          创建并关联 Evidence
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.rep-page {
  gap: var(--rf-space-2);
  overflow-x: hidden;
  overflow-y: auto;
}

.session-tabs {
  width: 100%;
  min-width: 0;
  margin-bottom: 4px;
}

.tab-label {
  display: flex;
  align-items: center;
  gap: 6px;
  min-width: 0;
  max-width: 160px;
  overflow: hidden;
}

.tab-title {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 12px;
}

.tab-count {
  flex: 0 0 auto;
  min-width: 16px;
  padding: 0 4px;
  border-radius: 4px;
  background: var(--rf-bg-raised);
  color: var(--rf-text-muted);
  font-size: 10px;
  line-height: 16px;
  text-align: center;
}

.session-policy {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 8px;
  padding: 6px 10px;
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-control);
  background: var(--rf-bg-panel);
}

.session-title-input {
  width: 200px;
}

.policy-label {
  color: var(--rf-text-secondary);
  font-size: 11.5px;
  font-weight: 500;
}

.source-label {
  margin-left: auto;
  font-size: 11px;
  color: var(--rf-text-muted);
}

.tls-select {
  width: 190px;
}

.assessment-handoff-banner {
  display: grid;
  gap: 4px;
  margin-bottom: 8px;
  padding: 8px 12px;
  border: 1px solid rgba(245, 158, 11, 0.3);
  border-radius: var(--rf-radius-control);
  background: rgba(245, 158, 11, 0.08);
}

.handoff-header {
  display: flex;
  align-items: center;
  gap: 8px;
}

.handoff-header strong {
  color: var(--rf-text);
  font-size: 12px;
}

.handoff-instruction {
  margin: 0;
  color: var(--rf-text-secondary);
  font-size: 11.5px;
  line-height: 1.45;
}

.handoff-hash {
  color: var(--rf-text-muted);
  font-family: var(--rf-font-mono);
  font-size: 9.5px;
}

.request-toolbar {
  margin-bottom: 4px;
}

.request-bar {
  flex: 1;
  min-width: 0;
}

.method {
  width: 100px;
  flex-shrink: 0;
}

.url {
  flex: 1;
  min-width: 0;
}

.scope-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 4px 8px;
  background: var(--rf-bg-raised);
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-control);
  margin-bottom: 6px;
  font-size: 11px;
}

.scope-notice {
  color: var(--rf-text-muted);
}

.scope-ok {
  color: var(--rf-success);
  font-weight: 500;
}

.scope-denied {
  color: var(--rf-danger);
  font-weight: 500;
}

.content {
  min-height: 460px;
  margin-bottom: var(--rf-space-2);
}

.pane {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  padding: var(--rf-space-3);
  overflow: auto;
}

.pane-divider {
  width: 1px;
  flex-shrink: 0;
  background: var(--rf-border);
}

.pane-title {
  display: flex;
  align-items: center;
  justify-content: space-between;
  font-weight: 600;
  font-size: 12px;
  margin-bottom: var(--rf-space-2);
  color: var(--rf-text);
  letter-spacing: 0.02em;
  text-transform: uppercase;
}

.run-id {
  color: var(--rf-text-muted);
  font-size: 11px;
}

.field {
  margin-bottom: var(--rf-space-2);
  display: flex;
  flex-direction: column;
}

.field.grow {
  flex: 1;
  min-height: 0;
}

.body-label-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 4px;
}

.body-warning,
.resp-err {
  margin-bottom: 8px;
}

.resp-status {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: var(--rf-space-2);
}

.resp-meta {
  font-size: 11.5px;
  color: var(--rf-text-secondary);
}

.response-headers-field {
  flex: 0 1 auto;
  min-height: 0;
}

.response-headers {
  max-height: 180px;
}

.response-body-field {
  flex: 1 0 200px;
  min-height: 200px;
  margin-bottom: 0;
}

.body-view {
  min-height: 180px;
  max-height: none;
  flex: 1;
}

.empty-body {
  color: var(--rf-text-muted);
  font-size: 12px;
}

.failed-run {
  min-height: 160px;
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  gap: 6px;
  color: var(--rf-text-secondary);
  text-align: center;
}

.diff-shell {
  min-height: 160px;
  max-height: 65vh;
  overflow: auto;
}

.link-form {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.target-select {
  width: 100%;
}
</style>
