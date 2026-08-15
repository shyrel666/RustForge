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
      title="重放"
      description="项目内多会话手动改包；每次运行可复现、比较并关联为证据。"
    />

    <EmptyState
      v-if="!project.current"
      title="请先打开项目"
      description="Repeater 的会话、Scope 与证据都必须归属于明确项目。"
    >
      <template #icon><el-icon :size="20"><Connection /></el-icon></template>
    </EmptyState>

    <template v-else>
      <el-tabs
        :model-value="
          rep.activeSessionId === null ? '' : String(rep.activeSessionId)
        "
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
              <span v-if="session.run_count" class="tab-count">{{
                session.run_count
              }}</span>
            </span>
          </template>
        </el-tab-pane>
      </el-tabs>

      <div v-if="rep.activeSession" class="session-policy">
        <el-input
          v-model="sessionTitle"
          size="small"
          maxlength="120"
          class="session-title-input"
          aria-label="会话标题"
          @change="saveSessionSettings"
        />
        <span class="policy-label">TLS</span>
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
          TLS 身份校验已降低
        </el-tag>
        <span v-if="rep.activeSession.source_traffic_id" class="source-label">
          来源流量 #{{ rep.activeSession.source_traffic_id }}
        </span>
      </div>

      <section
        v-if="rep.activeAssessmentHandoff"
        class="assessment-handoff-banner"
        aria-live="polite"
      >
        <div>
          <el-tag size="small" type="warning">人工接力</el-tag>
          <strong>
            Mission #{{ rep.activeAssessmentHandoff.missionId }} ·
            {{ rep.activeAssessmentHandoff.recipeId }}@{{ rep.activeAssessmentHandoff.recipeVersion }}
          </strong>
        </div>
        <p>
          {{ rep.activeAssessmentHandoff.draft.proposedDifference?.instructions }}
          当前编辑器已载入后端版本化草稿；RustForge 不会替你点击发送。
        </p>
        <code>draft sha256: {{ rep.activeAssessmentHandoff.draftHash }}</code>
      </section>

      <div class="rf-toolbar">
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
            @keyup.enter="sendRequest"
          />
        </div>
        <el-button
          type="primary"
          :icon="Promotion"
          :loading="rep.sending"
          :disabled="!canSend"
          @click="sendRequest"
        >
          发送并记录 Run
        </el-button>
      </div>

      <div class="rf-inline-warn">
        <div>
          重放会真实向目标发送请求；不自动跟随重定向。后端会在每次发送前重新校验当前项目 Scope。
        </div>
        <div class="scope-state">
          <span v-if="rep.checkingAuthorization">正在由后端校验项目 Scope…</span>
          <span v-else-if="rep.authorization" class="scope-ok">
            已授权：{{ rep.authorization.normalized_host }}
            · 命中 {{ rep.authorization.matched_scope }}
          </span>
          <span v-else class="scope-denied">
            {{ rep.authorizationError || "等待填写 URL 并完成 Scope 校验" }}
          </span>
        </div>
      </div>

      <div class="rf-split-shell content">
        <div class="pane">
          <div class="pane-title">请求草稿</div>
          <el-alert
            v-if="rep.sourceReplayWarning"
            type="warning"
            :closable="false"
            class="body-warning"
            :title="rep.sourceReplayWarning"
          />
          <div class="field">
            <div class="rf-field-label">请求头（每行 Name: Value）</div>
            <el-input
              v-model="rep.draft.headersRaw"
              type="textarea"
              :rows="9"
              class="mono"
              placeholder="User-Agent: ...&#10;Cookie: ..."
            />
          </div>
          <div class="field grow">
            <div class="body-label-row">
              <div class="rf-field-label">请求体</div>
              <el-radio-group v-model="rep.draft.bodyEncoding" size="small">
                <el-radio-button value="text">UTF-8 文本</el-radio-button>
                <el-radio-button value="base64">Base64 原始字节</el-radio-button>
              </el-radio-group>
            </div>
            <el-alert
              v-if="rep.draft.bodyEncoding === 'base64'"
              type="info"
              :closable="false"
              class="body-warning"
              title="后端会先解码为原始字节；Base64 无效时不会建立网络连接，但会记录失败 run。"
            />
            <el-input
              v-model="rep.draft.body"
              type="textarea"
              :rows="8"
              class="mono body-input"
              :placeholder="
                rep.draft.bodyEncoding === 'base64'
                  ? 'AAEC/w=='
                  : '表单 / JSON / 其它'
              "
            />
          </div>
        </div>

        <div class="pane-divider" aria-hidden="true" />

        <div class="pane response-pane">
          <div class="pane-title">
            响应
            <span v-if="rep.resp" class="run-id">Run #{{ rep.resp.id }}</span>
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
              <el-tag :type="statusType(rep.resp.status)" effect="dark">
                {{ rep.resp.status }} {{ rep.resp.status_text }}
              </el-tag>
              <span class="resp-meta">
                {{ rep.resp.duration_ms }} ms · 捕获
                {{ formatSize(rep.resp.resp_captured_size) }} /
                {{ formatSize(rep.resp.resp_wire_size) }}
              </span>
              <el-tag v-if="rep.resp.resp_truncated" size="small" type="warning">
                已截断
              </el-tag>
            </div>
            <div class="scope-snapshot">
              Scope 快照：
              {{ rep.resp.scope_decision.normalized_host }}
              → {{ rep.resp.scope_decision.matched_scope }}
              · TLS {{ rep.resp.tls_policy }}
              · {{ rep.resp.resp_decode_status }}
            </div>
            <div class="field response-headers-field">
              <div class="rf-field-label">响应头（重复项逐项保留）</div>
              <pre class="rf-mono-pre response-headers">{{
                rep.resp.response_headers
                  .map((header) => `${header.name}: ${header.value}`)
                  .join("\n") || "(无)"
              }}</pre>
            </div>
            <div class="field grow response-body-field">
              <div class="rf-field-label">响应体</div>
              <pre
                v-if="rep.resp.response_body_text !== null"
                class="rf-mono-pre body-view"
              >{{ rep.resp.response_body_text || "(空)" }}</pre>
              <el-alert
                v-else-if="rep.resp.response_body_base64"
                type="info"
                :closable="false"
              >
                二进制有界捕获（Base64 预览）：
                <pre class="rf-mono-pre body-view">{{
                  rep.resp.response_body_base64.slice(0, 4000)
                }}{{ rep.resp.response_body_base64.length > 4000 ? "…" : "" }}</pre>
              </el-alert>
              <div v-else class="empty-body">无响应体</div>
            </div>
          </template>

          <div v-else-if="rep.resp" class="failed-run">
            <el-icon :size="20"><DocumentCopy /></el-icon>
            <strong>该次点击已记录，但没有成功响应</strong>
            <span>
              {{ rep.resp.error_code || rep.resp.outcome }} ·
              {{ rep.resp.error_message || "请求未完成" }}
            </span>
            <code>request sha256: {{ rep.resp.request_hash }}</code>
          </div>

          <EmptyState
            v-else-if="!rep.error"
            title="尚未发送"
            description="发送后响应与不可变 run 会显示在这里。"
          >
            <template #icon>
              <el-icon :size="20"><DocumentCopy /></el-icon>
            </template>
          </EmptyState>
        </div>
      </div>

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

    <el-dialog v-model="diffVisible" title="Repeater Run Diff" width="88%">
      <div v-loading="diffLoading" class="diff-shell">
        <ReplayDiff v-if="diffData" :diff="diffData" />
      </div>
    </el-dialog>

    <el-dialog v-model="linkVisible" title="将 Run 关联为 Evidence" width="520px">
      <div v-loading="linkLoading" class="link-form">
        <el-alert
          :type="linkRunQualifies ? 'info' : 'warning'"
          :closable="false"
          :title="
            linkRunQualifies
              ? '新 Finding Evidence 默认未接受，不能直接把 Finding 变成已确认。'
              : '该 Run 没有可用 HTTP 响应，只能作为审计记录；即使人工接受，也不能单独确认 Finding。'
          "
        />
        <div class="rf-field-label">关联对象</div>
        <el-radio-group v-model="linkTargetType">
          <el-radio-button value="finding">
            Finding（{{ linkFindings.length }}）
          </el-radio-button>
          <el-radio-button value="task">
            任务（{{ linkTasks.length }}）
          </el-radio-button>
        </el-radio-group>
        <el-select
          v-model="linkTargetId"
          class="target-select"
          filterable
          placeholder="选择关联对象"
        >
          <el-option
            v-for="target in linkTargets"
            :key="target.id"
            :label="target.label"
            :value="target.id"
          />
        </el-select>
        <div class="rf-field-label">人工观察</div>
        <el-input
          v-model="linkObservation"
          type="textarea"
          :rows="4"
          maxlength="4000"
          show-word-limit
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
.session-tabs {
  width: 100%;
  min-width: 0;
  margin-bottom: 8px;
}
.tab-label {
  display: flex;
  align-items: center;
  gap: 6px;
  min-width: 0;
  max-width: 180px;
  overflow: hidden;
}
.tab-title {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.tab-count {
  flex: 0 0 auto;
  min-width: 18px;
  padding: 0 5px;
  border-radius: 9px;
  background: var(--rf-bg-raised);
  color: var(--rf-text-muted);
  font-size: 10px;
  line-height: 18px;
  text-align: center;
}
.session-policy {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 10px;
  padding: 8px 10px;
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-control);
  background: var(--rf-bg-panel);
}
.session-title-input {
  width: 220px;
}
.policy-label,
.source-label {
  color: var(--rf-text-secondary);
  font-size: 12px;
}
.source-label {
  margin-left: auto;
  font-family: var(--rf-font-mono);
}
.tls-select {
  width: 210px;
}
.assessment-handoff-banner {
  display: grid;
  gap: 5px;
  margin-bottom: 10px;
  padding: 10px 12px;
  border: 1px solid color-mix(in srgb, var(--rf-warning) 55%, var(--rf-border));
  border-radius: var(--rf-radius-control);
  background: color-mix(in srgb, var(--rf-warning) 9%, var(--rf-bg-panel));
}
.assessment-handoff-banner > div {
  display: flex;
  align-items: center;
  gap: 8px;
}
.assessment-handoff-banner strong {
  color: var(--rf-text);
  font-size: 12px;
}
.assessment-handoff-banner p {
  margin: 0;
  color: var(--rf-text-secondary);
  font-size: 11px;
  line-height: 1.5;
}
.assessment-handoff-banner code {
  color: var(--rf-text-muted);
  font-family: var(--rf-font-mono);
  font-size: 9px;
}
.request-bar {
  flex: 1;
  min-width: 0;
}
.method {
  width: 110px;
  flex-shrink: 0;
}
.url {
  flex: 1;
  min-width: 0;
}
.content {
  min-height: 500px;
  margin-bottom: var(--rf-space-3);
}
.pane {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  padding: var(--rf-space-4);
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
  font-weight: 650;
  font-size: 13px;
  margin-bottom: var(--rf-space-3);
  color: var(--rf-text);
}
.run-id {
  color: var(--rf-text-muted);
  font: 11px var(--rf-font-mono);
}
.field {
  margin-bottom: var(--rf-space-3);
  display: flex;
  flex-direction: column;
}
.field.grow {
  flex: 1;
  min-height: 0;
}
.mono :deep(textarea),
.mono :deep(input) {
  font-family: var(--rf-font-mono);
  font-size: 12.5px;
}
.body-input :deep(textarea) {
  min-height: 120px;
}
.body-label-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  margin-bottom: 6px;
}
.body-label-row .rf-field-label {
  margin-bottom: 0;
}
.body-warning,
.resp-err {
  margin-bottom: 10px;
}
.resp-status {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 10px;
  margin-bottom: var(--rf-space-3);
}
.resp-meta {
  font-size: 12px;
  color: var(--rf-text-secondary);
}
.scope-state {
  display: flex;
  flex-wrap: wrap;
  gap: 8px 14px;
  margin-top: 4px;
  font-size: 12px;
}
.scope-ok {
  color: var(--el-color-success-dark-2);
}
.scope-denied {
  color: var(--el-color-danger-dark-2);
}
.scope-snapshot {
  margin: -2px 0 var(--rf-space-3);
  color: var(--rf-text-secondary);
  font-family: var(--rf-font-mono);
  font-size: 12px;
}
.response-headers-field {
  flex: 0 1 auto;
  min-height: 0;
}
.response-headers {
  max-height: 220px;
}
.response-body-field {
  flex: 1 0 240px;
  min-height: 240px;
  margin-bottom: 0;
}
.body-view {
  min-height: 210px;
  max-height: none;
  flex: 1;
}
.empty-body {
  color: var(--rf-text-muted);
  font-size: 13px;
}
.failed-run {
  min-height: 180px;
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  gap: 8px;
  color: var(--rf-text-secondary);
  text-align: center;
}
.failed-run code {
  max-width: 100%;
  overflow-wrap: anywhere;
  color: var(--rf-text-muted);
  font-size: 11px;
}
.diff-shell {
  min-height: 180px;
  max-height: 70vh;
  overflow: auto;
}
.link-form {
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.target-select {
  width: 100%;
}
</style>
