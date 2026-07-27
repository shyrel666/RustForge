<script setup lang="ts">
import { Promotion, DocumentCopy } from "@element-plus/icons-vue";
import { computed, onBeforeUnmount, watch } from "vue";
import { ElMessageBox } from "element-plus";
import { useProjectStore } from "../stores/project";
import { useRepeaterStore } from "../stores/repeater";
import EmptyState from "../components/shell/EmptyState.vue";
import PageHeader from "../components/shell/PageHeader.vue";

const rep = useRepeaterStore();
const project = useProjectStore();
const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
let authorizationTimer: ReturnType<typeof setTimeout> | null = null;

const currentProjectId = computed(() => project.current?.id ?? null);
const canSend = computed(
  () =>
    !rep.sending &&
    !rep.checkingAuthorization &&
    rep.authorization !== null &&
    rep.authorizationProjectId === currentProjectId.value &&
    rep.authorizationUrl === rep.draft.url.trim()
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
  if (authorizationTimer) {
    clearTimeout(authorizationTimer);
    authorizationTimer = null;
  }
  let allowTruncatedBody = false;
  if (rep.sourceBodyTruncated) {
    try {
      await ElMessageBox.confirm(
        "来源流量的请求体已被捕获上限截断。当前编辑区只有前缀，发送后可能产生与原请求完全不同的副作用。仍要按当前内容发送吗？",
        "确认发送截断正文",
        {
          type: "warning",
          confirmButtonText: "确认按当前内容发送",
          cancelButtonText: "取消",
        }
      );
      allowTruncatedBody = true;
    } catch {
      return;
    }
  }
  await rep.send(allowTruncatedBody);
}

watch(
  [
    () => project.current?.id ?? null,
    () => project.current?.scope.join("\u0000") ?? "",
    () => rep.draft.url,
  ],
  scheduleAuthorizationCheck,
  { immediate: true }
);

onBeforeUnmount(() => {
  if (authorizationTimer) clearTimeout(authorizationTimer);
});

function statusType(s: number): string {
  const cls = Math.floor(s / 100);
  return cls === 2 ? "success" : cls === 3 ? "info" : cls === 4 ? "warning" : "danger";
}

function fmtSize(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}
</script>

<template>
  <div class="rep-page rf-page rf-page--inset">
    <PageHeader
      title="重放"
      description="手动改包并向目标重发，用于人工验证。"
    />
    <div class="rf-toolbar">
      <div class="rf-toolbar-group request-bar">
        <el-select v-model="rep.draft.method" class="method" size="default">
          <el-option v-for="m in METHODS" :key="m" :label="m" :value="m" />
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
        发送
      </el-button>
    </div>

    <div class="rf-inline-warn">
      <div>
        重放会真实向目标发送请求——请确保目标在授权范围内。忽略证书错误、不自动跟随重定向。
        <template v-if="rep.loadedFrom"> 当前请求来自流量 #{{ rep.loadedFrom }}。</template>
      </div>
      <div class="scope-state">
        <span v-if="rep.checkingAuthorization">正在由后端校验项目 Scope…</span>
        <span v-else-if="rep.authorization" class="scope-ok">
          已授权：{{ rep.authorization.normalized_host }}
          · 命中 {{ rep.authorization.matched_scope }}
        </span>
        <span v-else class="scope-denied">
          {{ rep.authorizationError || "等待填写目标 URL 并完成 Scope 校验" }}
        </span>
        <span
          v-if="
            rep.loadedFromProject &&
            currentProjectId &&
            rep.loadedFromProject !== currentProjectId
          "
          class="scope-denied"
        >
          当前项目与来源流量所属项目不同，将按当前项目重新授权。
        </span>
      </div>
    </div>

    <div class="rf-split-shell content">
      <div class="pane">
        <div class="pane-title">请求</div>
        <el-alert
          v-if="rep.sourceBodyTruncated"
          type="warning"
          :closable="false"
          class="body-warning"
          title="来源请求体已截断；编辑区只包含捕获前缀，发送前会再次要求明确确认。"
        />
        <div class="field">
          <div class="rf-field-label">请求头（每行 Name: Value）</div>
          <el-input
            v-model="rep.draft.headersRaw"
            type="textarea"
            :rows="10"
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
            title="编辑区内容会在后端解码为原始字节；Base64 无效时不会发起网络请求。"
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

      <div class="pane">
        <div class="pane-title">响应</div>
        <el-alert v-if="rep.error" type="error" :closable="false" class="resp-err">
          {{ rep.error }}
        </el-alert>

        <template v-if="rep.resp">
          <div class="resp-status">
            <el-tag :type="statusType(rep.resp.status)" effect="dark">
              {{ rep.resp.status }} {{ rep.resp.status_text }}
            </el-tag>
            <span class="resp-meta">{{ rep.resp.duration_ms }} ms · {{ fmtSize(rep.resp.resp_size) }}</span>
          </div>
          <div class="scope-snapshot">
            Scope 快照：{{ rep.resp.scope_decision.normalized_host }}
            → {{ rep.resp.scope_decision.matched_scope }}
            （{{ rep.resp.scope_decision.match_kind === "exact" ? "精确" : "通配" }}）
          </div>
          <div class="field">
            <div class="rf-field-label">响应头</div>
            <pre class="rf-mono-pre">{{ rep.resp.headers.map((h) => `${h.name}: ${h.value}`).join("\n") || "(无)" }}</pre>
          </div>
          <div class="field grow">
            <div class="rf-field-label">响应体</div>
            <pre v-if="rep.resp.body_text !== null" class="rf-mono-pre body-view">{{ rep.resp.body_text || "(空)" }}</pre>
            <el-alert v-else-if="rep.resp.body_base64" type="info" :closable="false">
              二进制内容（{{ fmtSize(rep.resp.resp_size) }}），Base64（截断）：
              <pre class="rf-mono-pre">{{ rep.resp.body_base64.slice(0, 2000) }}…</pre>
            </el-alert>
            <div v-else class="empty-body">无响应体</div>
          </div>
        </template>

        <EmptyState
          v-else-if="!rep.error"
          title="尚未发送"
          description="改好请求后点「发送」，响应会显示在这里。"
        >
          <template #icon><el-icon :size="20"><DocumentCopy /></el-icon></template>
        </EmptyState>
      </div>
    </div>
  </div>
</template>

<style scoped>
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
  /* rf-split-shell provides chrome */
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
  font-weight: 650;
  font-size: 13px;
  margin-bottom: var(--rf-space-3);
  color: var(--rf-text);
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
.body-warning {
  margin-bottom: 10px;
}
.resp-err {
  margin-bottom: 10px;
}
.resp-status {
  display: flex;
  align-items: center;
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
.body-view {
  max-height: none;
  flex: 1;
}
.empty-body {
  color: var(--rf-text-muted);
  font-size: 13px;
}
</style>
