<script setup lang="ts">
import { Promotion, DocumentCopy } from "@element-plus/icons-vue";
import { useRepeaterStore } from "../stores/repeater";
import EmptyState from "../components/shell/EmptyState.vue";
import PageHeader from "../components/shell/PageHeader.vue";

const rep = useRepeaterStore();
const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

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
          @keyup.enter="rep.send()"
        />
      </div>
      <el-button type="primary" :icon="Promotion" :loading="rep.sending" @click="rep.send()">
        发送
      </el-button>
    </div>

    <div class="rf-inline-warn">
      <span>
        重放会真实向目标发送请求——请确保目标在授权范围内。忽略证书错误、不自动跟随重定向。
        <template v-if="rep.loadedFrom"> 当前请求来自流量 #{{ rep.loadedFrom }}。</template>
      </span>
    </div>

    <div class="rf-split-shell content">
      <div class="pane">
        <div class="pane-title">请求</div>
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
          <div class="rf-field-label">请求体</div>
          <el-input
            v-model="rep.draft.body"
            type="textarea"
            :rows="8"
            class="mono body-input"
            placeholder="表单 / JSON / 其它"
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
.body-view {
  max-height: none;
  flex: 1;
}
.empty-body {
  color: var(--rf-text-muted);
  font-size: 13px;
}
</style>
