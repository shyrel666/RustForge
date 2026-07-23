<script setup lang="ts">
import { Promotion } from "@element-plus/icons-vue";
import { useRepeaterStore } from "../stores/repeater";

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
  <div class="rep-page">
    <!-- 工具栏 -->
    <div class="toolbar">
      <el-select v-model="rep.draft.method" class="method">
        <el-option v-for="m in METHODS" :key="m" :label="m" :value="m" />
      </el-select>
      <el-input
        v-model="rep.draft.url"
        placeholder="https://target.example.com/path?a=1"
        class="url mono"
        @keyup.enter="rep.send()"
      />
      <el-button type="primary" :icon="Promotion" :loading="rep.sending" @click="rep.send()">
        发送
      </el-button>
    </div>

    <el-alert type="warning" :closable="false" class="hint">
      <b>Repeater 会真实地向目标发送请求</b>——这是人在回路的手动「验证」动作，请确保目标在你的授权范围内。
      忽略证书错误、不自动跟随重定向。
      <span v-if="rep.loadedFrom"> 当前请求来自流量 #{{ rep.loadedFrom }}。</span>
    </el-alert>

    <!-- 请求 / 响应 双栏 -->
    <div class="content">
      <!-- 请求编辑 -->
      <div class="pane">
        <div class="pane-title">请求（可自由改包）</div>
        <div class="field">
          <div class="field-label">请求头（每行 Name: Value）</div>
          <el-input
            v-model="rep.draft.headersRaw"
            type="textarea"
            :rows="10"
            class="mono"
            placeholder="User-Agent: ...&#10;Cookie: ..."
          />
        </div>
        <div class="field grow">
          <div class="field-label">请求体</div>
          <el-input
            v-model="rep.draft.body"
            type="textarea"
            :rows="8"
            class="mono body-input"
            placeholder="表单 / JSON / 其它"
          />
        </div>
      </div>

      <!-- 响应查看 -->
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
            <div class="field-label">响应头</div>
            <pre class="view">{{ rep.resp.headers.map((h) => `${h.name}: ${h.value}`).join("\n") || "(无)" }}</pre>
          </div>
          <div class="field grow">
            <div class="field-label">响应体</div>
            <pre v-if="rep.resp.body_text !== null" class="view body-view">{{ rep.resp.body_text || "(空)" }}</pre>
            <el-alert v-else-if="rep.resp.body_base64" type="info" :closable="false">
              二进制内容（{{ fmtSize(rep.resp.resp_size) }}），Base64（截断）：
              <pre class="view">{{ rep.resp.body_base64.slice(0, 2000) }}…</pre>
            </el-alert>
            <div v-else class="empty-body">无响应体</div>
          </div>
        </template>

        <el-empty
          v-else-if="!rep.error"
          description="尚未发送。改好请求后点「发送」，在此查看响应。"
          :image-size="48"
        />
      </div>
    </div>
  </div>
</template>

<style scoped>
.rep-page {
  height: 100%;
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.toolbar {
  display: flex;
  align-items: center;
  gap: 8px;
}
.method {
  width: 120px;
  flex-shrink: 0;
}
.url {
  flex: 1;
}
.hint {
  flex-shrink: 0;
}
.content {
  flex: 1;
  display: flex;
  gap: 12px;
  min-height: 0;
}
.pane {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  border: 1px solid var(--el-border-color);
  border-radius: 8px;
  padding: 12px;
  overflow: auto;
}
.pane-title {
  font-weight: 600;
  margin-bottom: 10px;
}
.field {
  margin-bottom: 12px;
  display: flex;
  flex-direction: column;
}
.field.grow {
  flex: 1;
  min-height: 0;
}
.field-label {
  font-size: 12px;
  color: var(--el-text-color-secondary);
  margin-bottom: 5px;
}
.mono :deep(textarea),
.mono :deep(input) {
  font-family: "JetBrains Mono", "Cascadia Code", Consolas, monospace;
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
  margin-bottom: 12px;
}
.resp-meta {
  font-size: 12px;
  color: var(--el-text-color-secondary);
}
.view {
  margin: 0;
  padding: 10px;
  background: var(--el-fill-color-dark);
  border-radius: 4px;
  font-family: "JetBrains Mono", "Cascadia Code", Consolas, monospace;
  font-size: 12px;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 260px;
  overflow: auto;
}
.body-view {
  max-height: none;
}
.empty-body {
  font-size: 13px;
  color: var(--el-text-color-secondary);
}
</style>
