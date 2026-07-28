<script setup lang="ts">
import { computed } from "vue";
import type {
  ReplayBodySnapshot,
  ReplayHeader,
  ReplayRunDiff,
} from "../api/tauri";

const props = defineProps<{
  diff: ReplayRunDiff;
}>();

const scalarRows = computed(() => [
  { label: "Method", value: props.diff.method },
  { label: "URL", value: props.diff.url },
  { label: "TLS 策略", value: props.diff.tls_policy },
  { label: "运行结果", value: props.diff.outcome },
  { label: "Status", value: props.diff.status },
  { label: "Duration", value: props.diff.duration_ms, suffix: " ms" },
]);

function scalar(value: unknown, suffix = ""): string {
  return value === null || value === undefined ? "—" : `${String(value)}${suffix}`;
}

function headersText(headers: ReplayHeader[]): string {
  return headers.map((header) => `${header.name}: ${header.value}`).join("\n") || "(无)";
}

function bodyText(body: ReplayBodySnapshot): string {
  if (body.encoding === "text") return body.text || "(空文本)";
  if (body.encoding === "base64") return body.base64 || "(空 Base64)";
  return "(无正文)";
}

function bodyMeta(body: ReplayBodySnapshot): string {
  const hash = body.full_hash ?? body.captured_hash;
  const hashKind =
    body.full_hash === null ? "captured-sha256" : "complete-sha256";
  return [
    `${body.captured_size}/${body.wire_size} B`,
    body.decode_status,
    body.truncated ? "已截断" : "完整",
    `${hashKind}:${hash.slice(0, 16)}…`,
  ].join(" · ");
}
</script>

<template>
  <div class="diff">
    <div class="run-head">
      <strong>Run #{{ diff.left_run_id }}</strong>
      <span>对比</span>
      <strong>Run #{{ diff.right_run_id }}</strong>
    </div>

    <div
      v-for="row in scalarRows"
      :key="row.label"
      class="diff-row"
      :class="{
        changed: row.value.changed,
        indeterminate: row.value.indeterminate,
      }"
    >
      <div class="label">{{ row.label }}</div>
      <pre>{{ scalar(row.value.left, row.suffix) }}</pre>
      <pre>{{ scalar(row.value.right, row.suffix) }}</pre>
    </div>

    <div
      class="diff-section"
      :class="{
        changed: diff.request_headers.changed,
        indeterminate: diff.request_headers.indeterminate,
      }"
    >
      <div class="section-title">请求头（有序；重复项不折叠）</div>
      <div class="side-grid">
        <pre>{{ headersText(diff.request_headers.left) }}</pre>
        <pre>{{ headersText(diff.request_headers.right) }}</pre>
      </div>
    </div>

    <div
      class="diff-section"
      :class="{
        changed: diff.request_body.changed,
        indeterminate: diff.request_body.indeterminate,
      }"
    >
      <div class="section-title">
        请求正文
        <span v-if="diff.request_body.indeterminate" class="indeterminate-note">
          捕获前缀相同，无法判定完整正文
        </span>
      </div>
      <div class="side-grid">
        <div>
          <div class="meta">{{ bodyMeta(diff.request_body.left) }}</div>
          <pre>{{ bodyText(diff.request_body.left) }}</pre>
        </div>
        <div>
          <div class="meta">{{ bodyMeta(diff.request_body.right) }}</div>
          <pre>{{ bodyText(diff.request_body.right) }}</pre>
        </div>
      </div>
    </div>

    <div
      class="diff-section"
      :class="{
        changed: diff.response_headers.changed,
        indeterminate: diff.response_headers.indeterminate,
      }"
    >
      <div class="section-title">响应头（有序；重复项不折叠）</div>
      <div class="side-grid">
        <pre>{{ headersText(diff.response_headers.left) }}</pre>
        <pre>{{ headersText(diff.response_headers.right) }}</pre>
      </div>
    </div>

    <div
      class="diff-section"
      :class="{
        changed: diff.response_body.changed,
        indeterminate: diff.response_body.indeterminate,
      }"
    >
      <div class="section-title">
        响应正文
        <span v-if="diff.response_body.indeterminate" class="indeterminate-note">
          捕获前缀相同，无法判定完整正文
        </span>
      </div>
      <div class="side-grid">
        <div>
          <div class="meta">{{ bodyMeta(diff.response_body.left) }}</div>
          <pre>{{ bodyText(diff.response_body.left) }}</pre>
        </div>
        <div>
          <div class="meta">{{ bodyMeta(diff.response_body.right) }}</div>
          <pre>{{ bodyText(diff.response_body.right) }}</pre>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.diff {
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.run-head,
.diff-row,
.side-grid {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: 10px;
}
.run-head {
  grid-template-columns: 1fr auto 1fr;
  text-align: center;
  align-items: center;
  color: var(--rf-text-secondary);
}
.diff-row {
  position: relative;
  padding-top: 22px;
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-control);
  overflow: hidden;
}
.diff-row .label {
  position: absolute;
  inset: 0 0 auto;
  padding: 4px 8px;
  background: var(--rf-bg-raised);
  color: var(--rf-text-secondary);
  font-size: 11px;
  font-weight: 650;
}
.diff-section {
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-control);
  overflow: hidden;
}
.section-title {
  padding: 6px 9px;
  background: var(--rf-bg-raised);
  color: var(--rf-text-secondary);
  font-size: 12px;
  font-weight: 650;
}
.changed {
  border-color: var(--el-color-warning-light-5);
}
.indeterminate {
  border-style: dashed;
  border-color: var(--el-color-info-light-5);
}
.changed > .section-title,
.diff-row.changed .label {
  background: var(--el-color-warning-light-9);
  color: var(--el-color-warning-dark-2);
}
.indeterminate-note {
  margin-left: 8px;
  color: var(--el-color-info-dark-2);
  font-weight: 500;
}
pre {
  min-height: 34px;
  max-height: 240px;
  margin: 0;
  padding: 8px 10px;
  overflow: auto;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  font: 12px/1.45 var(--rf-font-mono);
}
.side-grid > :first-child {
  border-right: 1px solid var(--rf-border);
}
.meta {
  padding: 6px 10px 0;
  color: var(--rf-text-muted);
  font: 11px/1.4 var(--rf-font-mono);
}
</style>
