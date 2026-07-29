<script setup lang="ts">
import { computed } from "vue";
import {
  Close,
  Download,
  Lock,
  Right,
} from "@element-plus/icons-vue";
import {
  formatUpdateVersion,
  parseUpdateNotes,
} from "../utils/updateNotes";

const props = withDefaults(
  defineProps<{
    modelValue: boolean;
    currentVersion: string;
    targetVersion: string;
    releaseNotes?: string;
    busy?: boolean;
  }>(),
  {
    releaseNotes: "",
    busy: false,
  },
);

const emit = defineEmits<{
  "update:modelValue": [value: boolean];
  confirm: [];
}>();

const notes = computed(() => parseUpdateNotes(props.releaseNotes));
const currentVersionLabel = computed(() =>
  formatUpdateVersion(props.currentVersion),
);
const targetVersionLabel = computed(() =>
  formatUpdateVersion(props.targetVersion),
);

function close() {
  if (props.busy) return;
  emit("update:modelValue", false);
}

function confirm() {
  if (props.busy) return;
  emit("confirm");
}
</script>

<template>
  <el-dialog
    :model-value="modelValue"
    width="min(660px, calc(100vw - 32px))"
    class="app-update-dialog"
    modal-class="app-update-dialog-modal"
    align-center
    append-to-body
    destroy-on-close
    :show-close="false"
    :close-on-click-modal="!busy"
    :close-on-press-escape="!busy"
    @close="close"
  >
    <template #header="{ titleId, titleClass }">
      <div class="update-dialog-header">
        <span class="update-dialog-mark" aria-hidden="true">
          <el-icon :size="22"><Download /></el-icon>
        </span>
        <div class="update-dialog-heading">
          <span class="update-dialog-eyebrow">RustForge 安全更新</span>
          <h2 :id="titleId" :class="titleClass">发现新版本</h2>
          <p>先了解本次变化，再决定何时安装。</p>
        </div>
        <button
          type="button"
          class="update-dialog-close"
          aria-label="关闭更新说明"
          :disabled="busy"
          @click="close"
        >
          <el-icon :size="17"><Close /></el-icon>
        </button>
      </div>
    </template>

    <div class="update-dialog-content">
      <div
        class="update-version-route"
        :aria-label="`从 ${currentVersionLabel} 更新到 ${targetVersionLabel}`"
      >
        <div class="update-version-card">
          <span>当前版本</span>
          <strong>{{ currentVersionLabel }}</strong>
        </div>
        <span class="update-version-arrow" aria-hidden="true">
          <el-icon :size="18"><Right /></el-icon>
        </span>
        <div class="update-version-card is-target">
          <span>可用版本</span>
          <strong>{{ targetVersionLabel }}</strong>
        </div>
      </div>

      <section class="update-highlights" aria-labelledby="update-highlights-title">
        <div class="update-section-heading">
          <div>
            <span class="update-section-kicker">更新要点</span>
            <h3 id="update-highlights-title">{{ notes.title }}</h3>
          </div>
          <span v-if="notes.highlights.length" class="update-count">
            {{ notes.highlights.length }} 项
          </span>
        </div>

        <ol v-if="notes.highlights.length" class="update-highlight-list">
          <li v-for="(highlight, index) in notes.highlights" :key="highlight">
            <span class="update-highlight-index" aria-hidden="true">
              {{ String(index + 1).padStart(2, "0") }}
            </span>
            <span>{{ highlight }}</span>
          </li>
        </ol>
        <p v-else class="update-notes-fallback">{{ notes.fallback }}</p>
      </section>

      <div class="update-trust-note">
        <span class="update-trust-icon" aria-hidden="true">
          <el-icon :size="17"><Lock /></el-icon>
        </span>
        <div>
          <strong>安装前会进行签名校验</strong>
          <span>只有通过应用内置公钥验证的安装包才会进入安装流程。</span>
        </div>
      </div>
    </div>

    <template #footer>
      <div class="update-dialog-footer">
        <p>稍后可在“设置 → 关于”中重新检查。</p>
        <div class="update-dialog-actions">
          <el-button size="large" :disabled="busy" @click="close">
            稍后处理
          </el-button>
          <el-button
            type="primary"
            size="large"
            :loading="busy"
            @click="confirm"
          >
            <el-icon><Download /></el-icon>
            下载并安装
          </el-button>
        </div>
      </div>
    </template>
  </el-dialog>
</template>

<style>
.app-update-dialog-modal {
  backdrop-filter: blur(5px);
}

.app-update-dialog.el-dialog {
  padding: 0;
  overflow: hidden;
  border-color: color-mix(
    in srgb,
    var(--rf-accent) 24%,
    var(--rf-border)
  );
  box-shadow:
    0 24px 70px color-mix(in srgb, var(--rf-bg-base) 65%, transparent),
    0 0 0 1px color-mix(in srgb, var(--rf-accent) 8%, transparent);
}

.app-update-dialog .el-dialog__header {
  margin: 0;
  padding: 0;
}

.app-update-dialog .el-dialog__body {
  padding: 0;
  color: var(--rf-text);
}

.app-update-dialog .el-dialog__footer {
  padding: 0;
  text-align: initial;
}

.update-dialog-header {
  position: relative;
  display: grid;
  grid-template-columns: auto 1fr auto;
  align-items: center;
  gap: var(--rf-space-4);
  padding: 24px 28px 22px;
  border-bottom: 1px solid var(--rf-border);
  background:
    radial-gradient(
      circle at 12% 20%,
      color-mix(in srgb, var(--rf-accent) 16%, transparent),
      transparent 42%
    ),
    linear-gradient(
      135deg,
      color-mix(in srgb, var(--rf-bg-raised) 88%, transparent),
      var(--rf-bg-panel)
    );
}

.update-dialog-mark {
  width: 46px;
  height: 46px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border: 1px solid
    color-mix(in srgb, var(--rf-accent) 38%, var(--rf-border));
  border-radius: 14px;
  background: var(--rf-accent-muted);
  color: var(--rf-accent);
  box-shadow: inset 0 1px 0 color-mix(in srgb, white 18%, transparent);
}

.update-dialog-heading {
  min-width: 0;
}

.update-dialog-eyebrow,
.update-section-kicker {
  display: block;
  margin-bottom: 4px;
  color: var(--rf-accent);
  font-size: 10px;
  font-weight: 750;
  letter-spacing: 0.12em;
}

.update-dialog-heading h2 {
  margin: 0;
  color: var(--rf-text);
  font-size: 21px;
  font-weight: 760;
  letter-spacing: -0.02em;
}

.update-dialog-heading p {
  margin: 5px 0 0;
  color: var(--rf-text-secondary);
  font-size: 12.5px;
  line-height: 1.5;
}

.update-dialog-close {
  width: 34px;
  height: 34px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border: 1px solid transparent;
  border-radius: 10px;
  background: transparent;
  color: var(--rf-text-muted);
  cursor: pointer;
  transition:
    color var(--rf-duration) var(--rf-ease),
    border-color var(--rf-duration) var(--rf-ease),
    background var(--rf-duration) var(--rf-ease);
}

.update-dialog-close:hover:not(:disabled) {
  border-color: var(--rf-border);
  background: var(--rf-bg-hover);
  color: var(--rf-text);
}

.update-dialog-close:focus-visible {
  outline: 2px solid var(--rf-accent);
  outline-offset: 2px;
}

.update-dialog-close:disabled {
  cursor: not-allowed;
  opacity: 0.5;
}

.update-dialog-content {
  display: grid;
  gap: 20px;
  max-height: min(62vh, 540px);
  padding: 24px 28px;
  overflow-y: auto;
  overscroll-behavior: contain;
}

.update-version-route {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto minmax(0, 1fr);
  align-items: stretch;
  gap: var(--rf-space-3);
}

.update-version-card {
  display: grid;
  gap: 5px;
  padding: 14px 16px;
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-control);
  background: var(--rf-bg-raised);
}

.update-version-card span {
  color: var(--rf-text-muted);
  font-size: 11px;
  font-weight: 650;
}

.update-version-card strong {
  color: var(--rf-text);
  font-family: var(--rf-font-mono);
  font-size: 16px;
  font-weight: 720;
}

.update-version-card.is-target {
  border-color: color-mix(
    in srgb,
    var(--rf-accent) 48%,
    var(--rf-border)
  );
  background: var(--rf-accent-muted);
  box-shadow: inset 3px 0 0 var(--rf-accent);
}

.update-version-card.is-target span,
.update-version-card.is-target strong {
  color: var(--rf-accent);
}

.update-version-arrow {
  align-self: center;
  display: inline-flex;
  color: var(--rf-text-muted);
}

.update-highlights {
  min-width: 0;
}

.update-section-heading {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: var(--rf-space-3);
  margin-bottom: 10px;
}

.update-section-heading h3 {
  margin: 0;
  color: var(--rf-text);
  font-size: 15px;
  font-weight: 720;
}

.update-section-kicker {
  color: var(--rf-text-muted);
}

.update-count {
  flex-shrink: 0;
  padding: 4px 9px;
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-tag);
  background: var(--rf-bg-raised);
  color: var(--rf-text-secondary);
  font-size: 11px;
  font-weight: 650;
}

.update-highlight-list {
  margin: 0;
  padding: 0;
  overflow: hidden;
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-control);
  background: var(--rf-bg-panel);
  list-style: none;
}

.update-highlight-list li {
  display: grid;
  grid-template-columns: 30px minmax(0, 1fr);
  align-items: start;
  gap: 11px;
  padding: 11px 13px;
  color: var(--rf-text-secondary);
  font-size: 12.5px;
  line-height: 1.55;
}

.update-highlight-list li + li {
  border-top: 1px solid var(--rf-border);
}

.update-highlight-list li:hover {
  background: color-mix(in srgb, var(--rf-bg-hover) 62%, transparent);
}

.update-highlight-index {
  width: 28px;
  height: 23px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border-radius: 7px;
  background: var(--rf-accent-muted);
  color: var(--rf-accent);
  font-family: var(--rf-font-mono);
  font-size: 10px;
  font-weight: 750;
}

.update-notes-fallback {
  margin: 0;
  padding: 14px 16px;
  border: 1px dashed var(--rf-border-strong);
  border-radius: var(--rf-radius-control);
  color: var(--rf-text-secondary);
  line-height: 1.6;
}

.update-trust-note {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr);
  gap: 11px;
  padding: 12px 14px;
  border: 1px solid
    color-mix(in srgb, var(--rf-success) 28%, var(--rf-border));
  border-radius: var(--rf-radius-control);
  background: color-mix(in srgb, var(--rf-success) 8%, transparent);
}

.update-trust-icon {
  width: 30px;
  height: 30px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border-radius: 9px;
  background: color-mix(in srgb, var(--rf-success) 14%, transparent);
  color: var(--rf-success);
}

.update-trust-note div {
  display: grid;
  gap: 3px;
}

.update-trust-note strong {
  color: var(--rf-text);
  font-size: 12.5px;
}

.update-trust-note span {
  color: var(--rf-text-secondary);
  font-size: 11.5px;
  line-height: 1.5;
}

.update-dialog-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--rf-space-4);
  padding: 16px 28px;
  border-top: 1px solid var(--rf-border);
  background: color-mix(in srgb, var(--rf-bg-raised) 72%, var(--rf-bg-panel));
}

.update-dialog-footer p {
  margin: 0;
  color: var(--rf-text-muted);
  font-size: 11.5px;
  line-height: 1.5;
}

.update-dialog-actions {
  display: flex;
  flex-shrink: 0;
  gap: var(--rf-space-2);
}

.update-dialog-actions .el-button {
  min-width: 108px;
}

@media (max-width: 560px) {
  .update-dialog-header {
    gap: var(--rf-space-3);
    padding: 20px;
  }

  .update-dialog-mark {
    width: 40px;
    height: 40px;
  }

  .update-dialog-content {
    padding: 20px;
  }

  .update-version-route {
    grid-template-columns: 1fr;
    gap: var(--rf-space-2);
  }

  .update-version-arrow {
    justify-self: center;
    transform: rotate(90deg);
  }

  .update-dialog-footer {
    align-items: stretch;
    flex-direction: column;
    padding: 16px 20px 20px;
  }

  .update-dialog-actions {
    display: grid;
    grid-template-columns: 1fr 1.2fr;
  }

  .update-dialog-actions .el-button {
    width: 100%;
    min-width: 0;
    margin: 0;
  }
}

@media (max-height: 680px) {
  .update-dialog-content {
    max-height: 46vh;
  }
}

@media (prefers-reduced-motion: reduce) {
  .update-dialog-close,
  .update-highlight-list li {
    transition: none;
  }
}
</style>
