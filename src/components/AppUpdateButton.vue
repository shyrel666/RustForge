<script setup lang="ts">
import { computed, ref } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";
import { Top } from "@element-plus/icons-vue";
import { useAppUpdater } from "../services/appUpdater";

const updater = useAppUpdater();
const confirming = ref(false);

const buttonBusy = computed(
  () => confirming.value || updater.busy.value,
);

const buttonTitle = computed(() => {
  if (confirming.value) return "等待更新确认";
  if (updater.status.value === "downloading") {
    const progress = updater.progressPercent.value;
    return progress === null
      ? "正在下载更新"
      : `正在下载更新 · ${progress}%`;
  }
  if (updater.status.value === "installing") return "正在安装更新";
  return `发现新版本 v${updater.targetVersion.value}`;
});

async function installAvailableUpdate() {
  if (buttonBusy.value) return;

  confirming.value = true;
  try {
    const versionLine = updater.currentVersion.value
      ? `v${updater.currentVersion.value} → v${updater.targetVersion.value}`
      : `更新到 v${updater.targetVersion.value}`;
    const notes = updater.releaseNotes.value;
    await ElMessageBox.confirm(
      notes ? `${versionLine}\n\n${notes}` : versionLine,
      "应用更新",
      {
        confirmButtonText: "立即更新",
        cancelButtonText: "稍后",
        type: "info",
      },
    );
  } catch {
    return;
  } finally {
    confirming.value = false;
  }

  const succeeded = await updater.downloadAndInstall();
  if (!succeeded) {
    const reason = updater.errorMessage.value || "更新任务正在进行";
    ElMessage.error(`更新失败：${reason}`);
  }
}
</script>

<template>
  <button
    v-if="updater.showUpdateButton.value"
    type="button"
    class="app-update-button"
    :class="{ busy: buttonBusy }"
    :title="buttonTitle"
    :aria-label="buttonTitle"
    :disabled="buttonBusy"
    aria-live="polite"
    @click.stop="installAvailableUpdate"
  >
    <span
      v-if="
        updater.status.value === 'downloading' &&
        updater.progressPercent.value !== null
      "
      class="update-progress"
    >
      {{ updater.progressPercent.value }}
    </span>
    <el-icon v-else :size="16"><Top /></el-icon>
  </button>
</template>

<style scoped>
.app-update-button {
  width: 30px;
  height: 30px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  padding: 0;
  border: 1px solid
    color-mix(in srgb, var(--rf-accent) 46%, var(--rf-border));
  border-radius: 50%;
  background: var(--rf-accent-muted);
  color: var(--rf-accent);
  font: inherit;
  cursor: pointer;
  transition:
    background var(--rf-duration) var(--rf-ease),
    border-color var(--rf-duration) var(--rf-ease),
    transform var(--rf-duration) var(--rf-ease);
}

.app-update-button:hover:not(:disabled) {
  border-color: var(--rf-accent);
  background: var(--rf-accent);
  color: var(--rf-accent-on);
  transform: translateY(-1px);
}

.app-update-button:focus-visible {
  outline: 2px solid var(--rf-accent);
  outline-offset: 2px;
}

.app-update-button:disabled {
  cursor: progress;
}

.app-update-button.busy {
  animation: update-pulse 1.2s ease-in-out infinite;
}

.update-progress {
  font-size: 9px;
  font-weight: 750;
  letter-spacing: -0.03em;
}

@keyframes update-pulse {
  0%,
  100% {
    opacity: 0.55;
  }
  50% {
    opacity: 1;
  }
}

@media (prefers-reduced-motion: reduce) {
  .app-update-button.busy {
    animation: none;
  }
}
</style>
