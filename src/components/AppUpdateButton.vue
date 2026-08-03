<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { ElMessage } from "element-plus";
import { useAppUpdater } from "../services/appUpdater";
import AppUpdateDialog from "./AppUpdateDialog.vue";

const updater = useAppUpdater();
const dialogVisible = ref(false);

const buttonBusy = computed(
  () => dialogVisible.value || updater.busy.value,
);

watch(
  () => updater.pendingUpdatePromptVersion.value,
  (version) => {
    if (!version) return;
    dialogVisible.value = true;
    updater.acknowledgeUpdatePrompt(version);
  },
  { immediate: true },
);

const buttonTitle = computed(() => {
  if (dialogVisible.value) return "正在查看更新详情";
  if (updater.status.value === "downloading") {
    const progress = updater.progressPercent.value;
    return progress === null
      ? "正在下载更新"
      : `正在下载更新 · ${progress}%`;
  }
  if (updater.status.value === "installing") return "正在安装更新";
  return `发现新版本 v${updater.targetVersion.value}`;
});

function openUpdateDialog() {
  if (buttonBusy.value) return;
  dialogVisible.value = true;
}

async function installAvailableUpdate() {
  if (updater.busy.value) return;
  dialogVisible.value = false;

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
    :title="buttonTitle"
    :aria-label="buttonTitle"
    :disabled="buttonBusy"
    aria-live="polite"
    @click.stop="openUpdateDialog"
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
    <svg
      v-else
      class="update-icon"
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2" />
      <path
        class="update-arrow"
        d="M12 16V8M8 12l4-4 4 4"
        stroke="currentColor"
        stroke-width="2"
        stroke-linecap="round"
        stroke-linejoin="round"
      />
    </svg>
  </button>

  <AppUpdateDialog
    v-model="dialogVisible"
    :current-version="updater.currentVersion.value"
    :target-version="updater.targetVersion.value"
    :release-notes="updater.releaseNotes.value"
    :busy="updater.busy.value"
    @confirm="installAvailableUpdate"
  />
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
  border: none;
  border-radius: 50%;
  background: transparent;
  color: var(--rf-accent);
  font: inherit;
  cursor: pointer;
  transition: color var(--rf-duration) var(--rf-ease);
}

.app-update-button:hover:not(:disabled) {
  color: var(--rf-accent-hover);
}

.app-update-button:focus-visible {
  outline: 2px solid var(--rf-accent);
  outline-offset: 2px;
}

.app-update-button:disabled {
  cursor: progress;
}

.update-icon {
  width: 22px;
  height: 22px;
  overflow: visible;
}

.update-arrow {
  transform-origin: center;
}

.app-update-button:hover:not(:disabled) .update-arrow {
  animation: update-arrow-rise 520ms var(--rf-ease) infinite alternate;
}

.update-progress {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 22px;
  height: 22px;
  border: 2px solid currentColor;
  border-radius: 50%;
  box-sizing: border-box;
  font-size: 8px;
  font-weight: 750;
  letter-spacing: -0.03em;
}

@keyframes update-arrow-rise {
  from {
    transform: translateY(1px);
  }
  to {
    transform: translateY(-1px);
  }
}

@media (prefers-reduced-motion: reduce) {
  .app-update-button:hover:not(:disabled) .update-arrow {
    animation: none;
  }
}
</style>
