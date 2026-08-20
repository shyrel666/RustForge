<script setup lang="ts">
import { onMounted, onUnmounted, ref } from "vue";
import { useSettingsStore } from "./stores/settings";
import { useProjectStore } from "./stores/project";
import { applyTheme, watchSystemTheme } from "./utils/theme";
import AppShell from "./components/shell/AppShell.vue";
import ConsentDialog from "./components/ConsentDialog.vue";

const settings = useSettingsStore();
const project = useProjectStore();
const ready = ref(false);
let stopWatch: (() => void) | undefined;

onMounted(async () => {
  // 加载完成前先按默认浅色渲染，避免主题闪烁
  applyTheme("light");
  await settings.load();
  await project.load();
  stopWatch = watchSystemTheme(() => {
    if (settings.theme === "system") applyTheme("system");
  });
  ready.value = true;
});

onUnmounted(() => {
  stopWatch?.();
});
</script>

<template>
  <AppShell v-if="ready" />
  <ConsentDialog v-if="ready && !settings.consent_accepted" />
</template>
