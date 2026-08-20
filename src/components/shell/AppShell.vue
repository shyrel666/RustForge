<script setup lang="ts">
import { computed, onMounted, watch } from "vue";
import { useRoute } from "vue-router";
import AppTopbar from "./AppTopbar.vue";
import { useProjectStore } from "../../stores/project";
import { useAppUpdater } from "../../services/appUpdater";
import { recordWorkspaceVisit } from "../../utils/workspaceHistory";

const route = useRoute();
const project = useProjectStore();
const updater = useAppUpdater();
const isImmersive = computed(() => !!route.meta.immersive);

onMounted(() => {
  void updater.checkForUpdates({ automatic: true, silent: true });
});

watch(
  [() => project.current?.id ?? null, () => route.path],
  ([projectId, path]) => {
    if (projectId !== null) recordWorkspaceVisit(projectId, path);
  },
  { immediate: true },
);
</script>

<template>
  <div class="app-shell" :class="{ 'is-immersive': isImmersive }">
    <AppTopbar v-if="!isImmersive" />
    <main class="work-area" :class="{ 'work-area--immersive': isImmersive }">
      <router-view v-slot="{ Component }">
        <transition name="rf-fade" mode="out-in">
          <component :is="Component" />
        </transition>
      </router-view>
    </main>
  </div>
</template>

<style scoped>
.app-shell {
  display: flex;
  flex-direction: column;
  height: 100%;
  min-height: 0;
  background: var(--rf-bg-base);
  color: var(--rf-text);
}

.work-area {
  flex: 1;
  min-height: 0;
  overflow: auto;
  padding: var(--rf-space-3) var(--rf-space-4) var(--rf-space-4);
  display: flex;
  flex-direction: column;
}

.work-area--immersive {
  padding: var(--rf-space-3) clamp(16px, 2.5vw, 32px) var(--rf-space-3);
}

.work-area > :deep(*) {
  flex: 1 1 auto;
  min-height: 0;
  width: 100%;
}

.rf-fade-enter-active,
.rf-fade-leave-active {
  transition: opacity var(--rf-duration) var(--rf-ease);
}

.rf-fade-enter-from,
.rf-fade-leave-to {
  opacity: 0;
}
</style>
