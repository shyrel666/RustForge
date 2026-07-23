<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import {
  Monitor,
  Share,
  Aim,
  Setting,
  Promotion,
  Plus,
} from "@element-plus/icons-vue";
import AppUpdateButton from "../AppUpdateButton.vue";
import ProjectCreateDialog from "../ProjectCreateDialog.vue";
import { useProjectStore } from "../../stores/project";
import { useTrafficStore } from "../../stores/traffic";

const route = useRoute();
const router = useRouter();
const project = useProjectStore();
const traffic = useTrafficStore();

const items = [
  { path: "/traffic", label: "流量", icon: Monitor },
  { path: "/repeater", label: "重放", icon: Promotion },
  { path: "/tasks", label: "任务树", icon: Share },
  { path: "/findings", label: "发现", icon: Aim },
  { path: "/settings", label: "设置", icon: Setting },
];

const proxyLabel = computed(() =>
  traffic.proxyRunning ? `代理 · ${traffic.proxyPort}` : "代理未运行"
);

onMounted(() => {
  void traffic.syncProxyStatus();
});

function go(path: string) {
  if (route.path !== path) router.push(path);
}

function goHome() {
  go("/");
}

function goTraffic() {
  go("/traffic");
}

async function onSelect(id: number) {
  await project.select(id);
}

const dialogVisible = ref(false);
</script>

<template>
  <header class="topbar">
    <div class="left">
      <div class="brand-group">
        <div class="brand" @click="goHome">
          <span class="brand-text">RustForge</span>
        </div>
        <AppUpdateButton />
      </div>
    </div>

    <nav class="nav-pills" aria-label="主导航">
      <button
        v-for="item in items"
        :key="item.path"
        type="button"
        class="nav-pill"
        :class="{ active: route.path === item.path }"
        @click="go(item.path)"
      >
        <el-icon :size="14"><component :is="item.icon" /></el-icon>
        <span>{{ item.label }}</span>
      </button>
    </nav>

    <div class="right">
      <button
        type="button"
        class="status-pill"
        :class="{ running: traffic.proxyRunning }"
        @click="goTraffic"
      >
        <span class="dot" aria-hidden="true" />
        {{ proxyLabel }}
      </button>

      <div class="project-group">
        <el-select
          :model-value="project.current?.id"
          placeholder="选择项目"
          size="small"
          class="project-select"
          @change="onSelect"
        >
          <el-option
            v-for="p in project.projects"
            :key="p.id"
            :value="p.id"
            :label="p.name"
          />
        </el-select>
        <button
          type="button"
          class="add-btn"
          title="新建项目"
          @click="dialogVisible = true"
        >
          <el-icon :size="18"><Plus /></el-icon>
        </button>
      </div>
    </div>

    <ProjectCreateDialog v-model="dialogVisible" />
  </header>
</template>

<style scoped>
.topbar {
  flex-shrink: 0;
  display: grid;
  grid-template-columns: 1fr auto 1fr;
  align-items: center;
  gap: var(--rf-space-4);
  min-height: var(--rf-topbar-height);
  padding: 10px var(--rf-space-5);
  background: var(--rf-bg-shell);
  border-bottom: 1px solid var(--rf-border);
}

.left,
.right {
  display: flex;
  align-items: center;
  gap: var(--rf-space-3);
  min-width: 0;
}

.left {
  justify-self: start;
}

.right {
  justify-self: end;
  flex-shrink: 0;
}

.nav-pills {
  justify-self: center;
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  padding: 4px;
  background: var(--rf-bg-pill);
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-tag);
}

.brand-group {
  display: inline-flex;
  align-items: center;
  gap: 8px;
}

.brand {
  display: inline-flex;
  align-items: center;
  cursor: pointer;
  user-select: none;
  flex-shrink: 0;
}

.brand-text {
  font-size: 17px;
  font-weight: 700;
  color: var(--rf-accent);
  letter-spacing: -0.02em;
}

.nav-pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  border: none;
  background: transparent;
  color: var(--rf-text-secondary);
  font: inherit;
  font-size: 12.5px;
  font-weight: 500;
  padding: 7px 12px;
  border-radius: var(--rf-radius-tag);
  cursor: pointer;
  transition:
    background var(--rf-duration) var(--rf-ease),
    color var(--rf-duration) var(--rf-ease);
}

.nav-pill:hover {
  color: var(--rf-text);
  background: var(--rf-bg-hover);
}

.nav-pill.active {
  background: var(--rf-accent);
  color: var(--rf-accent-on);
  font-weight: 650;
}

.status-pill {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  height: 32px;
  padding: 0 12px;
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-tag);
  background: var(--rf-bg-raised);
  color: var(--rf-text-secondary);
  font: inherit;
  font-size: 12px;
  cursor: pointer;
  white-space: nowrap;
}

.status-pill:hover {
  border-color: var(--rf-border-strong);
  color: var(--rf-text);
}

.status-pill.running {
  border-color: rgba(52, 211, 153, 0.45);
  color: var(--rf-success);
}

.dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--rf-text-muted);
}

.status-pill.running .dot {
  background: var(--rf-success);
  box-shadow: 0 0 0 3px rgba(52, 211, 153, 0.2);
}

.project-group {
  display: inline-flex;
  align-items: center;
  gap: 8px;
}

.project-select {
  width: 160px;
}

.add-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 34px;
  height: 34px;
  border: none;
  border-radius: 50%;
  background: var(--rf-cta);
  color: #fff;
  cursor: pointer;
  box-shadow: 0 0 0 3px var(--rf-cta-muted);
  transition:
    background var(--rf-duration) var(--rf-ease),
    transform var(--rf-duration) var(--rf-ease);
}

.add-btn:hover {
  background: var(--rf-cta-hover);
  transform: scale(1.04);
}
</style>
