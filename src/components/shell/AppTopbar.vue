<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import { ElMessage } from "element-plus";
import {
  Monitor,
  Share,
  Aim,
  Setting,
  Promotion,
  Plus,
  Sunny,
  Moon,
} from "@element-plus/icons-vue";
import AppUpdateButton from "../AppUpdateButton.vue";
import ProjectCreateDialog from "../ProjectCreateDialog.vue";
import { useProjectStore } from "../../stores/project";
import { useSettingsStore } from "../../stores/settings";
import { useTrafficStore } from "../../stores/traffic";
import { resolveDark, watchSystemTheme } from "../../utils/theme";

const route = useRoute();
const router = useRouter();
const project = useProjectStore();
const settings = useSettingsStore();
const traffic = useTrafficStore();
const darkThemeActive = ref(resolveDark(settings.theme));
const themeSwitching = ref(false);
let stopSystemThemeWatch: (() => void) | undefined;

const items = [
  { path: "/traffic", label: "流量", icon: Monitor },
  { path: "/repeater", label: "重放", icon: Promotion },
  { path: "/tasks", label: "AI 评估", icon: Share },
  { path: "/findings", label: "发现", icon: Aim },
  { path: "/settings", label: "设置", icon: Setting },
];

const proxyLabel = computed(() =>
  traffic.proxyRunning ? `代理 · ${traffic.proxyPort}` : "代理未运行"
);
const themeToggleTitle = computed(() =>
  darkThemeActive.value ? "切换到浅色主题" : "切换到深色主题"
);

onMounted(() => {
  void traffic.syncProxyStatus();
  darkThemeActive.value = resolveDark(settings.theme);
  stopSystemThemeWatch = watchSystemTheme(() => {
    darkThemeActive.value = resolveDark(settings.theme);
  });
});

onUnmounted(() => {
  stopSystemThemeWatch?.();
});

function go(path: string) {
  if (route.path !== path) router.push(path);
}

function goHome() {
  go("/");
}

function goTokenUsage() {
  void router.push({ path: "/settings", hash: "#token-usage" });
}

async function toggleTheme(event: MouseEvent) {
  if (themeSwitching.value) return;
  themeSwitching.value = true;
  const nextTheme = darkThemeActive.value ? "light" : "dark";
  const nextDark = nextTheme === "dark";
  const button = event.currentTarget as HTMLElement;
  const rect = button.getBoundingClientRect();
  const originX = rect.left + rect.width / 2;
  const originY = rect.top + rect.height / 2;
  let persistTheme: Promise<void> = Promise.resolve();

  const applyNextTheme = async () => {
    darkThemeActive.value = nextDark;
    persistTheme = settings.setTheme(nextTheme);
    void persistTheme.catch(() => undefined);
    await nextTick();
  };

  try {
    const reduceMotion = window.matchMedia(
      "(prefers-reduced-motion: reduce)"
    ).matches;
    if (typeof document.startViewTransition !== "function" || reduceMotion) {
      await applyNextTheme();
    } else {
      const transition = document.startViewTransition(applyNextTheme);
      try {
        await transition.ready;
        const endRadius = Math.hypot(
          Math.max(originX, window.innerWidth - originX),
          Math.max(originY, window.innerHeight - originY)
        );
        const reveal = document.documentElement.animate(
          {
            clipPath: [
              `circle(0px at ${originX}px ${originY}px)`,
              `circle(${endRadius}px at ${originX}px ${originY}px)`,
            ],
          },
          {
            duration: 520,
            easing: "cubic-bezier(0.22, 1, 0.36, 1)",
            pseudoElement: "::view-transition-new(root)",
          }
        );
        await reveal.finished;
      } catch {
        // 过渡属于渐进增强；捕获失败时仍保留已完成的主题切换。
      }
      await transition.updateCallbackDone;
    }
    await persistTheme;
  } catch (e) {
    darkThemeActive.value = resolveDark(settings.theme);
    ElMessage.error(`切换主题失败：${String(e)}`);
  } finally {
    themeSwitching.value = false;
  }
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
        <button
          type="button"
          class="shortcut-button token-usage-button"
          title="Token 统计"
          aria-label="打开 Token 统计"
          @click="goTokenUsage"
        >
          <span class="token-chart-icon" aria-hidden="true">
            <span class="token-chart-bar token-chart-bar--short" />
            <span class="token-chart-bar token-chart-bar--tall" />
            <span class="token-chart-bar token-chart-bar--medium" />
          </span>
        </button>
        <button
          type="button"
          class="shortcut-button theme-toggle-button"
          :title="themeToggleTitle"
          :aria-label="themeToggleTitle"
          :aria-pressed="darkThemeActive"
          :disabled="themeSwitching"
          @click="toggleTheme"
        >
          <el-icon class="theme-toggle-icon" :size="18">
            <Sunny v-if="darkThemeActive" />
            <Moon v-else />
          </el-icon>
        </button>
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

.shortcut-button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  width: 30px;
  height: 30px;
  padding: 0;
  border: none;
  border-radius: 50%;
  background: transparent;
  color: var(--rf-text-secondary);
  font: inherit;
  cursor: pointer;
  transition: color var(--rf-duration) var(--rf-ease);
}

.shortcut-button:hover:not(:disabled) {
  color: var(--rf-accent);
}

.shortcut-button:focus-visible {
  outline: 2px solid var(--rf-accent);
  outline-offset: 2px;
}

.shortcut-button:disabled {
  cursor: progress;
}

.theme-toggle-icon {
  transform-origin: center;
}

.theme-toggle-button:hover:not(:disabled) .theme-toggle-icon {
  animation: theme-icon-sway 520ms var(--rf-ease) infinite alternate;
}

.token-chart-icon {
  display: inline-flex;
  align-items: flex-end;
  justify-content: center;
  gap: 3px;
  width: 18px;
  height: 18px;
  padding: 2px 1px;
  box-sizing: border-box;
}

.token-chart-bar {
  width: 2px;
  border-radius: 2px;
  background: currentColor;
  transform-origin: center bottom;
}

.token-chart-bar--short {
  height: 7px;
}

.token-chart-bar--tall {
  height: 14px;
}

.token-chart-bar--medium {
  height: 10px;
}

.token-usage-button:hover .token-chart-bar {
  animation: token-chart-wave 560ms ease-in-out infinite alternate;
}

.token-usage-button:hover .token-chart-bar--tall {
  animation-delay: 110ms;
}

.token-usage-button:hover .token-chart-bar--medium {
  animation-delay: 220ms;
}

@keyframes token-chart-wave {
  from {
    transform: scaleY(0.55);
  }
  to {
    transform: scaleY(1);
  }
}

@keyframes theme-icon-sway {
  from {
    transform: rotate(-8deg) scale(0.94);
  }
  to {
    transform: rotate(8deg) scale(1.06);
  }
}

@media (prefers-reduced-motion: reduce) {
  .theme-toggle-button:hover:not(:disabled) .theme-toggle-icon,
  .token-usage-button:hover .token-chart-bar {
    animation: none;
  }
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
