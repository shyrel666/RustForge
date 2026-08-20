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

const router = useRouter();
const route = useRoute();
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
  traffic.proxyRunning ? `127.0.0.1:${traffic.proxyPort}` : "代理未启动"
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
            duration: 400,
            easing: "cubic-bezier(0.16, 1, 0.3, 1)",
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
      <div class="brand">
        <span class="brand-wordmark">
          <span class="brand-rust">RUST</span>
          <span class="brand-ember" aria-hidden="true" />
          <span class="brand-forge">FORGE</span>
        </span>
      </div>

      <div class="divider" />

      <div class="utility-actions">
        <button
          type="button"
          class="utility-btn"
          title="Token 统计与成本"
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
          class="utility-btn"
          :title="themeToggleTitle"
          :aria-label="themeToggleTitle"
          :aria-pressed="darkThemeActive"
          :disabled="themeSwitching"
          @click="toggleTheme"
        >
          <el-icon :size="15">
            <Sunny v-if="darkThemeActive" />
            <Moon v-else />
          </el-icon>
        </button>

        <AppUpdateButton />
      </div>
    </div>

    <nav class="center-nav" aria-label="主导航">
      <div class="nav-segmented">
        <button
          v-for="item in items"
          :key="item.path"
          type="button"
          class="nav-tab"
          :class="{ 'is-active': route.path === item.path }"
          @click="go(item.path)"
        >
          <el-icon :size="13"><component :is="item.icon" /></el-icon>
          <span>{{ item.label }}</span>
        </button>
      </div>
    </nav>

    <div class="right">
      <button
        type="button"
        class="proxy-pill"
        :class="{ 'is-running': traffic.proxyRunning }"
        title="点击跳转到流量配置"
        @click="goTraffic"
      >
        <span class="rf-pulse-dot" :class="traffic.proxyRunning ? 'rf-pulse-dot--active' : 'rf-pulse-dot--stopped'" />
        <span class="proxy-text">{{ proxyLabel }}</span>
      </button>

      <div class="project-suite">
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
          class="new-project-btn"
          title="新建项目"
          @click="dialogVisible = true"
        >
          <el-icon :size="14"><Plus /></el-icon>
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
  gap: var(--rf-space-3);
  height: var(--rf-topbar-height);
  padding: 0 var(--rf-space-4);
  background: var(--rf-bg-shell);
  border-bottom: 1px solid var(--rf-border);
  z-index: 100;
}

.left,
.right {
  display: flex;
  align-items: center;
  gap: var(--rf-space-2);
  min-width: 0;
}

.left {
  justify-self: start;
}

.right {
  justify-self: end;
}

.divider {
  width: 1px;
  height: 16px;
  background: var(--rf-border);
}

.brand {
  display: inline-flex;
  align-items: center;
  user-select: none;
  flex-shrink: 0;
  padding: 4px 7px;
  border-radius: var(--rf-radius-control);
}

.brand-wordmark {
  font-family: var(--rf-font-ui);
  font-size: 13px;
  line-height: 1;
  display: inline-flex;
  align-items: center;
  gap: 5px;
  letter-spacing: 0.09em;
}

.brand-rust {
  font-weight: 800;
  color: var(--rf-text);
  letter-spacing: 0.09em;
  transition: color var(--rf-duration) var(--rf-ease);
}

.brand-ember {
  display: inline-block;
  width: 4px;
  height: 4px;
  border-radius: 0.8px;
  background: linear-gradient(135deg, #fbbf24, #ea580c);
  transform: rotate(45deg);
  box-shadow: 0 0 5px rgba(249, 115, 22, 0.4);
  flex-shrink: 0;
  transition: transform var(--rf-duration) var(--rf-ease), box-shadow var(--rf-duration) var(--rf-ease);
}

.brand-forge {
  font-weight: 700;
  letter-spacing: 0.09em;
  background: linear-gradient(135deg, #fbbf24 0%, #f97316 55%, #ea580c 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}

.utility-actions {
  display: inline-flex;
  align-items: center;
  gap: 2px;
}

.utility-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 28px;
  height: 28px;
  padding: 0;
  border: none;
  border-radius: var(--rf-radius-control);
  background: transparent;
  color: var(--rf-text-secondary);
  cursor: pointer;
  transition: all var(--rf-duration) var(--rf-ease);
}

.utility-btn:hover:not(:disabled) {
  background: var(--rf-bg-hover);
  color: var(--rf-text);
}

.utility-btn:disabled {
  opacity: 0.5;
  cursor: progress;
}

.token-chart-icon {
  display: inline-flex;
  align-items: flex-end;
  justify-content: center;
  gap: 2px;
  width: 14px;
  height: 14px;
  padding: 1px 0;
}

.token-chart-bar {
  width: 2px;
  border-radius: 1px;
  background: currentColor;
}

.token-chart-bar--short { height: 5px; }
.token-chart-bar--tall { height: 12px; }
.token-chart-bar--medium { height: 8px; }

.center-nav {
  justify-self: center;
}

.nav-segmented {
  display: inline-flex;
  align-items: center;
  gap: 2px;
  padding: 3px;
  background: var(--rf-bg-pill);
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-control);
}

.nav-tab {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  border: none;
  background: transparent;
  color: var(--rf-text-secondary);
  font: inherit;
  font-size: 13px;
  font-weight: 600;
  padding: 4px 10px;
  border-radius: 4px;
  cursor: pointer;
  transition: all var(--rf-duration) var(--rf-ease);
}

.nav-tab:hover {
  color: var(--rf-text);
  background: var(--rf-bg-hover);
}

.nav-tab.is-active {
  background: var(--rf-bg-panel);
  color: var(--rf-accent);
  font-weight: 600;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.08);
  border: 1px solid var(--rf-border);
}

.proxy-pill {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  height: 26px;
  padding: 0 9px;
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-control);
  background: var(--rf-bg-raised);
  color: var(--rf-text-secondary);
  font-family: var(--rf-font-mono);
  font-size: 12px;
  font-weight: var(--rf-font-weight-secondary);
  cursor: pointer;
  white-space: nowrap;
  transition: all var(--rf-duration) var(--rf-ease);
}

.proxy-pill:hover {
  border-color: var(--rf-border-strong);
  color: var(--rf-text);
}

.proxy-pill.is-running {
  border-color: rgba(16, 185, 129, 0.25);
  color: var(--rf-text);
  background: rgba(16, 185, 129, 0.06);
}

.project-suite {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

.project-select {
  width: 140px;
}

.new-project-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 26px;
  height: 26px;
  border: 1px solid var(--rf-accent-muted);
  border-radius: var(--rf-radius-control);
  background: var(--rf-accent-muted);
  color: var(--rf-accent);
  cursor: pointer;
  transition: all var(--rf-duration) var(--rf-ease);
}

.new-project-btn:hover {
  transform: translateY(-1px);
  background: var(--rf-accent);
  border-color: var(--rf-accent);
  color: var(--rf-accent-on);
  box-shadow:
    inset 0 1px 0 rgba(255, 255, 255, 0.28),
    0 5px 14px color-mix(in srgb, var(--rf-accent) 45%, transparent);
}

.new-project-btn:active {
  transform: translateY(0) scale(0.96);
}

.new-project-btn:focus-visible {
  outline: 2px solid var(--rf-accent);
  outline-offset: 2px;
}
</style>
