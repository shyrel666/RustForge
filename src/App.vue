<script setup lang="ts">
import { onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import {
  Monitor,
  Share,
  Aim,
  Setting,
  Promotion,
} from "@element-plus/icons-vue";
import { useSettingsStore } from "./stores/settings";
import { useProjectStore } from "./stores/project";
import ConsentDialog from "./components/ConsentDialog.vue";
import ProjectPicker from "./components/ProjectPicker.vue";

const settings = useSettingsStore();
const project = useProjectStore();
const route = useRoute();
const ready = ref(false);

onMounted(async () => {
  document.documentElement.classList.add("dark");
  await settings.load();
  await project.load();
  ready.value = true;
});
</script>

<template>
  <el-container v-if="ready" class="layout">
    <el-aside width="200px" class="sidebar">
      <div class="logo">
        <span class="logo-icon">🛡️</span>
        <span class="logo-text">RustForge</span>
      </div>
      <el-menu :default-active="route.path" router class="menu">
        <el-menu-item index="/traffic">
          <el-icon><Monitor /></el-icon>
          <span>流量</span>
        </el-menu-item>
        <el-menu-item index="/repeater">
          <el-icon><Promotion /></el-icon>
          <span>Repeater</span>
        </el-menu-item>
        <el-menu-item index="/tasks">
          <el-icon><Share /></el-icon>
          <span>任务树</span>
        </el-menu-item>
        <el-menu-item index="/findings">
          <el-icon><Aim /></el-icon>
          <span>发现</span>
        </el-menu-item>
        <el-menu-item index="/settings">
          <el-icon><Setting /></el-icon>
          <span>设置</span>
        </el-menu-item>
      </el-menu>
      <div class="sidebar-footer">
        <ProjectPicker />
      </div>
    </el-aside>
    <el-main class="main">
      <router-view />
    </el-main>
    <ConsentDialog v-if="!settings.consent_accepted" />
  </el-container>
</template>

<style scoped>
.layout {
  height: 100%;
}
.sidebar {
  display: flex;
  flex-direction: column;
  border-right: 1px solid var(--el-border-color);
  background: var(--el-bg-color-page);
}
.logo {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 16px;
  font-weight: 600;
  font-size: 15px;
}
.menu {
  flex: 1;
  border-right: none;
}
.sidebar-footer {
  padding: 12px;
  border-top: 1px solid var(--el-border-color);
}
.main {
  padding: 16px;
  overflow: auto;
}
</style>
