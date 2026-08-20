<script setup lang="ts">
import { useRouter } from "vue-router";
import { ArrowLeft } from "@element-plus/icons-vue";

defineProps<{ title: string; description?: string }>();

const router = useRouter();

function goBack() {
  router.push("/");
}
</script>

<template>
  <header class="page-header">
    <button type="button" class="back-btn" aria-label="返回概览" title="返回概览" @click="goBack">
      <el-icon :size="14"><ArrowLeft /></el-icon>
    </button>
    <div class="page-copy">
      <h1 class="page-title">{{ title }}</h1>
      <p v-if="description" class="page-desc">{{ description }}</p>
    </div>
    <div v-if="$slots.default" class="page-actions">
      <slot />
    </div>
  </header>
</template>

<style scoped>
.page-header {
  display: flex;
  align-items: center;
  gap: var(--rf-space-3);
  flex-shrink: 0;
  padding-bottom: var(--rf-space-2);
  border-bottom: 1px solid var(--rf-border);
}

.back-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 28px;
  height: 28px;
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-control);
  background: var(--rf-bg-raised);
  color: var(--rf-text-secondary);
  cursor: pointer;
  flex-shrink: 0;
  transition: all var(--rf-duration) var(--rf-ease);
}

.back-btn:hover {
  color: var(--rf-text);
  border-color: var(--rf-border-strong);
  background: var(--rf-bg-hover);
}

.page-copy {
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 1px;
}

.page-title {
  margin: 0;
  font-size: 16px;
  font-weight: 700;
  letter-spacing: -0.015em;
  color: var(--rf-text);
  line-height: 1.25;
}

.page-desc {
  margin: 0;
  font-size: 13px;
  font-weight: var(--rf-font-weight-secondary);
  line-height: 1.4;
  color: var(--rf-text-secondary);
}

.page-actions {
  margin-left: auto;
  display: flex;
  align-items: center;
  gap: var(--rf-space-2);
}
</style>
