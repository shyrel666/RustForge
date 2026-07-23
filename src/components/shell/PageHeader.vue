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
    <button type="button" class="back-btn" aria-label="返回" @click="goBack">
      <el-icon :size="18"><ArrowLeft /></el-icon>
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
  align-items: flex-start;
  gap: var(--rf-space-3);
  flex-shrink: 0;
}

.back-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 36px;
  height: 36px;
  margin-top: 2px;
  border: none;
  border-radius: 10px;
  background: var(--rf-bg-pill);
  color: var(--rf-text-secondary);
  cursor: pointer;
  flex-shrink: 0;
  transition:
    background var(--rf-duration) var(--rf-ease),
    color var(--rf-duration) var(--rf-ease);
}

.back-btn:hover {
  color: var(--rf-text);
  background: var(--rf-bg-hover);
}

.page-copy {
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.page-title {
  margin: 0;
  font-size: 24px;
  font-weight: 750;
  letter-spacing: -0.02em;
  color: var(--rf-text);
  line-height: 1.2;
}

.page-desc {
  margin: 0;
  font-size: 13px;
  line-height: 1.45;
  color: var(--rf-text-secondary);
}

.page-actions {
  margin-left: auto;
  margin-top: 2px;
  display: flex;
  align-items: center;
  gap: var(--rf-space-2);
}
</style>
