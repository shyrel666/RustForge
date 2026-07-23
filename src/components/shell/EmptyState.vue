<script setup lang="ts">
withDefaults(
  defineProps<{
    title: string;
    description?: string;
    actionLabel?: string;
    /** 在剩余空间中居中（适合整页空态） */
    centered?: boolean;
  }>(),
  { centered: false }
);

const emit = defineEmits<{
  action: [];
}>();
</script>

<template>
  <div class="empty-state" :class="{ centered }">
    <div class="icon-wrap" aria-hidden="true">
      <slot name="icon" />
    </div>
    <h3 class="title">{{ title }}</h3>
    <p v-if="description" class="desc">{{ description }}</p>
    <div v-if="actionLabel || $slots.action" class="actions">
      <slot name="action">
        <el-button type="primary" size="small" @click="emit('action')">
          {{ actionLabel }}
        </el-button>
      </slot>
    </div>
  </div>
</template>

<style scoped>
.empty-state {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: var(--rf-space-2);
  padding: var(--rf-space-4);
  border: 1px dashed var(--rf-border-strong);
  border-radius: var(--rf-radius-shell);
  background: var(--rf-bg-panel);
}

.empty-state.centered {
  flex: 1;
  min-height: 220px;
  align-items: center;
  justify-content: center;
  text-align: center;
  padding: var(--rf-space-6);
}

.empty-state.centered .desc {
  max-width: 420px;
}

.icon-wrap {
  display: inline-flex;
  color: var(--rf-accent);
  margin-bottom: 2px;
}

.title {
  margin: 0;
  font-size: 13px;
  font-weight: 600;
  color: var(--rf-text);
}

.desc {
  margin: 0;
  max-width: 560px;
  font-size: 12.5px;
  line-height: 1.55;
  color: var(--rf-text-secondary);
}

.actions {
  margin-top: var(--rf-space-1);
}
</style>
