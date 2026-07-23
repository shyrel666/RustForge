<script setup lang="ts">
import { ref, watch } from "vue";
import { getKnowledgeCards, type KnowledgeCard } from "../api/tauri";

const props = defineProps<{ owasp: string; cwe: string }>();
const cards = ref<KnowledgeCard[]>([]);

async function load() {
  cards.value = [];
  const owasp = props.owasp?.trim() ?? "";
  const cwe = props.cwe?.trim() ?? "";
  if (!owasp && !cwe) return;
  try {
    cards.value = await getKnowledgeCards(owasp, cwe);
  } catch {
    /* 知识库查询失败不影响主流程，静默 */
  }
}

watch(() => [props.owasp, props.cwe], load, { immediate: true });
</script>

<template>
  <div v-if="cards.length" class="kb">
    <div v-for="c in cards" :key="c.key" class="kb-card">
      <div class="kb-head">
        <el-tag size="small" :type="c.kind === 'owasp' ? 'primary' : 'warning'" effect="dark">
          {{ c.key }}
        </el-tag>
        <span class="kb-title">{{ c.title }}</span>
      </div>
      <div class="kb-grid">
        <div class="kb-item"><span class="kb-label">原理</span>{{ c.principle }}</div>
        <div class="kb-item"><span class="kb-label">危害</span>{{ c.impact }}</div>
        <div class="kb-item"><span class="kb-label">成因</span>{{ c.cause }}</div>
        <div class="kb-item kb-fix"><span class="kb-label">修复</span>{{ c.remediation }}</div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.kb {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.kb-card {
  border: 1px solid var(--el-border-color);
  border-radius: 6px;
  padding: 10px 12px;
  background: var(--el-fill-color-dark);
}
.kb-head {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
}
.kb-title {
  font-weight: 600;
  font-size: 13px;
}
.kb-grid {
  display: flex;
  flex-direction: column;
  gap: 5px;
}
.kb-item {
  font-size: 12.5px;
  line-height: 1.65;
  color: var(--el-text-color-regular);
}
.kb-label {
  display: inline-block;
  min-width: 34px;
  margin-right: 8px;
  padding: 0 5px;
  border-radius: 3px;
  font-size: 11px;
  color: var(--el-text-color-secondary);
  background: var(--el-fill-color);
}
.kb-fix {
  color: var(--el-color-success);
}
.kb-fix .kb-label {
  color: var(--el-color-success);
}
</style>
