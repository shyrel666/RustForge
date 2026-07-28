<script setup lang="ts">
import { ref, watch } from "vue";
import {
  getKnowledgeCards,
  type KnowledgeCard,
  type StandardReference,
  type UnresolvedReference,
} from "../api/tauri";

const props = defineProps<{ references: StandardReference[] }>();
const cards = ref<KnowledgeCard[]>([]);
const unresolved = ref<UnresolvedReference[]>([]);
const error = ref("");

async function load() {
  cards.value = [];
  unresolved.value = [];
  error.value = "";
  if (!props.references.length) return;
  try {
    const lookup = await getKnowledgeCards(props.references);
    cards.value = lookup.cards;
    unresolved.value = lookup.unresolved;
  } catch (e) {
    error.value = String(e);
  }
}

watch(() => props.references, load, { immediate: true, deep: true });
</script>

<template>
  <el-alert
    v-if="error"
    type="warning"
    :closable="false"
    title="知识库不可用"
    :description="error"
    show-icon
  />
  <div v-else-if="cards.length || unresolved.length" class="kb">
    <div v-for="c in cards" :key="c.key" class="kb-card">
      <div class="kb-head">
        <el-tag size="small" type="primary" effect="dark">
          {{ c.key }}
        </el-tag>
        <div>
          <div class="kb-title">{{ c.title }}</div>
          <div class="kb-meta">
            {{ c.framework_label }} · 发布 {{ c.published_at }} · {{ c.license_name }}
          </div>
        </div>
      </div>
      <div class="kb-grid">
        <div class="kb-item"><span class="kb-label">原理</span>{{ c.principle }}</div>
        <div class="kb-item"><span class="kb-label">危害</span>{{ c.impact }}</div>
        <div class="kb-item"><span class="kb-label">成因</span>{{ c.cause }}</div>
        <div class="kb-item kb-fix"><span class="kb-label">修复</span>{{ c.remediation }}</div>
      </div>
    </div>
    <div v-for="u in unresolved" :key="u.key" class="kb-card kb-unresolved">
      <div class="kb-head">
        <el-tag size="small" :type="u.state === 'not_in_pack' ? 'info' : 'warning'">
          {{ u.key }}
        </el-tag>
        <div>
          <div class="kb-title">
            {{ u.state === "not_in_pack" ? "未收录，不影响判定" : "编号不成立" }}
          </div>
          <div class="kb-meta">{{ u.framework_label }} · {{ u.reason }}</div>
        </div>
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
.kb-unresolved {
  background: transparent;
  border-style: dashed;
}
.kb-unresolved .kb-head {
  margin-bottom: 0;
}
.kb-title {
  font-weight: 600;
  font-size: 13px;
}
.kb-meta {
  margin-top: 2px;
  color: var(--el-text-color-secondary);
  font-size: 11px;
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
