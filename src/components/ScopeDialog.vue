<script setup lang="ts">
import { ref, watch } from "vue";
import { ElMessage } from "element-plus";
import { useProjectStore } from "../stores/project";
import { normalizeScopeList } from "../utils/scope";

const props = defineProps<{ modelValue: boolean }>();
const emit = defineEmits<{ "update:modelValue": [boolean] }>();

const project = useProjectStore();
const scope = ref<string[]>([]);
const saving = ref(false);

watch(
  () => props.modelValue,
  (v) => {
    if (v) scope.value = [...(project.current?.scope ?? [])];
  }
);

async function save() {
  if (!project.current) return;
  saving.value = true;
  try {
    // 粘贴 URL/带端口也能用：入库前统一清洗成纯 host 模式
    await project.updateScope(project.current.id, normalizeScopeList(scope.value));
    ElMessage.success("Scope 已更新，即刻生效");
    emit("update:modelValue", false);
  } catch (e) {
    ElMessage.error(String(e));
  } finally {
    saving.value = false;
  }
}
</script>

<template>
  <el-dialog
    :model-value="modelValue"
    title="Scope 拦截白名单"
    width="560px"
    @update:model-value="emit('update:modelValue', $event)"
  >
    <el-alert type="warning" :closable="false" class="mb">
      <b>设计红线</b>：只有命中白名单的 host 才会被解密和记录，其余流量原样盲转发。
      这保证你只会拦截已授权目标的流量。
    </el-alert>
    <el-select
      v-model="scope"
      multiple
      filterable
      allow-create
      default-first-option
      :reserve-keyword="false"
      placeholder="输入域名后回车，如 example.com 或 *.example.com"
      class="scope-select"
    />
    <div class="tips">
      <p>• <code>example.com</code> — 仅精确匹配该域名（不含子域）</p>
      <p>• <code>*.example.com</code> — 匹配 example.com 及所有子域</p>
      <p>• <code>192.168.1.1</code> — IP 直接填</p>
      <p>• 直接粘贴 <code>https://example.com/path</code> 也行，保存时自动清洗成域名</p>
    </div>
    <template #footer>
      <el-button @click="emit('update:modelValue', false)">取消</el-button>
      <el-button type="primary" :loading="saving" @click="save">保存</el-button>
    </template>
  </el-dialog>
</template>

<style scoped>
.mb {
  margin-bottom: 12px;
}
.scope-select {
  width: 100%;
}
.tips {
  margin-top: 12px;
  color: var(--el-text-color-secondary);
  font-size: 12px;
  line-height: 1.6;
}
.tips p {
  margin: 2px 0;
}
</style>
