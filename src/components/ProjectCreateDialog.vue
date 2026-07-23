<script setup lang="ts">
import { reactive, ref } from "vue";
import { ElMessage } from "element-plus";
import { useProjectStore } from "../stores/project";
import { normalizeScopeList } from "../utils/scope";

const visible = defineModel<boolean>({ default: false });
const project = useProjectStore();
const saving = ref(false);
const form = reactive({
  name: "",
  target_host: "",
  scopeText: "",
});

async function createProject() {
  if (!form.name.trim()) {
    ElMessage.warning("请填写项目名称");
    return;
  }

  saving.value = true;
  try {
    const scope = normalizeScopeList(form.scopeText.split(/[\n,;]+/));
    await project.create(form.name.trim(), form.target_host.trim(), scope);
    visible.value = false;
    form.name = "";
    form.target_host = "";
    form.scopeText = "";
    ElMessage.success("项目已创建");
  } catch (error) {
    ElMessage.error(String(error));
  } finally {
    saving.value = false;
  }
}
</script>

<template>
  <el-dialog v-model="visible" title="新建项目" width="480px">
    <el-alert type="warning" :closable="false" class="project-alert">
      一个项目对应一个已获授权的渗透目标。
    </el-alert>
    <el-form label-width="90px">
      <el-form-item label="项目名称" required>
        <el-input
          v-model="form.name"
          placeholder="如：某靶场 / example.com 授权测试"
        />
      </el-form-item>
      <el-form-item label="目标主机">
        <el-input
          v-model="form.target_host"
          placeholder="如 target.example.com"
        />
      </el-form-item>
      <el-form-item label="Scope 白名单">
        <el-input
          v-model="form.scopeText"
          type="textarea"
          :rows="3"
          placeholder="每行一个域名，支持 *.example.com 通配"
        />
      </el-form-item>
    </el-form>
    <template #footer>
      <el-button @click="visible = false">取消</el-button>
      <el-button type="primary" :loading="saving" @click="createProject">
        创建
      </el-button>
    </template>
  </el-dialog>
</template>

<style scoped>
.project-alert {
  margin-bottom: var(--rf-space-3);
}
</style>
