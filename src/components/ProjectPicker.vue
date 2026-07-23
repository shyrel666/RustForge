<script setup lang="ts">
import { reactive, ref } from "vue";
import { ElMessage } from "element-plus";
import { Plus } from "@element-plus/icons-vue";
import { useProjectStore } from "../stores/project";
import { normalizeScopeList } from "../utils/scope";

const project = useProjectStore();
const dialogVisible = ref(false);
const form = reactive({ name: "", target_host: "", scopeText: "" });
const saving = ref(false);

async function save() {
  if (!form.name.trim()) {
    ElMessage.warning("请填写项目名称");
    return;
  }
  saving.value = true;
  try {
    const scope = normalizeScopeList(form.scopeText.split(/[\n,;]+/));
    await project.create(form.name.trim(), form.target_host.trim(), scope);
    dialogVisible.value = false;
    form.name = form.target_host = form.scopeText = "";
    ElMessage.success("项目已创建");
  } catch (e) {
    ElMessage.error(String(e));
  } finally {
    saving.value = false;
  }
}

async function onSelect(id: number) {
  await project.select(id);
}
</script>

<template>
  <div class="picker">
    <div class="picker-label">当前项目</div>
    <el-select
      :model-value="project.current?.id"
      placeholder="选择授权目标"
      size="small"
      class="picker-select"
      @change="onSelect"
    >
      <el-option
        v-for="p in project.projects"
        :key="p.id"
        :value="p.id"
        :label="p.name"
      />
    </el-select>
    <el-button
      size="small"
      :icon="Plus"
      class="picker-add"
      @click="dialogVisible = true"
    >
      新建项目
    </el-button>

    <el-dialog v-model="dialogVisible" title="新建项目" width="480px">
      <el-alert type="warning" :closable="false" style="margin-bottom: 12px">
        一个项目对应一个已获授权的渗透目标。
      </el-alert>
      <el-form label-width="90px">
        <el-form-item label="项目名称" required>
          <el-input v-model="form.name" placeholder="如：某靶场 / example.com 授权测试" />
        </el-form-item>
        <el-form-item label="目标主机">
          <el-input v-model="form.target_host" placeholder="如 target.example.com" />
        </el-form-item>
        <el-form-item label="Scope 白名单">
          <el-input
            v-model="form.scopeText"
            type="textarea"
            :rows="3"
            placeholder="每行一个域名，支持 *.example.com 通配；仅拦截白名单内的流量"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="save">创建</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.picker-label {
  margin-bottom: 6px;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.04em;
  color: var(--rf-text-muted);
  text-transform: uppercase;
}
.picker-select {
  width: 100%;
}
.picker-add {
  width: 100%;
  margin-top: 8px;
}
</style>
