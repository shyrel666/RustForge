<script setup lang="ts">
import { ref } from "vue";
import { ElMessageBox } from "element-plus";
import { useSettingsStore } from "../stores/settings";

const settings = useSettingsStore();
const visible = ref(true);
const checked = ref(false);
const loading = ref(false);

async function accept() {
  if (!checked.value) return;
  loading.value = true;
  try {
    await settings.acceptConsent();
    visible.value = false;
  } finally {
    loading.value = false;
  }
}

function decline() {
  ElMessageBox.alert(
    "未同意授权使用声明，本应用无法使用。请关闭应用。",
    "已拒绝",
    { type: "warning", confirmButtonText: "我知道了" }
  );
}
</script>

<template>
  <el-dialog
    v-model="visible"
    title="授权使用声明"
    width="640px"
    :close-on-click-modal="false"
    :close-on-press-escape="false"
    :show-close="false"
    class="consent-dialog"
  >
    <div class="consent-body">
      <p class="lead"><strong>本工具仅供学习与授权测试使用。</strong>在继续之前，请确认：</p>
      <ol>
        <li>你仅对<strong>已获得书面授权</strong>的目标系统使用本工具（如：自己的网站、公司授权目标、CTF 靶场、漏洞赏金范围内的目标）。</li>
        <li>对未授权目标进行扫描、探测或攻击<strong>违反《中华人民共和国网络安全法》等相关法律法规</strong>，需自行承担全部法律责任。</li>
        <li>本工具的 AI 分析结果仅供参考，可能存在误报；所有结论需人工验证，不构成任何保证。</li>
        <li>开启 AI 分析后，你选中的 HTTP 请求/响应内容会发送到你配置的云端大模型服务，请勿对包含敏感数据的流量使用该功能。</li>
        <li>本工具不会在未经你操作的情况下主动向目标发送任何攻击载荷。</li>
      </ol>
      <el-checkbox v-model="checked" size="large">
        我已阅读并同意以上条款，确认仅在授权范围内使用本工具
      </el-checkbox>
    </div>
    <template #footer>
      <el-button @click="decline">不同意</el-button>
      <el-button type="primary" :disabled="!checked" :loading="loading" @click="accept">
        同意并继续
      </el-button>
    </template>
  </el-dialog>
</template>

<style scoped>
.consent-body {
  color: var(--rf-text-secondary);
  font-size: 13px;
}
.consent-body .lead {
  margin: 0 0 var(--rf-space-3);
  color: var(--rf-text);
}
.consent-body ol {
  padding-left: 20px;
  margin: 0 0 var(--rf-space-4);
  line-height: 1.85;
}
.consent-body :deep(.el-checkbox) {
  align-items: flex-start;
  height: auto;
  white-space: normal;
}
</style>
