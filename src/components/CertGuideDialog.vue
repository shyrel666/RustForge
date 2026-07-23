<script setup lang="ts">
import { ref, watch } from "vue";
import { ElMessage } from "element-plus";
import {
  CaInfo,
  getCaInfo,
  exportCaCert,
  installCaCert,
  revealCaCert,
} from "../api/tauri";

const props = defineProps<{ modelValue: boolean; proxyPort: number }>();
const emit = defineEmits<{ "update:modelValue": [boolean] }>();

const info = ref<CaInfo | null>(null);
const loading = ref(false);
const installing = ref(false);
const exportedTo = ref("");

// 打开时加载 CA 信息
watch(
  () => props.modelValue,
  async (v) => {
    if (v) await refresh();
  }
);

async function refresh() {
  loading.value = true;
  try {
    info.value = await getCaInfo();
  } catch (e) {
    ElMessage.error(String(e));
  } finally {
    loading.value = false;
  }
}

async function install() {
  installing.value = true;
  try {
    await installCaCert();
    ElMessage.success("安装命令已执行（若弹出安全警告请点“是”），正在重新检测…");
    // certutil 是同步的，稍等系统弹窗处理后刷新状态
    setTimeout(refresh, 800);
  } catch (e) {
    ElMessage.error(String(e));
  } finally {
    installing.value = false;
  }
}

async function doExport() {
  try {
    exportedTo.value = await exportCaCert();
    ElMessage.success("证书已导出");
  } catch (e) {
    ElMessage.error(String(e));
  }
}

async function reveal() {
  try {
    await revealCaCert();
  } catch (e) {
    ElMessage.error(String(e));
  }
}
</script>

<template>
  <el-dialog
    :model-value="modelValue"
    title="HTTPS 解密前置：安装并信任 CA 证书"
    width="640px"
    @update:model-value="emit('update:modelValue', $event)"
  >
    <div v-loading="loading">
      <el-alert type="warning" :closable="false" class="mb">
        代理通过自带根证书（CA）解密 HTTPS 流量，类似 Burp/Caido 的 PortSwigger CA。
        该证书<b>仅用于你已授权的测试目标</b>，私钥只保存在本机，不会上传。
        测试结束后可在 certmgr.msc 中删除「{{ info ? "RustForge MITM CA" : "RustForge" }}」。
      </el-alert>

      <el-descriptions v-if="info" :column="1" border size="small" class="mb">
        <el-descriptions-item label="信任状态">
          <el-tag :type="info.trusted ? 'success' : 'danger'">
            {{ info.trusted ? "已信任（当前用户 Root store）" : "未信任 — HTTPS 站点会报证书错误" }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="证书路径">
          <span class="mono">{{ info.cert_path }}</span>
        </el-descriptions-item>
        <el-descriptions-item label="SHA-256 指纹">
          <span class="mono fingerprint">{{ info.fingerprint }}</span>
        </el-descriptions-item>
      </el-descriptions>

      <el-steps :active="info?.trusted ? 3 : 1" align-center class="mb">
        <el-step title="安装 CA" description="一键或手动导入" />
        <el-step title="设代理" :description="`浏览器 → 127.0.0.1:${proxyPort}`" />
        <el-step title="抓包" description="HTTPS 流量入表" />
      </el-steps>

      <div class="actions">
        <el-button type="primary" :loading="installing" @click="install">
          一键安装到当前用户（推荐）
        </el-button>
        <el-button @click="doExport">导出 .cer 文件</el-button>
        <el-button @click="reveal">打开证书所在文件夹</el-button>
        <el-button @click="refresh">重新检测</el-button>
      </div>

      <el-alert v-if="exportedTo" type="success" :closable="false" class="mb">
        已导出到：<span class="mono">{{ exportedTo }}</span>
      </el-alert>

      <el-collapse class="mb">
        <el-collapse-item title="手动安装步骤（一键安装失败时）" name="manual">
          <ol class="manual">
            <li>双击导出的 <code>.cer</code> 文件 → 「安装证书」</li>
            <li>存储位置选「当前用户」→ 下一步</li>
            <li>选「将所有的证书都放入下列存储」→ 浏览 → <b>受信任的根证书颁发机构</b></li>
            <li>完成 → 安全警告点「是」</li>
          </ol>
        </el-collapse-item>
        <el-collapse-item title="Firefox 用户注意" name="firefox">
          Firefox 不用系统证书库：设置 → 隐私与安全 → 证书 → 查看证书 →
          「证书颁发机构」→ 导入上面导出的 .cer → 勾选「信任由此证书颁发机构标识的网站」。
        </el-collapse-item>
        <el-collapse-item title="浏览器代理怎么设？" name="proxy">
          系统代理：设置 → 网络 → 代理 → 手动设置 →
          <code>127.0.0.1:{{ proxyPort }}</code>；
          或用 SwitchyOmega 等插件只对目标站点走代理（推荐，减少噪音流量）。
        </el-collapse-item>
      </el-collapse>
    </div>
  </el-dialog>
</template>

<style scoped>
.mb {
  margin-bottom: 12px;
}
.mono {
  font-family: Consolas, monospace;
  font-size: 12px;
  word-break: break-all;
}
.fingerprint {
  font-size: 11px;
}
.actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  margin-bottom: 12px;
}
.manual {
  margin: 0;
  padding-left: 20px;
  line-height: 1.8;
}
</style>
