<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { useRouter } from "vue-router";
import { ElMessage, ElMessageBox } from "element-plus";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import {
  VideoPlay,
  VideoPause,
  Lock,
  Aim,
  Delete,
  Refresh,
  Promotion,
} from "@element-plus/icons-vue";
import { useTrafficStore } from "../stores/traffic";
import { useProjectStore } from "../stores/project";
import { useSettingsStore } from "../stores/settings";
import { useRepeaterStore } from "../stores/repeater";
import CertGuideDialog from "../components/CertGuideDialog.vue";
import ScopeDialog from "../components/ScopeDialog.vue";
import AnalysisPanel from "../components/AnalysisPanel.vue";

const traffic = useTrafficStore();
const project = useProjectStore();
const settings = useSettingsStore();
const repeater = useRepeaterStore();
const router = useRouter();

/** 把当前详情送入 Repeater 手动改包重发（人在回路的验证动作） */
function sendToRepeater() {
  if (!traffic.detail) return;
  repeater.loadFromDetail(traffic.detail);
  traffic.drawerVisible = false;
  router.push("/repeater");
}

const certGuideVisible = ref(false);
const scopeVisible = ref(false);
const proxyBusy = ref(false);
let unlistenError: UnlistenFn | null = null;
let searchTimer: ReturnType<typeof setTimeout> | null = null;

const projectId = computed(() => project.current?.id ?? null);
const scopeEmpty = computed(
  () => !!project.current && project.current.scope.length === 0
);

onMounted(async () => {
  await traffic.syncProxyStatus();
  if (projectId.value !== null) await traffic.refresh(projectId.value);
  await traffic.bindEvents(() => projectId.value);
  unlistenError = await listen<string>("proxy:error", (e) => {
    ElMessage.error(e.payload);
  });
});

onUnmounted(() => {
  traffic.unbindEvents();
  unlistenError?.();
  if (searchTimer) clearTimeout(searchTimer);
});

// 切换项目后重新拉取
watch(projectId, async (id) => {
  if (id !== null) await traffic.refresh(id);
  else traffic.items = [];
});

async function toggleProxy() {
  proxyBusy.value = true;
  try {
    if (traffic.proxyRunning) {
      await traffic.stopProxy();
      ElMessage.info("代理已停止");
    } else {
      await traffic.startProxy(settings.proxy_port);
      ElMessage.success(`代理已启动：127.0.0.1:${traffic.proxyPort}`);
      if (!certGuideDismissed.value) certGuideVisible.value = true;
    }
  } catch (e) {
    ElMessage.error(String(e));
  } finally {
    proxyBusy.value = false;
  }
}

// 首次启动代理时自动弹证书引导（本组件生命周期内只弹一次）
const certGuideDismissed = ref(false);
watch(certGuideVisible, (v) => {
  if (!v) certGuideDismissed.value = true;
});

function onSearchInput() {
  if (searchTimer) clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    if (projectId.value !== null) traffic.refresh(projectId.value);
  }, 300);
}

async function onClear() {
  if (projectId.value === null) return;
  await ElMessageBox.confirm(
    "删除当前项目的全部流量记录？（不影响 Findings 和任务树）",
    "清空流量",
    { type: "warning", confirmButtonText: "清空", cancelButtonText: "取消" }
  );
  await traffic.clear(projectId.value);
  ElMessage.success("已清空");
}

// ---------- 展示辅助 ----------

function methodTag(m: string): string {
  const map: Record<string, string> = {
    GET: "success",
    POST: "primary",
    PUT: "warning",
    PATCH: "warning",
    DELETE: "danger",
  };
  return map[m] ?? "info";
}

function statusTag(s: number | null): { text: string; type: string } {
  if (s === null) return { text: "失败", type: "info" };
  const cls = Math.floor(s / 100);
  const type =
    cls === 2 ? "success" : cls === 3 ? "info" : cls === 4 ? "warning" : "danger";
  return { text: String(s), type };
}

function fmtSize(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function shortType(ct: string | null): string {
  if (!ct) return "—";
  return ct.split(";")[0].trim() || "—";
}

function shortTime(ts: string): string {
  return ts.split(" ")[1] ?? ts;
}

/** headers JSON 字符串 → kv 数组（详情抽屉用） */
function headerPairs(json: string | null): { k: string; v: string }[] {
  if (!json) return [];
  try {
    const obj = JSON.parse(json) as Record<string, string>;
    return Object.entries(obj).map(([k, v]) => ({ k, v }));
  } catch {
    return [];
  }
}
</script>

<template>
  <div class="traffic-page">
    <!-- 工具栏 -->
    <div class="toolbar">
      <el-button
        :type="traffic.proxyRunning ? 'danger' : 'primary'"
        :loading="proxyBusy"
        :icon="traffic.proxyRunning ? VideoPause : VideoPlay"
        @click="toggleProxy"
      >
        {{ traffic.proxyRunning ? "停止代理" : "启动代理" }}
      </el-button>
      <el-tag :type="traffic.proxyRunning ? 'success' : 'info'" effect="dark">
        {{ traffic.proxyRunning ? `监听 127.0.0.1:${traffic.proxyPort}` : "未运行" }}
      </el-tag>
      <el-button :icon="Lock" @click="certGuideVisible = true">证书引导</el-button>
      <el-button :icon="Aim" :disabled="!project.current" @click="scopeVisible = true">
        Scope（{{ project.current?.scope.length ?? 0 }}）
      </el-button>
      <el-button
        :icon="Refresh"
        :disabled="projectId === null"
        @click="projectId !== null && traffic.refresh(projectId)"
      />
      <el-button :icon="Delete" :disabled="projectId === null" @click="onClear">
        清空
      </el-button>

      <div class="filters">
        <el-select
          v-model="traffic.filterMethod"
          placeholder="方法"
          clearable
          class="f-method"
          @change="projectId !== null && traffic.refresh(projectId)"
        >
          <el-option v-for="m in ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD']"
            :key="m" :label="m" :value="m" />
        </el-select>
        <el-select
          v-model="traffic.filterStatusClass"
          placeholder="状态"
          clearable
          class="f-status"
          @change="projectId !== null && traffic.refresh(projectId)"
        >
          <el-option v-for="s in ['2', '3', '4', '5']" :key="s" :label="`${s}xx`" :value="s" />
        </el-select>
        <el-input
          v-model="traffic.filterSearch"
          placeholder="搜索 host / path…"
          clearable
          class="f-search"
          @input="onSearchInput"
          @clear="projectId !== null && traffic.refresh(projectId)"
        />
      </div>
    </div>

    <!-- 引导提示 -->
    <el-alert v-if="!project.current" type="warning" :closable="false" class="hint">
      请先在左下角创建/选择一个项目（一个项目 = 一个授权测试目标）。
    </el-alert>
    <el-alert v-else-if="scopeEmpty" type="warning" :closable="false" class="hint">
      当前项目 Scope 为空，<b>不会拦截任何流量</b>（设计红线：只拦截白名单内的授权目标）。
      点击上方「Scope」添加目标域名。
    </el-alert>
    <el-alert
      v-else-if="!traffic.proxyRunning"
      type="info"
      :closable="false"
      class="hint"
    >
      代理未运行。点击「启动代理」后，把浏览器代理设为 127.0.0.1:{{ settings.proxy_port }}，
      首次使用请先完成「证书引导」。
    </el-alert>

    <!-- 流量表格 -->
    <el-table
      v-loading="traffic.loading"
      :data="traffic.items"
      class="flow-table"
      size="small"
      highlight-current-row
      @row-click="(row: any) => traffic.openDetail(row.id)"
    >
      <el-table-column prop="id" label="#" width="70" sortable />
      <el-table-column label="方法" width="80">
        <template #default="{ row }">
          <el-tag size="small" :type="methodTag(row.method)" effect="plain">{{ row.method }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="Host" min-width="180" show-overflow-tooltip>
        <template #default="{ row }">
          {{ row.host }}<span class="port" v-if="row.port !== 80 && row.port !== 443">:{{ row.port }}</span>
        </template>
      </el-table-column>
      <el-table-column prop="path" label="Path" min-width="220" show-overflow-tooltip />
      <el-table-column label="状态" width="80">
        <template #default="{ row }">
          <el-tag size="small" :type="statusTag(row.status).type">{{ statusTag(row.status).text }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="类型" width="130" show-overflow-tooltip>
        <template #default="{ row }">{{ shortType(row.content_type) }}</template>
      </el-table-column>
      <el-table-column label="标签" width="150">
        <template #default="{ row }">
          <template v-if="row.rule_tags?.length">
            <el-tag
              v-for="t in row.rule_tags.slice(0, 2)"
              :key="t"
              size="small"
              type="danger"
              effect="plain"
              class="rule-tag"
            >{{ t }}</el-tag>
            <el-tooltip v-if="row.rule_tags.length > 2" :content="row.rule_tags.join('、')">
              <el-tag size="small" type="info" effect="plain">+{{ row.rule_tags.length - 2 }}</el-tag>
            </el-tooltip>
          </template>
        </template>
      </el-table-column>
      <el-table-column label="请求" width="90" align="right">
        <template #default="{ row }">{{ fmtSize(row.req_size) }}</template>
      </el-table-column>
      <el-table-column label="响应" width="90" align="right">
        <template #default="{ row }">{{ fmtSize(row.resp_size) }}</template>
      </el-table-column>
      <el-table-column label="耗时" width="90" align="right">
        <template #default="{ row }">{{ row.duration_ms }} ms</template>
      </el-table-column>
      <el-table-column label="时间" width="100">
        <template #default="{ row }">{{ shortTime(row.created_at) }}</template>
      </el-table-column>
      <template #empty>
        <el-empty description="暂无流量。启动代理并浏览目标站点后，流量会实时出现在这里。" />
      </template>
    </el-table>

    <div class="table-footer">
      <span class="footer-info">已加载 {{ traffic.items.length }} / 共 {{ traffic.total }} 条</span>
      <el-button
        v-if="traffic.hasMore"
        size="small"
        :loading="traffic.loading"
        :disabled="projectId === null"
        @click="projectId !== null && traffic.loadMore(projectId)"
      >加载更多</el-button>
    </div>

    <!-- 详情抽屉 -->
    <el-drawer v-model="traffic.drawerVisible" size="62%" :with-header="false">
      <div v-if="traffic.detail" v-loading="traffic.detailLoading" class="detail">
        <div class="detail-head">
          <el-tag :type="methodTag(traffic.detail.method)" effect="dark">{{ traffic.detail.method }}</el-tag>
          <span class="detail-url">{{ traffic.detail.url }}</span>
          <el-button size="small" :icon="Promotion" class="to-repeater" @click="sendToRepeater">
            发送到 Repeater
          </el-button>
        </div>
        <el-descriptions :column="4" border size="small" class="detail-meta">
          <el-descriptions-item label="状态">
            <el-tag size="small" :type="statusTag(traffic.detail.status).type">
              {{ statusTag(traffic.detail.status).text }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="耗时">{{ traffic.detail.duration_ms }} ms</el-descriptions-item>
          <el-descriptions-item label="请求/响应">
            {{ fmtSize(traffic.detail.req_size) }} / {{ fmtSize(traffic.detail.resp_size) }}
          </el-descriptions-item>
          <el-descriptions-item label="时间">{{ traffic.detail.created_at }}</el-descriptions-item>
        </el-descriptions>

        <el-tabs class="detail-tabs">
          <el-tab-pane label="请求头">
            <el-table :data="headerPairs(traffic.detail.req_headers)" size="small" max-height="480">
              <el-table-column prop="k" label="Header" width="240" />
              <el-table-column prop="v" label="Value" show-overflow-tooltip />
            </el-table>
          </el-tab-pane>
          <el-tab-pane label="请求体">
            <pre v-if="traffic.detail.req_body_text !== null" class="body-view">{{ traffic.detail.req_body_text || "(空)" }}</pre>
            <el-alert v-else-if="traffic.detail.req_body_base64" type="info" :closable="false">
              二进制内容（{{ fmtSize(traffic.detail.req_size) }}），Base64：
              <pre class="body-view">{{ traffic.detail.req_body_base64.slice(0, 2000) }}…</pre>
            </el-alert>
            <el-empty v-else description="无请求体" :image-size="40" />
          </el-tab-pane>
          <el-tab-pane label="响应头">
            <el-table :data="headerPairs(traffic.detail.resp_headers)" size="small" max-height="480">
              <el-table-column prop="k" label="Header" width="240" />
              <el-table-column prop="v" label="Value" show-overflow-tooltip />
            </el-table>
          </el-tab-pane>
          <el-tab-pane label="响应体">
            <pre v-if="traffic.detail.resp_body_text !== null" class="body-view">{{ traffic.detail.resp_body_text || "(空)" }}</pre>
            <el-alert v-else-if="traffic.detail.resp_body_base64" type="info" :closable="false">
              二进制或压缩内容（{{ fmtSize(traffic.detail.resp_size) }}），Base64：
              <pre class="body-view">{{ traffic.detail.resp_body_base64.slice(0, 2000) }}…</pre>
            </el-alert>
            <el-empty v-else description="无响应体" :image-size="40" />
          </el-tab-pane>
          <el-tab-pane label="🤖 AI 分析">
            <AnalysisPanel v-if="traffic.detail" :traffic-id="traffic.detail.id" />
          </el-tab-pane>
        </el-tabs>
      </div>
    </el-drawer>

    <CertGuideDialog v-model="certGuideVisible" :proxy-port="settings.proxy_port" />
    <ScopeDialog v-model="scopeVisible" />
  </div>
</template>

<style scoped>
.traffic-page {
  height: 100%;
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.toolbar {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.filters {
  margin-left: auto;
  display: flex;
  gap: 8px;
}
.f-method {
  width: 110px;
}
.f-status {
  width: 100px;
}
.f-search {
  width: 220px;
}
.hint {
  flex-shrink: 0;
}
.flow-table {
  flex: 1;
  cursor: pointer;
}
.table-footer {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-shrink: 0;
}
.footer-info {
  font-size: 12px;
  color: var(--el-text-color-secondary);
}
.port {
  color: var(--el-text-color-secondary);
}
.rule-tag {
  margin-right: 4px;
}
.detail {
  padding: 0 4px;
}
.detail-head {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 12px;
}
.detail-url {
  font-family: Consolas, monospace;
  font-size: 13px;
  word-break: break-all;
}
.to-repeater {
  margin-left: auto;
  flex-shrink: 0;
}
.detail-meta {
  margin-bottom: 12px;
}
.body-view {
  margin: 0;
  padding: 10px;
  background: var(--el-fill-color-dark);
  border-radius: 4px;
  font-family: Consolas, monospace;
  font-size: 12px;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 480px;
  overflow: auto;
}
</style>
