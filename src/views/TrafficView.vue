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
  FolderOpened,
} from "@element-plus/icons-vue";
import { useTrafficStore } from "../stores/traffic";
import { useProjectStore } from "../stores/project";
import { useSettingsStore } from "../stores/settings";
import { useRepeaterStore } from "../stores/repeater";
import CertGuideDialog from "../components/CertGuideDialog.vue";
import ScopeDialog from "../components/ScopeDialog.vue";
import AnalysisPanel from "../components/AnalysisPanel.vue";
import EmptyState from "../components/shell/EmptyState.vue";
import PageHeader from "../components/shell/PageHeader.vue";

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

/** headers JSON 字符串 → kv 数组；重复 header 逐项展示。 */
function headerPairs(json: string | null): { k: string; v: string }[] {
  if (!json) return [];
  try {
    const obj = JSON.parse(json) as Record<string, string | string[]>;
    return Object.entries(obj).flatMap(([k, value]) =>
      (Array.isArray(value) ? value : [value]).map((v) => ({ k, v }))
    );
  } catch {
    return [];
  }
}

function decodeStatusLabel(status: string): string {
  const labels: Record<string, string> = {
    not_received: "未收到正文",
    empty: "空正文",
    identity_text: "文本正文",
    identity_binary: "非文本正文",
    decoded_text: "已解压文本",
    decoded_binary: "已解压非文本",
    decode_failed: "正文解码失败",
    unsupported_encoding: "不支持的正文编码",
    encoded_truncated: "压缩正文在线缆上已截断，未解压",
    decode_truncated: "多层解压达到上限，未完成全部解码",
    stream_error: "正文流读取失败",
    stream_incomplete: "正文流未完整结束",
  };
  return labels[status] ?? `未知正文状态：${status}`;
}

function captureNotice(
  wireSize: number,
  capturedSize: number,
  truncated: boolean,
  decodeStatus: string
): string {
  const size = `线缆 ${fmtSize(wireSize)}，已保存 ${fmtSize(capturedSize)}`;
  return `${decodeStatusLabel(decodeStatus)}；${size}${truncated ? "；已截断" : ""}`;
}

function captureAlertType(
  truncated: boolean,
  decodeStatus: string
): "info" | "warning" | "error" {
  if (decodeStatus === "decode_failed" || decodeStatus === "stream_error") return "error";
  if (
    truncated ||
    ["unsupported_encoding", "encoded_truncated", "decode_truncated", "stream_incomplete"].includes(
      decodeStatus
    )
  ) {
    return "warning";
  }
  return "info";
}

function shouldShowCaptureAlert(truncated: boolean, decodeStatus: string): boolean {
  return (
    truncated ||
    !["empty", "identity_text", "decoded_text", "not_received"].includes(decodeStatus)
  );
}
</script>

<template>
  <div class="traffic-page rf-page rf-page--inset">
    <PageHeader
      title="流量"
      description="启动 MITM 代理，捕获授权范围内的请求并进行分析。"
    />
    <div class="rf-toolbar">
      <div class="rf-toolbar-group">
        <el-button
          :type="traffic.proxyRunning ? 'danger' : 'primary'"
          :loading="proxyBusy"
          :icon="traffic.proxyRunning ? VideoPause : VideoPlay"
          @click="toggleProxy"
        >
          {{ traffic.proxyRunning ? "停止代理" : "启动代理" }}
        </el-button>
        <el-tag :type="traffic.proxyRunning ? 'success' : 'info'" effect="plain" size="small">
          {{ traffic.proxyRunning ? `127.0.0.1:${traffic.proxyPort}` : "未运行" }}
        </el-tag>
      </div>
      <div class="rf-toolbar-group">
        <el-button :icon="Lock" @click="certGuideVisible = true">证书引导</el-button>
        <el-button :icon="Aim" :disabled="!project.current" @click="scopeVisible = true">
          Scope（{{ project.current?.scope.length ?? 0 }}）
        </el-button>
      </div>
      <div class="rf-toolbar-group">
        <el-button
          :icon="Refresh"
          :disabled="projectId === null"
          @click="projectId !== null && traffic.refresh(projectId)"
        />
        <el-button :icon="Delete" :disabled="projectId === null" @click="onClear">
          清空
        </el-button>
      </div>

      <div class="rf-filters">
        <div class="rf-toolbar-group">
          <el-select
            v-model="traffic.filterMethod"
            placeholder="方法"
            clearable
            size="small"
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
            size="small"
            class="f-status"
            @change="projectId !== null && traffic.refresh(projectId)"
          >
            <el-option v-for="s in ['2', '3', '4', '5']" :key="s" :label="`${s}xx`" :value="s" />
          </el-select>
          <el-input
            v-model="traffic.filterSearch"
            placeholder="搜索 host / path…"
            clearable
            size="small"
            class="f-search"
            @input="onSearchInput"
            @clear="projectId !== null && traffic.refresh(projectId)"
          />
        </div>
      </div>
    </div>

    <EmptyState
      v-if="!project.current"
      title="尚未选择项目"
      description="请先在顶部创建或选择一个项目。一个项目对应一个已获授权的测试目标。"
    >
      <template #icon><el-icon :size="20"><FolderOpened /></el-icon></template>
    </EmptyState>
    <EmptyState
      v-else-if="scopeEmpty"
      title="Scope 为空，不会拦截流量"
      description="设计红线：仅拦截白名单内的授权目标。请添加目标域名后再启动代理。"
      action-label="配置 Scope"
      @action="scopeVisible = true"
    >
      <template #icon><el-icon :size="20"><Aim /></el-icon></template>
    </EmptyState>
    <el-alert
      v-else-if="!traffic.proxyRunning"
      type="info"
      :closable="false"
      class="hint"
      show-icon
    >
      代理未运行。启动后将浏览器代理设为 127.0.0.1:{{ settings.proxy_port }}；首次使用请完成证书引导。
    </el-alert>

    <!-- 流量表格 -->
    <el-table
      v-loading="traffic.loading"
      :data="traffic.items"
      class="flow-table rf-table-shell"
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
        <template #default="{ row }">
          {{ fmtSize(row.req_wire_size) }}<span v-if="row.req_truncated" class="truncated-mark"> *</span>
        </template>
      </el-table-column>
      <el-table-column label="响应" width="90" align="right">
        <template #default="{ row }">
          {{ fmtSize(row.resp_wire_size) }}<span v-if="row.resp_truncated" class="truncated-mark"> *</span>
        </template>
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
            发送到重放
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
            {{ fmtSize(traffic.detail.req_wire_size) }} /
            {{ fmtSize(traffic.detail.resp_wire_size) }}
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
            <el-alert
              v-if="shouldShowCaptureAlert(traffic.detail.req_truncated, traffic.detail.req_decode_status)"
              :type="captureAlertType(traffic.detail.req_truncated, traffic.detail.req_decode_status)"
              :title="captureNotice(traffic.detail.req_wire_size, traffic.detail.req_captured_size, traffic.detail.req_truncated, traffic.detail.req_decode_status)"
              :closable="false"
              show-icon
              class="body-state"
            />
            <pre v-if="traffic.detail.req_body_text !== null" class="body-view">{{ traffic.detail.req_body_text || "(空)" }}</pre>
            <el-alert v-else-if="traffic.detail.req_body_base64" type="info" :closable="false">
              已保存的非文本内容（{{ fmtSize(traffic.detail.req_captured_size) }}），Base64：
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
            <el-alert
              v-if="shouldShowCaptureAlert(traffic.detail.resp_truncated, traffic.detail.resp_decode_status)"
              :type="captureAlertType(traffic.detail.resp_truncated, traffic.detail.resp_decode_status)"
              :title="captureNotice(traffic.detail.resp_wire_size, traffic.detail.resp_captured_size, traffic.detail.resp_truncated, traffic.detail.resp_decode_status)"
              :closable="false"
              show-icon
              class="body-state"
            />
            <pre v-if="traffic.detail.resp_body_text !== null" class="body-view">{{ traffic.detail.resp_body_text || "(空)" }}</pre>
            <el-alert v-else-if="traffic.detail.resp_body_base64" type="info" :closable="false">
              已保存的非文本或未解码内容（{{ fmtSize(traffic.detail.resp_captured_size) }}），Base64：
              <pre class="body-view">{{ traffic.detail.resp_body_base64.slice(0, 2000) }}…</pre>
            </el-alert>
            <el-empty v-else description="无响应体" :image-size="40" />
          </el-tab-pane>
          <el-tab-pane label="AI 分析">
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
.f-method {
  width: 100px;
}
.f-status {
  width: 90px;
}

.truncated-mark {
  color: var(--el-color-warning);
  font-weight: 700;
}

.body-state {
  margin-bottom: 10px;
}
.f-search {
  width: 200px;
}
.hint {
  flex-shrink: 0;
}
.flow-table {
  cursor: pointer;
}
.table-footer {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: var(--rf-space-3);
  flex-shrink: 0;
}
.footer-info {
  margin-right: auto;
  font-size: 12px;
  color: var(--rf-text-secondary);
}
.port {
  color: var(--rf-text-muted);
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
  margin-bottom: var(--rf-space-3);
  padding-bottom: var(--rf-space-3);
  border-bottom: 1px solid var(--rf-border);
}
.detail-url {
  font-family: var(--rf-font-mono);
  font-size: 13px;
  word-break: break-all;
  color: var(--rf-text);
}
.to-repeater {
  margin-left: auto;
  flex-shrink: 0;
}
.detail-meta {
  margin-bottom: var(--rf-space-3);
}
.body-view {
  margin: 0;
  padding: 10px;
  background: var(--rf-bg-raised);
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-control);
  font-family: var(--rf-font-mono);
  font-size: 12px;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 480px;
  overflow: auto;
}
</style>
