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

/** 把当前详情送入 Repeater 手动改包重发 */
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
  () => !project.current || project.current.scope.length === 0
);

onMounted(async () => {
  await traffic.syncProxyStatus();
  traffic.activateProject(projectId.value);
  if (projectId.value !== null) await traffic.refresh(projectId.value);
  await traffic.bindEvents(() => projectId.value);
  unlistenError = await listen<string>("proxy:error", (e) => {
    ElMessage.error(e.payload);
  });
});

onUnmounted(() => {
  traffic.invalidateRequests();
  traffic.unbindEvents();
  unlistenError?.();
  if (searchTimer) clearTimeout(searchTimer);
});

watch(projectId, async (id) => {
  traffic.activateProject(id);
  if (id !== null) await traffic.refresh(id);
});

async function toggleProxy() {
  proxyBusy.value = true;
  try {
    if (traffic.proxyRunning) {
      await traffic.stopProxy();
      ElMessage.info("MITM 代理已停止");
    } else {
      await traffic.startProxy(settings.proxy_port);
      ElMessage.success(`MITM 代理已启动：127.0.0.1:${traffic.proxyPort}`);
    }
  } catch (e) {
    ElMessage.error(String(e));
  } finally {
    proxyBusy.value = false;
  }
}

function onSearchInput() {
  if (searchTimer) clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    if (projectId.value !== null) traffic.refresh(projectId.value);
  }, 250);
}

async function onClear() {
  if (projectId.value === null) return;
  await ElMessageBox.confirm(
    "确定清空当前项目的全部流量记录？（不会影响 Findings 和安全测试计划）",
    "清空流量数据",
    { type: "warning", confirmButtonText: "清空", cancelButtonText: "取消" }
  );
  await traffic.clear(projectId.value);
  ElMessage.success("流量记录已清空");
}

function methodClass(m: string): string {
  const map: Record<string, string> = {
    GET: "rf-method-get",
    POST: "rf-method-post",
    PUT: "rf-method-put",
    PATCH: "rf-method-patch",
    DELETE: "rf-method-delete",
    OPTIONS: "rf-method-options",
    HEAD: "rf-method-head",
  };
  return map[m] ?? "rf-method";
}

function statusTag(s: number | null): { text: string; type: "success" | "info" | "warning" | "danger" } {
  if (s === null) return { text: "ERR", type: "info" };
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
  return labels[status] ?? `未知状态: ${status}`;
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
      title="HTTP 流量捕获与分析"
      description="启动有界 MITM 代理，自动过滤非授权 Scope，解析请求与被动规则命中证据。"
    />

    <!-- 控制指令条 -->
    <div class="rf-toolbar">
      <div class="rf-toolbar-group">
        <el-button
          :type="traffic.proxyRunning ? 'danger' : 'primary'"
          :loading="proxyBusy"
          :icon="traffic.proxyRunning ? VideoPause : VideoPlay"
          size="small"
          @click="toggleProxy"
        >
          {{ traffic.proxyRunning ? "停止代理" : "启动代理" }}
        </el-button>
        <span class="proxy-state-badge" :class="{ running: traffic.proxyRunning }">
          <span class="rf-pulse-dot" :class="traffic.proxyRunning ? 'rf-pulse-dot--active' : 'rf-pulse-dot--stopped'" />
          <span>{{ traffic.proxyRunning ? `127.0.0.1:${traffic.proxyPort}` : "已停止" }}</span>
        </span>
      </div>

      <div class="rf-toolbar-group">
        <el-button size="small" :icon="Lock" @click="certGuideVisible = true">CA 证书</el-button>
        <el-button size="small" :icon="Aim" :disabled="!project.current" @click="scopeVisible = true">
          Scope ({{ project.current?.scope.length ?? 0 }})
        </el-button>
      </div>

      <div class="rf-toolbar-group">
        <el-button
          size="small"
          :icon="Refresh"
          :disabled="projectId === null"
          title="刷新流量"
          @click="projectId !== null && traffic.refresh(projectId)"
        />
        <el-button size="small" :icon="Delete" :disabled="projectId === null" @click="onClear">
          清空
        </el-button>
      </div>

      <div class="rf-filters">
        <div class="rf-toolbar-group">
          <el-select
            v-model="traffic.filterMethod"
            placeholder="Method"
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
            placeholder="Status"
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

    <!-- 状态提示 -->
    <EmptyState
      v-if="!project.current"
      title="尚未选择项目"
      description="请先在顶部创建或选择项目；所有流量、重放与评估均严格绑定项目目标。"
    >
      <template #icon><FolderOpened :size="20" /></template>
    </EmptyState>

    <EmptyState
      v-else-if="scopeEmpty"
      title="Scope 目标范围为空"
      description="设计准则：代理仅拦截白名单内的授权目标。请先添加目标域名/IP 后启动代理。"
      action-label="配置 Scope"
      @action="scopeVisible = true"
    >
      <template #icon><Aim :size="20" /></template>
    </EmptyState>

    <div v-else-if="!traffic.proxyRunning" class="rf-inline-info">
      代理当前处于停止状态。启动后将客户端 HTTP/HTTPS 代理设为 127.0.0.1:{{ settings.proxy_port }} 即可捕获流量。
    </div>

    <!-- 流量表格 -->
    <el-table
      v-loading="traffic.loading"
      :data="traffic.items"
      class="flow-table rf-table-shell"
      size="small"
      highlight-current-row
      @row-click="(row: any) => traffic.openDetail(row.id)"
    >
      <el-table-column prop="id" label="#" width="65" sortable />

      <el-table-column label="Method" width="80">
        <template #default="{ row }">
          <span class="rf-method" :class="methodClass(row.method)">{{ row.method }}</span>
        </template>
      </el-table-column>

      <el-table-column label="Host" min-width="170" show-overflow-tooltip>
        <template #default="{ row }">
          <span class="mono">{{ row.host }}</span><span class="port mono" v-if="row.port !== 80 && row.port !== 443">:{{ row.port }}</span>
        </template>
      </el-table-column>

      <el-table-column prop="path" label="Path" min-width="220" show-overflow-tooltip>
        <template #default="{ row }">
          <span class="mono">{{ row.path }}</span>
        </template>
      </el-table-column>

      <el-table-column label="Status" width="80">
        <template #default="{ row }">
          <el-tag size="small" :type="statusTag(row.status).type">{{ statusTag(row.status).text }}</el-tag>
        </template>
      </el-table-column>

      <el-table-column label="Type" width="120" show-overflow-tooltip>
        <template #default="{ row }">
          <span class="mono">{{ shortType(row.content_type) }}</span>
        </template>
      </el-table-column>

      <el-table-column label="Tags" width="140">
        <template #default="{ row }">
          <template v-if="row.rule_tags?.length">
            <el-tag
              v-for="t in row.rule_tags.slice(0, 2)"
              :key="t"
              size="small"
              type="danger"
              class="rule-tag"
            >{{ t }}</el-tag>
            <el-tooltip v-if="row.rule_tags.length > 2" :content="row.rule_tags.join('、')">
              <el-tag size="small" type="info">+{{ row.rule_tags.length - 2 }}</el-tag>
            </el-tooltip>
          </template>
        </template>
      </el-table-column>

      <el-table-column label="Req Size" width="85" align="right">
        <template #default="{ row }">
          <span class="mono">{{ fmtSize(row.req_wire_size) }}</span><span v-if="row.req_truncated" class="truncated-mark">*</span>
        </template>
      </el-table-column>

      <el-table-column label="Resp Size" width="85" align="right">
        <template #default="{ row }">
          <span class="mono">{{ fmtSize(row.resp_wire_size) }}</span><span v-if="row.resp_truncated" class="truncated-mark">*</span>
        </template>
      </el-table-column>

      <el-table-column label="Latency" width="85" align="right">
        <template #default="{ row }">
          <span class="mono">{{ row.duration_ms }} ms</span>
        </template>
      </el-table-column>

      <el-table-column label="Time" width="90">
        <template #default="{ row }">
          <span class="mono text-muted">{{ shortTime(row.created_at) }}</span>
        </template>
      </el-table-column>

      <template #empty>
        <el-empty description="暂无流量。启动代理并在浏览器中访问目标，流量将实时记录。" />
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

    <!-- 报文详情抽屉 -->
    <el-drawer v-model="traffic.drawerVisible" size="60%" :with-header="false">
      <div v-if="traffic.detail" v-loading="traffic.detailLoading" class="detail">
        <div class="detail-head">
          <span class="rf-method" :class="methodClass(traffic.detail.method)">{{ traffic.detail.method }}</span>
          <span class="detail-url mono">{{ traffic.detail.url }}</span>
          <el-button size="small" type="primary" :icon="Promotion" class="to-repeater" @click="sendToRepeater">
            送入重放 (Repeater)
          </el-button>
        </div>

        <el-descriptions :column="4" border size="small" class="detail-meta">
          <el-descriptions-item label="状态">
            <el-tag size="small" :type="statusTag(traffic.detail.status).type">
              {{ statusTag(traffic.detail.status).text }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="耗时">{{ traffic.detail.duration_ms }} ms</el-descriptions-item>
          <el-descriptions-item label="Wire 体积">
            {{ fmtSize(traffic.detail.req_wire_size) }} / {{ fmtSize(traffic.detail.resp_wire_size) }}
          </el-descriptions-item>
          <el-descriptions-item label="捕获时间">{{ traffic.detail.created_at }}</el-descriptions-item>
        </el-descriptions>

        <el-tabs class="detail-tabs">
          <el-tab-pane label="请求 Headers">
            <el-table :data="headerPairs(traffic.detail.req_headers)" size="small" max-height="450">
              <el-table-column prop="k" label="Header" width="220">
                <template #default="{ row }"><span class="mono">{{ row.k }}</span></template>
              </el-table-column>
              <el-table-column prop="v" label="Value" show-overflow-tooltip>
                <template #default="{ row }"><span class="mono">{{ row.v }}</span></template>
              </el-table-column>
            </el-table>
          </el-tab-pane>

          <el-tab-pane label="请求 Body">
            <el-alert
              v-if="shouldShowCaptureAlert(traffic.detail.req_truncated, traffic.detail.req_decode_status)"
              :type="captureAlertType(traffic.detail.req_truncated, traffic.detail.req_decode_status)"
              :title="captureNotice(traffic.detail.req_wire_size, traffic.detail.req_captured_size, traffic.detail.req_truncated, traffic.detail.req_decode_status)"
              :closable="false"
              show-icon
              class="body-state"
            />
            <pre v-if="traffic.detail.req_body_text !== null" class="rf-mono-pre">{{ traffic.detail.req_body_text || "(空)" }}</pre>
            <el-alert v-else-if="traffic.detail.req_body_base64" type="info" :closable="false">
              非文本内容（{{ fmtSize(traffic.detail.req_captured_size) }}），Base64 预览：
              <pre class="rf-mono-pre">{{ traffic.detail.req_body_base64.slice(0, 2000) }}…</pre>
            </el-alert>
            <el-empty v-else description="无请求正文" :image-size="30" />
          </el-tab-pane>

          <el-tab-pane label="响应 Headers">
            <el-table :data="headerPairs(traffic.detail.resp_headers)" size="small" max-height="450">
              <el-table-column prop="k" label="Header" width="220">
                <template #default="{ row }"><span class="mono">{{ row.k }}</span></template>
              </el-table-column>
              <el-table-column prop="v" label="Value" show-overflow-tooltip>
                <template #default="{ row }"><span class="mono">{{ row.v }}</span></template>
              </el-table-column>
            </el-table>
          </el-tab-pane>

          <el-tab-pane label="响应 Body">
            <el-alert
              v-if="shouldShowCaptureAlert(traffic.detail.resp_truncated, traffic.detail.resp_decode_status)"
              :type="captureAlertType(traffic.detail.resp_truncated, traffic.detail.resp_decode_status)"
              :title="captureNotice(traffic.detail.resp_wire_size, traffic.detail.resp_captured_size, traffic.detail.resp_truncated, traffic.detail.resp_decode_status)"
              :closable="false"
              show-icon
              class="body-state"
            />
            <pre v-if="traffic.detail.resp_body_text !== null" class="rf-mono-pre">{{ traffic.detail.resp_body_text || "(空)" }}</pre>
            <el-alert v-else-if="traffic.detail.resp_body_base64" type="info" :closable="false">
              非文本或未解码内容（{{ fmtSize(traffic.detail.resp_captured_size) }}），Base64 预览：
              <pre class="rf-mono-pre">{{ traffic.detail.resp_body_base64.slice(0, 2000) }}…</pre>
            </el-alert>
            <el-empty v-else description="无响应正文" :image-size="30" />
          </el-tab-pane>

          <el-tab-pane label="被动诊断与 AI 分析">
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
  gap: var(--rf-space-2);
}

.proxy-state-badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 3px 8px;
  border-radius: 4px;
  background: var(--rf-bg-raised);
  font-family: var(--rf-font-mono);
  font-size: 11.5px;
  color: var(--rf-text-secondary);
}

.proxy-state-badge.running {
  color: var(--rf-text);
}

.f-method { width: 95px; }
.f-status { width: 85px; }
.f-search { width: 180px; }

.truncated-mark {
  color: var(--rf-warning);
  font-weight: 700;
  margin-left: 2px;
}

.text-muted {
  color: var(--rf-text-muted);
}

.body-state {
  margin-bottom: 8px;
}

.flow-table {
  cursor: pointer;
  flex: 1;
}

.table-footer {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: var(--rf-space-3);
  padding: 4px 0;
}

.footer-info {
  margin-right: auto;
  font-size: 11.5px;
  color: var(--rf-text-secondary);
  font-family: var(--rf-font-mono);
}

.port {
  color: var(--rf-text-muted);
}

.rule-tag {
  margin-right: 4px;
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
  font-size: 12.5px;
  word-break: break-all;
  color: var(--rf-text);
  flex: 1;
}

.to-repeater {
  flex-shrink: 0;
}

.detail-meta {
  margin-bottom: var(--rf-space-3);
}
</style>
