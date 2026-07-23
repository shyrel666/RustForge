<script setup lang="ts">
import { computed, nextTick, onMounted, ref, watch } from "vue";
import { useRouter } from "vue-router";
import { ElMessage, ElMessageBox } from "element-plus";
import { MagicStick, Refresh, Plus, Delete } from "@element-plus/icons-vue";
import MarkdownIt from "markdown-it";
import { VueFlow, useVueFlow, Handle, Position } from "@vue-flow/core";
import type { Node, Edge } from "@vue-flow/core";
import "@vue-flow/core/dist/style.css";
import "@vue-flow/core/dist/theme-default.css";
import { useTreeStore } from "../stores/tree";
import { useProjectStore } from "../stores/project";
import { useSettingsStore } from "../stores/settings";
import { getTaskFindings, type Finding, type TaskNode } from "../api/tauri";

const tree = useTreeStore();
const project = useProjectStore();
const settings = useSettingsStore();
const router = useRouter();
const md = new MarkdownIt({ breaks: true, linkify: true });
const { fitView } = useVueFlow("task-tree");

const projectId = computed(() => project.current?.id ?? null);

// ---------- 整齐树布局：层 = 深度（左→右），兄弟按 slot 纵向排列 ----------
const COL_W = 250;
const ROW_H = 84;
const flowNodes = ref<Node[]>([]);
const flowEdges = ref<Edge[]>([]);

function buildFlow(): { nodes: Node[]; edges: Edge[] } {
  const all = tree.nodes;
  const byParent = new Map<number | null, TaskNode[]>();
  for (const n of all) {
    const arr = byParent.get(n.parent_id) ?? [];
    arr.push(n);
    byParent.set(n.parent_id, arr);
  }
  for (const arr of byParent.values())
    arr.sort((a, b) => a.sort_order - b.sort_order || a.id - b.id);
  const childrenOf = (id: number | null) => byParent.get(id) ?? [];

  // DFS 分配纵坐标：叶子/折叠节点占一个 slot，内部节点取子节点中点
  const pos = new Map<number, { x: number; y: number }>();
  let slot = 0;
  const walk = (node: TaskNode, depth: number): number => {
    const kids = childrenOf(node.id);
    const collapsed = tree.collapsed.has(node.id);
    let y: number;
    if (kids.length === 0 || collapsed) {
      y = slot * ROW_H;
      slot += 1;
    } else {
      const ys = kids.map((k) => walk(k, depth + 1));
      y = (ys[0] + ys[ys.length - 1]) / 2;
    }
    pos.set(node.id, { x: depth * COL_W, y });
    return y;
  };
  for (const root of childrenOf(null)) walk(root, 0);

  const nodes: Node[] = [];
  const edges: Edge[] = [];
  for (const n of all) {
    const p = pos.get(n.id);
    if (!p) continue; // 折叠祖先下的后代不参与布局，隐藏
    nodes.push({
      id: String(n.id),
      type: "task",
      position: p,
      draggable: false,
      data: {
        node: n,
        depth: Math.round(p.x / COL_W),
        childCount: childrenOf(n.id).length,
        collapsed: tree.collapsed.has(n.id),
        selected: tree.selectedId === n.id,
        isNext: tree.lastNextId === n.id,
      },
    });
    if (n.parent_id !== null && pos.has(n.parent_id)) {
      edges.push({
        id: `e-${n.parent_id}-${n.id}`,
        source: String(n.parent_id),
        target: String(n.id),
        type: "smoothstep",
      });
    }
  }
  return { nodes, edges };
}

function rebuild() {
  const { nodes, edges } = buildFlow();
  flowNodes.value = nodes;
  flowEdges.value = edges;
}

async function fitAll() {
  await nextTick();
  try {
    fitView({ padding: 0.2, duration: 300 });
  } catch {
    /* 画布尚未就绪，忽略 */
  }
}

// 树/折叠/选中/下一步高亮变化时重建图
watch(
  () => [tree.nodes, tree.collapsed, tree.selectedId, tree.lastNextId],
  rebuild,
  { deep: true }
);

onMounted(async () => {
  if (projectId.value !== null) {
    await tree.refresh(projectId.value);
    rebuild();
    await fitAll();
  }
});

// 切换项目：重置选中并重新拉取
watch(projectId, async (id) => {
  tree.selectedId = null;
  tree.lastNextId = null;
  if (id !== null) {
    await tree.refresh(id);
  } else {
    tree.nodes = [];
  }
  rebuild();
  await fitAll();
});

// ---------- 选中节点的关联发现（双向关联展示） ----------
const nodeFindings = ref<Finding[]>([]);
const findingsLoading = ref(false);
watch(
  () => tree.selectedId,
  async (id) => {
    nodeFindings.value = [];
    if (id === null) return;
    const node = tree.nodes.find((n) => n.id === id);
    if (!node || node.finding_ids.length === 0) return;
    findingsLoading.value = true;
    try {
      nodeFindings.value = await getTaskFindings(id);
    } catch {
      /* 忽略，面板仅退化为不显示关联发现 */
    } finally {
      findingsLoading.value = false;
    }
  }
);

// ---------- 交互 ----------
function onNodeClick(e: { node: { id: string } }) {
  tree.selectedId = Number(e.node.id);
}
function onPaneClick() {
  tree.selectedId = null;
}

async function doGenerate(replace: boolean) {
  const pid = projectId.value;
  if (pid === null) return;
  try {
    await tree.generate(pid, replace);
    tree.selectedId = null;
    await fitAll();
    ElMessage.success(`任务树已生成（${tree.nodes.length} 个节点）`);
  } catch (e) {
    ElMessage.error(String(e));
  }
}

async function onRegenerate() {
  try {
    await ElMessageBox.confirm(
      "重新生成会清空当前任务树，包括你手动添加/修改的节点与进度状态。确定继续？",
      "重新生成任务树",
      { type: "warning", confirmButtonText: "清空并重建", cancelButtonText: "取消" }
    );
  } catch {
    return; // 用户取消
  }
  await doGenerate(true);
}

async function onNext() {
  const pid = projectId.value;
  if (pid === null) return;
  try {
    const node = await tree.goNext(pid);
    if (!node) {
      ElMessage.success("没有待执行的任务了 —— 全部完成 🎉");
    } else {
      await fitAll();
    }
  } catch (e) {
    ElMessage.error(String(e));
  }
}

async function onExpand(id: number) {
  try {
    await tree.expand(id);
    await fitAll();
    ElMessage.success("已展开子任务");
  } catch (e) {
    ElMessage.error(String(e));
  }
}

async function onAlternative(id: number) {
  try {
    await tree.alternative(id);
    ElMessage.success("已换一种思路（该节点已重置为「待做」）");
  } catch (e) {
    ElMessage.error(String(e));
  }
}

async function onSetStatus(id: number, status: string) {
  try {
    await tree.setStatus(id, status);
  } catch (e) {
    ElMessage.error(String(e));
  }
}

async function onDelete(id: number) {
  try {
    await ElMessageBox.confirm(
      "删除该节点及其所有子节点？此操作不可撤销。",
      "删除节点",
      { type: "warning", confirmButtonText: "删除", cancelButtonText: "取消" }
    );
  } catch {
    return;
  }
  try {
    await tree.remove(id);
    await fitAll();
  } catch (e) {
    ElMessage.error(String(e));
  }
}

// ---------- 手动添加节点 ----------
const addVisible = ref(false);
const addParentId = ref<number | null>(null);
const addForm = ref({ title: "", description: "", why: "", how_to: "", verify_criteria: "" });
function openAdd(parentId: number | null) {
  addParentId.value = parentId;
  addForm.value = { title: "", description: "", why: "", how_to: "", verify_criteria: "" };
  addVisible.value = true;
}
async function submitAdd() {
  const pid = projectId.value;
  if (pid === null) return;
  if (!addForm.value.title.trim()) {
    ElMessage.warning("标题不能为空");
    return;
  }
  try {
    await tree.create(pid, addParentId.value, { ...addForm.value });
    addVisible.value = false;
    await fitAll();
    ElMessage.success("已添加节点");
  } catch (e) {
    ElMessage.error(String(e));
  }
}

function gotoFindings() {
  router.push("/findings");
}

// ---------- 展示辅助 ----------
const STATUS_META: Record<string, { label: string; type: string }> = {
  todo: { label: "待做", type: "info" },
  in_progress: { label: "进行中", type: "primary" },
  done: { label: "完成", type: "success" },
  blocked: { label: "受阻", type: "danger" },
};
// 与后端状态机 tree/state.rs 的白名单保持一致
const TRANSITIONS: Record<string, string[]> = {
  todo: ["in_progress", "blocked"],
  in_progress: ["done", "blocked", "todo"],
  blocked: ["todo", "in_progress"],
  done: ["todo"],
};
const TRANSITION_LABEL: Record<string, string> = {
  in_progress: "▶ 进行中",
  done: "✓ 完成",
  blocked: "⛔ 受阻",
  todo: "↺ 重置",
};
function statusMeta(s: string) {
  return STATUS_META[s] ?? { label: s, type: "info" };
}
function severityTag(s: string): string {
  const map: Record<string, string> = {
    critical: "danger",
    high: "danger",
    medium: "warning",
    low: "info",
    info: "info",
  };
  return map[s] ?? "info";
}

const total = computed(() => tree.nodes.length);
const progress = computed(() =>
  total.value === 0 ? 0 : Math.round((tree.doneCount / total.value) * 100)
);
const aiDisabled = computed(() => projectId.value === null || !settings.ai_enabled);
</script>

<template>
  <div class="tree-page">
    <!-- 工具栏 -->
    <div class="toolbar">
      <h3 class="title">渗透任务树</h3>
      <template v-if="total > 0">
        <el-progress :percentage="progress" :stroke-width="10" status="success" class="progress" />
        <span class="prog-text">{{ tree.doneCount }} / {{ total }} 完成</span>
      </template>
      <div class="actions">
        <template v-if="total === 0">
          <el-button
            type="primary"
            :icon="MagicStick"
            :loading="tree.aiBusy === 'generate'"
            :disabled="aiDisabled"
            @click="doGenerate(false)"
          >AI 生成任务树</el-button>
        </template>
        <template v-else>
          <el-button type="primary" :disabled="projectId === null" @click="onNext">
            ⏭ 下一步
          </el-button>
          <el-button :icon="Plus" :disabled="projectId === null" @click="openAdd(null)">
            添加阶段
          </el-button>
          <el-button
            :icon="Refresh"
            :loading="tree.aiBusy === 'generate'"
            :disabled="aiDisabled"
            @click="onRegenerate"
          >重新生成</el-button>
          <el-button @click="fitAll">🎯 适应视图</el-button>
        </template>
      </div>
    </div>

    <!-- 引导 / 红线提示 -->
    <el-alert v-if="!project.current" type="warning" :closable="false" class="hint">
      请先在左下角创建/选择一个项目。任务树基于该项目已抓取的流量摘要生成。
    </el-alert>
    <el-alert v-else-if="!settings.ai_enabled" type="info" :closable="false" class="hint">
      AI 功能已在设置中全局禁用（隐私开关），无法生成/展开任务树；你仍可手动添加节点并推进状态。
    </el-alert>
    <el-alert v-else type="info" :closable="false" class="hint">
      <b>人在回路：</b>任务树只做「引导」——每一步都由你手动执行，AI 不会自动对目标发起攻击。
      点「下一步」让 AI 帮你定位当前该做什么；带 🔗 的节点关联了「发现」。
    </el-alert>

    <!-- 主体：画布 + 详情面板 -->
    <div class="content">
      <div v-loading="tree.loading" class="canvas">
        <VueFlow
          id="task-tree"
          :nodes="flowNodes"
          :edges="flowEdges"
          :nodes-draggable="false"
          :nodes-connectable="false"
          :elements-selectable="true"
          :min-zoom="0.2"
          :max-zoom="1.5"
          fit-view-on-init
          @node-click="onNodeClick"
          @pane-click="onPaneClick"
        >
          <template #node-task="{ data }">
            <div
              class="tnode"
              :class="[
                `st-${data.node.status}`,
                { sel: data.selected, pulse: data.isNext, phase: data.depth === 0 },
              ]"
            >
              <Handle type="target" :position="Position.Left" :connectable="false" />
              <div class="tnode-title">{{ data.node.title }}</div>
              <div class="tnode-foot">
                <span class="tnode-badge">{{ statusMeta(data.node.status).label }}</span>
                <span v-if="data.node.finding_ids.length" class="tnode-link" title="关联发现数">
                  🔗 {{ data.node.finding_ids.length }}
                </span>
                <span class="tnode-spacer" />
                <button
                  v-if="data.childCount"
                  class="tnode-toggle"
                  :title="data.collapsed ? '展开子树' : '折叠子树'"
                  @click.stop="tree.toggleCollapse(data.node.id)"
                >
                  {{ data.collapsed ? `+${data.childCount}` : "−" }}
                </button>
              </div>
              <Handle type="source" :position="Position.Right" :connectable="false" />
            </div>
          </template>
        </VueFlow>

        <!-- 空态引导 -->
        <div v-if="total === 0 && !tree.loading" class="empty-overlay">
          <div class="empty-card">
            <div class="empty-icon">🌳</div>
            <div class="empty-title">还没有任务树</div>
            <div class="empty-desc">
              AI 会读取当前项目的流量侦察摘要（端点聚合、被动规则标签、已有发现），
              生成一棵「信息收集 → 输入点探测 → 鉴权与会话 → 业务逻辑 → 验证与报告」的引导式任务树。
              每个节点都会讲清楚：做什么、为什么、怎么手动做、怎样算完成。
            </div>
            <el-button
              type="primary"
              :icon="MagicStick"
              :loading="tree.aiBusy === 'generate'"
              :disabled="aiDisabled"
              @click="doGenerate(false)"
            >AI 生成任务树</el-button>
            <div class="empty-tip">
              需先在「流量」页抓取一段目标流量，并在「设置」页配置 API Key。
            </div>
          </div>
        </div>
      </div>

      <!-- 节点详情面板 -->
      <div v-if="tree.selected" class="detail">
        <div class="detail-head">
          <el-tag :type="statusMeta(tree.selected.status).type" effect="dark" size="small">
            {{ statusMeta(tree.selected.status).label }}
          </el-tag>
          <span class="detail-title">{{ tree.selected.title }}</span>
          <el-button link class="detail-close" @click="tree.selectedId = null">✕</el-button>
        </div>

        <!-- 状态流转（白名单按钮，非法流转后端会拒绝） -->
        <div class="status-row">
          <span class="status-label">推进：</span>
          <el-button
            v-for="s in TRANSITIONS[tree.selected.status] ?? []"
            :key="s"
            size="small"
            :type="statusMeta(s).type"
            plain
            @click="onSetStatus(tree.selected.id, s)"
          >{{ TRANSITION_LABEL[s] }}</el-button>
        </div>

        <div class="scroll">
          <!-- 为什么：直接展示存储字段，不消耗 token -->
          <div v-if="tree.selected.why" class="field field-why">
            <div class="field-label">💡 为什么做这步</div>
            <div class="field-body">{{ tree.selected.why }}</div>
          </div>
          <div v-if="tree.selected.description" class="field">
            <div class="field-label">🎯 做什么</div>
            <div class="md" v-html="md.render(tree.selected.description)" />
          </div>
          <div v-if="tree.selected.how_to" class="field">
            <div class="field-label">🛠 怎么做（手动操作）</div>
            <div class="md" v-html="md.render(tree.selected.how_to)" />
          </div>
          <div v-if="tree.selected.verify_criteria" class="field">
            <div class="field-label">✅ 怎样算完成</div>
            <div class="md" v-html="md.render(tree.selected.verify_criteria)" />
          </div>

          <!-- 关联发现 -->
          <div v-if="tree.selected.finding_ids.length" class="field">
            <div class="field-label">🔗 关联发现（{{ tree.selected.finding_ids.length }}）</div>
            <div v-loading="findingsLoading">
              <div
                v-for="f in nodeFindings"
                :key="f.id"
                class="finding-item"
                @click="gotoFindings"
              >
                <el-tag size="small" :type="severityTag(f.severity)" effect="dark">
                  {{ f.severity }}
                </el-tag>
                <span class="finding-title">{{ f.title }}</span>
                <span class="finding-conf">置信度 {{ f.confidence }}</span>
              </div>
              <div v-if="!findingsLoading && !nodeFindings.length" class="finding-empty">
                关联发现已被删除
              </div>
            </div>
          </div>
        </div>

        <!-- 操作区 -->
        <div class="detail-actions">
          <el-button
            size="small"
            :icon="MagicStick"
            :loading="tree.aiBusy === 'expand'"
            :disabled="!settings.ai_enabled"
            @click="onExpand(tree.selected.id)"
          >展开子任务</el-button>
          <el-button
            size="small"
            :loading="tree.aiBusy === 'alternative'"
            :disabled="!settings.ai_enabled"
            @click="onAlternative(tree.selected.id)"
          >🔄 换个思路</el-button>
          <el-button size="small" :icon="Plus" @click="openAdd(tree.selected.id)">子任务</el-button>
          <el-button
            size="small"
            type="danger"
            :icon="Delete"
            plain
            @click="onDelete(tree.selected.id)"
          >删除</el-button>
        </div>
      </div>
    </div>

    <!-- 手动添加节点对话框 -->
    <el-dialog
      v-model="addVisible"
      :title="addParentId === null ? '添加阶段（顶层节点）' : '添加子任务'"
      width="540px"
    >
      <el-form label-width="88px">
        <el-form-item label="标题" required>
          <el-input v-model="addForm.title" placeholder="一句话概括这一步" />
        </el-form-item>
        <el-form-item label="做什么">
          <el-input v-model="addForm.description" type="textarea" :rows="2" />
        </el-form-item>
        <el-form-item label="为什么">
          <el-input v-model="addForm.why" type="textarea" :rows="2" />
        </el-form-item>
        <el-form-item label="怎么做">
          <el-input
            v-model="addForm.how_to"
            type="textarea"
            :rows="3"
            placeholder="2~5 步可手动执行的操作"
          />
        </el-form-item>
        <el-form-item label="完成标准">
          <el-input v-model="addForm.verify_criteria" type="textarea" :rows="2" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="addVisible = false">取消</el-button>
        <el-button type="primary" @click="submitAdd">添加</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.tree-page {
  height: 100%;
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.toolbar {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
}
.title {
  margin: 0;
}
.progress {
  width: 160px;
}
.prog-text {
  font-size: 12px;
  color: var(--el-text-color-secondary);
}
.actions {
  margin-left: auto;
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}
.hint {
  flex-shrink: 0;
}
.content {
  flex: 1;
  display: flex;
  gap: 12px;
  min-height: 0;
}
.canvas {
  flex: 1;
  position: relative;
  min-height: 0;
  border: 1px solid var(--el-border-color);
  border-radius: 8px;
  overflow: hidden;
  background: var(--el-bg-color-page);
}

/* 自定义节点：重置 vue-flow 默认样式 */
.canvas :deep(.vue-flow__node-task) {
  padding: 0;
  border: none;
  background: transparent;
  width: 200px;
}
.canvas :deep(.vue-flow__handle) {
  width: 6px;
  height: 6px;
  min-width: 6px;
  min-height: 6px;
  background: var(--el-border-color-darker);
  border: none;
  opacity: 0.6;
}
.canvas :deep(.vue-flow__edge-path) {
  stroke: var(--el-border-color-darker);
  stroke-width: 1.5;
}

.tnode {
  width: 200px;
  box-sizing: border-box;
  border-radius: 8px;
  border: 1px solid var(--el-border-color);
  border-left-width: 4px;
  background: var(--el-bg-color-overlay);
  padding: 8px 10px;
  cursor: pointer;
  transition: box-shadow 0.15s, transform 0.15s;
}
.tnode:hover {
  box-shadow: 0 3px 12px rgba(0, 0, 0, 0.35);
  transform: translateY(-1px);
}
.tnode.sel {
  box-shadow: 0 0 0 2px var(--el-color-primary);
}
.tnode.phase {
  background: var(--el-fill-color-darker);
}
.tnode.phase .tnode-title {
  font-weight: 600;
}
.st-todo {
  border-left-color: #909399;
}
.st-in_progress {
  border-left-color: #409eff;
}
.st-done {
  border-left-color: #67c23a;
}
.st-blocked {
  border-left-color: #f56c6c;
}
.tnode-title {
  font-size: 13px;
  line-height: 1.35;
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
  word-break: break-word;
}
.tnode-foot {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-top: 6px;
  font-size: 11px;
  color: var(--el-text-color-secondary);
}
.tnode-badge {
  padding: 0 5px;
  border-radius: 3px;
  background: var(--el-fill-color);
}
.tnode-link {
  color: var(--el-color-warning);
}
.tnode-spacer {
  flex: 1;
}
.tnode-toggle {
  border: none;
  background: var(--el-fill-color);
  color: var(--el-text-color-primary);
  border-radius: 4px;
  padding: 1px 7px;
  cursor: pointer;
  font-size: 12px;
  line-height: 1.4;
}
.tnode-toggle:hover {
  background: var(--el-fill-color-dark);
}
.tnode.pulse {
  animation: pulse 1.3s ease-in-out infinite;
}
@keyframes pulse {
  0%,
  100% {
    box-shadow: 0 0 0 0 rgba(64, 158, 255, 0.6);
  }
  50% {
    box-shadow: 0 0 0 7px rgba(64, 158, 255, 0);
  }
}

.empty-overlay {
  position: absolute;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  pointer-events: none;
}
.empty-card {
  max-width: 440px;
  text-align: center;
  padding: 24px;
  pointer-events: auto;
}
.empty-icon {
  font-size: 56px;
}
.empty-title {
  font-size: 16px;
  font-weight: 600;
  margin: 8px 0;
}
.empty-desc {
  color: var(--el-text-color-secondary);
  font-size: 13px;
  line-height: 1.8;
  margin-bottom: 16px;
}
.empty-tip {
  margin-top: 12px;
  font-size: 12px;
  color: var(--el-text-color-secondary);
}

/* 详情面板 */
.detail {
  width: 380px;
  flex-shrink: 0;
  display: flex;
  flex-direction: column;
  border: 1px solid var(--el-border-color);
  border-radius: 8px;
  background: var(--el-bg-color-overlay);
  overflow: hidden;
}
.detail-head {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px;
  border-bottom: 1px solid var(--el-border-color);
}
.detail-title {
  font-weight: 600;
  flex: 1;
  word-break: break-word;
}
.detail-close {
  margin-left: auto;
  color: var(--el-text-color-secondary);
}
.status-row {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 10px 12px;
  border-bottom: 1px solid var(--el-border-color);
  flex-wrap: wrap;
}
.status-label {
  font-size: 12px;
  color: var(--el-text-color-secondary);
}
.scroll {
  flex: 1;
  overflow: auto;
  padding: 12px;
}
.field {
  margin-bottom: 14px;
}
.field-label {
  font-size: 12px;
  color: var(--el-text-color-secondary);
  margin-bottom: 5px;
}
.field-why {
  background: var(--el-color-primary-light-9);
  border-left: 3px solid var(--el-color-primary);
  border-radius: 4px;
  padding: 8px 10px;
}
.field-why .field-body {
  font-size: 13px;
  line-height: 1.7;
  white-space: pre-wrap;
}
.finding-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 8px;
  border: 1px solid var(--el-border-color);
  border-radius: 6px;
  margin-bottom: 6px;
  cursor: pointer;
}
.finding-item:hover {
  background: var(--el-fill-color);
}
.finding-title {
  flex: 1;
  font-size: 13px;
}
.finding-conf {
  font-size: 11px;
  color: var(--el-text-color-secondary);
}
.finding-empty {
  font-size: 12px;
  color: var(--el-text-color-secondary);
}
.detail-actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  padding: 12px;
  border-top: 1px solid var(--el-border-color);
}
.md {
  font-size: 13px;
  line-height: 1.7;
  background: var(--el-fill-color-dark);
  border-radius: 4px;
  padding: 8px 12px;
}
.md :deep(p) {
  margin: 4px 0;
}
.md :deep(ol),
.md :deep(ul) {
  margin: 4px 0;
  padding-left: 20px;
}
.md :deep(code) {
  background: var(--el-fill-color);
  padding: 1px 4px;
  border-radius: 3px;
}
</style>
