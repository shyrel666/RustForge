<script setup lang="ts">
import { computed, nextTick, onMounted, ref, watch } from "vue";
import { useRouter } from "vue-router";
import { ElMessage, ElMessageBox } from "element-plus";
import { MagicStick, Refresh, Plus, Delete, Aim, FolderOpened, FullScreen } from "@element-plus/icons-vue";
import MarkdownIt from "markdown-it";
import { VueFlow, useVueFlow, Handle, Position } from "@vue-flow/core";
import type { Node, Edge } from "@vue-flow/core";
import "@vue-flow/core/dist/style.css";
import "@vue-flow/core/dist/theme-default.css";
import { useTreeStore } from "../stores/tree";
import { useProjectStore } from "../stores/project";
import { useSettingsStore } from "../stores/settings";
import {
  formatStandardReference,
  getTaskFindings,
  previewTaskAi,
  type AiContextPreview,
  type Finding,
  type TaskAiOperation,
  type TaskNode,
} from "../api/tauri";
import AiContextPreviewDialog from "../components/AiContextPreviewDialog.vue";
import KnowledgeCard from "../components/KnowledgeCard.vue";
import EmptyState from "../components/shell/EmptyState.vue";
import PageHeader from "../components/shell/PageHeader.vue";

const tree = useTreeStore();
const project = useProjectStore();
const settings = useSettingsStore();
const router = useRouter();
const md = new MarkdownIt({ breaks: true, linkify: true });
const { fitView } = useVueFlow("task-tree");

const projectId = computed(() => project.current?.id ?? null);
interface PendingTaskAi {
  operation: TaskAiOperation;
  projectId: number;
  nodeId: number | null;
  replace: boolean;
}
const aiPreviewVisible = ref(false);
const pendingTaskAi = ref<PendingTaskAi | null>(null);

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

function openTaskAiPreview(
  operation: TaskAiOperation,
  projectId: number,
  nodeId: number | null,
  replace = false
) {
  pendingTaskAi.value = { operation, projectId, nodeId, replace };
  aiPreviewVisible.value = true;
}

function doGenerate(replace: boolean) {
  const pid = projectId.value;
  if (pid === null) return;
  openTaskAiPreview("generate", pid, null, replace);
}

async function loadTaskAiPreview(): Promise<AiContextPreview> {
  const pending = pendingTaskAi.value;
  if (!pending) throw new Error("没有待预览的任务规划操作");
  return previewTaskAi(
    pending.operation,
    pending.projectId,
    pending.nodeId
  );
}

async function confirmTaskAi(payload: { inputHash: string }) {
  const pending = pendingTaskAi.value;
  if (!pending) return;
  try {
    if (pending.operation === "generate") {
      const execution = await tree.generate(
        pending.projectId,
        pending.replace,
        payload.inputHash
      );
      tree.selectedId = null;
      await fitAll();
      ElMessage.success(
        `任务树已生成（${tree.nodes.length} 个节点，审计运行 #${execution.analysis_run_id}）`
      );
    } else if (pending.operation === "expand" && pending.nodeId !== null) {
      const execution = await tree.expand(pending.nodeId, payload.inputHash);
      await fitAll();
      ElMessage.success(
        `已展开 ${execution.affected_nodes} 个子任务（审计运行 #${execution.analysis_run_id}）`
      );
    } else if (
      pending.operation === "alternative" &&
      pending.nodeId !== null
    ) {
      const execution = await tree.alternative(
        pending.nodeId,
        payload.inputHash
      );
      ElMessage.success(
        `已换一种思路（审计运行 #${execution.analysis_run_id}，节点已重置为「待做」）`
      );
    }
  } catch (error) {
    ElMessage.error(String(error));
  } finally {
    pendingTaskAi.value = null;
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

function onExpand(id: number) {
  const pid = projectId.value;
  if (pid === null) return;
  openTaskAiPreview("expand", pid, id);
}

function onAlternative(id: number) {
  const pid = projectId.value;
  if (pid === null) return;
  openTaskAiPreview("alternative", pid, id);
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
  in_progress: "进行中",
  done: "完成",
  blocked: "受阻",
  todo: "重置",
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
  <div class="tree-page rf-page rf-page--inset">
    <PageHeader
      title="任务树"
      description="基于流量摘要生成引导式渗透任务，每一步由你手动执行。"
    />
    <div class="rf-toolbar">
      <div v-if="total > 0" class="rf-toolbar-group">
        <el-progress :percentage="progress" :stroke-width="8" status="success" class="progress" />
        <span class="prog-text">{{ tree.doneCount }} / {{ total }} 完成</span>
      </div>
      <div class="rf-filters">
        <div class="rf-toolbar-group">
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
              下一步
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
            <el-button :icon="FullScreen" @click="fitAll">适应视图</el-button>
          </template>
        </div>
      </div>
    </div>

    <EmptyState
      v-if="!project.current"
      title="尚未选择项目"
      description="请先在顶部创建或选择项目。任务树基于该项目已抓取的流量摘要生成。"
    >
      <template #icon><el-icon :size="20"><FolderOpened /></el-icon></template>
    </EmptyState>
    <el-alert v-else-if="!settings.ai_enabled" type="info" :closable="false" class="hint" show-icon>
      AI 功能已在设置中全局禁用。你仍可手动添加节点并推进状态。
    </el-alert>
    <el-alert v-else type="info" :closable="false" class="hint" show-icon>
      人在回路：任务树只做引导——每一步由你手动执行。点「下一步」定位当前该做什么；带链接标记的节点关联了发现。
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
                  <el-icon :size="12"><Aim /></el-icon> {{ data.node.finding_ids.length }}
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
          <EmptyState
            class="empty-on-canvas"
            title="还没有任务树"
            description="AI 会读取当前项目的流量侦察摘要，生成引导式任务树。每个节点说明做什么、为什么、怎么手动做、怎样算完成。"
          >
            <template #icon><el-icon :size="20"><MagicStick /></el-icon></template>
            <template #action>
              <p class="empty-tip">
                需先在「流量」页抓取目标流量，并在「设置」页配置 API Key。
              </p>
            </template>
          </EmptyState>
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
            <div class="field-label">为什么做这步</div>
            <div class="field-body">{{ tree.selected.why }}</div>
          </div>
          <div v-if="tree.selected.description" class="field">
            <div class="field-label">做什么</div>
            <div class="md" v-html="md.render(tree.selected.description)" />
          </div>
          <div v-if="tree.selected.how_to" class="field">
            <div class="field-label">怎么做（手动操作）</div>
            <div class="md" v-html="md.render(tree.selected.how_to)" />
          </div>
          <div v-if="tree.selected.verify_criteria" class="field">
            <div class="field-label">怎样算完成</div>
            <div class="md" v-html="md.render(tree.selected.verify_criteria)" />
          </div>

          <div v-if="tree.selected.standard_references.length" class="field">
            <div class="field-label">标准引用</div>
            <div class="reference-list">
              <el-tag
                v-for="reference in tree.selected.standard_references"
                :key="`${reference.framework}@${reference.version}/${reference.id}`"
                size="small"
                effect="plain"
              >
                {{ formatStandardReference(reference) }}
              </el-tag>
            </div>
            <KnowledgeCard :references="tree.selected.standard_references" />
          </div>

          <div v-if="tree.selected.finding_ids.length" class="field">
            <div class="field-label">关联发现（{{ tree.selected.finding_ids.length }}）</div>
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
          >换个思路</el-button>
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

    <AiContextPreviewDialog
      v-model="aiPreviewVisible"
      :load-preview="loadTaskAiPreview"
      :allow-policy-editing="false"
      confirm-text="确认并调用 AI"
      description="任务规划只发送下方经过脱敏和长度限制的项目摘要；确认时后端会从数据库重新构建内容，并核对供应商、提示词和消息哈希。"
      @confirm="confirmTaskAi"
    />
  </div>
</template>

<style scoped>
.progress {
  width: 140px;
}
.prog-text {
  font-size: 12px;
  color: var(--rf-text-secondary);
}
.hint {
  flex-shrink: 0;
}
.content {
  flex: 1;
  display: flex;
  gap: var(--rf-space-3);
  min-height: 0;
}
.canvas {
  flex: 1;
  position: relative;
  min-height: 0;
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-shell);
  overflow: hidden;
  background: var(--rf-bg-panel);
}

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
  background: var(--rf-border-strong);
  border: none;
  opacity: 0.7;
}
.canvas :deep(.vue-flow__edge-path) {
  stroke: var(--rf-border-strong);
  stroke-width: 1.5;
}
.canvas :deep(.vue-flow__background) {
  background: var(--rf-bg-base);
}

.tnode {
  width: 200px;
  box-sizing: border-box;
  border-radius: var(--rf-radius-shell);
  border: 1px solid var(--rf-border);
  border-left-width: 3px;
  background: var(--rf-bg-panel);
  padding: 8px 10px;
  cursor: pointer;
  transition:
    box-shadow var(--rf-duration) var(--rf-ease),
    transform var(--rf-duration) var(--rf-ease),
    border-color var(--rf-duration) var(--rf-ease);
}
.tnode:hover {
  border-color: var(--rf-border-strong);
  transform: translateY(-1px);
}
.tnode.sel {
  box-shadow: 0 0 0 2px var(--rf-accent-muted);
  border-color: var(--rf-accent);
}
.tnode.phase {
  background: var(--rf-bg-raised);
}
.tnode.phase .tnode-title {
  font-weight: 600;
}
.st-todo {
  border-left-color: var(--rf-text-muted);
}
.st-in_progress {
  border-left-color: var(--rf-accent);
}
.st-done {
  border-left-color: var(--rf-success);
}
.st-blocked {
  border-left-color: var(--rf-danger);
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
  color: var(--rf-text-secondary);
}
.tnode-badge {
  padding: 0 5px;
  border-radius: var(--rf-radius-tag);
  background: var(--rf-bg-raised);
}
.tnode-link {
  display: inline-flex;
  align-items: center;
  gap: 2px;
  color: var(--rf-warning);
}
.tnode-spacer {
  flex: 1;
}
.tnode-toggle {
  border: none;
  background: var(--rf-bg-raised);
  color: var(--rf-text);
  border-radius: var(--rf-radius-tag);
  padding: 1px 7px;
  cursor: pointer;
  font-size: 12px;
  line-height: 1.4;
}
.tnode-toggle:hover {
  background: var(--rf-bg-hover);
}
.tnode.pulse {
  animation: pulse 1.3s ease-in-out infinite;
}
@keyframes pulse {
  0%,
  100% {
    box-shadow: 0 0 0 0 rgba(45, 212, 191, 0.55);
  }
  50% {
    box-shadow: 0 0 0 7px rgba(45, 212, 191, 0);
  }
}

.empty-overlay {
  position: absolute;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  pointer-events: none;
  background: color-mix(in srgb, var(--rf-bg-base) 55%, transparent);
  padding: var(--rf-space-5);
}
.empty-on-canvas {
  max-width: 440px;
  width: 100%;
  pointer-events: auto;
  box-shadow: 0 8px 28px color-mix(in srgb, var(--rf-bg-base) 45%, transparent);
}
.empty-tip {
  margin: var(--rf-space-2) 0 0;
  font-size: 12px;
  color: var(--rf-text-muted);
  line-height: 1.5;
}

.detail {
  width: 380px;
  flex-shrink: 0;
  display: flex;
  flex-direction: column;
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-shell);
  background: var(--rf-bg-panel);
  overflow: hidden;
}
.detail-head {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: var(--rf-space-3);
  border-bottom: 1px solid var(--rf-border);
}
.detail-title {
  font-weight: 600;
  flex: 1;
  word-break: break-word;
}
.detail-close {
  margin-left: auto;
  color: var(--rf-text-secondary);
}
.status-row {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 10px 12px;
  border-bottom: 1px solid var(--rf-border);
  flex-wrap: wrap;
}
.status-label {
  font-size: 12px;
  color: var(--rf-text-secondary);
}
.scroll {
  flex: 1;
  overflow: auto;
  padding: var(--rf-space-3);
}
.field {
  margin-bottom: 14px;
}
.field-label {
  font-size: 12px;
  font-weight: 600;
  color: var(--rf-text-muted);
  margin-bottom: 6px;
}
.field-why {
  background: var(--rf-accent-muted);
  border-left: 3px solid var(--rf-accent);
  border-radius: var(--rf-radius-control);
  padding: 8px 10px;
}
.field-why .field-body {
  font-size: 13px;
  line-height: 1.7;
  white-space: pre-wrap;
}
.reference-list {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  margin-bottom: var(--rf-space-2);
}
.finding-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 8px;
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-control);
  margin-bottom: 6px;
  cursor: pointer;
}
.finding-item:hover {
  background: var(--rf-bg-hover);
}
.finding-title {
  flex: 1;
  font-size: 13px;
}
.finding-conf {
  font-size: 11px;
  color: var(--rf-text-secondary);
}
.finding-empty {
  font-size: 12px;
  color: var(--rf-text-secondary);
}
.detail-actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  padding: var(--rf-space-3);
  border-top: 1px solid var(--rf-border);
}
.md {
  font-size: 13px;
  line-height: 1.7;
  background: var(--rf-bg-raised);
  border-radius: var(--rf-radius-control);
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
  background: var(--rf-bg-hover);
  padding: 1px 4px;
  border-radius: 3px;
}
</style>
