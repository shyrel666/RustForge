import { defineStore } from "pinia";
import {
  TaskNode,
  getTaskTree,
  generateTaskTree,
  expandTaskNode,
  alternativeTaskNode,
  nextTask,
  updateTaskStatus,
  createTaskNode,
  deleteTaskNode,
} from "../api/tauri";

export const useTreeStore = defineStore("tree", {
  state: () => ({
    nodes: [] as TaskNode[],
    loading: false,
    /** 当前选中（详情面板展示的）节点 */
    selectedId: null as number | null,
    /** 折叠的节点 id 集合 */
    collapsed: new Set<number>(),
    /** 正在跑的 AI 操作（生成/展开/换思路），用于按钮 loading 与防重入 */
    aiBusy: "" as "" | "generate" | "expand" | "alternative",
    /** "下一步"刚定位到的节点（高亮脉冲） */
    lastNextId: null as number | null,
  }),
  getters: {
    doneCount: (s) => s.nodes.filter((n) => n.status === "done").length,
    childrenOf: (s) => (id: number | null) =>
      s.nodes
        .filter((n) => n.parent_id === id)
        .sort((a, b) => a.sort_order - b.sort_order || a.id - b.id),
    selected: (s) => s.nodes.find((n) => n.id === s.selectedId) ?? null,
  },
  actions: {
    async refresh(projectId: number) {
      this.loading = true;
      try {
        this.nodes = await getTaskTree(projectId);
      } finally {
        this.loading = false;
      }
    },

    async generate(projectId: number, replace: boolean, expectedInputHash: string) {
      this.aiBusy = "generate";
      try {
        const execution = await generateTaskTree(
          projectId,
          replace,
          expectedInputHash
        );
        await this.refresh(projectId);
        return execution;
      } finally {
        this.aiBusy = "";
      }
    },

    async expand(nodeId: number, expectedInputHash: string) {
      this.aiBusy = "expand";
      try {
        const execution = await expandTaskNode(nodeId, expectedInputHash);
        const node = this.nodes.find((n) => n.id === nodeId);
        if (node) await this.refresh(node.project_id);
        // 展开后自动打开折叠
        this.collapsed.delete(nodeId);
        this.collapsed = new Set(this.collapsed);
        return execution;
      } finally {
        this.aiBusy = "";
      }
    },

    async alternative(nodeId: number, expectedInputHash: string) {
      this.aiBusy = "alternative";
      try {
        const execution = await alternativeTaskNode(nodeId, expectedInputHash);
        const node = this.nodes.find((n) => n.id === nodeId);
        if (node) await this.refresh(node.project_id);
        return execution;
      } finally {
        this.aiBusy = "";
      }
    },

    /** "下一步"：定位节点并选中；沿途展开折叠的祖先 */
    async goNext(projectId: number): Promise<TaskNode | null> {
      const node = await nextTask(projectId);
      if (!node) return null;
      this.lastNextId = node.id;
      this.selectedId = node.id;
      // 展开祖先链
      const expand = new Set(this.collapsed);
      let cur = node.parent_id;
      let guard = 0;
      while (cur !== null && guard++ < 20) {
        expand.delete(cur);
        cur = this.nodes.find((n) => n.id === cur)?.parent_id ?? null;
      }
      this.collapsed = expand;
      return node;
    },

    async setStatus(nodeId: number, status: string) {
      await updateTaskStatus(nodeId, status);
      const n = this.nodes.find((x) => x.id === nodeId);
      if (n) n.status = status;
    },

    async create(
      projectId: number,
      parentId: number | null,
      fields: { title: string; description: string; why: string; how_to: string; verify_criteria: string }
    ) {
      await createTaskNode(projectId, parentId, fields);
      await this.refresh(projectId);
    },

    async remove(nodeId: number) {
      await deleteTaskNode(nodeId);
      const node = this.nodes.find((n) => n.id === nodeId);
      if (this.selectedId === nodeId) this.selectedId = null;
      if (node) await this.refresh(node.project_id);
    },

    toggleCollapse(id: number) {
      const s = new Set(this.collapsed);
      if (s.has(id)) s.delete(id);
      else s.add(id);
      this.collapsed = s;
    },
  },
});
