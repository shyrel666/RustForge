import { defineStore } from "pinia";
import {
  type CreateTaskNodeInput,
  type TaskNode,
  type TaskPlanProposal,
  type TaskStatus,
  type TestPlan,
  type UpdateTaskNodeInput,
  getTaskTree,
  getTestPlan,
  generateTaskTree,
  expandTaskNode,
  alternativeTaskNode,
  applyTaskPlanProposal,
  rejectTaskPlanProposal,
  nextTask,
  updateTaskStatus,
  createTaskNode,
  updateTaskNode,
  deleteTaskNode,
} from "../api/tauri";
import { isCurrentProjectGeneration } from "../utils/asyncOwnership";

const staleWorkspaceError = () =>
  new Error("[STALE_WORKSPACE] 项目已切换，已丢弃旧项目的异步结果");

export const useTreeStore = defineStore("tree", {
  state: () => ({
    nodes: [] as TaskNode[],
    plan: null as TestPlan | null,
    pendingProposal: null as TaskPlanProposal | null,
    loading: false,
    selectedId: null as number | null,
    collapsed: new Set<number>(),
    aiBusy: "" as "" | "generate" | "expand" | "alternative",
    applyingProposal: false,
    lastNextId: null as number | null,
    workspaceProjectId: null as number | null,
    _generation: 0,
    _refreshOwner: 0,
    _aiGeneration: 0,
    _aiOwner: 0,
    _applyingOwner: 0,
  }),
  getters: {
    doneCount: (state) =>
      state.nodes.filter((node) =>
        ["done", "skipped", "not_applicable"].includes(node.status)
      ).length,
    childrenOf: (state) => (id: number | null) =>
      state.nodes
        .filter((node) => node.parent_id === id)
        .sort(
          (left, right) =>
            left.sort_order - right.sort_order || left.id - right.id
        ),
    selected: (state) =>
      state.nodes.find((node) => node.id === state.selectedId) ?? null,
  },
  actions: {
    activateProject(projectId: number | null) {
      if (this.workspaceProjectId === projectId) return;
      this.workspaceProjectId = projectId;
      this._generation += 1;
      this._aiGeneration += 1;
      this._refreshOwner = 0;
      this._aiOwner = 0;
      this._applyingOwner = 0;
      this.nodes = [];
      this.plan = null;
      this.pendingProposal = null;
      this.loading = false;
      this.selectedId = null;
      this.collapsed = new Set<number>();
      this.aiBusy = "";
      this.applyingProposal = false;
      this.lastNextId = null;
    },

    async refresh(projectId: number) {
      if (this.workspaceProjectId !== projectId) {
        this.activateProject(projectId);
      }
      const generation = ++this._generation;
      this._refreshOwner = generation;
      this.loading = true;
      try {
        const [nodes, plan] = await Promise.all([
          getTaskTree(projectId),
          getTestPlan(projectId),
        ]);
        if (
          isCurrentProjectGeneration(
            this.workspaceProjectId,
            this._generation,
            projectId,
            generation
          )
        ) {
          this.nodes = nodes;
          this.plan = plan;
          if (
            this.selectedId !== null &&
            !nodes.some((node) => node.id === this.selectedId)
          ) {
            this.selectedId = null;
          }
        }
      } finally {
        if (this._refreshOwner === generation) {
          this.loading = false;
          this._refreshOwner = 0;
        }
      }
    },

    async generate(projectId: number, expectedInputHash: string) {
      if (this.workspaceProjectId !== projectId) throw staleWorkspaceError();
      const generation = ++this._aiGeneration;
      this._aiOwner = generation;
      this.aiBusy = "generate";
      try {
        const execution = await generateTaskTree(projectId, expectedInputHash);
        if (
          !isCurrentProjectGeneration(
            this.workspaceProjectId,
            this._aiGeneration,
            projectId,
            generation
          ) ||
          execution.proposal.project_id !== projectId
        ) {
          throw staleWorkspaceError();
        }
        this.pendingProposal = execution.proposal;
        return execution;
      } finally {
        if (this._aiOwner === generation) {
          this.aiBusy = "";
          this._aiOwner = 0;
        }
      }
    },

    async expand(nodeId: number, expectedInputHash: string) {
      const projectId = this.workspaceProjectId;
      if (projectId === null) throw staleWorkspaceError();
      const generation = ++this._aiGeneration;
      this._aiOwner = generation;
      this.aiBusy = "expand";
      try {
        const execution = await expandTaskNode(nodeId, expectedInputHash);
        if (
          !isCurrentProjectGeneration(
            this.workspaceProjectId,
            this._aiGeneration,
            projectId,
            generation
          ) ||
          execution.proposal.project_id !== projectId
        ) {
          throw staleWorkspaceError();
        }
        this.pendingProposal = execution.proposal;
        return execution;
      } finally {
        if (this._aiOwner === generation) {
          this.aiBusy = "";
          this._aiOwner = 0;
        }
      }
    },

    async alternative(nodeId: number, expectedInputHash: string) {
      const projectId = this.workspaceProjectId;
      if (projectId === null) throw staleWorkspaceError();
      const generation = ++this._aiGeneration;
      this._aiOwner = generation;
      this.aiBusy = "alternative";
      try {
        const execution = await alternativeTaskNode(
          nodeId,
          expectedInputHash
        );
        if (
          !isCurrentProjectGeneration(
            this.workspaceProjectId,
            this._aiGeneration,
            projectId,
            generation
          ) ||
          execution.proposal.project_id !== projectId
        ) {
          throw staleWorkspaceError();
        }
        this.pendingProposal = execution.proposal;
        return execution;
      } finally {
        if (this._aiOwner === generation) {
          this.aiBusy = "";
          this._aiOwner = 0;
        }
      }
    },

    async applyProposal() {
      const proposal = this.pendingProposal;
      if (!proposal) throw new Error("没有待确认的测试计划 proposal");
      const projectId = this.workspaceProjectId;
      if (projectId === null || proposal.project_id !== projectId) {
        this.pendingProposal = null;
        throw staleWorkspaceError();
      }
      const generation = ++this._generation;
      this._aiGeneration += 1;
      this._applyingOwner = generation;
      this.applyingProposal = true;
      try {
        const result = await applyTaskPlanProposal(projectId, proposal.id);
        if (
          !isCurrentProjectGeneration(
            this.workspaceProjectId,
            this._generation,
            projectId,
            generation
          )
        ) {
          throw staleWorkspaceError();
        }
        this.pendingProposal = null;
        await this.refresh(projectId);
        if (this.workspaceProjectId !== projectId) throw staleWorkspaceError();
        if (proposal.target_node_id !== null) {
          const collapsed = new Set(this.collapsed);
          collapsed.delete(proposal.target_node_id);
          this.collapsed = collapsed;
        }
        return result;
      } finally {
        if (this._applyingOwner === generation) {
          this.applyingProposal = false;
          this._applyingOwner = 0;
        }
      }
    },

    async rejectProposal() {
      const proposal = this.pendingProposal;
      if (!proposal) return;
      const projectId = this.workspaceProjectId;
      if (projectId === null || proposal.project_id !== projectId) {
        this.pendingProposal = null;
        throw staleWorkspaceError();
      }
      await rejectTaskPlanProposal(proposal.id);
      if (
        this.workspaceProjectId === projectId &&
        this.pendingProposal?.id === proposal.id
      ) {
        this.pendingProposal = null;
      }
    },

    async goNext(projectId: number): Promise<TaskNode | null> {
      if (this.workspaceProjectId !== projectId) throw staleWorkspaceError();
      const generation = ++this._generation;
      const node = await nextTask(projectId);
      if (
        !isCurrentProjectGeneration(
          this.workspaceProjectId,
          this._generation,
          projectId,
          generation
        )
      ) {
        return null;
      }
      if (!node) return null;
      this.lastNextId = node.id;
      this.selectedId = node.id;
      const expanded = new Set(this.collapsed);
      let current = node.parent_id;
      let guard = 0;
      while (current !== null && guard++ < 20) {
        expanded.delete(current);
        current =
          this.nodes.find((candidate) => candidate.id === current)?.parent_id ??
          null;
      }
      this.collapsed = expanded;
      return node;
    },

    async setStatus(
      nodeId: number,
      status: TaskStatus,
      reason: string | null
    ) {
      const projectId = this.workspaceProjectId;
      if (projectId === null) throw staleWorkspaceError();
      const generation = ++this._generation;
      const updated = await updateTaskStatus(nodeId, status, reason);
      if (
        updated.project_id !== projectId ||
        !isCurrentProjectGeneration(
          this.workspaceProjectId,
          this._generation,
          projectId,
          generation
        )
      ) {
        return updated;
      }
      const index = this.nodes.findIndex((node) => node.id === nodeId);
      if (index >= 0) this.nodes[index] = updated;
      if (this.plan) await this.refresh(projectId);
      return updated;
    },

    async create(input: CreateTaskNodeInput) {
      if (this.workspaceProjectId !== input.project_id) throw staleWorkspaceError();
      const generation = ++this._generation;
      await createTaskNode(input);
      if (
        isCurrentProjectGeneration(
          this.workspaceProjectId,
          this._generation,
          input.project_id,
          generation
        )
      ) {
        await this.refresh(input.project_id);
      }
    },

    async update(input: UpdateTaskNodeInput) {
      const projectId = this.workspaceProjectId;
      if (projectId === null) throw staleWorkspaceError();
      const generation = ++this._generation;
      const updated = await updateTaskNode(input);
      if (
        updated.project_id === projectId &&
        isCurrentProjectGeneration(
          this.workspaceProjectId,
          this._generation,
          projectId,
          generation
        )
      ) {
        await this.refresh(projectId);
      }
      return updated;
    },

    async remove(nodeId: number) {
      const projectId = this.workspaceProjectId;
      if (projectId === null) throw staleWorkspaceError();
      const node = this.nodes.find((candidate) => candidate.id === nodeId);
      const generation = ++this._generation;
      await deleteTaskNode(nodeId);
      if (
        !isCurrentProjectGeneration(
          this.workspaceProjectId,
          this._generation,
          projectId,
          generation
        )
      ) {
        return;
      }
      if (this.selectedId === nodeId) this.selectedId = null;
      if (node?.project_id === projectId) await this.refresh(projectId);
    },

    toggleCollapse(id: number) {
      const collapsed = new Set(this.collapsed);
      if (collapsed.has(id)) collapsed.delete(id);
      else collapsed.add(id);
      this.collapsed = collapsed;
    },
  },
});
