import { defineStore } from "pinia";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import {
  Finding,
  listFindings,
  updateFindingReview,
  updateFindingStatus,
} from "../api/tauri";
import { isCurrentProjectGeneration } from "../utils/asyncOwnership";

export const useFindingsStore = defineStore("findings", {
  state: () => ({
    items: [] as Finding[],
    loading: false,
    filterStatus: "",
    filterSeverity: "",
    filterSource: "",
    workspaceProjectId: null as number | null,
    _generation: 0,
    _loadingOwner: 0,
    _unlisteners: [] as UnlistenFn[],
  }),
  actions: {
    activateProject(projectId: number | null) {
      if (this.workspaceProjectId === projectId) return;
      this.workspaceProjectId = projectId;
      this._generation += 1;
      this._loadingOwner = 0;
      this.items = [];
      this.loading = false;
    },

    async refresh(projectId: number) {
      if (this.workspaceProjectId !== projectId) {
        this.activateProject(projectId);
      }
      const generation = ++this._generation;
      this._loadingOwner = generation;
      this.loading = true;
      try {
        const items = await listFindings(projectId, {
          status: this.filterStatus,
          severity: this.filterSeverity,
          source: this.filterSource,
        });
        if (
          isCurrentProjectGeneration(
            this.workspaceProjectId,
            this._generation,
            projectId,
            generation
          )
        ) {
          this.items = items;
        }
      } finally {
        if (this._loadingOwner === generation) {
          this.loading = false;
          this._loadingOwner = 0;
        }
      }
    },

    applyFinding(finding: Finding) {
      if (this.workspaceProjectId !== finding.project_id) return;
      const index = this.items.findIndex((item) => item.id === finding.id);
      const matches =
        (!this.filterStatus || finding.status === this.filterStatus) &&
        (!this.filterSeverity || finding.severity === this.filterSeverity) &&
        (!this.filterSource || finding.source === this.filterSource);
      if (!matches) {
        if (index >= 0) this.items.splice(index, 1);
        return;
      }
      if (index >= 0) this.items[index] = finding;
      else this.items.unshift(finding);
    },

    async setStatus(id: number, status: string, reason?: string) {
      const projectId = this.workspaceProjectId;
      if (projectId === null) throw new Error("当前没有活动项目");
      const generation = ++this._generation;
      const finding = await updateFindingStatus(id, status, reason);
      if (
        finding.project_id === projectId &&
        isCurrentProjectGeneration(
          this.workspaceProjectId,
          this._generation,
          projectId,
          generation
        )
      ) {
        this.applyFinding(finding);
      }
      return finding;
    },

    async updateReview(
      id: number,
      severity: string,
      analystNotes: string,
      reason?: string
    ) {
      const projectId = this.workspaceProjectId;
      if (projectId === null) throw new Error("当前没有活动项目");
      const generation = ++this._generation;
      const finding = await updateFindingReview(
        id,
        severity,
        analystNotes,
        reason
      );
      if (
        finding.project_id === projectId &&
        isCurrentProjectGeneration(
          this.workspaceProjectId,
          this._generation,
          projectId,
          generation
        )
      ) {
        this.applyFinding(finding);
      }
      return finding;
    },

    /** 订阅规则/AI 实时产生的新 Finding（幂等） */
    async bindEvents(getProjectId: () => number | null) {
      this.unbindEvents();
      const acceptEvent = (finding: Finding) => {
        const projectId = getProjectId();
        if (
          projectId === null ||
          this.workspaceProjectId !== projectId ||
          finding.project_id !== projectId
        ) {
          return;
        }
        if (this.filterStatus || this.filterSeverity || this.filterSource) {
          void this.refresh(projectId);
        } else {
          this._generation += 1;
          this.applyFinding(finding);
        }
      };
      this._unlisteners = await Promise.all([
        listen<Finding>("finding:new", (event) => acceptEvent(event.payload)),
        listen<Finding>("finding:updated", (event) =>
          acceptEvent(event.payload)
        ),
      ]);
    },

    unbindEvents() {
      this._unlisteners.forEach((u) => u());
      this._unlisteners = [];
    },
  },
});
