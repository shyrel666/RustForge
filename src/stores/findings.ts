import { defineStore } from "pinia";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import {
  Finding,
  listFindings,
  updateFindingStatus,
} from "../api/tauri";

export const useFindingsStore = defineStore("findings", {
  state: () => ({
    items: [] as Finding[],
    loading: false,
    filterStatus: "",
    filterSeverity: "",
    filterSource: "",
    _unlisteners: [] as UnlistenFn[],
  }),
  actions: {
    async refresh(projectId: number) {
      this.loading = true;
      try {
        this.items = await listFindings(projectId, {
          status: this.filterStatus,
          severity: this.filterSeverity,
          source: this.filterSource,
        });
      } finally {
        this.loading = false;
      }
    },

    async setStatus(id: number, status: string) {
      await updateFindingStatus(id, status);
      const f = this.items.find((x) => x.id === id);
      if (f) f.status = status;
    },

    /** 订阅规则/AI 实时产生的新 Finding（幂等） */
    async bindEvents(getProjectId: () => number | null) {
      this.unbindEvents();
      this._unlisteners = await Promise.all([
        listen<Finding>("finding:new", (e) => {
          const pid = getProjectId();
          const f = e.payload;
          if (pid === null || f.project_id !== pid) return;
          // 有筛选条件时直接触发刷新，保证一致性
          if (this.filterStatus || this.filterSeverity || this.filterSource) {
            if (pid !== null) this.refresh(pid);
          } else {
            this.items.unshift(f);
          }
        }),
      ]);
    },

    unbindEvents() {
      this._unlisteners.forEach((u) => u());
      this._unlisteners = [];
    },
  },
});
