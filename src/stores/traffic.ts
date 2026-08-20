import { defineStore } from "pinia";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import {
  TrafficSummary,
  TrafficDetail,
  TrafficTagsUpdate,
  listTraffic,
  countTraffic,
  getTrafficDetail,
  clearTraffic,
  startProxy,
  stopProxy,
  proxyStatus,
} from "../api/tauri";
import { isCurrentProjectGeneration } from "../utils/asyncOwnership";

/** 每页条数（数据库里是全量的，前端按需加载更多） */
const PAGE_SIZE = 200;

export const useTrafficStore = defineStore("traffic", {
  state: () => ({
    items: [] as TrafficSummary[],
    total: 0,
    limit: PAGE_SIZE,
    loading: false,
    // 筛选条件（类 HTTPQL 的全文搜索 Phase 2 再加强）
    filterMethod: "",
    filterStatusClass: "",
    filterSearch: "",
    // 代理状态
    proxyRunning: false,
    proxyPort: 0,
    // 详情抽屉
    detail: null as TrafficDetail | null,
    drawerVisible: false,
    detailLoading: false,
    workspaceProjectId: null as number | null,
    _generation: 0,
    _loadingOwner: 0,
    _detailGeneration: 0,
    _detailOwner: 0,
    // 事件订阅句柄
    _unlisteners: [] as UnlistenFn[],
  }),
  getters: {
    /** 是否还有更多可加载 */
    hasMore: (s) => s.items.length < s.total,
  },
  actions: {
    activateProject(projectId: number | null) {
      if (this.workspaceProjectId === projectId) return;
      this.workspaceProjectId = projectId;
      this.invalidateRequests();
      this.items = [];
      this.total = 0;
      this.limit = PAGE_SIZE;
      this.detail = null;
      this.drawerVisible = false;
    },

    invalidateRequests() {
      this._generation += 1;
      this._detailGeneration += 1;
      this._loadingOwner = 0;
      this._detailOwner = 0;
      this.loading = false;
      this.detailLoading = false;
    },

    /** 内部：按当前 limit 拉列表 + 统计总数 */
    async load(projectId: number) {
      if (this.workspaceProjectId !== projectId) this.activateProject(projectId);
      const generation = ++this._generation;
      this._loadingOwner = generation;
      this.loading = true;
      try {
        const filter = {
          method: this.filterMethod,
          statusClass: this.filterStatusClass,
          search: this.filterSearch,
        };
        const [items, total] = await Promise.all([
          listTraffic(projectId, { ...filter, limit: this.limit }),
          countTraffic(projectId, filter),
        ]);
        if (
          isCurrentProjectGeneration(
            this.workspaceProjectId,
            this._generation,
            projectId,
            generation
          )
        ) {
          this.items = items;
          this.total = total;
        }
      } finally {
        if (this._loadingOwner === generation) {
          this.loading = false;
          this._loadingOwner = 0;
        }
      }
    },

    /** 按当前筛选条件重新拉取列表（回到第一页） */
    async refresh(projectId: number) {
      this.limit = PAGE_SIZE;
      await this.load(projectId);
    },

    /** 加载更多（扩大窗口再拉一次） */
    async loadMore(projectId: number) {
      this.limit += PAGE_SIZE;
      await this.load(projectId);
    },

    async clear(projectId: number) {
      if (this.workspaceProjectId !== projectId) this.activateProject(projectId);
      const generation = ++this._generation;
      await clearTraffic(projectId);
      if (
        isCurrentProjectGeneration(
          this.workspaceProjectId,
          this._generation,
          projectId,
          generation
        )
      ) {
        // Clearing invalidates every row-backed view. A detail request that
        // started before the delete must not restore a now-deleted record.
        this._detailGeneration += 1;
        this._detailOwner = 0;
        this.detailLoading = false;
        this._loadingOwner = 0;
        this.loading = false;
        this.items = [];
        this.total = 0;
        this.limit = PAGE_SIZE;
        this.detail = null;
        this.drawerVisible = false;
      }
    },

    async openDetail(id: number) {
      const projectId = this.workspaceProjectId;
      if (projectId === null) return;
      const generation = ++this._detailGeneration;
      this._detailOwner = generation;
      this.drawerVisible = true;
      this.detailLoading = true;
      this.detail = null;
      try {
        const detail = await getTrafficDetail(id);
        if (
          this.workspaceProjectId === projectId &&
          this._detailGeneration === generation &&
          detail.project_id === projectId
        ) {
          this.detail = detail;
        }
      } finally {
        if (this._detailOwner === generation) {
          this.detailLoading = false;
          this._detailOwner = 0;
        }
      }
    },

    async startProxy(port: number) {
      const st = await startProxy(port);
      this.proxyRunning = st.running;
      this.proxyPort = st.port;
    },

    async stopProxy() {
      const st = await stopProxy();
      this.proxyRunning = st.running;
      this.proxyPort = st.port;
    },

    async syncProxyStatus() {
      const st = await proxyStatus();
      this.proxyRunning = st.running;
      this.proxyPort = st.port;
    },

    /** 订阅后端事件（幂等，重复调用先解绑旧的） */
    async bindEvents(getProjectId: () => number | null) {
      this.unbindEvents();
      this._unlisteners = await Promise.all([
        listen<TrafficSummary>("traffic:new", (e) => {
          const pid = getProjectId();
          const row = e.payload;
          if (
            pid === null ||
            this.workspaceProjectId !== pid ||
            row.project_id !== pid
          )
            return;
          if (!this.matchesFilter(row)) return;
          this._generation += 1;
          this.items.unshift(row);
          this.total += 1;
          // 保持窗口大小，丢弃最旧的（需要时可「加载更多」）
          if (this.items.length > this.limit) this.items.length = this.limit;
        }),
        listen<TrafficTagsUpdate>("traffic:tags", (e) => {
          const pid = getProjectId();
          const update = e.payload;
          if (
            pid === null ||
            this.workspaceProjectId !== pid ||
            update.project_id !== pid
          )
            return;
          this._generation += 1;
          const row = this.items.find((item) => item.id === update.id);
          if (row) row.rule_tags = update.rule_tags;
          if (this.detail?.id === update.id) {
            this.detail.rule_tags = update.rule_tags;
          }
        }),
        listen<{ running: boolean; port: number }>("proxy:status", (e) => {
          this.proxyRunning = e.payload.running;
          this.proxyPort = e.payload.port;
        }),
      ]);
    },

    unbindEvents() {
      this._unlisteners.forEach((u) => u());
      this._unlisteners = [];
    },

    /** 新流量是否满足当前筛选（用于实时追加） */
    matchesFilter(row: TrafficSummary): boolean {
      if (this.filterMethod && row.method !== this.filterMethod) return false;
      if (this.filterStatusClass) {
        const cls = row.status ? Math.floor(row.status / 100) : 0;
        if (String(cls) !== this.filterStatusClass) return false;
      }
      if (this.filterSearch) {
        const q = this.filterSearch.toLowerCase();
        if (
          !row.host.toLowerCase().includes(q) &&
          !row.path.toLowerCase().includes(q)
        )
          return false;
      }
      return true;
    },
  },
});
