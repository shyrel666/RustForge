import { defineStore } from "pinia";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import {
  TrafficSummary,
  TrafficDetail,
  listTraffic,
  countTraffic,
  getTrafficDetail,
  clearTraffic,
  startProxy,
  stopProxy,
  proxyStatus,
} from "../api/tauri";

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
    // 事件订阅句柄
    _unlisteners: [] as UnlistenFn[],
  }),
  getters: {
    /** 是否还有更多可加载 */
    hasMore: (s) => s.items.length < s.total,
  },
  actions: {
    /** 内部：按当前 limit 拉列表 + 统计总数 */
    async load(projectId: number) {
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
        this.items = items;
        this.total = total;
      } finally {
        this.loading = false;
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
      await clearTraffic(projectId);
      this.items = [];
      this.total = 0;
      this.limit = PAGE_SIZE;
    },

    async openDetail(id: number) {
      this.drawerVisible = true;
      this.detailLoading = true;
      try {
        this.detail = await getTrafficDetail(id);
      } finally {
        this.detailLoading = false;
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
          if (pid === null || row.project_id !== pid) return;
          if (!this.matchesFilter(row)) return;
          this.items.unshift(row);
          this.total += 1;
          // 保持窗口大小，丢弃最旧的（需要时可「加载更多」）
          if (this.items.length > this.limit) this.items.length = this.limit;
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
