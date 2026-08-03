import { defineStore } from "pinia";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import {
  cancelAssessment,
  createAssessmentAuthProfile,
  deleteAssessmentAuthProfile,
  getAssessmentDetail,
  importAssessmentAuthProfile,
  listAssessmentAuthCandidates,
  listAssessmentAuthProfiles,
  listAssessmentRuns,
  setAssessmentAuthProfile,
  startAssessment,
  type AssessmentAuthCandidate,
  type AssessmentAuthProfile,
  type AssessmentContractInput,
  type AssessmentDetail,
  type AssessmentProgress,
  type AssessmentRun,
} from "../api/tauri";
import {
  assessmentProgressEventKey,
  isAssessmentProgressForWorkspace,
} from "../utils/assessmentProgress";

const ACTIVE_STATUSES = new Set([
  "queued",
  "discovering",
  "planning",
  "executing",
  "verifying",
]);

const staleWorkspaceError = () =>
  new Error("[STALE_WORKSPACE] 项目已切换，已丢弃旧项目的评估结果");

export const useAssessmentStore = defineStore("assessment", {
  state: () => ({
    profiles: [] as AssessmentAuthProfile[],
    authCandidates: [] as AssessmentAuthCandidate[],
    authCandidatesLoading: false,
    authCandidatesError: "",
    runs: [] as AssessmentRun[],
    detail: null as AssessmentDetail | null,
    progress: null as AssessmentProgress | null,
    selectedRunId: null as number | null,
    workspaceProjectId: null as number | null,
    loading: false,
    starting: false,
    cancelling: false,
    error: "",
    _generation: 0,
    _loadingOwner: 0,
    _startOwner: 0,
    _cancelOwner: 0,
    _candidateOwner: 0,
    _unlisten: null as UnlistenFn | null,
    _lastEventKey: "",
    _eventRefreshTimer: null as number | null,
  }),

  getters: {
    activeRun: (state): AssessmentRun | null =>
      state.runs.find((run) => ACTIVE_STATUSES.has(run.status)) ?? null,
    selectedRun: (state): AssessmentRun | null =>
      state.runs.find((run) => run.id === state.selectedRunId) ?? null,
    isRunning(): boolean {
      return Boolean(this.activeRun);
    },
  },

  actions: {
    activateProject(projectId: number | null) {
      if (this.workspaceProjectId === projectId) return;
      this.workspaceProjectId = projectId;
      this._generation += 1;
      this._loadingOwner = 0;
      this._startOwner = 0;
      this._cancelOwner = 0;
      this._candidateOwner = 0;
      this.profiles = [];
      this.authCandidates = [];
      this.authCandidatesLoading = false;
      this.authCandidatesError = "";
      this.runs = [];
      this.detail = null;
      this.progress = null;
      this.selectedRunId = null;
      this.loading = false;
      this.starting = false;
      this.cancelling = false;
      this.error = "";
      this._lastEventKey = "";
      if (this._eventRefreshTimer !== null) {
        window.clearTimeout(this._eventRefreshTimer);
        this._eventRefreshTimer = null;
      }
    },

    async refresh(projectId: number) {
      if (this.workspaceProjectId !== projectId) {
        this.activateProject(projectId);
      }
      const generation = ++this._generation;
      this._loadingOwner = generation;
      this.loading = true;
      this.error = "";
      try {
        const [runs, profiles] = await Promise.all([
          listAssessmentRuns(projectId),
          listAssessmentAuthProfiles(projectId),
        ]);
        if (
          this.workspaceProjectId !== projectId ||
          this._generation !== generation
        ) {
          return;
        }
        this.runs = runs;
        this.profiles = profiles;

        const active = runs.find((run) => ACTIVE_STATUSES.has(run.status));
        const selectedStillExists = runs.some(
          (run) => run.id === this.selectedRunId
        );
        if (!selectedStillExists) {
          this.selectedRunId = active?.id ?? runs[0]?.id ?? null;
        }
        if (this.selectedRunId === null) {
          this.detail = null;
          this.progress = null;
          return;
        }
        const detail = await getAssessmentDetail(projectId, this.selectedRunId);
        if (
          this.workspaceProjectId === projectId &&
          this._generation === generation &&
          this.selectedRunId === detail.run.id
        ) {
          this.detail = detail;
          this.mergeRun(detail.run);
          this.restoreProgress(detail);
        }
      } catch (error) {
        if (
          this.workspaceProjectId === projectId &&
          this._generation === generation
        ) {
          this.error = String(error);
        }
        throw error;
      } finally {
        if (this._loadingOwner === generation) {
          this.loading = false;
          this._loadingOwner = 0;
        }
      }
    },

    async selectRun(runId: number) {
      const projectId = this.workspaceProjectId;
      if (projectId === null) throw staleWorkspaceError();
      if (!this.runs.some((run) => run.id === runId)) {
        throw new Error("评估运行不属于当前项目");
      }
      this.selectedRunId = runId;
      this.detail = null;
      this.progress = null;
      const generation = ++this._generation;
      this._loadingOwner = generation;
      this.loading = true;
      try {
        const detail = await getAssessmentDetail(projectId, runId);
        if (
          this.workspaceProjectId !== projectId ||
          this._generation !== generation ||
          this.selectedRunId !== runId
        ) {
          // 用户已切换到其它 run 或项目：静默丢弃过期结果，不误报 stale。
          return;
        }
        this.detail = detail;
        this.mergeRun(detail.run);
        this.restoreProgress(detail);
      } finally {
        if (this._loadingOwner === generation) {
          this.loading = false;
          this._loadingOwner = 0;
        }
      }
    },

    async start(contract: AssessmentContractInput, contractHash: string) {
      const projectId = this.workspaceProjectId;
      if (projectId === null || contract.projectId !== projectId) {
        throw staleWorkspaceError();
      }
      const generation = ++this._generation;
      this._startOwner = generation;
      this.starting = true;
      this.error = "";
      try {
        const run = await startAssessment(contract, contractHash);
        if (
          this.workspaceProjectId !== projectId ||
          this._generation !== generation ||
          run.projectId !== projectId
        ) {
          throw staleWorkspaceError();
        }
        this.mergeRun(run);
        this.selectedRunId = run.id;
        // 先清空旧 run 的 detail，避免拉取失败时残留上一 run 的数据错配。
        this.detail = null;
        this.progress = {
          projectId,
          runId: run.id,
          status: run.status,
          phase: "queued",
          message: "评估已进入后台队列",
          requestCount: run.requestCount,
          requestBudget: run.requestBudget,
          completedChecks: 0,
          totalChecks: 0,
          occurredAt: run.createdAt,
        };
        try {
          this.detail = await getAssessmentDetail(projectId, run.id);
        } catch {
          // 后台刚启动时 detail 读取可短暂落后；保持 null，进度事件或下一次刷新会恢复。
        }
        return run;
      } catch (error) {
        if (
          this.workspaceProjectId === projectId &&
          this._generation === generation
        ) {
          this.error = String(error);
        }
        throw error;
      } finally {
        if (this._startOwner === generation) {
          this.starting = false;
          this._startOwner = 0;
        }
      }
    },

    async cancel() {
      const projectId = this.workspaceProjectId;
      const run = this.activeRun;
      if (projectId === null || !run) return;
      const generation = this._generation;
      this._cancelOwner = generation;
      this.cancelling = true;
      try {
        await cancelAssessment(projectId, run.id);
        if (
          this.workspaceProjectId === projectId &&
          this._generation === generation
        ) {
          this.progress = {
            projectId,
            runId: run.id,
            status: run.status,
            phase: "cancelling",
            message: "已发出停止请求，正在终止当前等待并保存部分结果",
            requestCount: run.requestCount,
            requestBudget: run.requestBudget,
            completedChecks: this.detail?.verifications.length ?? 0,
            totalChecks: this.detail?.checks.length ?? 0,
            occurredAt: new Date().toISOString(),
          };
          // 事件通道可能不可用；主动拉取一次持久化状态，保证 UI 收敛到终态。
          await this.refresh(projectId).catch(() => {});
        }
      } finally {
        if (this._cancelOwner === generation) {
          this.cancelling = false;
          this._cancelOwner = 0;
        }
      }
    },

    async createProfile(input: {
      label: string;
      headerName: AssessmentAuthProfile["headerName"];
      secret: string;
      sourceTrafficId?: number | null;
    }) {
      const projectId = this.workspaceProjectId;
      if (projectId === null) throw staleWorkspaceError();
      const created = await createAssessmentAuthProfile({
        projectId,
        label: input.label,
        headerName: input.headerName,
        secret: input.secret,
        sourceTrafficId: input.sourceTrafficId ?? null,
      });
      if (this.workspaceProjectId !== projectId) throw staleWorkspaceError();
      this.profiles.push(created);
      this.profiles.sort((left, right) => left.id - right.id);
      return created;
    },

    async updateProfileSecret(
      profileId: number,
      headerName: AssessmentAuthProfile["headerName"],
      secret: string
    ) {
      const projectId = this.workspaceProjectId;
      if (projectId === null) throw staleWorkspaceError();
      const updated = await setAssessmentAuthProfile({
        projectId,
        profileId,
        headerName,
        secret,
      });
      if (this.workspaceProjectId !== projectId) throw staleWorkspaceError();
      const index = this.profiles.findIndex((item) => item.id === profileId);
      if (index >= 0) this.profiles[index] = updated;
      return updated;
    },

    async importProfile(
      trafficId: number,
      label: string,
      headerName: AssessmentAuthProfile["headerName"]
    ) {
      const projectId = this.workspaceProjectId;
      if (projectId === null) throw staleWorkspaceError();
      const created = await importAssessmentAuthProfile({
        projectId,
        trafficId,
        label,
        headerName,
      });
      if (this.workspaceProjectId !== projectId) throw staleWorkspaceError();
      this.profiles.push(created);
      this.profiles.sort((left, right) => left.id - right.id);
      return created;
    },

    async removeProfile(profileId: number) {
      const projectId = this.workspaceProjectId;
      if (projectId === null) throw staleWorkspaceError();
      await deleteAssessmentAuthProfile(projectId, profileId);
      if (this.workspaceProjectId !== projectId) throw staleWorkspaceError();
      this.profiles = this.profiles.filter((item) => item.id !== profileId);
    },

    /** 对话框每次打开时重置候选状态，避免旧结果残留。 */
    resetAuthCandidates() {
      this._candidateOwner += 1;
      this.authCandidates = [];
      this.authCandidatesLoading = false;
      this.authCandidatesError = "";
    },

    /**
     * 扫描最近 Traffic，列出可提取指定鉴权 Header 的候选请求。
     * 用请求序号守卫并发：快速切换 Header 时，先发请求的迟到响应不会
     * 覆盖后发请求的结果。
     */
    async loadAuthCandidates(
      headerName: AssessmentAuthProfile["headerName"]
    ): Promise<void> {
      const projectId = this.workspaceProjectId;
      if (projectId === null) {
        this.authCandidates = [];
        return;
      }
      const owner = ++this._candidateOwner;
      this.authCandidatesLoading = true;
      this.authCandidatesError = "";
      try {
        const candidates = await listAssessmentAuthCandidates(projectId, headerName);
        if (
          this.workspaceProjectId !== projectId ||
          owner !== this._candidateOwner
        ) {
          return;
        }
        this.authCandidates = candidates;
      } catch (error) {
        if (
          this.workspaceProjectId === projectId &&
          owner === this._candidateOwner
        ) {
          this.authCandidates = [];
          this.authCandidatesError = String(error);
        }
      } finally {
        if (
          this.workspaceProjectId === projectId &&
          owner === this._candidateOwner
        ) {
          this.authCandidatesLoading = false;
        }
      }
    },

    async bindEvents(getProjectId: () => number | null) {
      this.unbindEvents();
      this._unlisten = await listen<AssessmentProgress>(
        "assessment:progress",
        (event) => {
          const progress = event.payload;
          const projectId = getProjectId();
          if (
            projectId === null ||
            !isAssessmentProgressForWorkspace(
              progress,
              projectId,
              this.workspaceProjectId,
              this.selectedRunId,
            )
          ) {
            return;
          }
          const eventKey = assessmentProgressEventKey(progress);
          if (eventKey === this._lastEventKey) return;
          this._lastEventKey = eventKey;
          this.progress = progress;

          const run = this.runs.find((candidate) => candidate.id === progress.runId);
          if (run) {
            run.status = progress.status;
            run.requestCount = progress.requestCount;
          }
          this.scheduleEventRefresh(projectId, progress.runId);
        }
      );
    },

    scheduleEventRefresh(projectId: number, runId: number) {
      if (this._eventRefreshTimer !== null) return;
      this._eventRefreshTimer = window.setTimeout(async () => {
        this._eventRefreshTimer = null;
        if (
          this.workspaceProjectId !== projectId ||
          this.selectedRunId !== runId
        ) {
          return;
        }
        try {
          const [detail, runs] = await Promise.all([
            getAssessmentDetail(projectId, runId),
            listAssessmentRuns(projectId),
          ]);
          if (
            this.workspaceProjectId === projectId &&
            this.selectedRunId === runId
          ) {
            this.detail = detail;
            this.runs = runs;
            this.restoreProgress(detail);
          }
        } catch {
          // 事件后的持久化恢复是 best-effort；下一事件或手动刷新会继续同步。
        }
      }, 180);
    },

    unbindEvents() {
      this._unlisten?.();
      this._unlisten = null;
      if (this._eventRefreshTimer !== null) {
        window.clearTimeout(this._eventRefreshTimer);
        this._eventRefreshTimer = null;
      }
    },

    mergeRun(run: AssessmentRun) {
      const index = this.runs.findIndex((candidate) => candidate.id === run.id);
      if (index >= 0) this.runs[index] = run;
      else this.runs.unshift(run);
      this.runs.sort((left, right) => right.id - left.id);
    },

    restoreProgress(detail: AssessmentDetail) {
      if (detail.run.id !== this.selectedRunId) return;
      const latestEvent = detail.events[detail.events.length - 1];
      this.progress = {
        projectId: detail.run.projectId,
        runId: detail.run.id,
        status: detail.run.status,
        phase: latestEvent?.eventType ?? detail.run.status,
        message:
          typeof latestEvent?.details === "object" &&
          latestEvent.details !== null &&
          "message" in latestEvent.details &&
          typeof latestEvent.details.message === "string"
            ? latestEvent.details.message
            : detail.run.stopReason || "已从持久化运行详情恢复进度",
        requestCount: detail.run.requestCount,
        requestBudget: detail.run.requestBudget,
        completedChecks: detail.verifications.length,
        totalChecks: detail.checks.length,
        occurredAt:
          latestEvent?.createdAt ??
          detail.run.endedAt ??
          detail.run.startedAt ??
          detail.run.createdAt,
      };
    },
  },
});
