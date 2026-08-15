import { defineStore } from "pinia";
import {
  authorizeReplayTarget,
  createReplaySession,
  deleteReplaySession,
  getReplayRun,
  getReplaySessionAssessmentHandoff,
  getTrafficDetail,
  listReplayRuns,
  listReplaySessions,
  replayRequest,
  selectReplaySession,
  updateReplaySession,
  type ReplayHeader,
  type AssessmentHandoffReplayDraft,
  type ReplayRun,
  type ReplayRunSummary,
  type ReplaySession,
  type ScopeDecision,
  type TlsPolicy,
  type TrafficDetail,
} from "../api/tauri";
import {
  claimExclusiveOperation,
} from "../utils/asyncOwnership";
import {
  cloneReplayDraftState,
  draftStateFromRun,
  draftStateFromAssessmentHandoff,
  draftStateFromTraffic,
  emptyReplayDraftState,
  replayWarningIsConfirmed,
  replayRunSummary,
  shouldApplyReplayResult,
  type ReplayDraft,
  type ReplayDraftState,
  type ReplayWarningConfirmation,
} from "../utils/repeaterDraft";
import { useProjectStore } from "./project";

const RUN_PAGE_SIZE = 50;

/*
 * SQLite guarantees one selected session per project, but two tab clicks can
 * otherwise finish their Tauri calls out of order. Serialising only this small
 * mutation keeps the last click authoritative without serialising run reads.
 */
let selectionQueue: Promise<void> = Promise.resolve();

function persistSessionSelection(sessionId: number): Promise<ReplaySession> {
  const result = selectionQueue.then(() => selectReplaySession(sessionId));
  selectionQueue = result.then(
    () => undefined,
    () => undefined
  );
  return result;
}

function draftKey(projectId: number, sessionId: number): string {
  return `${projectId}:${sessionId}`;
}

function runKey(projectId: number, runId: number): string {
  return `${projectId}:${runId}`;
}

/** "Name: Value" 逐行文本 → 头部数组；无冒号行不会被悄悄伪造为头部。 */
function parseHeaders(raw: string): ReplayHeader[] {
  return raw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && line.includes(":"))
    .map((line) => {
      const separator = line.indexOf(":");
      return {
        name: line.slice(0, separator).trim(),
        value: line.slice(separator + 1).trim(),
      };
    })
    .filter((header) => header.name.length > 0);
}

function sourceTitle(source: ReplayDraftState): string {
  const sourceId = source.sourceTrafficId;
  const prefix = sourceId === null ? "流量来源" : `流量 #${sourceId}`;
  let target = source.draft.url;
  try {
    const url = new URL(source.draft.url);
    target = `${url.host}${url.pathname}`;
  } catch {
    // 保留用户看到的原 URL；后端仍会负责 URL 和 Scope 校验。
  }
  return `${prefix} · ${source.draft.method} ${target}`.slice(0, 120);
}

function isScopeError(message: string): boolean {
  return [
    "[OUT_OF_SCOPE]",
    "[EMPTY_SCOPE]",
    "[PROJECT_NOT_FOUND]",
    "[INVALID_URL]",
  ].some((code) => message.includes(code));
}

export const useRepeaterStore = defineStore("repeater", {
  state: () => {
    const empty = emptyReplayDraftState();
    return {
      sessions: [] as ReplaySession[],
      runs: [] as ReplayRunSummary[],
      nextBeforeId: null as number | null,
      activeSessionId: null as number | null,
      pendingSessionId: null as number | null,
      selectedRunId: null as number | null,
      workspaceProjectId: null as number | null,

      draft: empty.draft as ReplayDraft,
      draftStates: {} as Record<string, ReplayDraftState>,
      runDetails: {} as Record<string, ReplayRun>,
      pendingSource: null as ReplayDraftState | null,
      resp: null as ReplayRun | null,
      activeAssessmentHandoff: null as AssessmentHandoffReplayDraft | null,

      loadedFrom: null as number | null,
      loadedFromProject: null as number | null,
      sourceBodyTruncated: false,
      sourceDecodeStatus: "",
      sourceReplayWarning: "",

      sending: false,
      loadingWorkspace: false,
      loadingRuns: false,
      loadingMoreRuns: false,
      loadingRunDetail: false,
      error: "",

      /** 无网络预检；真正发送前后端仍会再次执行 ScopePolicy。 */
      authorization: null as ScopeDecision | null,
      authorizationError: "",
      authorizationProjectId: null as number | null,
      authorizationUrl: "",
      checkingAuthorization: false,
      authorizationCheckId: 0,

      workspaceLoadId: 0,
      sessionLoadId: 0,
      runDetailLoadId: 0,
      sendOperationId: 0,
    };
  },

  getters: {
    activeSession(state): ReplaySession | null {
      return (
        state.sessions.find(
          (session) => session.id === state.activeSessionId
        ) ?? null
      );
    },
    hasMoreRuns(state): boolean {
      return state.nextBeforeId !== null;
    },
  },

  actions: {
    currentDraftState(): ReplayDraftState {
      return {
        draft: { ...this.draft },
        sourceTrafficId: this.loadedFrom,
        sourceProjectId: this.loadedFromProject,
        decodeStatus: this.sourceDecodeStatus,
        bodyTruncated: this.sourceBodyTruncated,
        replayWarning: this.sourceReplayWarning,
      };
    },

    applyDraftState(state: ReplayDraftState) {
      const copy = cloneReplayDraftState(state);
      this.draft = copy.draft;
      this.loadedFrom = copy.sourceTrafficId;
      this.loadedFromProject = copy.sourceProjectId;
      this.sourceDecodeStatus = copy.decodeStatus;
      this.sourceBodyTruncated = copy.bodyTruncated;
      this.sourceReplayWarning = copy.replayWarning;
    },

    stashDraft() {
      const projectId = this.workspaceProjectId;
      const sessionId = this.activeSessionId;
      if (projectId === null || sessionId === null) return;
      this.draftStates[draftKey(projectId, sessionId)] =
        cloneReplayDraftState(this.currentDraftState());
    },

    /** TrafficView 调用；进入 Repeater 时会为该来源建立独立会话。 */
    loadFromDetail(detail: TrafficDetail) {
      this.stashDraft();
      const source = draftStateFromTraffic(detail);
      this.pendingSource = cloneReplayDraftState(source);
      this.applyDraftState(source);
      this.resp = null;
      this.activeAssessmentHandoff = null;
      this.selectedRunId = null;
      this.error = "";
      this.clearAuthorization();
    },

    clearAuthorization() {
      this.authorizationCheckId += 1;
      this.authorization = null;
      this.authorizationError = "";
      this.authorizationProjectId = null;
      this.authorizationUrl = "";
      this.checkingAuthorization = false;
    },

    /** 旧 URL 的异步结果不能覆盖较新的项目、会话或编辑器 URL。 */
    async checkAuthorization(projectId: number | null) {
      const checkId = ++this.authorizationCheckId;
      const url = this.draft.url.trim();
      this.authorization = null;
      this.authorizationError = "";
      this.authorizationProjectId = null;
      this.authorizationUrl = "";
      this.checkingAuthorization = true;
      try {
        const decision = await authorizeReplayTarget(projectId, url);
        if (
          checkId !== this.authorizationCheckId ||
          this.workspaceProjectId !== projectId ||
          this.draft.url.trim() !== url
        ) {
          return;
        }
        this.authorization = decision;
        this.authorizationProjectId = projectId;
        this.authorizationUrl = url;
      } catch (error) {
        if (checkId !== this.authorizationCheckId) return;
        this.authorizationError = String(error);
      } finally {
        if (checkId === this.authorizationCheckId) {
          this.checkingAuthorization = false;
        }
      }
    },

    async loadWorkspace(projectId: number) {
      /*
       * loadFromDetail already stashed the prior tab before placing the source
       * draft in the editor. Stashing again here would associate that source
       * draft with the old session.
       */
      const source =
        this.pendingSource?.sourceProjectId === projectId
          ? cloneReplayDraftState(this.pendingSource)
          : null;
      if (source === null) this.stashDraft();
      if (source !== null) this.pendingSource = null;

      const loadId = ++this.workspaceLoadId;
      this.sessionLoadId += 1;
      this.runDetailLoadId += 1;
      this.sendOperationId += 1;
      this.workspaceProjectId = projectId;
      this.sessions = [];
      this.runs = [];
      this.nextBeforeId = null;
      this.activeSessionId = null;
      this.pendingSessionId = null;
      this.selectedRunId = null;
      this.resp = null;
      this.activeAssessmentHandoff = null;
      this.error = "";
      this.loadingWorkspace = true;
      this.loadingRuns = false;
      this.loadingMoreRuns = false;
      this.loadingRunDetail = false;
      this.sending = false;
      this.clearAuthorization();
      this.applyDraftState(source ?? emptyReplayDraftState());

      let sourcePersisted = false;
      try {
        let sessions = await listReplaySessions(projectId);
        let preferredSessionId: number | null = null;
        if (
          loadId !== this.workspaceLoadId ||
          this.workspaceProjectId !== projectId
        ) {
          return;
        }

        if (source !== null) {
          try {
            const created = await createReplaySession(
              projectId,
              sourceTitle(source),
              source.sourceTrafficId,
              "strict"
            );
            this.draftStates[draftKey(projectId, created.id)] =
              cloneReplayDraftState(source);
            sourcePersisted = true;
            sessions = [
              ...sessions.filter((session) => session.id !== created.id),
              created,
            ];
            preferredSessionId = created.id;
          } catch (error) {
            if (
              this.workspaceProjectId === projectId &&
              this.pendingSource === null
            ) {
              this.pendingSource = cloneReplayDraftState(source);
            }
            throw error;
          }
        }

        if (sessions.length === 0) {
          const created = await createReplaySession(
            projectId,
            "会话 1",
            null,
            "strict"
          );
          sessions = [created];
          preferredSessionId = created.id;
        }

        if (
          loadId !== this.workspaceLoadId ||
          this.workspaceProjectId !== projectId
        ) {
          return;
        }

        this.sessions = sessions;
        const selected =
          sessions.find((session) => session.id === preferredSessionId) ??
          sessions.find((session) => session.is_selected) ??
          sessions[0];
        await this.activateSession(selected.id, false);
      } catch (error) {
        if (
          loadId === this.workspaceLoadId &&
          this.workspaceProjectId === projectId
        ) {
          if (
            source !== null &&
            !sourcePersisted &&
            this.pendingSource === null
          ) {
            this.pendingSource = cloneReplayDraftState(source);
          }
          this.error = String(error);
        }
      } finally {
        if (loadId === this.workspaceLoadId) {
          this.loadingWorkspace = false;
        }
      }
    },

    async activateSession(sessionId: number, persistSelection = true) {
      const projectId = this.workspaceProjectId;
      const session = this.sessions.find(
        (item) => item.id === sessionId && item.project_id === projectId
      );
      if (projectId === null || !session) return;

      this.stashDraft();
      const loadId = ++this.sessionLoadId;
      this.runDetailLoadId += 1;
      this.pendingSessionId = sessionId;
      this.loadingRuns = true;
      this.loadingMoreRuns = false;
      this.error = "";
      this.clearAuthorization();

      try {
        const pagePromise = listReplayRuns(
          sessionId,
          null,
          RUN_PAGE_SIZE
        ).then(
          (page) => ({ page, warning: "" }),
          (error) => ({
            page: { runs: [], next_before_id: null },
            warning: String(error),
          })
        );
        const selectionPromise = persistSelection
          ? persistSessionSelection(sessionId)
          : Promise.resolve(session);
        const handoffPromise = getReplaySessionAssessmentHandoff(projectId, sessionId).catch(
          () => null
        );
        const [{ page, warning }, , handoff] = await Promise.all([
          pagePromise,
          selectionPromise,
          handoffPromise,
        ]);
        let loadWarning = warning;

        let latest: ReplayRun | null = null;
        if (page.runs.length > 0) {
          try {
            latest = await this.loadRunDetail(
              projectId,
              page.runs[0].id,
              false
            );
          } catch (error) {
            loadWarning = String(error);
          }
        }

        let nextDraft =
          this.draftStates[draftKey(projectId, sessionId)] ?? null;
        if (nextDraft === null && handoff !== null && page.runs.length === 0) {
          nextDraft = draftStateFromAssessmentHandoff(handoff, projectId);
        }
        if (nextDraft === null && latest !== null) {
          nextDraft = draftStateFromRun(latest);
        }
        if (
          nextDraft === null &&
          session.source_traffic_id !== null &&
          page.runs.length === 0
        ) {
          try {
            const detail = await getTrafficDetail(session.source_traffic_id);
            if (detail.project_id === projectId) {
              nextDraft = draftStateFromTraffic(detail);
            }
          } catch {
            // 来源可以按项目生命周期删除；空草稿仍能正常使用。
          }
        }
        nextDraft ??= emptyReplayDraftState();

        if (
          loadId !== this.sessionLoadId ||
          this.workspaceProjectId !== projectId
        ) {
          return;
        }

        this.activeSessionId = sessionId;
        this.pendingSessionId = null;
        this.sessions = this.sessions.map((item) => ({
          ...item,
          is_selected: item.id === sessionId,
        }));
        this.runs = page.runs;
        this.nextBeforeId = page.next_before_id;
        this.resp = latest;
        this.selectedRunId = latest?.id ?? null;
        this.activeAssessmentHandoff = handoff;
        this.applyDraftState(nextDraft);
        this.error = loadWarning;
        this.draftStates[draftKey(projectId, sessionId)] =
          cloneReplayDraftState(nextDraft);
      } catch (error) {
        if (
          loadId === this.sessionLoadId &&
          this.workspaceProjectId === projectId
        ) {
          this.error = String(error);
          this.pendingSessionId = null;
        }
      } finally {
        if (loadId === this.sessionLoadId) {
          this.loadingRuns = false;
        }
      }
    },

    async loadMoreRuns() {
      const projectId = this.workspaceProjectId;
      const sessionId = this.activeSessionId;
      const beforeId = this.nextBeforeId;
      const loadId = this.sessionLoadId;
      if (
        projectId === null ||
        sessionId === null ||
        beforeId === null ||
        this.loadingMoreRuns
      ) {
        return;
      }

      this.loadingMoreRuns = true;
      try {
        const page = await listReplayRuns(
          sessionId,
          beforeId,
          RUN_PAGE_SIZE
        );
        if (
          loadId !== this.sessionLoadId ||
          !shouldApplyReplayResult(
            this.workspaceProjectId,
            this.activeSessionId,
            projectId,
            sessionId
          ) ||
          this.nextBeforeId !== beforeId
        ) {
          return;
        }
        const known = new Set(this.runs.map((run) => run.id));
        this.runs.push(...page.runs.filter((run) => !known.has(run.id)));
        this.nextBeforeId = page.next_before_id;
      } catch (error) {
        if (
          loadId === this.sessionLoadId &&
          this.workspaceProjectId === projectId
        ) {
          this.error = String(error);
        }
      } finally {
        if (loadId === this.sessionLoadId) {
          this.loadingMoreRuns = false;
        }
      }
    },

    async loadRunDetail(
      projectId: number,
      runId: number,
      exposeLoading = true
    ): Promise<ReplayRun> {
      const key = runKey(projectId, runId);
      const cached = this.runDetails[key];
      if (cached) return cached;
      if (exposeLoading) this.loadingRunDetail = true;
      try {
        const run = await getReplayRun(projectId, runId);
        this.runDetails[key] = run;
        return run;
      } finally {
        if (exposeLoading) this.loadingRunDetail = false;
      }
    },

    async selectRun(summary: ReplayRunSummary) {
      const projectId = this.workspaceProjectId;
      const sessionId = this.activeSessionId;
      if (
        projectId === null ||
        sessionId === null ||
        summary.project_id !== projectId ||
        summary.session_id !== sessionId
      ) {
        return;
      }
      const loadId = ++this.runDetailLoadId;
      try {
        const run = await this.loadRunDetail(projectId, summary.id);
        if (
          loadId !== this.runDetailLoadId ||
          !shouldApplyReplayResult(
            this.workspaceProjectId,
            this.activeSessionId,
            run.project_id,
            run.session_id
          )
        ) {
          return;
        }
        this.resp = run;
        this.selectedRunId = run.id;
        this.error = "";
      } catch (error) {
        if (loadId === this.runDetailLoadId) this.error = String(error);
      }
    },

    async restoreRun(summary: ReplayRunSummary) {
      const projectId = this.workspaceProjectId;
      const sessionId = this.activeSessionId;
      if (
        projectId === null ||
        sessionId === null ||
        summary.project_id !== projectId ||
        summary.session_id !== sessionId
      ) {
        return;
      }
      const loadId = ++this.runDetailLoadId;
      try {
        const run = await this.loadRunDetail(projectId, summary.id);
        if (
          loadId !== this.runDetailLoadId ||
          !shouldApplyReplayResult(
            this.workspaceProjectId,
            this.activeSessionId,
            run.project_id,
            run.session_id
          )
        ) {
          return;
        }
        const nextDraft = draftStateFromRun(run);
        this.applyDraftState(nextDraft);
        this.draftStates[draftKey(projectId, sessionId)] =
          cloneReplayDraftState(nextDraft);
        this.resp = run;
        this.selectedRunId = run.id;
        this.error = "";
        this.clearAuthorization();
      } catch (error) {
        if (loadId === this.runDetailLoadId) this.error = String(error);
      }
    },

    async send(warningConfirmation: ReplayWarningConfirmation | null = null) {
      const warningConfirmed = replayWarningIsConfirmed(
        this.sourceReplayWarning,
        this.workspaceProjectId,
        this.activeSessionId,
        warningConfirmation
      );
      if (
        this.loadingWorkspace ||
        this.loadingRuns ||
        !warningConfirmed
      ) {
        if (this.sourceReplayWarning && !warningConfirmed) {
          this.error = `[REPLAY_CONFIRMATION_REQUIRED] ${this.sourceReplayWarning}`;
        }
        return;
      }

      const currentProjectId = useProjectStore().current?.id ?? null;
      const projectId = this.workspaceProjectId;
      const sessionId = this.activeSessionId;
      const draft = { ...this.draft };
      const url = draft.url.trim();
      if (
        projectId === null ||
        currentProjectId !== projectId ||
        sessionId === null
      ) {
        return;
      }

      // 在第一个 await 之前取得所有权，授权预检也属于一次发送操作。
      // 这使快速 Enter、按钮连点和程序化重复调用都只能产生一个网络副作用。
      const sendOperationId = claimExclusiveOperation(
        this.sending,
        this.sendOperationId
      );
      if (sendOperationId === null) return;
      this.sendOperationId = sendOperationId;
      this.sending = true;
      this.error = "";
      try {
        let authorization = this.authorization;
        if (
          authorization === null ||
          this.authorizationProjectId !== projectId ||
          this.authorizationUrl !== url
        ) {
          try {
            authorization = await authorizeReplayTarget(projectId, url);
          } catch (error) {
            if (
              shouldApplyReplayResult(
                this.workspaceProjectId,
                this.activeSessionId,
                projectId,
                sessionId
              )
            ) {
              this.authorization = null;
              this.authorizationError = String(error);
            }
            return;
          }
        }

        if (
          authorization === null ||
          useProjectStore().current?.id !== projectId ||
          !shouldApplyReplayResult(
            this.workspaceProjectId,
            this.activeSessionId,
            projectId,
            sessionId
          )
        ) {
          return;
        }

        const run = await replayRequest(
          projectId,
          sessionId,
          draft.method,
          url,
          parseHeaders(draft.headersRaw),
          draft.bodyEncoding === "text" ? draft.body || null : null,
          draft.bodyEncoding === "base64" ? draft.body || null : null
        );
        this.runDetails[runKey(run.project_id, run.id)] = run;
        if (this.workspaceProjectId === run.project_id) {
          this.sessions = this.sessions.map((session) =>
            session.id === run.session_id
              ? {
                  ...session,
                  run_count: session.run_count + 1,
                  last_run_at: run.created_at,
                }
              : session
          );
        }
        if (
          !shouldApplyReplayResult(
            this.workspaceProjectId,
            this.activeSessionId,
            run.project_id,
            run.session_id
          )
        ) {
          return;
        }

        const summary = replayRunSummary(run);
        this.runs = [
          summary,
          ...this.runs.filter((item) => item.id !== summary.id),
        ];
        this.resp = run;
        this.selectedRunId = run.id;
      } catch (error) {
        const message = String(error);
        if (
          shouldApplyReplayResult(
            this.workspaceProjectId,
            this.activeSessionId,
            projectId,
            sessionId
          )
        ) {
          this.error = message;
          this.resp = null;
          if (isScopeError(message)) {
            this.clearAuthorization();
            this.authorizationError = message;
          }
        }
      } finally {
        if (this.sendOperationId === sendOperationId) {
          this.sending = false;
        }
      }
    },

    async addSession(projectId: number) {
      if (this.workspaceProjectId !== projectId) return;
      this.stashDraft();
      const title = `会话 ${this.sessions.length + 1}`;
      const created = await createReplaySession(
        projectId,
        title,
        null,
        "strict"
      );
      if (this.workspaceProjectId !== projectId) return;
      this.sessions = [
        ...this.sessions.filter((session) => session.id !== created.id),
        created,
      ];
      await this.activateSession(created.id, false);
    },

    async saveActiveSession(title: string, tlsPolicy: TlsPolicy) {
      const projectId = this.workspaceProjectId;
      const sessionId = this.activeSessionId;
      if (projectId === null || sessionId === null) return;
      const updated = await updateReplaySession(sessionId, title, tlsPolicy);
      if (this.workspaceProjectId !== updated.project_id) return;
      this.sessions = this.sessions.map((session) =>
        session.id === updated.id ? updated : session
      );
    },

    async removeSession(sessionId: number) {
      const projectId = this.workspaceProjectId;
      if (projectId === null) return;
      const index = this.sessions.findIndex(
        (session) => session.id === sessionId
      );
      if (index < 0) return;

      await deleteReplaySession(sessionId);
      if (this.workspaceProjectId !== projectId) return;
      delete this.draftStates[draftKey(projectId, sessionId)];
      const wasActive = this.activeSessionId === sessionId;
      this.sessions = this.sessions.filter((session) => session.id !== sessionId);
      if (!wasActive) return;

      this.sessionLoadId += 1;
      this.runDetailLoadId += 1;
      this.activeSessionId = null;
      this.pendingSessionId = null;
      this.runs = [];
      this.nextBeforeId = null;
      this.resp = null;
      this.activeAssessmentHandoff = null;
      this.selectedRunId = null;
      this.clearAuthorization();

      const replacement =
        this.sessions[Math.min(index, this.sessions.length - 1)] ?? null;
      if (replacement) {
        await this.activateSession(replacement.id);
      } else {
        await this.addSession(projectId);
      }
    },

    resetWorkspace() {
      this.stashDraft();
      this.workspaceLoadId += 1;
      this.sessionLoadId += 1;
      this.runDetailLoadId += 1;
      this.workspaceProjectId = null;
      this.sessions = [];
      this.runs = [];
      this.nextBeforeId = null;
      this.activeSessionId = null;
      this.pendingSessionId = null;
      this.selectedRunId = null;
      this.pendingSource = null;
      this.resp = null;
      this.activeAssessmentHandoff = null;
      this.error = "";
      this.loadingWorkspace = false;
      this.loadingRuns = false;
      this.loadingMoreRuns = false;
      this.loadingRunDetail = false;
      this.applyDraftState(emptyReplayDraftState());
      this.clearAuthorization();
    },
  },
});
