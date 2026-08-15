import { defineStore } from "pinia";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import {
  attachAssessmentMissionResource,
  confirmAssessmentMissionContext,
  createAssessmentMission,
  createAssessmentMissionHandoff,
  decideAssessmentAction,
  getAssessmentMissionDetail,
  importAssessmentMissionOpenApi,
  linkAssessmentMissionHandoffReplay,
  listAssessmentAuthProfiles,
  listAssessmentMissions,
  pickAssessmentOpenApiFile,
  previewAssessmentMissionContext,
  sendAssessmentMissionMessage,
  setAssessmentToolPermission,
  startAssessmentMission,
  stopAssessmentMission,
  type AssessmentAction,
  type AssessmentAuthProfile,
  type AssessmentMission,
  type AssessmentMissionDetail,
  type AssessmentMissionEvent,
  type AssessmentToolPermissionDecision,
  type CreateAssessmentMissionInput,
  type MissionContextPreview,
} from "../api/tauri";

const ACTIVE_STATUSES = new Set([
  "queued",
  "discovering",
  "planning",
  "executing",
  "verifying",
]);

const staleWorkspaceError = () =>
  new Error("[STALE_WORKSPACE] 项目已切换，已丢弃旧项目的任务结果");

export const useAssessmentMissionStore = defineStore("assessmentMission", {
  state: () => ({
    workspaceProjectId: null as number | null,
    missions: [] as AssessmentMission[],
    profiles: [] as AssessmentAuthProfile[],
    selectedMissionId: null as number | null,
    detail: null as AssessmentMissionDetail | null,
    context: null as MissionContextPreview | null,
    loading: false,
    mutating: false,
    error: "",
    lastEvent: null as AssessmentMissionEvent | null,
    _generation: 0,
    _unlisten: null as UnlistenFn | null,
    _refreshTimer: null as number | null,
    _lastEventKey: "",
  }),

  getters: {
    selectedMission(state): AssessmentMission | null {
      return (
        state.missions.find((mission) => mission.id === state.selectedMissionId) ??
        state.detail?.mission ??
        null
      );
    },
    pendingActions(state): AssessmentAction[] {
      return (state.detail?.actions ?? []).filter(
        (action) => action.approvalStatus === "pending"
      );
    },
    hasNetworkTask(state): boolean {
      return state.missions.some((mission) => ACTIVE_STATUSES.has(mission.status));
    },
  },

  actions: {
    activateProject(projectId: number | null) {
      if (this.workspaceProjectId === projectId) return;
      this.workspaceProjectId = projectId;
      this._generation += 1;
      this.missions = [];
      this.profiles = [];
      this.selectedMissionId = null;
      this.detail = null;
      this.context = null;
      this.loading = false;
      this.mutating = false;
      this.error = "";
      this.lastEvent = null;
      this._lastEventKey = "";
      if (this._refreshTimer !== null) {
        window.clearTimeout(this._refreshTimer);
        this._refreshTimer = null;
      }
    },

    mergeMission(mission: AssessmentMission) {
      const index = this.missions.findIndex((candidate) => candidate.id === mission.id);
      if (index >= 0) this.missions[index] = mission;
      else this.missions.unshift(mission);
      this.missions.sort((left, right) => right.id - left.id);
    },

    async refresh(projectId: number) {
      if (this.workspaceProjectId !== projectId) this.activateProject(projectId);
      const generation = ++this._generation;
      this.loading = true;
      this.error = "";
      try {
        const [missions, profiles] = await Promise.all([
          listAssessmentMissions(projectId),
          listAssessmentAuthProfiles(projectId),
        ]);
        if (this.workspaceProjectId !== projectId || this._generation !== generation) return;
        this.missions = missions;
        this.profiles = profiles;
        if (!missions.some((mission) => mission.id === this.selectedMissionId)) {
          this.selectedMissionId = missions[0]?.id ?? null;
        }
        if (this.selectedMissionId === null) {
          this.detail = null;
          this.context = null;
          return;
        }
        await this.loadSelected(generation);
      } catch (error) {
        if (this.workspaceProjectId === projectId && this._generation === generation) {
          this.error = String(error);
        }
        throw error;
      } finally {
        if (this._generation === generation) this.loading = false;
      }
    },

    async loadSelected(generation?: number) {
      const owner = generation ?? this._generation;
      const projectId = this.workspaceProjectId;
      const missionId = this.selectedMissionId;
      if (projectId === null || missionId === null) return;
      const detail = await getAssessmentMissionDetail(projectId, missionId);
      if (
        this.workspaceProjectId !== projectId ||
        this.selectedMissionId !== missionId ||
        this._generation !== owner
      ) {
        return;
      }
      this.detail = detail;
      this.mergeMission(detail.mission);
      if (detail.mission.legacy) {
        this.context = null;
        return;
      }
      try {
        const context = await previewAssessmentMissionContext(projectId, missionId);
        if (
          this.workspaceProjectId === projectId &&
          this.selectedMissionId === missionId &&
          this._generation === owner
        ) {
          this.context = context;
        }
      } catch {
        this.context = null;
      }
    },

    async selectMission(missionId: number) {
      const projectId = this.workspaceProjectId;
      if (projectId === null) throw staleWorkspaceError();
      if (!this.missions.some((mission) => mission.id === missionId)) {
        throw new Error("任务不属于当前项目");
      }
      this.selectedMissionId = missionId;
      this.detail = null;
      this.context = null;
      const generation = ++this._generation;
      this.loading = true;
      try {
        await this.loadSelected(generation);
      } finally {
        if (this._generation === generation) this.loading = false;
      }
    },

    applyDetail(detail: AssessmentMissionDetail) {
      const projectId = this.workspaceProjectId;
      if (projectId === null || detail.mission.projectId !== projectId) {
        throw staleWorkspaceError();
      }
      this.selectedMissionId = detail.mission.id;
      this.detail = detail;
      this.mergeMission(detail.mission);
    },

    async create(input: CreateAssessmentMissionInput) {
      if (this.workspaceProjectId === null || input.projectId !== this.workspaceProjectId) {
        throw staleWorkspaceError();
      }
      this.mutating = true;
      try {
        const detail = await createAssessmentMission(input);
        this.applyDetail(detail);
        this.context = await previewAssessmentMissionContext(input.projectId, detail.mission.id);
        return detail;
      } finally {
        this.mutating = false;
      }
    },

    async confirmContext() {
      const detail = this.requireDetail();
      const context = this.context;
      if (!context) throw new Error("请先加载并检查 AI 上下文");
      this.mutating = true;
      try {
        this.applyDetail(
          await confirmAssessmentMissionContext({
            projectId: detail.mission.projectId,
            missionId: detail.mission.id,
            expectedRevision: detail.mission.revision,
            contextHash: context.contextHash,
          })
        );
        this.context = await previewAssessmentMissionContext(
          detail.mission.projectId,
          detail.mission.id
        );
      } finally {
        this.mutating = false;
      }
    },

    async attachResource(
      resourceType: "traffic" | "finding" | "assessment_run",
      sourceId: number
    ) {
      const detail = this.requireDetail();
      this.mutating = true;
      try {
        this.applyDetail(
          await attachAssessmentMissionResource({
            projectId: detail.mission.projectId,
            missionId: detail.mission.id,
            expectedRevision: detail.mission.revision,
            resourceType,
            sourceId,
          })
        );
        this.context = await previewAssessmentMissionContext(
          detail.mission.projectId,
          detail.mission.id
        );
      } finally {
        this.mutating = false;
      }
    },

    async importOpenApi() {
      const detail = this.requireDetail();
      const path = await pickAssessmentOpenApiFile();
      if (!path) return false;
      this.mutating = true;
      try {
        this.applyDetail(
          await importAssessmentMissionOpenApi({
            projectId: detail.mission.projectId,
            missionId: detail.mission.id,
            expectedRevision: detail.mission.revision,
            path,
          })
        );
        this.context = await previewAssessmentMissionContext(
          detail.mission.projectId,
          detail.mission.id
        );
        return true;
      } finally {
        this.mutating = false;
      }
    },

    async sendMessage(content: string) {
      const detail = this.requireDetail();
      this.mutating = true;
      try {
        this.applyDetail(
          await sendAssessmentMissionMessage({
            projectId: detail.mission.projectId,
            missionId: detail.mission.id,
            expectedRevision: detail.mission.revision,
            content,
          })
        );
      } finally {
        this.mutating = false;
      }
    },

    async decide(action: AssessmentAction, approve: boolean, applyToSameTool = false) {
      const detail = this.requireDetail();
      this.mutating = true;
      try {
        this.applyDetail(
          await decideAssessmentAction({
            projectId: detail.mission.projectId,
            missionId: detail.mission.id,
            actionId: action.id,
            expectedMissionRevision: detail.mission.revision,
            expectedActionRevision: action.revision,
            approve,
            applyToSameTool,
          })
        );
      } finally {
        this.mutating = false;
      }
    },

    async start() {
      const detail = this.requireDetail();
      this.mutating = true;
      try {
        this.applyDetail(
          await startAssessmentMission({
            projectId: detail.mission.projectId,
            missionId: detail.mission.id,
            expectedRevision: detail.mission.revision,
          })
        );
      } finally {
        this.mutating = false;
      }
    },

    async stop() {
      const detail = this.requireDetail();
      this.mutating = true;
      try {
        this.applyDetail(
          await stopAssessmentMission({
            projectId: detail.mission.projectId,
            missionId: detail.mission.id,
            expectedRevision: detail.mission.revision,
          })
        );
      } finally {
        this.mutating = false;
      }
    },

    async setPermission(toolId: string, decision: AssessmentToolPermissionDecision) {
      const detail = this.requireDetail();
      const current = detail.toolPermissions.find((item) => item.toolId === toolId);
      this.mutating = true;
      try {
        detail.toolPermissions = await setAssessmentToolPermission({
          projectId: detail.mission.projectId,
          toolId,
          decision,
          expectedRevision: current?.revision ?? null,
        });
        this.context = await previewAssessmentMissionContext(
          detail.mission.projectId,
          detail.mission.id
        );
      } finally {
        this.mutating = false;
      }
    },

    async createHandoff(action: AssessmentAction) {
      const detail = this.requireDetail();
      this.mutating = true;
      try {
        const handoff = await createAssessmentMissionHandoff({
          projectId: detail.mission.projectId,
          missionId: detail.mission.id,
          actionId: action.id,
          expectedActionRevision: action.revision,
        });
        await this.loadSelected();
        return handoff;
      } finally {
        this.mutating = false;
      }
    },

    async linkHandoff(handoffId: number, replayRunId: number) {
      const detail = this.requireDetail();
      this.mutating = true;
      try {
        const handoff = await linkAssessmentMissionHandoffReplay({
          projectId: detail.mission.projectId,
          missionId: detail.mission.id,
          handoffId,
          replayRunId,
        });
        await this.loadSelected();
        return handoff;
      } finally {
        this.mutating = false;
      }
    },

    requireDetail(): AssessmentMissionDetail {
      if (!this.detail || this.detail.mission.projectId !== this.workspaceProjectId) {
        throw staleWorkspaceError();
      }
      return this.detail;
    },

    async bindEvents() {
      await this.unbindEvents();
      this._unlisten = await listen<AssessmentMissionEvent>(
        "assessment:mission-event",
        ({ payload }) => {
          if (payload.projectId !== this.workspaceProjectId) return;
          const key = `${payload.missionId}:${payload.revision}:${payload.eventType}:${payload.actionId ?? ""}`;
          if (key === this._lastEventKey) return;
          this._lastEventKey = key;
          this.lastEvent = payload;
          const mission = this.missions.find((item) => item.id === payload.missionId);
          if (mission && payload.revision >= mission.revision) {
            mission.status = payload.status;
            mission.revision = payload.revision;
            mission.requestCount = payload.requestCount;
            mission.requestBudget = payload.requestBudget;
          }
          if (this.selectedMissionId !== payload.missionId) return;
          if (this._refreshTimer !== null) window.clearTimeout(this._refreshTimer);
          this._refreshTimer = window.setTimeout(() => {
            this._refreshTimer = null;
            void this.loadSelected().catch((error) => {
              this.error = String(error);
            });
          }, 100);
        }
      );
    },

    async unbindEvents() {
      this._unlisten?.();
      this._unlisten = null;
      if (this._refreshTimer !== null) {
        window.clearTimeout(this._refreshTimer);
        this._refreshTimer = null;
      }
    },
  },
});
