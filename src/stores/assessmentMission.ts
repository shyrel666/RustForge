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
    _loadingOwner: 0,
    _mutationOwner: 0,
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
      this._loadingOwner = 0;
      this._mutationOwner = 0;
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
      this._loadingOwner = generation;
      this._mutationOwner = 0;
      this.mutating = false;
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
        if (this._loadingOwner === generation) {
          this.loading = false;
          this._loadingOwner = 0;
        }
      }
    },

    async loadSelected(generation?: number) {
      const owner = generation ?? ++this._generation;
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
        if (
          this.workspaceProjectId === projectId &&
          this.selectedMissionId === missionId &&
          this._generation === owner
        ) {
          this.context = null;
        }
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
      this._loadingOwner = generation;
      this._mutationOwner = 0;
      this.mutating = false;
      this.loading = true;
      try {
        await this.loadSelected(generation);
      } finally {
        if (this._loadingOwner === generation) {
          this.loading = false;
          this._loadingOwner = 0;
        }
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

    beginMutation(projectId: number, missionId: number | null) {
      if (
        this.workspaceProjectId !== projectId ||
        (missionId !== null && this.selectedMissionId !== missionId)
      ) {
        throw staleWorkspaceError();
      }
      const generation = ++this._generation;
      this._loadingOwner = 0;
      this.loading = false;
      this._mutationOwner = generation;
      this.mutating = true;
      return generation;
    },

    ownsMutation(projectId: number, missionId: number | null, generation: number) {
      return (
        this.workspaceProjectId === projectId &&
        this._generation === generation &&
        this._mutationOwner === generation &&
        (missionId === null || this.selectedMissionId === missionId)
      );
    },

    finishMutation(generation: number) {
      if (this._mutationOwner !== generation) return;
      this._mutationOwner = 0;
      this.mutating = false;
    },

    async create(input: CreateAssessmentMissionInput) {
      if (this.workspaceProjectId === null || input.projectId !== this.workspaceProjectId) {
        throw staleWorkspaceError();
      }
      const generation = this.beginMutation(input.projectId, null);
      try {
        const detail = await createAssessmentMission(input);
        if (!this.ownsMutation(input.projectId, null, generation)) return detail;
        this.applyDetail(detail);
        const context = await previewAssessmentMissionContext(
          input.projectId,
          detail.mission.id
        );
        if (this.ownsMutation(input.projectId, detail.mission.id, generation)) {
          this.context = context;
        }
        return detail;
      } finally {
        this.finishMutation(generation);
      }
    },

    async confirmContext() {
      const detail = this.requireDetail();
      const context = this.context;
      if (!context) throw new Error("请先加载并检查 AI 上下文");
      const projectId = detail.mission.projectId;
      const missionId = detail.mission.id;
      const generation = this.beginMutation(projectId, missionId);
      try {
        const updated = await confirmAssessmentMissionContext({
          projectId,
          missionId,
          expectedRevision: detail.mission.revision,
          contextHash: context.contextHash,
        });
        if (!this.ownsMutation(projectId, missionId, generation)) return;
        this.applyDetail(updated);
        const nextContext = await previewAssessmentMissionContext(projectId, missionId);
        if (this.ownsMutation(projectId, missionId, generation)) {
          this.context = nextContext;
        }
      } finally {
        this.finishMutation(generation);
      }
    },

    async attachResource(
      resourceType: "traffic" | "finding" | "assessment_run",
      sourceId: number
    ) {
      const detail = this.requireDetail();
      const projectId = detail.mission.projectId;
      const missionId = detail.mission.id;
      const generation = this.beginMutation(projectId, missionId);
      try {
        const updated = await attachAssessmentMissionResource({
          projectId,
          missionId,
          expectedRevision: detail.mission.revision,
          resourceType,
          sourceId,
        });
        if (!this.ownsMutation(projectId, missionId, generation)) return;
        this.applyDetail(updated);
        const context = await previewAssessmentMissionContext(projectId, missionId);
        if (this.ownsMutation(projectId, missionId, generation)) {
          this.context = context;
        }
      } finally {
        this.finishMutation(generation);
      }
    },

    async importOpenApi() {
      const detail = this.requireDetail();
      const path = await pickAssessmentOpenApiFile();
      if (!path) return false;
      const projectId = detail.mission.projectId;
      const missionId = detail.mission.id;
      const generation = this.beginMutation(projectId, missionId);
      try {
        const updated = await importAssessmentMissionOpenApi({
          projectId,
          missionId,
          expectedRevision: detail.mission.revision,
          path,
        });
        if (!this.ownsMutation(projectId, missionId, generation)) return true;
        this.applyDetail(updated);
        const context = await previewAssessmentMissionContext(projectId, missionId);
        if (this.ownsMutation(projectId, missionId, generation)) {
          this.context = context;
        }
        return true;
      } finally {
        this.finishMutation(generation);
      }
    },

    async sendMessage(content: string) {
      const detail = this.requireDetail();
      const projectId = detail.mission.projectId;
      const missionId = detail.mission.id;
      const generation = this.beginMutation(projectId, missionId);
      try {
        const updated = await sendAssessmentMissionMessage({
          projectId,
          missionId,
          expectedRevision: detail.mission.revision,
          content,
        });
        if (this.ownsMutation(projectId, missionId, generation)) {
          this.applyDetail(updated);
        }
      } finally {
        this.finishMutation(generation);
      }
    },

    async decide(action: AssessmentAction, approve: boolean, applyToSameTool = false) {
      const detail = this.requireDetail();
      const projectId = detail.mission.projectId;
      const missionId = detail.mission.id;
      const generation = this.beginMutation(projectId, missionId);
      try {
        const updated = await decideAssessmentAction({
          projectId,
          missionId,
          actionId: action.id,
          expectedMissionRevision: detail.mission.revision,
          expectedActionRevision: action.revision,
          approve,
          applyToSameTool,
        });
        if (this.ownsMutation(projectId, missionId, generation)) {
          this.applyDetail(updated);
        }
      } finally {
        this.finishMutation(generation);
      }
    },

    async start() {
      const detail = this.requireDetail();
      const projectId = detail.mission.projectId;
      const missionId = detail.mission.id;
      const generation = this.beginMutation(projectId, missionId);
      try {
        const updated = await startAssessmentMission({
          projectId,
          missionId,
          expectedRevision: detail.mission.revision,
        });
        if (this.ownsMutation(projectId, missionId, generation)) {
          this.applyDetail(updated);
        }
      } finally {
        this.finishMutation(generation);
      }
    },

    async stop() {
      const detail = this.requireDetail();
      const projectId = detail.mission.projectId;
      const missionId = detail.mission.id;
      const generation = this.beginMutation(projectId, missionId);
      try {
        const updated = await stopAssessmentMission({
          projectId,
          missionId,
          expectedRevision: detail.mission.revision,
        });
        if (this.ownsMutation(projectId, missionId, generation)) {
          this.applyDetail(updated);
        }
      } finally {
        this.finishMutation(generation);
      }
    },

    async setPermission(toolId: string, decision: AssessmentToolPermissionDecision) {
      const detail = this.requireDetail();
      const current = detail.toolPermissions.find((item) => item.toolId === toolId);
      const projectId = detail.mission.projectId;
      const missionId = detail.mission.id;
      const generation = this.beginMutation(projectId, missionId);
      try {
        const permissions = await setAssessmentToolPermission({
          projectId,
          toolId,
          decision,
          expectedRevision: current?.revision ?? null,
        });
        if (!this.ownsMutation(projectId, missionId, generation)) return;
        if (this.detail) this.detail.toolPermissions = permissions;
        const context = await previewAssessmentMissionContext(projectId, missionId);
        if (this.ownsMutation(projectId, missionId, generation)) {
          this.context = context;
        }
      } finally {
        this.finishMutation(generation);
      }
    },

    async createHandoff(action: AssessmentAction) {
      const detail = this.requireDetail();
      const projectId = detail.mission.projectId;
      const missionId = detail.mission.id;
      const generation = this.beginMutation(projectId, missionId);
      try {
        const handoff = await createAssessmentMissionHandoff({
          projectId,
          missionId,
          actionId: action.id,
          expectedActionRevision: action.revision,
        });
        if (this.ownsMutation(projectId, missionId, generation)) {
          await this.loadSelected(generation);
        }
        return handoff;
      } finally {
        this.finishMutation(generation);
      }
    },

    async linkHandoff(handoffId: number, replayRunId: number) {
      const detail = this.requireDetail();
      const projectId = detail.mission.projectId;
      const missionId = detail.mission.id;
      const generation = this.beginMutation(projectId, missionId);
      try {
        const handoff = await linkAssessmentMissionHandoffReplay({
          projectId,
          missionId,
          handoffId,
          replayRunId,
        });
        if (this.ownsMutation(projectId, missionId, generation)) {
          await this.loadSelected(generation);
        }
        return handoff;
      } finally {
        this.finishMutation(generation);
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
          const refreshSelected = () => {
            this._refreshTimer = null;
            if (this.mutating) {
              this._refreshTimer = window.setTimeout(refreshSelected, 100);
              return;
            }
            void this.loadSelected().catch((error) => {
              this.error = String(error);
            });
          };
          this._refreshTimer = window.setTimeout(refreshSelected, 100);
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
