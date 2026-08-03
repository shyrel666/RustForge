export interface AssessmentProgressIdentity {
  projectId: number;
  runId: number;
  status: string;
  phase: string;
  requestCount: number;
  completedChecks: number;
  occurredAt: string;
}

/**
 * Progress events are workspace-local. An event from a project that has just
 * been left, or from a non-selected historical run, must never update the
 * visible assessment.
 */
export function isAssessmentProgressForWorkspace(
  progress: AssessmentProgressIdentity,
  routeProjectId: number | null,
  workspaceProjectId: number | null,
  selectedRunId: number | null,
): boolean {
  return (
    routeProjectId !== null &&
    progress.projectId === routeProjectId &&
    workspaceProjectId === routeProjectId &&
    progress.runId === selectedRunId
  );
}

/**
 * Tauri event delivery and a persisted-detail refresh may expose the same
 * transition more than once. Keep the key limited to stable event identity
 * fields so the store can ignore an exact duplicate without losing a later
 * transition.
 */
export function assessmentProgressEventKey(
  progress: AssessmentProgressIdentity,
): string {
  return [
    progress.runId,
    progress.status,
    progress.phase,
    progress.requestCount,
    progress.completedChecks,
    progress.occurredAt,
  ].join(":");
}
