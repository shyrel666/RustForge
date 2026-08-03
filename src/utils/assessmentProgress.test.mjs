import test from "node:test";
import assert from "node:assert/strict";
import {
  assessmentProgressEventKey,
  isAssessmentProgressForWorkspace,
} from "./assessmentProgress.ts";

const progress = {
  projectId: 7,
  runId: 21,
  status: "executing",
  phase: "check_started",
  requestCount: 8,
  completedChecks: 3,
  occurredAt: "2026-08-01T08:00:00Z",
};

test("assessment progress is accepted only for the active project and selected run", () => {
  assert.equal(isAssessmentProgressForWorkspace(progress, 7, 7, 21), true);
  assert.equal(isAssessmentProgressForWorkspace(progress, 8, 8, 21), false);
  assert.equal(isAssessmentProgressForWorkspace(progress, 7, 8, 21), false);
  assert.equal(isAssessmentProgressForWorkspace(progress, 7, 7, 22), false);
  assert.equal(isAssessmentProgressForWorkspace(progress, null, 7, 21), false);
});

test("a late event is discarded after the workspace project changes", () => {
  const routeProjectId = 8;
  const workspaceProjectId = 8;
  assert.equal(
    isAssessmentProgressForWorkspace(
      progress,
      routeProjectId,
      workspaceProjectId,
      21,
    ),
    false,
  );
});

test("identical progress events produce an identical deduplication key", () => {
  assert.equal(
    assessmentProgressEventKey(progress),
    assessmentProgressEventKey({ ...progress }),
  );
});

test("a real transition is not mistaken for a duplicate event", () => {
  const first = assessmentProgressEventKey(progress);
  const next = assessmentProgressEventKey({
    ...progress,
    phase: "check_completed",
    completedChecks: 4,
    occurredAt: "2026-08-01T08:00:01Z",
  });
  assert.notEqual(first, next);
});
