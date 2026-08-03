import test from "node:test";
import assert from "node:assert/strict";
import { loadHomeSummary } from "./homeSummary.ts";

test("loadHomeSummary returns traffic and the latest assessment result", async () => {
  const summary = await loadHomeSummary(7, {
    countTraffic: async () => 1284,
    listAssessmentRuns: async () => [{ id: 9, status: "completed" }],
    getAssessmentDetail: async () => ({
      verifications: [
        { verdict: "confirmed" },
        { verdict: "suspected" },
        { verdict: "suspected" },
        { verdict: "not_observed" },
      ],
    }),
  });

  assert.deepEqual(summary, {
    trafficTotal: 1284,
    latestAssessmentStatus: "completed",
    confirmedFindings: 1,
    suspectedFindings: 2,
  });
});

test("loadHomeSummary isolates partial failures", async () => {
  const summary = await loadHomeSummary(7, {
    countTraffic: async () => {
      throw new Error("offline");
    },
    listAssessmentRuns: async () => {
      throw new Error("offline");
    },
    getAssessmentDetail: async () => ({ verifications: [] }),
  });

  assert.deepEqual(summary, {
    trafficTotal: null,
    latestAssessmentStatus: null,
    confirmedFindings: null,
    suspectedFindings: null,
  });
});

test("loadHomeSummary keeps run status when detail loading fails", async () => {
  const summary = await loadHomeSummary(7, {
    countTraffic: async () => 0,
    listAssessmentRuns: async () => [{ id: 12, status: "stopped" }],
    getAssessmentDetail: async () => {
      throw new Error("detail unavailable");
    },
  });

  assert.deepEqual(summary, {
    trafficTotal: 0,
    latestAssessmentStatus: "stopped",
    confirmedFindings: null,
    suspectedFindings: null,
  });
});
