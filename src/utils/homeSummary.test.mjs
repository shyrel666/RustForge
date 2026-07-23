import test from "node:test";
import assert from "node:assert/strict";
import { loadHomeSummary } from "./homeSummary.ts";

test("loadHomeSummary returns traffic, task progress, and pending findings", async () => {
  const summary = await loadHomeSummary(7, {
    countTraffic: async () => 1284,
    getTaskTree: async () => [
      { status: "done" },
      { status: "todo" },
      { status: "done" },
    ],
    listPendingFindings: async () => [{}, {}, {}, {}],
  });

  assert.deepEqual(summary, {
    trafficTotal: 1284,
    tasksDone: 2,
    tasksTotal: 3,
    pendingFindings: 4,
  });
});

test("loadHomeSummary isolates partial failures", async () => {
  const summary = await loadHomeSummary(7, {
    countTraffic: async () => {
      throw new Error("offline");
    },
    getTaskTree: async () => [{ status: "todo" }],
    listPendingFindings: async () => {
      throw new Error("offline");
    },
  });

  assert.deepEqual(summary, {
    trafficTotal: null,
    tasksDone: 0,
    tasksTotal: 1,
    pendingFindings: null,
  });
});

test("loadHomeSummary keeps task metrics unavailable when task loading fails", async () => {
  const summary = await loadHomeSummary(7, {
    countTraffic: async () => 0,
    getTaskTree: async () => {
      throw new Error("offline");
    },
    listPendingFindings: async () => [],
  });

  assert.deepEqual(summary, {
    trafficTotal: 0,
    tasksDone: null,
    tasksTotal: null,
    pendingFindings: 0,
  });
});
