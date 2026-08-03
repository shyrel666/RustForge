import test from "node:test";
import assert from "node:assert/strict";
import {
  formatRelativeVisit,
  getProjectMark,
  getResumePath,
  parseWorkspaceHistory,
  readWorkspaceHistory,
  recordWorkspaceVisit,
  sortRecentProjects,
} from "./workspaceHistory.ts";

class MemoryStorage {
  values = new Map();

  getItem(key) {
    return this.values.get(key) ?? null;
  }

  setItem(key, value) {
    this.values.set(key, value);
  }
}

const projects = [
  {
    id: 1,
    name: "当前",
    target_host: "one.test",
    scope: [],
    created_at: "2026-07-20T00:00:00Z",
  },
  {
    id: 2,
    name: "Alpha API",
    target_host: "two.test",
    scope: [],
    created_at: "2026-07-21T00:00:00Z",
  },
  {
    id: 3,
    name: "内部后台",
    target_host: "three.test",
    scope: [],
    created_at: "2026-07-22T00:00:00Z",
  },
];

test("parseWorkspaceHistory keeps only valid visits", () => {
  assert.deepEqual(
    parseWorkspaceHistory(
      JSON.stringify({
        1: { path: "/traffic", openedAt: 10 },
        2: { path: "/settings", openedAt: 20 },
        broken: null,
      }),
    ),
    { 1: { path: "/traffic", openedAt: 10 } },
  );
  assert.deepEqual(parseWorkspaceHistory("{not-json"), {});
});

test("recordWorkspaceVisit persists valid workspace routes only", () => {
  const storage = new MemoryStorage();

  recordWorkspaceVisit(2, "/tasks", 100, storage);
  recordWorkspaceVisit(2, "/settings", 200, storage);

  assert.deepEqual(
    parseWorkspaceHistory(
      storage.getItem("rustforge.workspace-history.v1"),
    ),
    { 2: { path: "/tasks", openedAt: 100 } },
  );
});

test("getResumePath falls back to AI assessment", () => {
  assert.equal(getResumePath(9, {}), "/tasks");
  assert.equal(
    getResumePath(2, { 2: { path: "/findings", openedAt: 100 } }),
    "/findings",
  );
});

test("sortRecentProjects excludes current and prioritizes visit time", () => {
  const result = sortRecentProjects(
    projects,
    1,
    {
      2: { path: "/traffic", openedAt: 50 },
      3: { path: "/tasks", openedAt: 100 },
    },
    5,
  );

  assert.deepEqual(
    result.map((project) => project.id),
    [3, 2],
  );
});

test("sortRecentProjects falls back to project creation time", () => {
  const result = sortRecentProjects(projects, null, {}, 2);

  assert.deepEqual(
    result.map((project) => project.id),
    [3, 2],
  );
});

test("formatRelativeVisit and getProjectMark provide compact labels", () => {
  assert.equal(formatRelativeVisit(undefined, 120_000), "尚未打开");
  assert.equal(formatRelativeVisit(90_000, 120_000), "刚刚");
  assert.equal(formatRelativeVisit(60_000, 3_660_000), "1 小时前");
  assert.equal(getProjectMark("Alpha API"), "AA");
  assert.equal(getProjectMark("内部后台"), "内");
});

test("storage access failures never break workspace navigation", () => {
  const unavailableStorage = {
    getItem() {
      throw new Error("storage unavailable");
    },
    setItem() {
      throw new Error("storage unavailable");
    },
  };

  assert.deepEqual(readWorkspaceHistory(unavailableStorage), {});
  assert.deepEqual(
    recordWorkspaceVisit(2, "/repeater", 300, unavailableStorage),
    { 2: { path: "/repeater", openedAt: 300 } },
  );
});
