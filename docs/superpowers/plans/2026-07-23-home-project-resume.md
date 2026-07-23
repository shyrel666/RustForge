# RustForge Home Project Resume Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the redundant module-launcher home page with a CC Switch-inspired current-project resume card, compact project statistics, and a recent-project list.

**Architecture:** Keep persistence and data aggregation in small TypeScript utilities so they can be tested with Node's built-in test runner and used without changing module-page stores. `AppShell` records valid project workspace visits, `HomeView` reads that history and independently loads summary data, and a dedicated topbar dialog component owns project creation.

**Tech Stack:** Vue 3 Composition API, TypeScript, Pinia, Vue Router, Element Plus, Tauri invoke APIs, Node 22 built-in test runner.

**Working tree note:** Implement in the current workspace because this feature depends on the uncommitted shell, token, and theme redesign already present there. Do not create commits unless the user explicitly requests them.

---

### Task 1: Add tested workspace-history behavior

**Files:**
- Create: `src/utils/workspaceHistory.test.mjs`
- Create: `src/utils/workspaceHistory.ts`
- Modify: `.gitignore`

- [ ] **Step 1: Ignore visual brainstorming artifacts**

Append `.superpowers/` to `.gitignore` so the local mockup server files do not enter Git status.

- [ ] **Step 2: Write failing workspace-history tests**

Create `src/utils/workspaceHistory.test.mjs` with Node's built-in runner. Using `.mjs` avoids adding Node type packages to the frontend TypeScript project.

```js
import test from "node:test";
import assert from "node:assert/strict";
import {
  formatRelativeVisit,
  getProjectMark,
  getResumePath,
  parseWorkspaceHistory,
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
  { id: 1, name: "当前", target_host: "one.test", scope: [], created_at: "2026-07-20T00:00:00Z" },
  { id: 2, name: "Alpha API", target_host: "two.test", scope: [], created_at: "2026-07-21T00:00:00Z" },
  { id: 3, name: "内部后台", target_host: "three.test", scope: [], created_at: "2026-07-22T00:00:00Z" },
];

test("parseWorkspaceHistory keeps only valid visits", () => {
  assert.deepEqual(
    parseWorkspaceHistory(JSON.stringify({
      1: { path: "/traffic", openedAt: 10 },
      2: { path: "/settings", openedAt: 20 },
      broken: null,
    })),
    { 1: { path: "/traffic", openedAt: 10 } },
  );
  assert.deepEqual(parseWorkspaceHistory("{not-json"), {});
});

test("recordWorkspaceVisit persists valid workspace routes only", () => {
  const storage = new MemoryStorage();
  recordWorkspaceVisit(2, "/tasks", 100, storage);
  recordWorkspaceVisit(2, "/settings", 200, storage);
  assert.deepEqual(parseWorkspaceHistory(storage.getItem("rustforge.workspace-history.v1")), {
    2: { path: "/tasks", openedAt: 100 },
  });
});

test("getResumePath falls back to traffic", () => {
  assert.equal(getResumePath(9, {}), "/traffic");
  assert.equal(getResumePath(2, { 2: { path: "/findings", openedAt: 100 } }), "/findings");
});

test("sortRecentProjects excludes current and prioritizes visit time", () => {
  const result = sortRecentProjects(
    projects,
    1,
    { 2: { path: "/traffic", openedAt: 50 }, 3: { path: "/tasks", openedAt: 100 } },
    5,
  );
  assert.deepEqual(result.map((project) => project.id), [3, 2]);
});

test("formatRelativeVisit and getProjectMark provide compact labels", () => {
  assert.equal(formatRelativeVisit(undefined, 120_000), "尚未打开");
  assert.equal(formatRelativeVisit(90_000, 120_000), "刚刚");
  assert.equal(formatRelativeVisit(60_000, 3_660_000), "1 小时前");
  assert.equal(getProjectMark("Alpha API"), "AA");
  assert.equal(getProjectMark("内部后台"), "内");
});
```

- [ ] **Step 3: Run the test and verify RED**

Run:

```powershell
node --test "src/utils/workspaceHistory.test.mjs"
```

Expected: FAIL because `src/utils/workspaceHistory.ts` does not exist.

- [ ] **Step 4: Implement the workspace-history utility**

Create `src/utils/workspaceHistory.ts` with:

```ts
import type { Project } from "../api/tauri";

export const WORKSPACE_PATHS = [
  "/traffic",
  "/repeater",
  "/tasks",
  "/findings",
] as const;

export type WorkspacePath = (typeof WORKSPACE_PATHS)[number];

export interface WorkspaceVisit {
  path: WorkspacePath;
  openedAt: number;
}

export type WorkspaceHistory = Record<string, WorkspaceVisit>;

export interface HistoryStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

export const WORKSPACE_HISTORY_KEY = "rustforge.workspace-history.v1";

const WORKSPACE_LABELS: Record<WorkspacePath, string> = {
  "/traffic": "流量分析",
  "/repeater": "请求重放",
  "/tasks": "任务树",
  "/findings": "发现",
};

function isWorkspacePath(value: unknown): value is WorkspacePath {
  return typeof value === "string" &&
    WORKSPACE_PATHS.includes(value as WorkspacePath);
}

export function parseWorkspaceHistory(raw: string | null): WorkspaceHistory {
  if (!raw) return {};
  try {
    const value: unknown = JSON.parse(raw);
    if (!value || typeof value !== "object" || Array.isArray(value)) return {};
    const history: WorkspaceHistory = {};
    for (const [projectId, candidate] of Object.entries(value)) {
      if (!/^[1-9]\d*$/.test(projectId) ||
          !candidate ||
          typeof candidate !== "object") continue;
      const visit = candidate as { path?: unknown; openedAt?: unknown };
      if (!isWorkspacePath(visit.path) ||
          typeof visit.openedAt !== "number" ||
          !Number.isFinite(visit.openedAt) ||
          visit.openedAt < 0) continue;
      history[projectId] = { path: visit.path, openedAt: visit.openedAt };
    }
    return history;
  } catch {
    return {};
  }
}

export function readWorkspaceHistory(
  storage: HistoryStorage = window.localStorage,
): WorkspaceHistory {
  return parseWorkspaceHistory(storage.getItem(WORKSPACE_HISTORY_KEY));
}

export function recordWorkspaceVisit(
  projectId: number,
  path: string,
  openedAt = Date.now(),
  storage: HistoryStorage = window.localStorage,
): WorkspaceHistory {
  const history = readWorkspaceHistory(storage);
  if (!isWorkspacePath(path) || !Number.isInteger(projectId) || projectId <= 0) {
    return history;
  }
  history[String(projectId)] = { path, openedAt };
  storage.setItem(WORKSPACE_HISTORY_KEY, JSON.stringify(history));
  return history;
}

export function getResumePath(
  projectId: number,
  history: WorkspaceHistory,
): WorkspacePath {
  return history[String(projectId)]?.path ?? "/traffic";
}

export function getWorkspaceLabel(path: WorkspacePath): string {
  return WORKSPACE_LABELS[path];
}

export function sortRecentProjects(
  projects: Project[],
  currentId: number | null,
  history: WorkspaceHistory,
  limit = 5,
): Project[] {
  return projects
    .filter((project) => project.id !== currentId)
    .sort((a, b) => {
      const aVisit = history[String(a.id)]?.openedAt;
      const bVisit = history[String(b.id)]?.openedAt;
      if (aVisit !== undefined && bVisit !== undefined) return bVisit - aVisit;
      if (aVisit !== undefined) return -1;
      if (bVisit !== undefined) return 1;
      return Date.parse(b.created_at) - Date.parse(a.created_at);
    })
    .slice(0, limit);
}

export function formatRelativeVisit(
  openedAt: number | undefined,
  now = Date.now(),
): string {
  if (openedAt === undefined) return "尚未打开";
  const elapsed = Math.max(0, now - openedAt);
  if (elapsed < 60_000) return "刚刚";
  if (elapsed < 3_600_000) return `${Math.floor(elapsed / 60_000)} 分钟前`;
  if (elapsed < 86_400_000) return `${Math.floor(elapsed / 3_600_000)} 小时前`;
  if (elapsed < 604_800_000) return `${Math.floor(elapsed / 86_400_000)} 天前`;
  return new Intl.DateTimeFormat("zh-CN", {
    month: "numeric",
    day: "numeric",
  }).format(openedAt);
}

export function getProjectMark(name: string): string {
  const trimmed = name.trim();
  if (!trimmed) return "RF";
  if (/^[\x00-\x7F]+$/.test(trimmed)) {
    return trimmed
      .split(/\s+/)
      .filter(Boolean)
      .slice(0, 2)
      .map((part) => part[0]?.toUpperCase())
      .join("") || "RF";
  }
  return [...trimmed][0] ?? "RF";
}
```

- [ ] **Step 5: Run the test and verify GREEN**

Run the same Node test command. Expected: 5 tests pass, 0 fail.

### Task 2: Add tested home-summary aggregation

**Files:**
- Create: `src/utils/homeSummary.test.mjs`
- Create: `src/utils/homeSummary.ts`

- [ ] **Step 1: Write failing aggregation tests**

Create tests that inject the Tauri boundary functions:

```js
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
    countTraffic: async () => { throw new Error("offline"); },
    getTaskTree: async () => [{ status: "todo" }],
    listPendingFindings: async () => { throw new Error("offline"); },
  });

  assert.deepEqual(summary, {
    trafficTotal: null,
    tasksDone: 0,
    tasksTotal: 1,
    pendingFindings: null,
  });
});
```

- [ ] **Step 2: Run the test and verify RED**

Run:

```powershell
node --test "src/utils/homeSummary.test.mjs"
```

Expected: FAIL because `src/utils/homeSummary.ts` does not exist.

- [ ] **Step 3: Implement independent aggregation**

Create:

```ts
export interface HomeSummary {
  trafficTotal: number | null;
  tasksDone: number | null;
  tasksTotal: number | null;
  pendingFindings: number | null;
}

export interface HomeSummaryApi {
  countTraffic(projectId: number): Promise<number>;
  getTaskTree(projectId: number): Promise<Array<{ status: string }>>;
  listPendingFindings(projectId: number): Promise<unknown[]>;
}

export async function loadHomeSummary(
  projectId: number,
  api: HomeSummaryApi,
): Promise<HomeSummary> {
  const [traffic, tasks, findings] = await Promise.allSettled([
    api.countTraffic(projectId),
    api.getTaskTree(projectId),
    api.listPendingFindings(projectId),
  ]);

  const taskItems = tasks.status === "fulfilled" ? tasks.value : null;
  return {
    trafficTotal: traffic.status === "fulfilled" ? traffic.value : null,
    tasksDone: taskItems
      ? taskItems.filter((task) => task.status === "done").length
      : null,
    tasksTotal: taskItems?.length ?? null,
    pendingFindings:
      findings.status === "fulfilled" ? findings.value.length : null,
  };
}
```

- [ ] **Step 4: Run both utility test files**

```powershell
node --test "src/utils/workspaceHistory.test.mjs" "src/utils/homeSummary.test.mjs"
```

Expected: 7 tests pass, 0 fail.

### Task 3: Extract the project-creation dialog

**Files:**
- Create: `src/components/ProjectCreateDialog.vue`
- Modify: `src/components/shell/AppTopbar.vue`

- [ ] **Step 1: Create `ProjectCreateDialog.vue`**

Move the existing project form and submit behavior from `AppTopbar` into a component using:

```ts
const visible = defineModel<boolean>({ default: false });
const project = useProjectStore();
const form = reactive({ name: "", target_host: "", scopeText: "" });
const saving = ref(false);

async function createProject() {
  if (!form.name.trim()) {
    ElMessage.warning("请填写项目名称");
    return;
  }
  saving.value = true;
  try {
    const scope = normalizeScopeList(form.scopeText.split(/[\n,;]+/));
    await project.create(form.name.trim(), form.target_host.trim(), scope);
    visible.value = false;
    form.name = form.target_host = form.scopeText = "";
    ElMessage.success("项目已创建");
  } catch (error) {
    ElMessage.error(String(error));
  } finally {
    saving.value = false;
  }
}
```

Retain the existing warning, field labels, placeholders, width, cancel action, and loading state.

- [ ] **Step 2: Replace the inline topbar dialog**

In `AppTopbar.vue`:

- remove `reactive`, `ElMessage`, `normalizeScopeList`, the form, saving state, and inline `createProject`;
- retain `const dialogVisible = ref(false)`;
- import `ProjectCreateDialog`;
- replace the inline `<el-dialog>` with:

```vue
<ProjectCreateDialog v-model="dialogVisible" />
```

- [ ] **Step 3: Run a production build**

Run `pnpm build`. Expected: TypeScript/Vite build succeeds.

### Task 4: Record project workspace visits

**Files:**
- Modify: `src/components/shell/AppShell.vue`

- [ ] **Step 1: Add the project/route watcher**

Import `watch`, `useProjectStore`, and `recordWorkspaceVisit`. Watch the tuple of current project ID and current route:

```ts
const project = useProjectStore();

watch(
  [() => project.current?.id ?? null, () => route.path],
  ([projectId, path]) => {
    if (projectId !== null) recordWorkspaceVisit(projectId, path);
  },
  { immediate: true },
);
```

The utility rejects `/`, `/settings`, and unknown routes, so this watcher cannot overwrite a valid project workspace with a non-workspace route.

- [ ] **Step 2: Run utility tests and build**

Run the two Node test files, then `pnpm build`. Expected: all tests and build pass.

### Task 5: Replace the home page

**Files:**
- Modify: `src/views/HomeView.vue`

- [ ] **Step 1: Replace module-launcher state with project-resume state**

The script must:

- import `countTraffic`, `getTaskTree`, `listFindings`, and `Project`;
- import the history and summary utilities;
- read history once when the home route mounts;
- derive the current visit and up to five recent projects;
- watch current project ID and load summary data;
- use a monotonically increasing request token to reject stale responses;
- switch project before routing when a recent project is resumed;
- default unknown resume paths to `/traffic`.

Use this request shape:

```ts
const summary = ref<HomeSummary>({
  trafficTotal: null,
  tasksDone: null,
  tasksTotal: null,
  pendingFindings: null,
});
const summaryLoading = ref(false);
let summaryRequest = 0;

async function refreshSummary(projectId: number | null) {
  const request = ++summaryRequest;
  summary.value = {
    trafficTotal: null,
    tasksDone: null,
    tasksTotal: null,
    pendingFindings: null,
  };
  summaryLoading.value = projectId !== null;
  if (projectId === null) return;

  try {
    const next = await loadHomeSummary(projectId, {
      countTraffic: (id) => countTraffic(id, {}),
      getTaskTree,
      listPendingFindings: (id) => listFindings(id, { status: "pending" }),
    });
    if (request === summaryRequest && project.current?.id === projectId) {
      summary.value = next;
    }
  } finally {
    if (request === summaryRequest) summaryLoading.value = false;
  }
}
```

`loadHomeSummary` already isolates expected per-source failures; the `finally` guard prevents an unexpected error from leaving the current request loading while also avoiding stale requests clearing a newer spinner.

- [ ] **Step 2: Implement the final approved template**

Render:

1. no-project empty state that directs the user to the top-right `+` without providing another create button;
2. when current exists, the “当前项目” label and focus card;
3. project mark, name, target fallback, Scope count, workspace label, and relative visit;
4. one “继续{工作区}” button;
5. the three-cell metric strip;
6. a recent-project section only when the computed list is non-empty;
7. when projects exist but no current project, a compact “请选择项目继续” prompt before the list.

Use semantic buttons for resume actions and visible `:focus-visible` styles.

- [ ] **Step 3: Implement token-driven responsive styles**

Required style behavior:

- `max-width: 760px`, centered, with larger top padding than module pages;
- focus card uses `--rf-bg-panel`, `--rf-border-strong`, and restrained `--rf-accent-muted`;
- metric strip uses internal borders rather than separate cards;
- recent projects share one rounded list container with row dividers;
- row hover uses `--rf-bg-hover`;
- narrow widths stack the focus CTA and allow metadata wrapping;
- no hardcoded dark background/text colors.

- [ ] **Step 4: Run tests and production build**

Run:

```powershell
node --test "src/utils/workspaceHistory.test.mjs" "src/utils/homeSummary.test.mjs"
pnpm build
```

Expected: 7 tests pass; Vite build succeeds.

### Task 6: Verify the completed behavior

**Files:**
- Check: `src/views/HomeView.vue`
- Check: `src/components/shell/AppShell.vue`
- Check: `src/components/shell/AppTopbar.vue`
- Check: `src/components/ProjectCreateDialog.vue`
- Check: `src/utils/workspaceHistory.ts`
- Check: `src/utils/homeSummary.ts`

- [ ] **Step 1: Check IDE diagnostics**

Read lints for all changed frontend files. Fix only newly introduced diagnostics.

- [ ] **Step 2: Exercise the running Tauri app**

Use the existing `pnpm tauri dev` process and verify:

- current project focus card and all three metrics;
- “继续” returns to the last of the four workspace routes;
- settings and home do not replace the remembered route;
- selecting a recent project switches the current project before navigation;
- a project without history falls back to traffic;
- empty/no-current states remain actionable;
- the home empty state directs users to the topbar, and project creation works there;
- dark and light themes remain readable;
- current window width has no horizontal overflow.

- [ ] **Step 3: Run final verification**

Run the complete Node test command and `pnpm build` again. Record exact pass/fail output before claiming completion.
