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
  return (
    typeof value === "string" &&
    WORKSPACE_PATHS.includes(value as WorkspacePath)
  );
}

export function parseWorkspaceHistory(raw: string | null): WorkspaceHistory {
  if (!raw) return {};

  try {
    const value: unknown = JSON.parse(raw);
    if (!value || typeof value !== "object" || Array.isArray(value)) return {};

    const history: WorkspaceHistory = {};
    for (const [projectId, candidate] of Object.entries(value)) {
      if (
        !/^[1-9]\d*$/.test(projectId) ||
        !candidate ||
        typeof candidate !== "object"
      ) {
        continue;
      }

      const visit = candidate as { path?: unknown; openedAt?: unknown };
      if (
        !isWorkspacePath(visit.path) ||
        typeof visit.openedAt !== "number" ||
        !Number.isFinite(visit.openedAt) ||
        visit.openedAt < 0
      ) {
        continue;
      }

      history[projectId] = {
        path: visit.path,
        openedAt: visit.openedAt,
      };
    }
    return history;
  } catch {
    return {};
  }
}

export function readWorkspaceHistory(
  storage: HistoryStorage = window.localStorage,
): WorkspaceHistory {
  try {
    return parseWorkspaceHistory(storage.getItem(WORKSPACE_HISTORY_KEY));
  } catch {
    return {};
  }
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
  try {
    storage.setItem(WORKSPACE_HISTORY_KEY, JSON.stringify(history));
  } catch {
    // Persistence is best-effort; navigation must keep working without storage.
  }
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

      if (aVisit !== undefined && bVisit !== undefined) {
        return bVisit - aVisit;
      }
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
  if (elapsed < 3_600_000) {
    return `${Math.floor(elapsed / 60_000)} 分钟前`;
  }
  if (elapsed < 86_400_000) {
    return `${Math.floor(elapsed / 3_600_000)} 小时前`;
  }
  if (elapsed < 604_800_000) {
    return `${Math.floor(elapsed / 86_400_000)} 天前`;
  }
  return new Intl.DateTimeFormat("zh-CN", {
    month: "numeric",
    day: "numeric",
  }).format(openedAt);
}

export function getProjectMark(name: string): string {
  const trimmed = name.trim();
  if (!trimmed) return "RF";

  if (/^[\x00-\x7F]+$/.test(trimmed)) {
    return (
      trimmed
        .split(/\s+/)
        .filter(Boolean)
        .slice(0, 2)
        .map((part) => part[0]?.toUpperCase())
        .join("") || "RF"
    );
  }

  return [...trimmed][0] ?? "RF";
}
