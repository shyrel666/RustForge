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

export const EMPTY_HOME_SUMMARY: HomeSummary = {
  trafficTotal: null,
  tasksDone: null,
  tasksTotal: null,
  pendingFindings: null,
};

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
