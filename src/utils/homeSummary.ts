export interface HomeSummary {
  trafficTotal: number | null;
  latestAssessmentStatus: string | null;
  confirmedFindings: number | null;
  suspectedFindings: number | null;
}

export interface HomeSummaryApi {
  countTraffic(projectId: number): Promise<number>;
  listAssessmentRuns(
    projectId: number,
  ): Promise<Array<{ id: number; status: string }>>;
  getAssessmentDetail(
    projectId: number,
    runId: number,
  ): Promise<{ verifications: Array<{ verdict: string }> }>;
}

export const EMPTY_HOME_SUMMARY: HomeSummary = {
  trafficTotal: null,
  latestAssessmentStatus: null,
  confirmedFindings: null,
  suspectedFindings: null,
};

export async function loadHomeSummary(
  projectId: number,
  api: HomeSummaryApi,
): Promise<HomeSummary> {
  const [traffic, runs] = await Promise.allSettled([
    api.countTraffic(projectId),
    api.listAssessmentRuns(projectId),
  ]);

  const latestRun = runs.status === "fulfilled" ? runs.value[0] : undefined;
  let verifications: Array<{ verdict: string }> | null = null;
  if (latestRun) {
    try {
      verifications = (
        await api.getAssessmentDetail(projectId, latestRun.id)
      ).verifications;
    } catch {
      verifications = null;
    }
  }

  return {
    trafficTotal: traffic.status === "fulfilled" ? traffic.value : null,
    latestAssessmentStatus: latestRun?.status ?? null,
    confirmedFindings: verifications
      ? verifications.filter((item) => item.verdict === "confirmed").length
      : null,
    suspectedFindings: verifications
      ? verifications.filter((item) => item.verdict === "suspected").length
      : null,
  };
}
