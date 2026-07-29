export interface DiagnosticJob {
  label: string;
  run: () => Promise<void>;
}

export interface DiagnosticRunResult {
  failures: string[];
}

export const DEFAULT_DIAGNOSTIC_TIMEOUT_MS = 15_000;

function describeError(error: unknown): string {
  if (error instanceof Error && error.message.trim()) {
    return error.message.trim();
  }
  const text = String(error).trim();
  return text || "未知错误";
}

async function withTimeout(
  operation: Promise<void>,
  timeoutMs: number,
): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      reject(
        new Error(
          `读取超过 ${Math.max(1, Math.ceil(timeoutMs / 1_000))} 秒`,
        ),
      );
    }, timeoutMs);
  });

  try {
    await Promise.race([operation, timeout]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

export async function runDiagnosticJobs(
  jobs: DiagnosticJob[],
  timeoutMs = DEFAULT_DIAGNOSTIC_TIMEOUT_MS,
): Promise<DiagnosticRunResult> {
  const outcomes = await Promise.all(
    jobs.map(async (job) => {
      try {
        await withTimeout(job.run(), timeoutMs);
        return null;
      } catch (error) {
        return `${job.label}：${describeError(error)}`;
      }
    }),
  );

  return {
    failures: outcomes.filter((failure): failure is string => failure !== null),
  };
}
