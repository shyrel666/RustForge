import { computed, ref, shallowRef } from "vue";

export type AppUpdateStatus =
  | "idle"
  | "checking"
  | "latest"
  | "available"
  | "downloading"
  | "installing"
  | "error";

export type UpdateDownloadEvent =
  | { event: "Started"; data: { contentLength?: number } }
  | { event: "Progress"; data: { chunkLength: number } }
  | { event: "Finished"; data?: Record<string, never> };

export interface UpdateHandle {
  currentVersion: string;
  version: string;
  body?: string | null;
  downloadAndInstall(
    onEvent: (event: UpdateDownloadEvent) => void,
  ): Promise<void>;
}

export interface AppUpdaterDependencies {
  check(): Promise<UpdateHandle | null>;
}

export interface CheckUpdateOptions {
  automatic?: boolean;
  silent?: boolean;
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

const RELEASE_NOT_FOUND_ERROR =
  "Could not fetch a valid release JSON from the remote";

export function isUpdaterReleaseNotFound(error: unknown): boolean {
  return errorText(error).includes(RELEASE_NOT_FOUND_ERROR);
}

export function createAppUpdater(dependencies: AppUpdaterDependencies) {
  const status = ref<AppUpdateStatus>("idle");
  const update = shallowRef<UpdateHandle | null>(null);
  const currentVersion = computed(() => update.value?.currentVersion ?? "");
  const targetVersion = computed(() => update.value?.version ?? "");
  const releaseNotes = computed(() => update.value?.body?.trim() ?? "");
  const downloadedBytes = ref(0);
  const totalBytes = ref<number | null>(null);
  const errorMessage = ref("");
  const automaticChecked = ref(false);
  const pendingUpdatePromptVersion = ref("");
  const promptedVersions = new Set<string>();
  let activeCheck: Promise<AppUpdateStatus> | null = null;

  const progressPercent = computed(() => {
    const total = totalBytes.value;
    if (!total || total <= 0) return null;
    return Math.min(
      100,
      Math.round((downloadedBytes.value / total) * 100),
    );
  });

  const busy = computed(
    () =>
      status.value === "checking" ||
      status.value === "downloading" ||
      status.value === "installing",
  );

  const showUpdateButton = computed(
    () =>
      update.value !== null &&
      ["available", "downloading", "installing", "error"].includes(
        status.value,
      ),
  );

  async function checkForUpdates(
    options: CheckUpdateOptions = {},
  ): Promise<AppUpdateStatus> {
    if (options.automatic && automaticChecked.value) return status.value;
    if (options.automatic) automaticChecked.value = true;
    if (activeCheck) return activeCheck;
    if (status.value === "downloading" || status.value === "installing") {
      return status.value;
    }

    activeCheck = (async () => {
      status.value = "checking";
      errorMessage.value = "";
      try {
        const result = await dependencies.check();
        update.value = result;
        if (result && !promptedVersions.has(result.version)) {
          pendingUpdatePromptVersion.value = result.version;
        } else if (!result) {
          pendingUpdatePromptVersion.value = "";
        }
        status.value = result ? "available" : "latest";
      } catch (error) {
        errorMessage.value = errorText(error);
        status.value = "error";
      }
      return status.value;
    })();

    try {
      return await activeCheck;
    } finally {
      activeCheck = null;
    }
  }

  function acknowledgeUpdatePrompt(version: string) {
    if (!version) return;
    promptedVersions.add(version);
    if (pendingUpdatePromptVersion.value === version) {
      pendingUpdatePromptVersion.value = "";
    }
  }

  function applyDownloadEvent(event: UpdateDownloadEvent) {
    if (event.event === "Started") {
      downloadedBytes.value = 0;
      totalBytes.value = event.data.contentLength ?? null;
    } else if (event.event === "Progress") {
      downloadedBytes.value += event.data.chunkLength;
    } else {
      status.value = "installing";
    }
  }

  async function downloadAndInstall(): Promise<boolean> {
    const candidate = update.value;
    if (!candidate || busy.value) return false;
    errorMessage.value = "";

    try {
      downloadedBytes.value = 0;
      totalBytes.value = null;
      status.value = "downloading";
      await candidate.downloadAndInstall(applyDownloadEvent);
      status.value = "installing";
      return true;
    } catch (error) {
      errorMessage.value = errorText(error);
      status.value = "error";
      return false;
    }
  }

  function resetError() {
    errorMessage.value = "";
    status.value = update.value ? "available" : "idle";
  }

  return {
    status,
    currentVersion,
    targetVersion,
    releaseNotes,
    downloadedBytes,
    totalBytes,
    progressPercent,
    errorMessage,
    automaticChecked,
    pendingUpdatePromptVersion,
    busy,
    showUpdateButton,
    checkForUpdates,
    acknowledgeUpdatePrompt,
    downloadAndInstall,
    resetError,
  };
}
