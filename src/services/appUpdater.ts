import { check } from "@tauri-apps/plugin-updater";
import {
  createAppUpdater,
  isUpdaterReleaseNotFound,
  type UpdateDownloadEvent,
} from "./appUpdaterCore";

const appUpdater = createAppUpdater({
  check: async () => {
    let update;
    try {
      update = await check();
    } catch (error) {
      if (isUpdaterReleaseNotFound(error)) return null;
      throw error;
    }

    if (!update) return null;

    return {
      currentVersion: update.currentVersion,
      version: update.version,
      body: update.body,
      downloadAndInstall: (onEvent) =>
        update.downloadAndInstall((event) => {
          onEvent(event as UpdateDownloadEvent);
        }),
    };
  },
});

export function useAppUpdater() {
  return appUpdater;
}
