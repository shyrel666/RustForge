import test from "node:test";
import assert from "node:assert/strict";
import {
  createAppUpdater,
  isUpdaterReleaseNotFound,
} from "./appUpdaterCore.ts";

function fakeUpdate(overrides = {}) {
  return {
    currentVersion: "0.1.0",
    version: "0.2.0",
    body: "New release",
    async downloadAndInstall(onEvent) {
      onEvent({ event: "Started", data: { contentLength: 100 } });
      onEvent({ event: "Progress", data: { chunkLength: 40 } });
      onEvent({ event: "Progress", data: { chunkLength: 60 } });
      onEvent({ event: "Finished", data: {} });
    },
    ...overrides,
  };
}

test("automatic update checks run once while manual checks can repeat", async () => {
  let checks = 0;
  const updater = createAppUpdater({
    check: async () => {
      checks += 1;
      return null;
    },
  });

  await updater.checkForUpdates({ automatic: true, silent: true });
  await updater.checkForUpdates({ automatic: true, silent: true });
  await updater.checkForUpdates({ silent: false });

  assert.equal(checks, 2);
  assert.equal(updater.status.value, "latest");
});

test("available updates report progress and hand off to the installer", async () => {
  const updater = createAppUpdater({
    check: async () => fakeUpdate(),
  });

  await updater.checkForUpdates();
  const installed = await updater.downloadAndInstall();

  assert.equal(installed, true);
  assert.equal(updater.currentVersion.value, "0.1.0");
  assert.equal(updater.targetVersion.value, "0.2.0");
  assert.equal(updater.downloadedBytes.value, 100);
  assert.equal(updater.totalBytes.value, 100);
  assert.equal(updater.progressPercent.value, 100);
  assert.equal(updater.status.value, "installing");
});

test("each detected version queues one automatic prompt per app session", async () => {
  let version = "0.2.0";
  const updater = createAppUpdater({
    check: async () => fakeUpdate({ version }),
  });

  await updater.checkForUpdates({ automatic: true, silent: true });
  assert.equal(updater.pendingUpdatePromptVersion.value, "0.2.0");

  updater.acknowledgeUpdatePrompt("0.2.0");
  assert.equal(updater.pendingUpdatePromptVersion.value, "");

  await updater.checkForUpdates();
  assert.equal(updater.pendingUpdatePromptVersion.value, "");

  version = "0.3.0";
  await updater.checkForUpdates();
  assert.equal(updater.pendingUpdatePromptVersion.value, "0.3.0");
});

test("failed downloads preserve the update and can be retried", async () => {
  let attempts = 0;
  const update = fakeUpdate({
    async downloadAndInstall() {
      attempts += 1;
      if (attempts === 1) throw new Error("network interrupted");
    },
  });
  const updater = createAppUpdater({
    check: async () => update,
  });

  await updater.checkForUpdates();
  assert.equal(await updater.downloadAndInstall(), false);
  assert.equal(updater.status.value, "error");
  assert.equal(updater.showUpdateButton.value, true);
  assert.match(updater.errorMessage.value, /network interrupted/);

  assert.equal(await updater.downloadAndInstall(), true);
  assert.equal(attempts, 2);
});

test("checks are deduplicated while one is in flight", async () => {
  let resolveCheck;
  let checks = 0;
  const updater = createAppUpdater({
    check: () => {
      checks += 1;
      return new Promise((resolve) => {
        resolveCheck = resolve;
      });
    },
  });

  const first = updater.checkForUpdates();
  const second = updater.checkForUpdates();
  resolveCheck(null);
  await Promise.all([first, second]);

  assert.equal(checks, 1);
});

test("unknown download sizes keep percentage indeterminate", async () => {
  const updater = createAppUpdater({
    check: async () =>
      fakeUpdate({
        async downloadAndInstall(onEvent) {
          onEvent({ event: "Started", data: {} });
          onEvent({ event: "Progress", data: { chunkLength: 64 } });
          onEvent({ event: "Finished", data: {} });
        },
      }),
  });

  await updater.checkForUpdates();
  await updater.downloadAndInstall();

  assert.equal(updater.downloadedBytes.value, 64);
  assert.equal(updater.totalBytes.value, null);
  assert.equal(updater.progressPercent.value, null);
});

test("concurrent installs only invoke the updater once", async () => {
  let installs = 0;
  let finishInstall;
  const updater = createAppUpdater({
    check: async () =>
      fakeUpdate({
        downloadAndInstall() {
          installs += 1;
          return new Promise((resolve) => {
            finishInstall = resolve;
          });
        },
      }),
  });

  await updater.checkForUpdates();
  const first = updater.downloadAndInstall();
  const second = updater.downloadAndInstall();
  finishInstall();

  assert.equal(await second, false);
  assert.equal(await first, true);
  assert.equal(installs, 1);
});

test("only Tauri ReleaseNotFound errors are treated as no release", () => {
  assert.equal(
    isUpdaterReleaseNotFound(
      new Error("Could not fetch a valid release JSON from the remote"),
    ),
    true,
  );
  assert.equal(isUpdaterReleaseNotFound(new Error("HTTP 404 proxy error")), false);
  assert.equal(isUpdaterReleaseNotFound(new Error("invalid updater signature")), false);
});
