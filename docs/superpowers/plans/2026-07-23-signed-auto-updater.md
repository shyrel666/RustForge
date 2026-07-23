# RustForge Signed Auto-Updater Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add signed Windows x64 in-app updates from GitHub Releases, expose an automatic update button beside the RustForge brand, and remove the duplicated GitHub action from the About page.

**Architecture:** A tested updater controller owns all check/download/install state and receives Tauri operations through dependency injection. A thin adapter binds it to the official updater/process plugins; `AppShell` starts one silent check, while `AppTopbar` and `SettingsView` consume the same singleton state. Tauri config and a tag-triggered GitHub Actions workflow produce and distribute signed updater artifacts.

**Tech Stack:** Vue 3, TypeScript, Element Plus, Tauri 2, `@tauri-apps/plugin-updater`, `@tauri-apps/plugin-process`, Rust updater/process plugins, Node 22 test runner, GitHub Actions.

**Working tree note:** Continue in the existing dirty `main` workspace because this feature depends on the uncommitted UI redesign. Do not commit, push, tag, create a release, or configure remote Secrets unless the user explicitly requests it.

---

### Task 1: Generate the password-protected updater key

**Files:**
- Create outside repository: `%USERPROFILE%\.tauri\rustforge.key`
- Create outside repository: `%USERPROFILE%\.tauri\rustforge.key.pub`

- [ ] **Step 1: Have the user generate the key interactively**

The user runs this command in their own PowerShell terminal so the password is never exposed to the agent:

```powershell
pnpm tauri signer generate --write-keys "$HOME/.tauri/rustforge.key"
```

Expected: the CLI prompts for a password and creates the private/public key pair.

- [ ] **Step 2: Read only the public key**

Read `%USERPROFILE%\.tauri\rustforge.key.pub`. Never read or print the private key or password.

- [ ] **Step 3: Confirm secret handoff requirements**

Record only the GitHub Secret names:

```text
TAURI_SIGNING_PRIVATE_KEY
TAURI_SIGNING_PRIVATE_KEY_PASSWORD
```

Do not place their values in repository files.

### Task 2: Build the updater controller with TDD

**Files:**
- Create: `src/services/appUpdaterCore.test.mjs`
- Create: `src/services/appUpdaterCore.ts`

- [ ] **Step 1: Write failing controller tests**

Create `src/services/appUpdaterCore.test.mjs`:

```js
import test from "node:test";
import assert from "node:assert/strict";
import { createAppUpdater } from "./appUpdaterCore.ts";

function fakeUpdate(overrides = {}) {
  return {
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
    relaunch: async () => {},
  });

  await updater.checkForUpdates({ automatic: true, silent: true });
  await updater.checkForUpdates({ automatic: true, silent: true });
  await updater.checkForUpdates({ silent: false });

  assert.equal(checks, 2);
  assert.equal(updater.status.value, "latest");
});

test("available updates report progress, install, and relaunch", async () => {
  let relaunches = 0;
  const updater = createAppUpdater({
    check: async () => fakeUpdate(),
    relaunch: async () => {
      relaunches += 1;
    },
  });

  await updater.checkForUpdates();
  const installed = await updater.downloadAndInstall();

  assert.equal(installed, true);
  assert.equal(updater.targetVersion.value, "0.2.0");
  assert.equal(updater.downloadedBytes.value, 100);
  assert.equal(updater.totalBytes.value, 100);
  assert.equal(updater.progressPercent.value, 100);
  assert.equal(updater.status.value, "installing");
  assert.equal(relaunches, 1);
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
    relaunch: async () => {},
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
    relaunch: async () => {},
  });

  const first = updater.checkForUpdates();
  const second = updater.checkForUpdates();
  resolveCheck(null);
  await Promise.all([first, second]);

  assert.equal(checks, 1);
});
```

- [ ] **Step 2: Run the controller test and verify RED**

```powershell
node --test "src/services/appUpdaterCore.test.mjs"
```

Expected: FAIL because `appUpdaterCore.ts` does not exist.

- [ ] **Step 3: Implement the updater controller**

Create `src/services/appUpdaterCore.ts`:

```ts
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
  | { event: "Finished"; data: Record<string, never> };

export interface UpdateHandle {
  version: string;
  body?: string | null;
  downloadAndInstall(
    onEvent: (event: UpdateDownloadEvent) => void,
  ): Promise<void>;
}

export interface AppUpdaterDependencies {
  check(): Promise<UpdateHandle | null>;
  relaunch(): Promise<void>;
}

export interface CheckUpdateOptions {
  automatic?: boolean;
  silent?: boolean;
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function createAppUpdater(dependencies: AppUpdaterDependencies) {
  const status = ref<AppUpdateStatus>("idle");
  const update = shallowRef<UpdateHandle | null>(null);
  const targetVersion = computed(() => update.value?.version ?? "");
  const releaseNotes = computed(() => update.value?.body?.trim() ?? "");
  const downloadedBytes = ref(0);
  const totalBytes = ref<number | null>(null);
  const errorMessage = ref("");
  const automaticChecked = ref(false);
  const installed = ref(false);
  let activeCheck: Promise<AppUpdateStatus> | null = null;

  const progressPercent = computed(() => {
    const total = totalBytes.value;
    if (!total || total <= 0) return null;
    return Math.min(100, Math.round((downloadedBytes.value / total) * 100));
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
        installed.value = false;
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
      if (!installed.value) {
        downloadedBytes.value = 0;
        totalBytes.value = null;
        status.value = "downloading";
        await candidate.downloadAndInstall(applyDownloadEvent);
        installed.value = true;
      }
      status.value = "installing";
      await dependencies.relaunch();
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
    targetVersion,
    releaseNotes,
    downloadedBytes,
    totalBytes,
    progressPercent,
    errorMessage,
    automaticChecked,
    busy,
    showUpdateButton,
    checkForUpdates,
    downloadAndInstall,
    resetError,
  };
}
```

- [ ] **Step 4: Run the controller test and verify GREEN**

Run the same Node command. Expected: 4 tests pass.

### Task 3: Install and register official Tauri plugins

**Files:**
- Modify: `package.json`
- Modify: `pnpm-lock.yaml`
- Modify: `src-tauri/Cargo.toml`
- Modify: `src-tauri/Cargo.lock`
- Modify: `src-tauri/src/lib.rs`
- Modify: `src-tauri/capabilities/default.json`
- Modify: `src-tauri/tauri.conf.json`

- [ ] **Step 1: Add frontend packages using pnpm**

```powershell
pnpm add @tauri-apps/plugin-updater @tauri-apps/plugin-process
```

- [ ] **Step 2: Add Rust plugins using Cargo**

From `src-tauri`:

```powershell
cargo add tauri-plugin-updater --target 'cfg(any(target_os = "macos", windows, target_os = "linux"))'
cargo add tauri-plugin-process
```

- [ ] **Step 3: Register plugins**

In `src-tauri/src/lib.rs`, add process to the Builder and updater inside setup:

```rust
tauri::Builder::default()
    .plugin(tauri_plugin_process::init())
    .setup(|app| {
        #[cfg(desktop)]
        app.handle()
            .plugin(tauri_plugin_updater::Builder::new().build())?;
        // existing database setup follows
        Ok(())
    })
```

- [ ] **Step 4: Grant capabilities**

Append to `src-tauri/capabilities/default.json`:

```json
"updater:default",
"process:allow-restart"
```

- [ ] **Step 5: Configure updater artifacts and endpoint**

Read the generated `.pub` file from Task 1 and write its exact one-line content to `plugins.updater.pubkey`. Configure the remaining static values in `src-tauri/tauri.conf.json`:

```json
{
  "bundle": {
    "createUpdaterArtifacts": true
  },
  "plugins": {
    "updater": {
      "endpoints": [
        "https://github.com/shyrel666/RustForge/releases/latest/download/latest.json"
      ]
    }
  }
}
```

The final `updater` object contains both the real `pubkey` and the shown `endpoints`; no sample key or placeholder is allowed in the configuration.

- [ ] **Step 6: Run backend verification**

```powershell
cargo check --manifest-path "src-tauri/Cargo.toml"
```

Expected: exit code 0.

### Task 4: Bind the controller to Tauri and check automatically

**Files:**
- Create: `src/services/appUpdater.ts`
- Modify: `src/components/shell/AppShell.vue`

- [ ] **Step 1: Create the Tauri adapter**

```ts
import { relaunch } from "@tauri-apps/plugin-process";
import { check } from "@tauri-apps/plugin-updater";
import {
  createAppUpdater,
  type UpdateDownloadEvent,
} from "./appUpdaterCore";

const appUpdater = createAppUpdater({
  check: async () => {
    let update;
    try {
      update = await check();
    } catch (error) {
      const message = String(error);
      if (message.includes("404") || /not found/i.test(message)) return null;
      throw error;
    }
    if (!update) return null;
    return {
      version: update.version,
      body: update.body,
      downloadAndInstall: (onEvent) =>
        update.downloadAndInstall((event) => {
          onEvent(event as UpdateDownloadEvent);
        }),
    };
  },
  relaunch,
});

export function useAppUpdater() {
  return appUpdater;
}
```

- [ ] **Step 2: Start one silent check from `AppShell`**

Import `onMounted` and `useAppUpdater`, then add:

```ts
const updater = useAppUpdater();

onMounted(() => {
  void updater.checkForUpdates({ automatic: true, silent: true });
});
```

The controller catches failures, so startup remains non-blocking.

- [ ] **Step 3: Run controller tests and frontend build**

```powershell
node --test "src/services/appUpdaterCore.test.mjs"
pnpm build
```

Expected: tests and build pass.

### Task 5: Add the topbar update button

**Files:**
- Modify: `src/components/shell/AppTopbar.vue`

- [ ] **Step 1: Add updater state and confirmation**

Import `ElMessage`, `ElMessageBox`, `Top`, and `useAppUpdater`. Add:

```ts
const updater = useAppUpdater();

const updateButtonTitle = computed(() => {
  if (updater.status.value === "downloading") {
    const progress = updater.progressPercent.value;
    return progress === null
      ? "正在下载更新"
      : `正在下载更新 · ${progress}%`;
  }
  if (updater.status.value === "installing") return "正在安装更新";
  return `发现新版本 v${updater.targetVersion.value}`;
});

async function installAvailableUpdate() {
  if (updater.busy.value) return;
  try {
    const notes = updater.releaseNotes.value;
    await ElMessageBox.confirm(
      notes
        ? `发现新版本 v${updater.targetVersion.value}\n\n${notes}`
        : `发现新版本 v${updater.targetVersion.value}`,
      "应用更新",
      {
        confirmButtonText: "立即更新",
        cancelButtonText: "稍后",
        type: "info",
      },
    );
  } catch {
    return;
  }

  const succeeded = await updater.downloadAndInstall();
  if (!succeeded) {
    ElMessage.error(`更新失败：${updater.errorMessage.value}`);
  }
}
```

- [ ] **Step 2: Render the button beside the brand**

Wrap the brand and conditional update button in `.brand-group`:

```vue
<div class="brand-group">
  <div class="brand" @click="goHome">
    <span class="brand-text">RustForge</span>
  </div>
  <button
    v-if="updater.showUpdateButton.value"
    type="button"
    class="brand-update"
    :class="{ busy: updater.busy.value }"
    :title="updateButtonTitle"
    :aria-label="updateButtonTitle"
    :disabled="updater.busy.value"
    @click.stop="installAvailableUpdate"
  >
    <span
      v-if="
        updater.status.value === 'downloading' &&
        updater.progressPercent.value !== null
      "
      class="brand-update-progress"
    >
      {{ updater.progressPercent.value }}
    </span>
    <el-icon v-else :size="16"><Top /></el-icon>
  </button>
</div>
```

- [ ] **Step 3: Add token-driven styles**

The 30px circular button uses `--rf-accent`, `--rf-accent-muted`, `--rf-border`, and a visible `:focus-visible` outline. `brand-update-progress` renders the integer percentage without a `%` sign so it fits in the circle. An indeterminate download/install uses a restrained pulse and respects `prefers-reduced-motion`.

- [ ] **Step 4: Run frontend build**

Run `pnpm build`. Expected: exit code 0.

### Task 6: Simplify and connect the About page

**Files:**
- Modify: `src/views/SettingsView.vue`

- [ ] **Step 1: Remove duplicate/manual GitHub update code**

Remove:

- `Position` and `Download` icon imports;
- duplicate `LINK_HOME`/`LINK_GITHUB` constants, leaving one repository URL;
- `parseSemver`, `isNewer`, GitHub API `checkUpdate`, and `onUpdateClick`;
- local `checkingUpdate`, `updateStatus`, and `latestVersion` refs.

Import `Refresh` and `useAppUpdater`.

- [ ] **Step 2: Add manual recheck behavior**

```ts
const updater = useAppUpdater();

async function recheckUpdate() {
  const result = await updater.checkForUpdates({ silent: false });
  if (result === "latest") {
    ElMessage.success("当前已是最新版本");
  } else if (result === "available") {
    ElMessage.success(`发现新版本 v${updater.targetVersion.value}`);
  } else if (result === "error") {
    ElMessage.error(`检查更新失败：${updater.errorMessage.value}`);
  }
}
```

- [ ] **Step 3: Replace About actions**

Render exactly:

```vue
<el-button :icon="Link" @click="openExternal(LINK_GITHUB)">GitHub</el-button>
<el-button :icon="Document" @click="openExternal(LINK_CHANGELOG)">更新日志</el-button>
<el-button
  :icon="Refresh"
  :loading="updater.status.value === 'checking'"
  :disabled="
    updater.status.value === 'downloading' ||
    updater.status.value === 'installing'
  "
  @click="recheckUpdate"
>
  重新检查
</el-button>
```

Update banners to consume controller state and show available version, download percentage, install state, latest state, or error.

- [ ] **Step 4: Run frontend tests and build**

```powershell
node --test "src/services/appUpdaterCore.test.mjs"
pnpm exec tsc --noEmit
pnpm build
```

Expected: all commands pass.

### Task 7: Add the signed Windows release workflow

**Files:**
- Create: `.github/workflows/release.yml`

- [ ] **Step 1: Add the tag-triggered workflow**

```yaml
name: Release

on:
  push:
    tags:
      - "v*"

permissions:
  contents: write

jobs:
  release-windows:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4

      - uses: pnpm/action-setup@v4
        with:
          version: 9

      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: pnpm

      - uses: dtolnay/rust-toolchain@stable

      - uses: swatinem/rust-cache@v2
        with:
          workspaces: "./src-tauri -> target"

      - name: Install frontend dependencies
        run: pnpm install --frozen-lockfile

      - name: Build and publish signed updater
        uses: tauri-apps/tauri-action@v0
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          TAURI_SIGNING_PRIVATE_KEY: ${{ secrets.TAURI_SIGNING_PRIVATE_KEY }}
          TAURI_SIGNING_PRIVATE_KEY_PASSWORD: ${{ secrets.TAURI_SIGNING_PRIVATE_KEY_PASSWORD }}
        with:
          tagName: v__VERSION__
          releaseName: "RustForge v__VERSION__"
          releaseBody: "See the assets below to download and install this version."
          releaseDraft: false
          prerelease: false
          args: "--target x86_64-pc-windows-msvc"
```

- [ ] **Step 2: Validate workflow structure locally**

Read the YAML and confirm:

- tag trigger is `v*`;
- permissions include `contents: write`;
- all three environment variables are present;
- target is Windows x64;
- no secret values are embedded.

Do not push a tag or create a release.

### Task 8: Final verification and handoff

**Files:**
- Check all files changed by Tasks 1–7.

- [ ] **Step 1: Run automated verification**

```powershell
node --test "src/utils/workspaceHistory.test.mjs" "src/utils/homeSummary.test.mjs" "src/services/appUpdaterCore.test.mjs"
pnpm exec tsc --noEmit
pnpm build
cargo check --manifest-path "src-tauri/Cargo.toml"
```

- [ ] **Step 2: Check IDE diagnostics and diff whitespace**

Read diagnostics for all changed TypeScript, Vue, Rust, JSON, and YAML files. Run scoped `git diff --check`.

- [ ] **Step 3: Verify the development app remains usable**

Confirm the existing `pnpm tauri dev` process reloads without frontend or Rust runtime errors. A missing GitHub Release may make the silent check fail, but it must not display a startup error or block the app.

- [ ] **Step 4: Report the required remote setup**

Tell the user to add:

1. encrypted private key content as `TAURI_SIGNING_PRIVATE_KEY`;
2. key password as `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`;
3. GitHub Actions read/write workflow permission if not already enabled.

Do not claim end-to-end updating is verified until a signed test Release has been published and installed from an older build.
